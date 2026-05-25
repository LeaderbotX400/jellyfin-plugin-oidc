using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Jellyfin.Database.Implementations.Enums;
using Jellyfin.Plugin.OIDC.Configuration;
using Jellyfin.Plugin.OIDC.Services;
using MediaBrowser.Controller.Library;
using MediaBrowser.Model.Activity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Xunit;

namespace Jellyfin.Plugin.OIDC.Integration.Tests;

/// <summary>
/// End-to-end test for the scheduled re-sync task. Builds a real DI container so the
/// task's <c>IServiceScopeFactory</c> can resolve a real <c>RbacService</c> per user.
/// </summary>
public sealed class RbacResyncTaskTests
{
    // ── helpers ─────────────────────────────────────────────────────────────

    private static (ServiceProvider sp, OidcUserStore oidcStore, FakeUserStore userStore, TestPluginConfigProvider configProvider)
        BuildContainer(PluginConfiguration? config = null, Mock<IActivityManager>? activityMock = null)
    {
        var userStore = new FakeUserStore();
        var oidcStore = new OidcUserStore(Path.Combine(Path.GetTempPath(), $"resync-test-{Guid.NewGuid():N}.json"));
        var configProvider = new TestPluginConfigProvider
        {
            Configuration = config ?? new PluginConfiguration
            {
                RoleMappings = new List<RoleMapping>
                {
                    new() { RoleName = "admin", IsAdmin = true },
                    new() { RoleName = "user", IsAdmin = false, EnableMediaPlayback = true }
                }
            }
        };

        var services = new ServiceCollection();
        services.AddSingleton(oidcStore);
        services.AddSingleton(FakeJellyfinFactory.CreateUserManager(userStore).Object);
        services.AddSingleton(FakeJellyfinFactory.CreateLibraryManager().Object);
        services.AddSingleton((activityMock ?? FakeJellyfinFactory.CreateActivityManager()).Object);
        services.AddSingleton<IPluginConfigProvider>(configProvider);
        services.AddLogging();
        services.AddScoped<RbacService>();
        var sp = services.BuildServiceProvider();

        return (sp, oidcStore, userStore, configProvider);
    }

    private static RbacResyncTask BuildTask(ServiceProvider sp, OidcUserStore oidcStore, TestPluginConfigProvider configProvider)
        => new RbacResyncTask(
            sp.GetRequiredService<IServiceScopeFactory>(),
            oidcStore,
            configProvider,
            NullLogger<RbacResyncTask>.Instance);

    // ── existing tests (updated for new 4-arg constructor) ──────────────────

    [Fact]
    public async Task ExecuteAsync_ReappliesPermissionsForAllStoredUsers()
    {
        var (sp, oidcStore, userStore, configProvider) = BuildContainer();

        var alice = userStore.CreateUser("alice");
        var bob = userStore.CreateUser("bob");

        await oidcStore.UpsertAsync(new OidcUserRecord
        {
            UserId = alice.Id,
            Username = "alice",
            Sub = "sub-alice",
            ProviderId = "idp",
            Roles = new[] { "admin" },
            Entitlements = Array.Empty<string>()
        });
        await oidcStore.UpsertAsync(new OidcUserRecord
        {
            UserId = bob.Id,
            Username = "bob",
            Sub = "sub-bob",
            ProviderId = "idp",
            Roles = new[] { "user" },
            Entitlements = Array.Empty<string>()
        });

        var task = BuildTask(sp, oidcStore, configProvider);
        await task.ExecuteAsync(new Progress<double>(), CancellationToken.None);

        Assert.True(HasPermission(alice, PermissionKind.IsAdministrator));
        Assert.False(HasPermission(bob, PermissionKind.IsAdministrator));
        Assert.True(HasPermission(bob, PermissionKind.EnableMediaPlayback));
    }

    [Fact]
    public async Task ExecuteAsync_NoStoredUsers_CompletesQuietly()
    {
        var (sp, oidcStore, _, configProvider) = BuildContainer();

        var task = BuildTask(sp, oidcStore, configProvider);
        // Must not throw
        await task.ExecuteAsync(new Progress<double>(), CancellationToken.None);
    }

    // ── new tests ────────────────────────────────────────────────────────────

    [Fact]
    public async Task ConcurrentExecutions_SecondCallSkips()
    {
        // Arrange: one user. We block task1 inside UpdateUserAsync (truly async) so that
        // task2 can observe _runState=1 and skip, without thread-blocking the test.
        var userStore = new FakeUserStore();
        var oidcStore = new OidcUserStore(Path.Combine(Path.GetTempPath(), $"resync-conc-{Guid.NewGuid():N}.json"));

        var alice = userStore.CreateUser("alice");
        await oidcStore.UpsertAsync(new OidcUserRecord
        {
            UserId = alice.Id,
            Username = "alice",
            Sub = "sub-alice",
            ProviderId = "idp",
            Roles = new[] { "admin" },
            Entitlements = Array.Empty<string>()
        });

        var activityLogs = new List<Jellyfin.Database.Implementations.Entities.ActivityLog>();
        var activityMock = new Mock<IActivityManager>();
        activityMock
            .Setup(m => m.CreateAsync(It.IsAny<Jellyfin.Database.Implementations.Entities.ActivityLog>()))
            .Callback<Jellyfin.Database.Implementations.Entities.ActivityLog>(e => { lock (activityLogs) activityLogs.Add(e); })
            .Returns(Task.CompletedTask);

        // Gate that holds task1 inside UpdateUserAsync (an async call) until we release it.
        var updateGate = new SemaphoreSlim(0, 1);
        var updateStarted = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);

        var userManagerMock = new Mock<IUserManager>();
        userManagerMock.Setup(m => m.GetUserById(alice.Id)).Returns(alice);
        userManagerMock.Setup(m => m.UpdateUserAsync(It.IsAny<Jellyfin.Database.Implementations.Entities.User>()))
            .Returns(async () =>
            {
                updateStarted.TrySetResult(true);
                await updateGate.WaitAsync(); // truly async wait — does NOT block threads
            });

        var configProvider = new TestPluginConfigProvider
        {
            Configuration = new PluginConfiguration
            {
                RoleMappings = new List<RoleMapping>
                {
                    new() { RoleName = "admin", IsAdmin = true }
                }
            }
        };

        var services = new ServiceCollection();
        services.AddSingleton(oidcStore);
        services.AddSingleton(userManagerMock.Object);
        services.AddSingleton(FakeJellyfinFactory.CreateLibraryManager().Object);
        services.AddSingleton(activityMock.Object);
        services.AddSingleton<IPluginConfigProvider>(configProvider);
        services.AddLogging();
        services.AddScoped<RbacService>();
        var sp = services.BuildServiceProvider();

        var task1 = BuildTask(sp, oidcStore, configProvider);
        var task2 = BuildTask(sp, oidcStore, configProvider);

        // Launch task1 without awaiting — it will block inside UpdateUserAsync
        var t1 = task1.ExecuteAsync(new Progress<double>(), CancellationToken.None);

        // Wait until task1 is inside UpdateUserAsync (i.e. _runState is definitely 1)
        await updateStarted.Task;

        // Now launch task2 — it should see _runState=1 and return immediately
        var t2 = task2.ExecuteAsync(new Progress<double>(), CancellationToken.None);
        await t2; // should complete very quickly (skipped)

        // Release task1
        updateGate.Release();
        await t1;

        // task1 wrote exactly one OidcResyncCompleted entry; task2 wrote none
        lock (activityLogs)
        {
            var completionEntries = activityLogs.FindAll(e => e.Type == "OidcResyncCompleted");
            Assert.Single(completionEntries);
        }
    }

    [Fact]
    public async Task ConfigChangedMidRun_StillUsesSnapshot()
    {
        // Arrange: configA grants admin; configB does NOT grant admin.
        var configA = new PluginConfiguration
        {
            RoleMappings = new List<RoleMapping>
            {
                new() { RoleName = "admin", IsAdmin = true }
            }
        };
        var configB = new PluginConfiguration
        {
            RoleMappings = new List<RoleMapping>() // no mappings
        };

        var userStore = new FakeUserStore();
        var oidcStore = new OidcUserStore(Path.Combine(Path.GetTempPath(), $"resync-snap-{Guid.NewGuid():N}.json"));

        var alice = userStore.CreateUser("alice");
        var bob = userStore.CreateUser("bob");

        await oidcStore.UpsertAsync(new OidcUserRecord
        {
            UserId = alice.Id, Username = "alice", Sub = "sub-alice", ProviderId = "idp",
            Roles = new[] { "admin" }, Entitlements = Array.Empty<string>()
        });
        await oidcStore.UpsertAsync(new OidcUserRecord
        {
            UserId = bob.Id, Username = "bob", Sub = "sub-bob", ProviderId = "idp",
            Roles = new[] { "admin" }, Entitlements = Array.Empty<string>()
        });

        var configProvider = new TestPluginConfigProvider { Configuration = configA };

        var services = new ServiceCollection();
        services.AddSingleton(oidcStore);
        services.AddSingleton(FakeJellyfinFactory.CreateUserManager(userStore).Object);
        services.AddSingleton(FakeJellyfinFactory.CreateLibraryManager().Object);
        services.AddSingleton(FakeJellyfinFactory.CreateActivityManager().Object);
        services.AddSingleton<IPluginConfigProvider>(configProvider);
        services.AddLogging();
        services.AddScoped<RbacService>();
        var sp = services.BuildServiceProvider();

        // Switch to configB AFTER the task object is created but BEFORE the loop processes bob.
        // We intercept via a callback config provider that switches on second call.
        var callCount = 0;
        var switchingProvider = new CallbackPluginConfigProvider(() =>
        {
            callCount++;
            // First call (snapshot) returns configA; any subsequent calls would return configB.
            // The snapshot overload means subsequent calls should NOT happen during the loop.
            return callCount == 1 ? configA : configB;
        });

        var task = new RbacResyncTask(
            sp.GetRequiredService<IServiceScopeFactory>(),
            oidcStore,
            switchingProvider,
            NullLogger<RbacResyncTask>.Instance);

        await task.ExecuteAsync(new Progress<double>(), CancellationToken.None);

        // Both alice and bob should be admin because configA was snapshotted at task start.
        Assert.True(HasPermission(alice, PermissionKind.IsAdministrator));
        Assert.True(HasPermission(bob, PermissionKind.IsAdministrator));

        // Config was read exactly once (the snapshot).
        Assert.Equal(1, callCount);
    }

    [Fact]
    public async Task PerUserFailure_OtherUsersStillSucceed_CountsAccurate()
    {
        var userStore = new FakeUserStore();
        var oidcStore = new OidcUserStore(Path.Combine(Path.GetTempPath(), $"resync-fail-{Guid.NewGuid():N}.json"));

        var alice = userStore.CreateUser("alice");
        var bob = userStore.CreateUser("bob");  // will fail
        var carol = userStore.CreateUser("carol");

        await oidcStore.UpsertAsync(new OidcUserRecord
        {
            UserId = alice.Id, Username = "alice", Sub = "sub-alice", ProviderId = "idp",
            Roles = new[] { "admin" }, Entitlements = Array.Empty<string>()
        });
        await oidcStore.UpsertAsync(new OidcUserRecord
        {
            UserId = bob.Id, Username = "bob", Sub = "sub-bob", ProviderId = "idp",
            Roles = new[] { "admin" }, Entitlements = Array.Empty<string>()
        });
        await oidcStore.UpsertAsync(new OidcUserRecord
        {
            UserId = carol.Id, Username = "carol", Sub = "sub-carol", ProviderId = "idp",
            Roles = new[] { "admin" }, Entitlements = Array.Empty<string>()
        });

        // UserManager that throws for bob
        var userManagerMock = new Mock<IUserManager>();
        userManagerMock.Setup(m => m.GetUserById(alice.Id)).Returns(alice);
        userManagerMock.Setup(m => m.GetUserById(bob.Id)).Throws(new InvalidOperationException("simulated failure for bob"));
        userManagerMock.Setup(m => m.GetUserById(carol.Id)).Returns(carol);
        userManagerMock.Setup(m => m.UpdateUserAsync(It.IsAny<Jellyfin.Database.Implementations.Entities.User>()))
            .Returns(Task.CompletedTask);

        var activityMock = new Mock<IActivityManager>();
        string? summaryEntry = null;
        Microsoft.Extensions.Logging.LogLevel? summarySeverity = null;
        activityMock
            .Setup(m => m.CreateAsync(It.IsAny<Jellyfin.Database.Implementations.Entities.ActivityLog>()))
            .Callback<Jellyfin.Database.Implementations.Entities.ActivityLog>(e =>
            {
                if (e.Type == "OidcResyncCompleted")
                {
                    summaryEntry = e.Name;
                    summarySeverity = e.LogSeverity;
                }
            })
            .Returns(Task.CompletedTask);

        var configProvider = new TestPluginConfigProvider
        {
            Configuration = new PluginConfiguration
            {
                RoleMappings = new List<RoleMapping>
                {
                    new() { RoleName = "admin", IsAdmin = true }
                }
            }
        };

        var services = new ServiceCollection();
        services.AddSingleton(oidcStore);
        services.AddSingleton(userManagerMock.Object);
        services.AddSingleton(FakeJellyfinFactory.CreateLibraryManager().Object);
        services.AddSingleton(activityMock.Object);
        services.AddSingleton<IPluginConfigProvider>(configProvider);
        services.AddLogging();
        services.AddScoped<RbacService>();
        var sp = services.BuildServiceProvider();

        var task = BuildTask(sp, oidcStore, configProvider);
        await task.ExecuteAsync(new Progress<double>(), CancellationToken.None);

        // Alice and Carol succeeded, Bob failed
        Assert.True(HasPermission(alice, PermissionKind.IsAdministrator));
        Assert.True(HasPermission(carol, PermissionKind.IsAdministrator));

        // Summary must mention 2 updated, 1 failed
        Assert.NotNull(summaryEntry);
        Assert.Contains("2 updated", summaryEntry);
        Assert.Contains("1 failed", summaryEntry);
        // Failure count > 0 => severity must be Warning
        Assert.Equal(Microsoft.Extensions.Logging.LogLevel.Warning, summarySeverity);
    }

    [Fact]
    public async Task CancellationToken_StopsLoop()
    {
        var userStore = new FakeUserStore();
        var oidcStore = new OidcUserStore(Path.Combine(Path.GetTempPath(), $"resync-cancel-{Guid.NewGuid():N}.json"));

        // Add 3 users; we'll cancel after processing 1
        var alice = userStore.CreateUser("alice");
        var bob = userStore.CreateUser("bob");
        var carol = userStore.CreateUser("carol");

        await oidcStore.UpsertAsync(new OidcUserRecord
        {
            UserId = alice.Id, Username = "alice", Sub = "sub-alice", ProviderId = "idp",
            Roles = new[] { "user" }, Entitlements = Array.Empty<string>()
        });
        await oidcStore.UpsertAsync(new OidcUserRecord
        {
            UserId = bob.Id, Username = "bob", Sub = "sub-bob", ProviderId = "idp",
            Roles = new[] { "user" }, Entitlements = Array.Empty<string>()
        });
        await oidcStore.UpsertAsync(new OidcUserRecord
        {
            UserId = carol.Id, Username = "carol", Sub = "sub-carol", ProviderId = "idp",
            Roles = new[] { "user" }, Entitlements = Array.Empty<string>()
        });

        var cts = new CancellationTokenSource();
        int applyCount = 0;

        // UserManager that cancels after the first UpdateUserAsync
        var userManagerMock = FakeJellyfinFactory.CreateUserManager(userStore);
        userManagerMock.Setup(m => m.UpdateUserAsync(It.IsAny<Jellyfin.Database.Implementations.Entities.User>()))
            .Returns<Jellyfin.Database.Implementations.Entities.User>(u =>
            {
                applyCount++;
                if (applyCount >= 1)
                    cts.Cancel();
                return Task.CompletedTask;
            });

        string? cancellationEntry = null;
        var activityMock = new Mock<IActivityManager>();
        activityMock
            .Setup(m => m.CreateAsync(It.IsAny<Jellyfin.Database.Implementations.Entities.ActivityLog>()))
            .Callback<Jellyfin.Database.Implementations.Entities.ActivityLog>(e =>
            {
                if (e.Type == "OidcResyncCancelled")
                    cancellationEntry = e.Name;
            })
            .Returns(Task.CompletedTask);

        var configProvider = new TestPluginConfigProvider
        {
            Configuration = new PluginConfiguration
            {
                RoleMappings = new List<RoleMapping>
                {
                    new() { RoleName = "user", EnableMediaPlayback = true }
                }
            }
        };

        var services = new ServiceCollection();
        services.AddSingleton(oidcStore);
        services.AddSingleton(userManagerMock.Object);
        services.AddSingleton(FakeJellyfinFactory.CreateLibraryManager().Object);
        services.AddSingleton(activityMock.Object);
        services.AddSingleton<IPluginConfigProvider>(configProvider);
        services.AddLogging();
        services.AddScoped<RbacService>();
        var sp = services.BuildServiceProvider();

        var task = BuildTask(sp, oidcStore, configProvider);
        await task.ExecuteAsync(new Progress<double>(), cts.Token);

        // Task completed without throwing (cancellation is handled gracefully)
        // Fewer than all 3 users were processed
        Assert.True(applyCount < 3, $"Expected fewer than 3 applies, got {applyCount}");

        // A cancellation activity entry must have been written
        Assert.NotNull(cancellationEntry);
        Assert.Contains("cancelled", cancellationEntry, StringComparison.OrdinalIgnoreCase);
    }

    // ── test helpers ─────────────────────────────────────────────────────────

    private static bool HasPermission(Jellyfin.Database.Implementations.Entities.User user, PermissionKind kind)
    {
        foreach (var p in user.Permissions)
        {
            if (p.Kind == kind) return p.Value;
        }

        return false;
    }
}

/// <summary>Config provider that delegates to a user-supplied factory, enabling call-count tracking.</summary>
internal sealed class CallbackPluginConfigProvider : IPluginConfigProvider
{
    private readonly Func<Jellyfin.Plugin.OIDC.Configuration.PluginConfiguration> _factory;
    public CallbackPluginConfigProvider(Func<Jellyfin.Plugin.OIDC.Configuration.PluginConfiguration> factory)
        => _factory = factory;

    public Jellyfin.Plugin.OIDC.Configuration.PluginConfiguration GetConfiguration() => _factory();
}
