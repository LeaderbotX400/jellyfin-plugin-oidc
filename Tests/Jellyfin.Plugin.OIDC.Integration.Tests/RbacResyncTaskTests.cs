using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Jellyfin.Data;
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
    [Fact]
    public async Task ExecuteAsync_ReappliesPermissionsForAllStoredUsers()
    {
        // Two stored OIDC users — one had "admin" role, one had "user".
        // We change the role mappings AFTER they logged in and verify the resync
        // applies the NEW mappings without requiring them to re-authenticate.
        var userStore = new FakeUserStore();
        var alice = userStore.CreateUser("alice");
        var bob = userStore.CreateUser("bob");

        var oidcStore = new OidcUserStore(Path.Combine(Path.GetTempPath(), $"resync-test-{Guid.NewGuid():N}.json"));
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

        var configProvider = new TestPluginConfigProvider
        {
            Configuration = new PluginConfiguration
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
        services.AddSingleton(FakeJellyfinFactory.CreateActivityManager().Object);
        services.AddSingleton<IPluginConfigProvider>(configProvider);
        services.AddLogging();
        services.AddScoped<RbacService>();
        var sp = services.BuildServiceProvider();

        var task = new RbacResyncTask(
            sp.GetRequiredService<IServiceScopeFactory>(),
            oidcStore,
            NullLogger<RbacResyncTask>.Instance);

        var progress = new Progress<double>();
        await task.ExecuteAsync(progress, CancellationToken.None);

        // Alice was "admin" — should have IsAdministrator now
        Assert.True(HasPermission(alice, PermissionKind.IsAdministrator));
        // Bob was "user" — should NOT be admin but should have media playback
        Assert.False(HasPermission(bob, PermissionKind.IsAdministrator));
        Assert.True(HasPermission(bob, PermissionKind.EnableMediaPlayback));
    }

    [Fact]
    public async Task ExecuteAsync_NoStoredUsers_CompletesQuietly()
    {
        var oidcStore = new OidcUserStore(Path.Combine(Path.GetTempPath(), $"resync-empty-{Guid.NewGuid():N}.json"));
        var configProvider = new TestPluginConfigProvider();

        var services = new ServiceCollection();
        services.AddSingleton(oidcStore);
        services.AddSingleton(new Mock<IUserManager>().Object);
        services.AddSingleton(new Mock<ILibraryManager>().Object);
        services.AddSingleton(new Mock<IActivityManager>().Object);
        services.AddSingleton<IPluginConfigProvider>(configProvider);
        services.AddLogging();
        services.AddScoped<RbacService>();
        var sp = services.BuildServiceProvider();

        var task = new RbacResyncTask(
            sp.GetRequiredService<IServiceScopeFactory>(),
            oidcStore,
            NullLogger<RbacResyncTask>.Instance);

        var reported = new List<double>();
        var progress = new Progress<double>(p => reported.Add(p));
        await task.ExecuteAsync(progress, CancellationToken.None);

        // Progress reporting is async; we just need to confirm the task didn't throw
        // and exited the early-return path. No assertion on progress count.
    }

    /// <summary>
    /// Resync of the only admin: the admin bit must be preserved and an activity-log entry must be created.
    /// </summary>
    [Fact]
    public async Task ExecuteAsync_LastAdminDemotion_PreservesAdminBitAndLogsActivity()
    {
        var userStore = new FakeUserStore();
        // alice is the sole admin
        var alice = userStore.CreateUser("alice");
        alice.SetPermission(PermissionKind.IsAdministrator, true);

        var oidcStore = new OidcUserStore(Path.Combine(Path.GetTempPath(), $"resync-lastadmin-{Guid.NewGuid():N}.json"));
        await oidcStore.UpsertAsync(new OidcUserRecord
        {
            UserId = alice.Id,
            Username = "alice",
            Sub = "sub-alice",
            ProviderId = "idp",
            // "user" role maps to IsAdmin=false — which would demote her
            Roles = new[] { "user" },
            Entitlements = Array.Empty<string>()
        });

        var configProvider = new TestPluginConfigProvider
        {
            Configuration = new PluginConfiguration
            {
                AllowLastAdminDemotion = false,
                RoleMappings = new List<RoleMapping>
                {
                    new() { RoleName = "user", IsAdmin = false, EnableMediaPlayback = true }
                }
            }
        };

        var activityManager = FakeJellyfinFactory.CreateActivityManager();
        var services = new ServiceCollection();
        services.AddSingleton(oidcStore);
        services.AddSingleton(FakeJellyfinFactory.CreateUserManager(userStore).Object);
        services.AddSingleton(FakeJellyfinFactory.CreateLibraryManager().Object);
        services.AddSingleton(activityManager.Object);
        services.AddSingleton<IPluginConfigProvider>(configProvider);
        services.AddLogging();
        services.AddScoped<RbacService>();
        var sp = services.BuildServiceProvider();

        var task = new RbacResyncTask(
            sp.GetRequiredService<IServiceScopeFactory>(),
            oidcStore,
            NullLogger<RbacResyncTask>.Instance);

        await task.ExecuteAsync(new Progress<double>(), CancellationToken.None);

        // Admin bit must be preserved even though the role mapping says IsAdmin=false
        Assert.True(HasPermission(alice, PermissionKind.IsAdministrator),
            "Last-admin bit must be preserved during resync");

        // An activity log entry must have been written for the block event
        activityManager.Verify(
            m => m.CreateAsync(It.Is<Jellyfin.Database.Implementations.Entities.ActivityLog>(
                entry => entry.Name.Contains("last-admin", StringComparison.OrdinalIgnoreCase))),
            Times.AtLeastOnce,
            "Expected an activity-log entry for the last-admin block event");
    }

    private static bool HasPermission(Jellyfin.Database.Implementations.Entities.User user, PermissionKind kind)
    {
        foreach (var p in user.Permissions)
        {
            if (p.Kind == kind) return p.Value;
        }

        return false;
    }
}
