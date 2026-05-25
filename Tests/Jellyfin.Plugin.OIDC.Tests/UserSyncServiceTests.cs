using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Jellyfin.Data;
using Jellyfin.Database.Implementations.Entities;
using Jellyfin.Database.Implementations.Enums;
using Jellyfin.Plugin.OIDC.Configuration;
using Jellyfin.Plugin.OIDC.Services;
using MediaBrowser.Controller.Library;
using MediaBrowser.Model.Activity;
using MediaBrowser.Model.Entities;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Xunit;

namespace Jellyfin.Plugin.OIDC.Tests;

/// <summary>
/// Tests for <see cref="UserSyncService"/> — specifically the account-takeover prevention
/// introduced in task-04. The original code auto-bound any incoming OIDC <c>sub</c> to a
/// local user whose name happened to match <c>preferred_username</c>, which is an
/// attacker-controlled value at most IdPs.
/// </summary>
public sealed class UserSyncServiceTests : IDisposable
{
    private const string ProviderId = "testidp";
    private readonly string _tempDir;
    private readonly TestConfigProvider _config = new();
    private readonly FakeUserStore _userStore = new();
    private readonly IUserManager _users;
    private readonly OidcUserStore _store;
    private readonly RbacService _rbac;
    private readonly UserSyncService _sync;

    public UserSyncServiceTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "oidc_sync_test_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tempDir);
        _store = new OidcUserStore(Path.Combine(_tempDir, "store.json"));

        // Moq-based IUserManager wired to a shared in-memory store (mirrors the integration-test fakes).
        var userManagerMock = new Mock<IUserManager>();
        userManagerMock.Setup(m => m.GetUserById(It.IsAny<Guid>()))
            .Returns<Guid>(id => _userStore.ById.TryGetValue(id, out var u) ? u : null);
        userManagerMock.Setup(m => m.GetUserByName(It.IsAny<string>()))
            .Returns<string>(name => _userStore.ByName.TryGetValue(name, out var id) ? _userStore.ById[id] : null);
        userManagerMock.Setup(m => m.CreateUserAsync(It.IsAny<string>()))
            .Returns<string>(name => Task.FromResult(_userStore.CreateUser(name)));
        userManagerMock.Setup(m => m.UpdateUserAsync(It.IsAny<User>()))
            .Returns<User>(u => { _userStore.ById[u.Id] = u; return Task.CompletedTask; });
        userManagerMock.Setup(m => m.ChangePassword(It.IsAny<User>(), It.IsAny<string>()))
            .Returns(Task.CompletedTask);
        _users = userManagerMock.Object;

        // RbacService needs ILibraryManager + IActivityManager; supply Moq stubs.
        var libMock = new Mock<ILibraryManager>();
        libMock.Setup(m => m.GetVirtualFolders()).Returns(new List<VirtualFolderInfo>());
        var actMock = new Mock<IActivityManager>();
        actMock.Setup(m => m.CreateAsync(It.IsAny<ActivityLog>()))
            .Returns(Task.CompletedTask);

        _rbac = new RbacService(_users, libMock.Object, actMock.Object, _config, NullLogger<RbacService>.Instance);
        _sync = new UserSyncService(_users, _rbac, _store, _config, NullLogger<UserSyncService>.Instance);

        _config.Configuration.AutoCreateUsers = true;
        _config.Configuration.Providers.Add(new OidcProviderConfig
        {
            ProviderId = ProviderId,
            Enabled = true
        });
    }

    public void Dispose()
    {
        try { Directory.Delete(_tempDir, recursive: true); } catch { }
    }

    private OidcProviderConfig Provider() => _config.Configuration.Providers[0];

    // ── Cases ─────────────────────────────────────────────────────────────────

    [Fact]
    public async Task LinkedSub_UsesLinkedUser()
    {
        var existing = _userStore.CreateUser("alice");
        await _store.LinkAsync(existing.Id, "sub-1", ProviderId);

        var resultId = await _sync.SyncUserAsync(
            username: "totally-different", displayName: null, sub: "sub-1",
            roles: Array.Empty<string>(), entitlements: Array.Empty<string>(),
            providerId: ProviderId, email: null, emailVerified: false);

        Assert.Equal(existing.Id, resultId);
        // No user named "totally-different" should have been created.
        Assert.Null(_users.GetUserByName("totally-different"));
    }

    [Fact]
    public async Task NoLink_NoCollision_CreatesAndLinks()
    {
        var resultId = await _sync.SyncUserAsync(
            "newuser", null, "sub-new", Array.Empty<string>(), Array.Empty<string>(),
            ProviderId, null, false);

        var user = _users.GetUserByName("newuser");
        Assert.NotNull(user);
        Assert.Equal(user!.Id, resultId);

        // Link must be persisted immediately.
        var linked = await _store.GetLinkedUserIdAsync("sub-new", ProviderId);
        Assert.Equal(user.Id, linked);
    }

    [Fact]
    public async Task NoLink_NameCollision_NoAutoLinkFlag_Throws()
    {
        var preexisting = _userStore.CreateUser("admin");
        var originalProvider = preexisting.AuthenticationProviderId;

        await Assert.ThrowsAsync<OidcUsernameCollisionException>(() =>
            _sync.SyncUserAsync(
                "admin", null, "attacker-sub",
                Array.Empty<string>(), Array.Empty<string>(),
                ProviderId, email: "attacker@evil.test", emailVerified: true));

        // The pre-existing user must NOT have been mutated.
        Assert.Equal(originalProvider, preexisting.AuthenticationProviderId);
        // No link must have been written.
        Assert.Null(await _store.GetLinkedUserIdAsync("attacker-sub", ProviderId));
    }

    [Fact]
    public async Task NoLink_NameCollision_AutoLinkByEmail_VerifiedAndMatches_Links()
    {
        Provider().AutoLinkByVerifiedEmail = true;
        // We compare token email to existing user's Username (per documented policy).
        var preexisting = _userStore.CreateUser("alice@example.com");
        preexisting.AuthenticationProviderId = string.Empty; // never converted before — eligible
        var originalProvider = preexisting.AuthenticationProviderId;

        var resultId = await _sync.SyncUserAsync(
            "alice@example.com", null, "sub-alice",
            Array.Empty<string>(), Array.Empty<string>(),
            ProviderId, email: "alice@example.com", emailVerified: true);

        Assert.Equal(preexisting.Id, resultId);
        Assert.Equal(preexisting.Id, await _store.GetLinkedUserIdAsync("sub-alice", ProviderId));
        // EnforceSsoOnLink=false → AuthenticationProviderId left alone.
        Assert.Equal(originalProvider, preexisting.AuthenticationProviderId);
    }

    [Fact]
    public async Task NoLink_NameCollision_AutoLinkByEmail_EmailMismatch_Throws()
    {
        Provider().AutoLinkByVerifiedEmail = true;
        var preexisting = _userStore.CreateUser("alice@example.com");
        preexisting.AuthenticationProviderId = string.Empty;

        await Assert.ThrowsAsync<OidcUsernameCollisionException>(() =>
            _sync.SyncUserAsync(
                "alice@example.com", null, "sub-alice",
                Array.Empty<string>(), Array.Empty<string>(),
                ProviderId, email: "different@evil.test", emailVerified: true));

        Assert.Null(await _store.GetLinkedUserIdAsync("sub-alice", ProviderId));
    }

    [Fact]
    public async Task NoLink_NameCollision_AutoLinkByEmail_NotVerified_Throws()
    {
        Provider().AutoLinkByVerifiedEmail = true;
        var preexisting = _userStore.CreateUser("alice@example.com");
        preexisting.AuthenticationProviderId = string.Empty;

        await Assert.ThrowsAsync<OidcUsernameCollisionException>(() =>
            _sync.SyncUserAsync(
                "alice@example.com", null, "sub-alice",
                Array.Empty<string>(), Array.Empty<string>(),
                ProviderId, email: "alice@example.com", emailVerified: false));

        Assert.Null(await _store.GetLinkedUserIdAsync("sub-alice", ProviderId));
    }

    [Fact]
    public async Task DisabledUser_StaysDisabled()
    {
        // Pre-existing OIDC-linked user that has been disabled by an admin.
        var existing = _userStore.CreateUser("bob");
        existing.SetPermission(PermissionKind.IsDisabled, true);
        await _store.LinkAsync(existing.Id, "sub-bob", ProviderId);

        await _sync.SyncUserAsync(
            "bob", null, "sub-bob",
            Array.Empty<string>(), Array.Empty<string>(),
            ProviderId, email: null, emailVerified: false);

        var disabled = existing.Permissions
            .FirstOrDefault(p => p.Kind == PermissionKind.IsDisabled)?.Value ?? false;
        Assert.True(disabled);
    }

    [Fact]
    public async Task ExistingLocalUser_AuthProviderIdNotOverwritten_UnlessEnforceSsoOnLink()
    {
        Provider().AutoLinkByVerifiedEmail = true;
        var existing = _userStore.CreateUser("carol@example.com");
        existing.AuthenticationProviderId = string.Empty; // unset → eligible for auto-link
        var beforeProvider = existing.AuthenticationProviderId;

        // EnforceSsoOnLink = false → must preserve the provider id.
        await _sync.SyncUserAsync(
            "carol@example.com", null, "sub-carol1",
            Array.Empty<string>(), Array.Empty<string>(),
            ProviderId, email: "carol@example.com", emailVerified: true);

        Assert.Equal(beforeProvider, existing.AuthenticationProviderId);

        // Now seed a fresh user + provider with EnforceSsoOnLink = true.
        Provider().EnforceSsoOnLink = true;
        var existing2 = _userStore.CreateUser("dave@example.com");
        existing2.AuthenticationProviderId = string.Empty;

        await _sync.SyncUserAsync(
            "dave@example.com", null, "sub-dave",
            Array.Empty<string>(), Array.Empty<string>(),
            ProviderId, email: "dave@example.com", emailVerified: true);

        Assert.Equal(typeof(Jellyfin.Plugin.OIDC.Auth.OidcAuthProvider).FullName!, existing2.AuthenticationProviderId);
    }

    [Fact]
    public async Task AutoLinkByEmail_ExistingUserAlreadyOnOtherProvider_Throws()
    {
        // Defense in depth: even with the flag on and email match, a user that's already
        // bound to a non-default auth provider should NOT be silently rebound.
        Provider().AutoLinkByVerifiedEmail = true;
        var existing = _userStore.CreateUser("alice@example.com");
        existing.AuthenticationProviderId = "SomeOtherProvider";

        await Assert.ThrowsAsync<OidcUsernameCollisionException>(() =>
            _sync.SyncUserAsync(
                "alice@example.com", null, "sub-alice",
                Array.Empty<string>(), Array.Empty<string>(),
                ProviderId, email: "alice@example.com", emailVerified: true));
    }
}


// ── Fakes ────────────────────────────────────────────────────────────────────

internal sealed class TestConfigProvider : IPluginConfigProvider
{
    public PluginConfiguration Configuration { get; set; } = new();
    public PluginConfiguration GetConfiguration() => Configuration;
}

/// <summary>In-memory user store keyed by id + username (mirrors the integration-test fake).</summary>
internal sealed class FakeUserStore
{
    public ConcurrentDictionary<Guid, User> ById { get; } = new();
    public ConcurrentDictionary<string, Guid> ByName { get; } = new(StringComparer.OrdinalIgnoreCase);

    public User CreateUser(string name)
    {
        var user = new User(name, "FakeAuthProvider", "FakeResetProvider");
        ById[user.Id] = user;
        ByName[name] = user.Id;
        return user;
    }
}
