using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Jellyfin.Data;
using Jellyfin.Database.Implementations.Entities;
using Jellyfin.Database.Implementations.Enums;
using Jellyfin.Plugin.OIDC.Configuration;
using Jellyfin.Plugin.OIDC.Services;
using MediaBrowser.Controller.Library;
using MediaBrowser.Model.Activity;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Xunit;

namespace Jellyfin.Plugin.OIDC.Integration.Tests;

/// <summary>
/// Unit tests for last-admin lockout protection in <see cref="RbacService"/>.
/// These tests build the service in isolation with mocked Jellyfin dependencies so they
/// exercise the guard without requiring a full DI container or running IdP.
/// </summary>
public class RbacServiceTests
{
    // ── Helpers ───────────────────────────────────────────────────────────────

    private static User MakeUser(string name, bool isAdmin = false)
    {
        var u = new User(name, "FakeAuth", "FakeReset");
        u.SetPermission(PermissionKind.IsAdministrator, isAdmin);
        return u;
    }

    private static bool GetPermission(User user, PermissionKind kind) =>
        user.Permissions.FirstOrDefault(p => p.Kind == kind)?.Value ?? false;

    private static (RbacService Service, Mock<IUserManager> UserManagerMock, Mock<IActivityManager> ActivityManagerMock)
        BuildService(
            PluginConfiguration config,
            User subject,
            IEnumerable<User>? otherUsers = null)
    {
        var allUsers = new List<User> { subject };
        if (otherUsers != null) allUsers.AddRange(otherUsers);

        var userManagerMock = new Mock<IUserManager>();
        userManagerMock.Setup(m => m.GetUserById(subject.Id)).Returns(subject);
        userManagerMock.Setup(m => m.UpdateUserAsync(It.IsAny<User>())).Returns(Task.CompletedTask);
        userManagerMock.Setup(m => m.GetUsers()).Returns(allUsers.AsQueryable());

        var libraryManagerMock = new Mock<ILibraryManager>();
        libraryManagerMock.Setup(m => m.GetVirtualFolders())
            .Returns(new List<MediaBrowser.Model.Entities.VirtualFolderInfo>());

        var activityManagerMock = new Mock<IActivityManager>();
        activityManagerMock
            .Setup(m => m.CreateAsync(It.IsAny<ActivityLog>()))
            .Returns(Task.CompletedTask);

        var configProvider = new TestPluginConfigProvider { Configuration = config };

        var service = new RbacService(
            userManagerMock.Object,
            libraryManagerMock.Object,
            activityManagerMock.Object,
            configProvider,
            NullLogger<RbacService>.Instance);

        return (service, userManagerMock, activityManagerMock);
    }

    // ── Tests ─────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Apply_NotLastAdmin_DemotionAllowed()
    {
        // Two admins — demoting alice is fine because bob remains.
        var alice = MakeUser("alice", isAdmin: true);
        var bob = MakeUser("bob", isAdmin: true);

        var config = new PluginConfiguration
        {
            RoleMappings = new List<RoleMapping>
            {
                new() { RoleName = "user", IsAdmin = false, EnableMediaPlayback = true }
            }
        };

        var (svc, _, _) = BuildService(config, alice, new[] { bob });

        await svc.ApplyRoleMappingsAsync(alice.Id, new[] { "user" }, Array.Empty<string>(), "idp");

        Assert.False(GetPermission(alice, PermissionKind.IsAdministrator),
            "Demotion should be allowed when another admin (bob) exists");
        Assert.True(GetPermission(alice, PermissionKind.EnableMediaPlayback),
            "Other permissions should still be applied");
    }

    [Fact]
    public async Task Apply_LastAdminDemoted_PreservesAdminBit()
    {
        // Only one admin — demotion must be blocked.
        var alice = MakeUser("alice", isAdmin: true);

        var config = new PluginConfiguration
        {
            AllowLastAdminDemotion = false,
            RoleMappings = new List<RoleMapping>
            {
                new() { RoleName = "user", IsAdmin = false, EnableMediaPlayback = true }
            }
        };

        var (svc, _, _) = BuildService(config, alice);

        await svc.ApplyRoleMappingsAsync(alice.Id, new[] { "user" }, Array.Empty<string>(), "idp");

        Assert.True(GetPermission(alice, PermissionKind.IsAdministrator),
            "Admin bit must be preserved when alice is the only admin");
    }

    [Fact]
    public async Task Apply_OtherPermissionsStillApplied_WhenAdminBitPreserved()
    {
        // Even when admin bit is protected, the rest of the permissions should be written normally.
        var alice = MakeUser("alice", isAdmin: true);

        var config = new PluginConfiguration
        {
            AllowLastAdminDemotion = false,
            RoleMappings = new List<RoleMapping>
            {
                new() { RoleName = "user", IsAdmin = false, EnableMediaPlayback = true, EnableDownload = true }
            }
        };

        var (svc, _, _) = BuildService(config, alice);

        await svc.ApplyRoleMappingsAsync(alice.Id, new[] { "user" }, Array.Empty<string>(), "idp");

        Assert.True(GetPermission(alice, PermissionKind.IsAdministrator),
            "Admin bit preserved");
        Assert.True(GetPermission(alice, PermissionKind.EnableMediaPlayback),
            "EnableMediaPlayback should be applied");
        Assert.True(GetPermission(alice, PermissionKind.EnableContentDownloading),
            "EnableDownload should be applied");
    }

    [Fact]
    public async Task Apply_LastAdminDemotion_WithAllowLastAdminDemotion_AllowsDemotion()
    {
        // Escape hatch: AllowLastAdminDemotion=true overrides the protection.
        var alice = MakeUser("alice", isAdmin: true);

        var config = new PluginConfiguration
        {
            AllowLastAdminDemotion = true,
            RoleMappings = new List<RoleMapping>
            {
                new() { RoleName = "user", IsAdmin = false, EnableMediaPlayback = true }
            }
        };

        var (svc, _, _) = BuildService(config, alice);

        await svc.ApplyRoleMappingsAsync(alice.Id, new[] { "user" }, Array.Empty<string>(), "idp");

        Assert.False(GetPermission(alice, PermissionKind.IsAdministrator),
            "AllowLastAdminDemotion=true should permit the demotion even when alice is the only admin");
    }

    [Fact]
    public async Task Apply_UserAlreadyNonAdmin_NoDemotionCheck()
    {
        // If the user is already non-admin, the lockout check must not be triggered.
        var alice = MakeUser("alice", isAdmin: false);

        var config = new PluginConfiguration
        {
            AllowLastAdminDemotion = false,
            RoleMappings = new List<RoleMapping>
            {
                new() { RoleName = "user", IsAdmin = false, EnableMediaPlayback = true }
            }
        };

        var (svc, userManagerMock, _) = BuildService(config, alice);

        await svc.ApplyRoleMappingsAsync(alice.Id, new[] { "user" }, Array.Empty<string>(), "idp");

        Assert.False(GetPermission(alice, PermissionKind.IsAdministrator));
        // Admin count should NOT be queried when the user isn't being demoted from admin
        userManagerMock.Verify(m => m.GetUsers(), Times.Never,
            "Users should not be enumerated when the user is already non-admin");
    }

    [Fact]
    public async Task Apply_LastAdminBlock_EmitsActivityLogEntry()
    {
        // The lockout guard must write an activity-log entry describing the block.
        var alice = MakeUser("alice", isAdmin: true);

        var config = new PluginConfiguration
        {
            AllowLastAdminDemotion = false,
            RoleMappings = new List<RoleMapping>
            {
                new() { RoleName = "user", IsAdmin = false, EnableMediaPlayback = true }
            }
        };

        var (svc, _, activityManagerMock) = BuildService(config, alice);

        await svc.ApplyRoleMappingsAsync(alice.Id, new[] { "user" }, Array.Empty<string>(), "idp");

        activityManagerMock.Verify(
            m => m.CreateAsync(It.Is<ActivityLog>(
                entry => entry.Name.Contains("last-admin", StringComparison.OrdinalIgnoreCase))),
            Times.AtLeastOnce,
            "Expected an activity-log entry for the last-admin block event");
    }
}
