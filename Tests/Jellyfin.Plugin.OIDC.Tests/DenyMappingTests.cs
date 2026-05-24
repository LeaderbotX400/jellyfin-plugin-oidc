using System;
using System.Collections.Generic;
using System.Linq;
using Jellyfin.Plugin.OIDC.Configuration;
using Jellyfin.Plugin.OIDC.Services;
using Xunit;

namespace Jellyfin.Plugin.OIDC.Tests;

/// <summary>
/// Tests deny semantics in the two-pass grant/deny role mapping logic.
/// TestableRbacService duplicates the core logic and only depends on RoleMapping + PermissionPreview —
/// no Jellyfin DI or MediaBrowser assemblies needed at test run time.
/// </summary>
public class DenyMappingTests
{
    private static PermissionPreview Preview(
        string[] roles,
        List<RoleMapping> mappings,
        string providerId = "")
    {
        var rbac = new TestableRbacService();
        return rbac.ComputePreview(roles, Array.Empty<string>(), providerId, mappings);
    }

    [Fact]
    public void DenyMapping_StripsAdminGrantedByOtherMapping()
    {
        var mappings = new List<RoleMapping>
        {
            new() { RoleName = "admin", IsAdmin = true },
            new() { RoleName = "restricted", IsAdmin = true, IsExplicitDeny = true }
        };

        var preview = Preview(new[] { "admin", "restricted" }, mappings);

        Assert.False(preview.IsAdmin, "Deny should override the grant");
    }

    [Fact]
    public void DenyMapping_DoesNotAffectUsersWithoutDenyRole()
    {
        var mappings = new List<RoleMapping>
        {
            new() { RoleName = "admin", IsAdmin = true },
            new() { RoleName = "restricted", IsAdmin = true, IsExplicitDeny = true }
        };

        var preview = Preview(new[] { "admin" }, mappings);

        Assert.True(preview.IsAdmin, "Without deny role, admin grant should apply");
    }

    [Fact]
    public void DenyMapping_OnlyDenyRole_NoPermissionsGranted()
    {
        var mappings = new List<RoleMapping>
        {
            new() { RoleName = "blocked", IsAdmin = true, EnableMediaPlayback = true, IsExplicitDeny = true }
        };

        var preview = Preview(new[] { "blocked" }, mappings);

        Assert.False(preview.IsAdmin);
    }

    [Fact]
    public void DenyMapping_GrantAndDenyDifferentPermissions()
    {
        var mappings = new List<RoleMapping>
        {
            new() { RoleName = "user", IsAdmin = false, EnableDownload = true },
            new() { RoleName = "nolive", EnableLiveTv = true, IsExplicitDeny = true }
        };

        var preview = Preview(new[] { "user", "nolive" }, mappings);

        Assert.True(preview.EnableDownload, "Non-denied permissions should still be granted");
        Assert.False(preview.EnableLiveTv, "Denied permission should be removed");
    }

    // ── Test helper that exposes the two-pass grant/deny logic without Jellyfin DI ──

    private sealed class TestableRbacService
    {
        public PermissionPreview ComputePreview(
            string[] roles,
            string[] entitlements,
            string providerId,
            List<RoleMapping> roleMappings)
        {
            var allMatching = roleMappings
                .Where(m =>
                    (string.IsNullOrEmpty(m.ProviderId) ||
                     string.Equals(m.ProviderId, providerId, StringComparison.OrdinalIgnoreCase)) &&
                    roles.Contains(m.RoleName, StringComparer.OrdinalIgnoreCase))
                .OrderByDescending(m => m.Priority)
                .ToList();

            var grantMappings = allMatching.Where(m => !m.IsExplicitDeny).ToList();
            var denyMappings = allMatching.Where(m => m.IsExplicitDeny).ToList();

            var merged = grantMappings.Count > 0 ? Merge(grantMappings) : new RoleMapping();
            var deny = denyMappings.Count > 0 ? Merge(denyMappings) : null;

            return new PermissionPreview(
                IsAdmin: merged.IsAdmin && !(deny?.IsAdmin ?? false),
                EnableMediaPlayback: merged.EnableMediaPlayback && !(deny?.EnableMediaPlayback ?? false),
                EnableRemoteAccess: merged.EnableRemoteAccess && !(deny?.EnableRemoteAccess ?? false),
                EnableTranscoding: merged.EnableTranscoding && !(deny?.EnableTranscoding ?? false),
                EnableLiveTv: merged.EnableLiveTv && !(deny?.EnableLiveTv ?? false),
                EnableLiveTvManagement: merged.EnableLiveTvManagement && !(deny?.EnableLiveTvManagement ?? false),
                EnableContentDeletion: merged.EnableContentDeletion && !(deny?.EnableContentDeletion ?? false),
                EnableCollectionManagement: merged.EnableCollectionManagement && !(deny?.EnableCollectionManagement ?? false),
                EnableSubtitleManagement: merged.EnableSubtitleManagement && !(deny?.EnableSubtitleManagement ?? false),
                EnableDownload: merged.EnableDownload && !(deny?.EnableDownload ?? false),
                EnableSyncplay: merged.EnableSyncplay && !(deny?.EnableSyncplay ?? false),
                EnableSyncplayGroupCreation: merged.EnableSyncplayGroupCreation && !(deny?.EnableSyncplayGroupCreation ?? false),
                EnableAllLibraries: merged.EnableAllLibraries && !(deny?.EnableAllLibraries ?? false),
                Libraries: new List<string>(),
                MaxParentalRating: null,
                MatchedGrantMappings: grantMappings.Select(m => m.RoleName).ToArray(),
                MatchedDenyMappings: denyMappings.Select(m => m.RoleName).ToArray(),
                ParsedEntitlements: entitlements);
        }

        private static RoleMapping Merge(List<RoleMapping> mappings) => new()
        {
            IsAdmin = mappings.Any(m => m.IsAdmin),
            EnableAllLibraries = mappings.Any(m => m.EnableAllLibraries),
            EnableLiveTv = mappings.Any(m => m.EnableLiveTv),
            EnableLiveTvManagement = mappings.Any(m => m.EnableLiveTvManagement),
            EnableMediaPlayback = mappings.Any(m => m.EnableMediaPlayback),
            EnableRemoteAccess = mappings.Any(m => m.EnableRemoteAccess),
            EnableTranscoding = mappings.Any(m => m.EnableTranscoding),
            EnableContentDeletion = mappings.Any(m => m.EnableContentDeletion),
            EnableCollectionManagement = mappings.Any(m => m.EnableCollectionManagement),
            EnableSubtitleManagement = mappings.Any(m => m.EnableSubtitleManagement),
            EnableDownload = mappings.Any(m => m.EnableDownload),
            EnableSyncplay = mappings.Any(m => m.EnableSyncplay || m.EnableSyncplayGroupCreation),
            EnableSyncplayGroupCreation = mappings.Any(m => m.EnableSyncplayGroupCreation)
        };
    }
}
