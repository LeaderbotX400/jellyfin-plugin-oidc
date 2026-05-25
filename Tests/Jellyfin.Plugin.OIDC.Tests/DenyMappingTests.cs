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

    // ── Existing tests (preserved with updated semantics) ─────────────────────

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
        // A deny mapping with only IsAdmin=true (non-nullable field).
        // The three nullable fields are null — they should be no-ops.
        var mappings = new List<RoleMapping>
        {
            new() { RoleName = "blocked", IsAdmin = true, IsExplicitDeny = true }
        };

        var preview = Preview(new[] { "blocked" }, mappings);

        // No grant mapping matched, so nothing was granted in the first place.
        Assert.False(preview.IsAdmin);
        // Deny mapping with null Playback/Remote/Transcode must NOT strip these.
        // (Nothing to strip since there's no grant, but the playback flag from the
        // grant side defaults to true when no grant matches — so we verify it's true.)
        Assert.True(preview.EnableMediaPlayback, "No explicit deny of playback — should default true from grant path");
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

    // ── New tests for nullable-bool deny semantics ────────────────────────────

    /// <summary>
    /// Headline regression: deny mapping for "admin" should only strip admin,
    /// not silently strip playback/remote/transcoding which were default-true on <see cref="RoleMapping"/>.
    /// </summary>
    [Fact]
    public void DenyMapping_OnlyIsAdmin_DoesNotStripPlayback()
    {
        var mappings = new List<RoleMapping>
        {
            // Grant: regular user with playback
            new() { RoleName = "user", EnableMediaPlayback = true, EnableRemoteAccess = true, EnableTranscoding = true },
            // Deny: only strips admin — EnableMediaPlayback/Remote/Transcoding are null (not set)
            new() { RoleName = "noadmin", IsAdmin = true, IsExplicitDeny = true }
        };

        var preview = Preview(new[] { "user", "noadmin" }, mappings);

        Assert.False(preview.IsAdmin, "Admin should be denied");
        Assert.True(preview.EnableMediaPlayback, "Playback was not in the deny mapping — must not be stripped");
        Assert.True(preview.EnableRemoteAccess, "Remote access was not in the deny mapping — must not be stripped");
        Assert.True(preview.EnableTranscoding, "Transcoding was not in the deny mapping — must not be stripped");
    }

    /// <summary>
    /// Deny mapping with only EnableMediaPlayback=true should strip only playback,
    /// leaving remote access and transcoding intact.
    /// </summary>
    [Fact]
    public void DenyMapping_OnlyPlayback_StripsOnlyPlayback()
    {
        var mappings = new List<RoleMapping>
        {
            new() { RoleName = "user", EnableMediaPlayback = true, EnableRemoteAccess = true, EnableTranscoding = true },
            new() { RoleName = "noplay", EnableMediaPlayback = true, IsExplicitDeny = true }
            // EnableRemoteAccess and EnableTranscoding are null on the deny mapping
        };

        var preview = Preview(new[] { "user", "noplay" }, mappings);

        Assert.False(preview.EnableMediaPlayback, "Explicitly denied — must be stripped");
        Assert.True(preview.EnableRemoteAccess, "Not in deny mapping — must remain granted");
        Assert.True(preview.EnableTranscoding, "Not in deny mapping — must remain granted");
    }

    /// <summary>
    /// A deny mapping where all nullable permission fields are null is a no-op —
    /// it strips nothing.
    /// </summary>
    [Fact]
    public void DenyMapping_AllFlagsNull_NoOp()
    {
        var mappings = new List<RoleMapping>
        {
            new()
            {
                RoleName = "user",
                EnableMediaPlayback = true,
                EnableRemoteAccess = true,
                EnableTranscoding = true,
                EnableDownload = true
            },
            // Deny mapping with everything null / false — no explicit denial of anything
            new()
            {
                RoleName = "emptydeny",
                IsExplicitDeny = true
                // EnableMediaPlayback = null (default)
                // EnableRemoteAccess  = null (default)
                // EnableTranscoding   = null (default)
                // IsAdmin             = false (default)
                // EnableDownload      = false (default)
            }
        };

        var preview = Preview(new[] { "user", "emptydeny" }, mappings);

        Assert.True(preview.EnableMediaPlayback, "Null deny = no-op");
        Assert.True(preview.EnableRemoteAccess, "Null deny = no-op");
        Assert.True(preview.EnableTranscoding, "Null deny = no-op");
        Assert.True(preview.EnableDownload, "false deny = no-op (false means not set, not 'deny')");
    }

    /// <summary>
    /// Existing allow-mapping behaviour must not regress after the nullable-bool change.
    /// Allow mappings with null for the three fields must behave as if they were true
    /// (the prior default).
    /// </summary>
    [Fact]
    public void AllowMapping_BackwardCompat_UnchangedBehavior()
    {
        // Simulate an allow mapping saved by the OLD serialiser (no XML element for the
        // three fields → deserialized as null).  The effective value must still be true.
        var mappings = new List<RoleMapping>
        {
            new()
            {
                RoleName = "user",
                // EnableMediaPlayback = null  ← old serialised form, missing element
                // EnableRemoteAccess  = null
                // EnableTranscoding   = null
            }
        };

        var preview = Preview(new[] { "user" }, mappings);

        Assert.True(preview.EnableMediaPlayback, "null on allow mapping = default true (backward compat)");
        Assert.True(preview.EnableRemoteAccess, "null on allow mapping = default true (backward compat)");
        Assert.True(preview.EnableTranscoding, "null on allow mapping = default true (backward compat)");
    }

    /// <summary>
    /// Migration: a legacy deny mapping that arrives with the old default-true values
    /// for Playback/Remote/Transcode should have those cleared by <see cref="OidcPlugin.MigrateDenyMappings"/>.
    /// We simulate this by constructing the pre-migration state and verifying the outcome.
    /// </summary>
    [Fact]
    public void Migration_LegacyDenyMapping_AllFlagsClearedToNull()
    {
        // Pre-migration state: deny mapping has explicit true on the three nullable fields
        // (as a pre-v0.1.3 serialiser would have written from the old bool default = true).
        var roleMappings = new List<RoleMapping>
        {
            new()
            {
                RoleName = "olddenyrole",
                IsExplicitDeny = true,
                EnableMediaPlayback = true,  // legacy default-true
                EnableRemoteAccess = true,   // legacy default-true
                EnableTranscoding = true,    // legacy default-true
                IsAdmin = true               // non-nullable explicitly set — must be preserved
            }
        };

        // Run the shared migration — same code path the plugin calls on startup.
        // ConfigMigration takes IList<RoleMapping> to avoid pulling MediaBrowser.Model into tests.
        ConfigMigration.MigrateDenyMappings(roleMappings);

        var m = roleMappings[0];
        Assert.Null(m.EnableMediaPlayback); // Legacy default-true should be cleared to null
        Assert.Null(m.EnableRemoteAccess);  // Legacy default-true should be cleared to null
        Assert.Null(m.EnableTranscoding);   // Legacy default-true should be cleared to null
        Assert.True(m.IsAdmin, "Explicitly-set non-nullable field must not be touched");
        Assert.True(m.MigratedDenyDefaults, "Migration sentinel must be set to prevent double-migration");
    }

    // ── NFKC Unicode normalization tests (TASK-20) ────────────────────────────

    /// <summary>
    /// Helper that calls the real PermissionResolver (with NFKC normalization) directly,
    /// bypassing the TestableRbacService which has its own simplified matching logic.
    /// </summary>
    private static PermissionPreview RealPreview(string[] roles, List<RoleMapping> mappings, string providerId = "")
    {
        var config = new ResolverConfig { RoleMappings = mappings };
        return PermissionResolver.Resolve(roles, Array.Empty<string>(), providerId, config);
    }

    [Fact]
    public void PermissionResolver_NfkcFullwidthChars_CollapseToAscii_DenyFires()
    {
        // Fullwidth "ａｄｍｉｎ" (U+FF41–U+FF4E) NFKC-normalizes to ASCII "admin".
        // A deny mapping for "admin" should therefore fire.
        var mappings = new List<RoleMapping>
        {
            new() { RoleName = "admin", IsAdmin = true },
            new() { RoleName = "admin", IsAdmin = true, IsExplicitDeny = true }
        };

        // The user's role claim contains fullwidth latin small letters
        var preview = RealPreview(new[] { "ａｄｍｉｎ" }, mappings);

        // NFKC maps fullwidth "ａｄｍｉｎ" → "admin", so both grant and deny match
        Assert.False(preview.IsAdmin, "Deny must fire after NFKC normalization of fullwidth chars");
    }

    [Fact]
    public void PermissionResolver_DotlessI_RemainsDistinctFromAsciiI()
    {
        // Turkish dotless-i (U+0131 'ı') does NOT normalize to ASCII 'i' under NFKC —
        // it stays as-is. A deny mapping for "admin" (with ASCII 'i') must NOT fire
        // for a role containing dotless-i. This documents intentional behavior.
        var mappings = new List<RoleMapping>
        {
            new() { RoleName = "admin", IsAdmin = true },
            new() { RoleName = "admin", IsAdmin = true, IsExplicitDeny = true }
        };

        // "admın" = "admın" with dotless-i — distinct from "admin" even after NFKC
        var preview = RealPreview(new[] { "admın" }, mappings);

        // Neither grant nor deny matches. In the default (EntitlementsAuthoritative) mode
        // the resolver returns false (not null) for unmatched booleans, so IsAdmin=false.
        // The user does NOT get admin rights — this is the important invariant.
        Assert.False(preview.IsAdmin);
        // Also verify the deny mapping did NOT fire (MatchedDenyMappings is empty)
        Assert.Empty(preview.MatchedDenyMappings);
        Assert.Empty(preview.MatchedGrantMappings);
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

            // Mirror the semantics in RbacService.ComputePermissions:
            // - Allow path: null = default true (backward compat).
            // - Deny path: only explicit true (== true) strips the permission.
            return new PermissionPreview(
                IsAdmin: merged.IsAdmin && !(deny?.IsAdmin ?? false),
                IsDisabled: false,
                IsHidden: false,
                EnableMediaPlayback: (merged.EnableMediaPlayback ?? true) && !(deny?.EnableMediaPlayback == true),
                EnableRemoteAccess: (merged.EnableRemoteAccess ?? true) && !(deny?.EnableRemoteAccess == true),
                EnableTranscoding: (merged.EnableTranscoding ?? true) && !(deny?.EnableTranscoding == true),
                EnableSyncTranscoding: false,
                ForceRemoteSourceTranscoding: false,
                EnablePlaybackRemuxing: false,
                EnableMediaConversion: false,
                EnableLiveTv: merged.EnableLiveTv && !(deny?.EnableLiveTv ?? false),
                EnableLiveTvManagement: merged.EnableLiveTvManagement && !(deny?.EnableLiveTvManagement ?? false),
                EnableContentDeletion: merged.EnableContentDeletion && !(deny?.EnableContentDeletion ?? false),
                EnableCollectionManagement: merged.EnableCollectionManagement && !(deny?.EnableCollectionManagement ?? false),
                EnableSubtitleManagement: merged.EnableSubtitleManagement && !(deny?.EnableSubtitleManagement ?? false),
                EnableLyricManagement: false,
                EnableDownload: merged.EnableDownload && !(deny?.EnableDownload ?? false),
                EnableSyncplay: merged.EnableSyncplay && !(deny?.EnableSyncplay ?? false),
                EnableSyncplayGroupCreation: merged.EnableSyncplayGroupCreation && !(deny?.EnableSyncplayGroupCreation ?? false),
                EnableAllLibraries: merged.EnableAllLibraries && !(deny?.EnableAllLibraries ?? false),
                EnableAllChannels: false,
                EnableAllDevices: false,
                EnableSharedDeviceControl: false,
                EnableRemoteControlOfOtherUsers: false,
                EnablePublicSharing: false,
                Libraries: new List<string>(),
                MaxParentalRating: null,
                ClearMaxParentalRating: false,
                MaxParentalRatingSub: null,
                ClearMaxParentalRatingSub: false,
                RemoteClientBitrateLimit: null,
                ClearRemoteClientBitrateLimit: false,
                MaxActiveSessions: null,
                LoginAttemptsBeforeLockout: null,
                ClearLoginAttemptsBeforeLockout: false,
                MatchedGrantMappings: grantMappings.Select(m => m.RoleName).ToArray(),
                MatchedDenyMappings: denyMappings.Select(m => m.RoleName).ToArray(),
                ParsedEntitlements: entitlements);
        }

        private static RoleMapping Merge(List<RoleMapping> mappings)
        {
            // For nullable bool? fields: OR semantics across mappings.
            // If any mapping explicitly sets true, result is true.
            // If all are null (not specified), result stays null.
            static bool? MergeNullable(List<RoleMapping> ms, Func<RoleMapping, bool?> selector)
            {
                var values = ms.Select(selector).Where(v => v.HasValue).Select(v => v!.Value).ToList();
                if (values.Count == 0) return null;
                return values.Any(v => v);
            }

            return new RoleMapping
            {
                IsAdmin = mappings.Any(m => m.IsAdmin),
                EnableAllLibraries = mappings.Any(m => m.EnableAllLibraries),
                EnableLiveTv = mappings.Any(m => m.EnableLiveTv),
                EnableLiveTvManagement = mappings.Any(m => m.EnableLiveTvManagement),
                EnableMediaPlayback = MergeNullable(mappings, m => m.EnableMediaPlayback),
                EnableRemoteAccess = MergeNullable(mappings, m => m.EnableRemoteAccess),
                EnableTranscoding = MergeNullable(mappings, m => m.EnableTranscoding),
                EnableContentDeletion = mappings.Any(m => m.EnableContentDeletion),
                EnableCollectionManagement = mappings.Any(m => m.EnableCollectionManagement),
                EnableSubtitleManagement = mappings.Any(m => m.EnableSubtitleManagement),
                EnableDownload = mappings.Any(m => m.EnableDownload),
                EnableSyncplay = mappings.Any(m => m.EnableSyncplay || m.EnableSyncplayGroupCreation),
                EnableSyncplayGroupCreation = mappings.Any(m => m.EnableSyncplayGroupCreation)
            };
        }
    }
}

