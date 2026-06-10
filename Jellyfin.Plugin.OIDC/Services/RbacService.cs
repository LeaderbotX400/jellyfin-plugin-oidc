using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Jellyfin.Data;
using Jellyfin.Database.Implementations.Entities;
using Jellyfin.Database.Implementations.Enums;
using Jellyfin.Plugin.OIDC.Configuration;
using MediaBrowser.Controller.Library;
using MediaBrowser.Model.Activity;
using Microsoft.Extensions.Logging;
using SyncPlayAccess = Jellyfin.Database.Implementations.Enums.SyncPlayUserAccessType;

namespace Jellyfin.Plugin.OIDC.Services;

public class RbacService
{
    private readonly IUserManager _userManager;
    private readonly ILibraryManager _libraryManager;
    private readonly IActivityManager _activityManager;
    private readonly IPluginConfigProvider _configProvider;
    private readonly ILogger<RbacService> _logger;

    public RbacService(
        IUserManager userManager,
        ILibraryManager libraryManager,
        IActivityManager activityManager,
        IPluginConfigProvider configProvider,
        ILogger<RbacService> logger)
    {
        _userManager = userManager;
        _libraryManager = libraryManager;
        _activityManager = activityManager;
        _configProvider = configProvider;
        _logger = logger;
    }

    /// <summary>
    /// Applies role mappings using a pre-captured configuration snapshot.
    /// Callers that process many users (e.g. the resync task) should capture the config once
    /// and pass it here so that mid-run config changes do not produce inconsistent results.
    /// </summary>
    public Task ApplyRoleMappingsAsync(
        Guid userId,
        string[] userRoles,
        string[] entitlements,
        string providerId,
        PluginConfiguration configSnapshot)
        => ApplyRoleMappingsCoreAsync(userId, userRoles, entitlements, providerId, configSnapshot);

    public Task ApplyRoleMappingsAsync(
        Guid userId,
        string[] userRoles,
        string[] entitlements,
        string providerId)
        => ApplyRoleMappingsCoreAsync(userId, userRoles, entitlements, providerId, _configProvider.GetConfiguration());

    private async Task ApplyRoleMappingsCoreAsync(
        Guid userId,
        string[] userRoles,
        string[] entitlements,
        string providerId,
        PluginConfiguration config)
    {
        var user = _userManager.GetUserById(userId);
        if (user == null)
        {
            _logger.LogWarning("User {UserId} not found for RBAC application", userId);
            return;
        }

        var preview = ComputePermissions(userRoles, entitlements, providerId, config);

        if (preview.MatchedGrantMappings.Length == 0 && preview.ParsedEntitlements.Length == 0)
        {
            var verbose = _configProvider.GetConfiguration().VerboseClaimLogging;
            _logger.LogInformation(
                "No role mappings or entitlements matched for user {Username} (roleCount={RoleCount})",
                user.Username, LogRedaction.RedactRoles(userRoles, verbose));
            return;
        }

        // Last-admin lockout protection: if the computed preview would demote this user from admin,
        // check whether any other admin exists. If not, refuse to clear the bit (unless the config
        // escape hatch is enabled). All other permissions are still applied normally.
        bool? effectiveIsAdmin = preview.IsAdmin;
        bool currentlyAdmin = user.HasPermission(Jellyfin.Database.Implementations.Enums.PermissionKind.IsAdministrator);
        if (currentlyAdmin && preview.IsAdmin == false && !config.AllowLastAdminDemotion)
        {
            int remainingAdmins = JellyfinCompat.EnumerateUsers(_userManager)
                .Count(u => u.Id != userId &&
                            u.HasPermission(Jellyfin.Database.Implementations.Enums.PermissionKind.IsAdministrator));
            if (remainingAdmins == 0)
            {
                _logger.LogError(
                    "Refusing to demote user={UserId} username={Username} reason=last_admin",
                    userId, user.Username);
                await LogActivityAsync(
                    "OIDC plugin: last-admin demotion blocked",
                    "OidcLastAdminBlocked",
                    userId,
                    $"OIDC-Auth would have removed administrator rights from {user.Username} but they are the last admin. Set AllowLastAdminDemotion=true in plugin config to override.",
                    Microsoft.Extensions.Logging.LogLevel.Warning).ConfigureAwait(false);
                // Preserve the admin bit; all other permission fields are applied normally below.
                effectiveIsAdmin = true;
            }
        }

        ApplyToUser(user, preview, effectiveIsAdmin);
        await _userManager.UpdateUserAsync(user).ConfigureAwait(false);

        string adminStr = preview.IsAdmin?.ToString() ?? "unchanged";
        string libsStr = preview.EnableAllLibraries switch
        {
            true => "ALL",
            false => (preview.Libraries?.Count ?? 0).ToString(System.Globalization.CultureInfo.InvariantCulture),
            null => "unchanged",
        };

        // Matched mapping names (RoleNames from config, not claim values) are safe to log at Info.
        // Raw role claim values from the IdP are NOT logged here (TASK-18).
        _logger.LogInformation(
            "Applied RBAC for user {Username}: admin={IsAdmin}, libraries={Libraries}, " +
            "grants=[{Grants}], denies=[{Denies}], entitlements={EntCount}",
            user.Username,
            adminStr,
            libsStr,
            string.Join(", ", preview.MatchedGrantMappings),
            string.Join(", ", preview.MatchedDenyMappings),
            entitlements.Length);

        // Activity log: user-friendly summary, no raw claim contents (other admins read this).
        await LogActivityAsync(
            "OIDC-Auth permissions updated",
            "OidcPermissionsChanged",
            userId,
            $"Admin: {adminStr}. Matched grants: {preview.MatchedGrantMappings.Length}, denies: {preview.MatchedDenyMappings.Length}.",
            Microsoft.Extensions.Logging.LogLevel.Information).ConfigureAwait(false);
    }

    /// <summary>Computes what permissions would be applied without writing to any user object.</summary>
    public PermissionPreview PreviewPermissions(string[] userRoles, string[] entitlements, string providerId)
    {
        return ComputePermissions(userRoles, entitlements, providerId, _configProvider.GetConfiguration());
    }

    public Dictionary<string, string> GetAvailableLibraries()
    {
        var folders = _libraryManager.GetVirtualFolders();
        return folders.ToDictionary(f => f.ItemId, f => f.Name);
    }

    // ── Internal computation ─────────────────────────────────────────────────

    private PermissionPreview ComputePermissions(
        string[] userRoles,
        string[] entitlements,
        string providerId,
        PluginConfiguration config)
    {
        return PermissionResolver.Resolve(userRoles, entitlements, providerId, config, ResolveLibraryIds);
    }

    /// <param name="effectiveIsAdmin">
    /// Overrides <c>p.IsAdmin</c> for the IsAdministrator bit only. Pass <c>null</c> to use
    /// <c>p.IsAdmin</c> unmodified. The last-admin lockout guard sets this to <c>true</c> when it
    /// refuses to demote; all other permissions in <paramref name="p"/> are applied normally.
    /// </param>
    private static void ApplyToUser(
        Jellyfin.Database.Implementations.Entities.User user,
        PermissionPreview p,
        bool? effectiveIsAdmin = null)
    {
        void Apply(PermissionKind kind, bool? value)
        {
            if (value.HasValue) user.SetPermission(kind, value.Value);
        }

        Apply(PermissionKind.IsAdministrator, effectiveIsAdmin ?? p.IsAdmin);
        Apply(PermissionKind.IsDisabled, p.IsDisabled);
        Apply(PermissionKind.IsHidden, p.IsHidden);
        Apply(PermissionKind.EnableMediaPlayback, p.EnableMediaPlayback);
        Apply(PermissionKind.EnableRemoteAccess, p.EnableRemoteAccess);
        Apply(PermissionKind.EnableAudioPlaybackTranscoding, p.EnableTranscoding);
        Apply(PermissionKind.EnableVideoPlaybackTranscoding, p.EnableTranscoding);
        Apply(PermissionKind.EnableSyncTranscoding, p.EnableSyncTranscoding);
        Apply(PermissionKind.ForceRemoteSourceTranscoding, p.ForceRemoteSourceTranscoding);
        Apply(PermissionKind.EnablePlaybackRemuxing, p.EnablePlaybackRemuxing);
        Apply(PermissionKind.EnableMediaConversion, p.EnableMediaConversion);
        Apply(PermissionKind.EnableLiveTvAccess, p.EnableLiveTv);
        Apply(PermissionKind.EnableLiveTvManagement, p.EnableLiveTvManagement);
        Apply(PermissionKind.EnableContentDeletion, p.EnableContentDeletion);
        Apply(PermissionKind.EnableCollectionManagement, p.EnableCollectionManagement);
        Apply(PermissionKind.EnableSubtitleManagement, p.EnableSubtitleManagement);
        Apply(PermissionKind.EnableLyricManagement, p.EnableLyricManagement);
        Apply(PermissionKind.EnableContentDownloading, p.EnableDownload);
        Apply(PermissionKind.EnableAllChannels, p.EnableAllChannels);
        Apply(PermissionKind.EnableAllDevices, p.EnableAllDevices);
        Apply(PermissionKind.EnableSharedDeviceControl, p.EnableSharedDeviceControl);
        Apply(PermissionKind.EnableRemoteControlOfOtherUsers, p.EnableRemoteControlOfOtherUsers);
        Apply(PermissionKind.EnablePublicSharing, p.EnablePublicSharing);

        // SyncPlay is a single tri-state column on the User entity; only write it when at least one
        // SyncPlay-related field has an opinion.
        if (p.EnableSyncplay.HasValue || p.EnableSyncplayGroupCreation.HasValue)
        {
            user.SyncPlayAccess = (p.EnableSyncplayGroupCreation == true)
                ? SyncPlayAccess.CreateAndJoinGroups
                : (p.EnableSyncplay == true)
                    ? SyncPlayAccess.JoinGroups
                    : SyncPlayAccess.None;
        }

        if (p.EnableAllLibraries == true)
        {
            user.SetPermission(PermissionKind.EnableAllFolders, true);
        }
        else if (p.EnableAllLibraries == false)
        {
            user.SetPermission(PermissionKind.EnableAllFolders, false);
            user.SetPreference(PreferenceKind.EnabledFolders, (p.Libraries ?? new List<string>()).ToArray());
        }
        // null → leave EnableAllFolders + EnabledFolders untouched

        if (p.ClearMaxParentalRating)
        {
            user.MaxParentalRatingScore = null;
        }
        else if (p.MaxParentalRating.HasValue)
        {
            user.MaxParentalRatingScore = p.MaxParentalRating;
        }

        if (p.ClearMaxParentalRatingSub)
        {
            user.MaxParentalRatingSubScore = null;
        }
        else if (p.MaxParentalRatingSub.HasValue)
        {
            user.MaxParentalRatingSubScore = p.MaxParentalRatingSub;
        }

        if (p.ClearRemoteClientBitrateLimit)
        {
            user.RemoteClientBitrateLimit = null;
        }
        else if (p.RemoteClientBitrateLimit.HasValue)
        {
            user.RemoteClientBitrateLimit = p.RemoteClientBitrateLimit;
        }

        if (p.MaxActiveSessions.HasValue)
        {
            user.MaxActiveSessions = p.MaxActiveSessions.Value;
        }

        if (p.ClearLoginAttemptsBeforeLockout)
        {
            user.LoginAttemptsBeforeLockout = null;
        }
        else if (p.LoginAttemptsBeforeLockout.HasValue)
        {
            user.LoginAttemptsBeforeLockout = p.LoginAttemptsBeforeLockout;
        }
    }

    private List<string> ResolveLibraryIds(List<string> ids, List<string> names)
    {
        var resolved = new HashSet<string>(ids, StringComparer.OrdinalIgnoreCase);
        if (names.Count == 0) return resolved.ToList();

        var folders = _libraryManager.GetVirtualFolders();
        foreach (var name in names)
        {
            var folder = folders.FirstOrDefault(f =>
                string.Equals(f.Name, name, StringComparison.OrdinalIgnoreCase));
            if (folder != null)
            {
                resolved.Add(folder.ItemId);
            }
            else
            {
                _logger.LogWarning("Library '{LibraryName}' not found during RBAC resolution", name);
            }
        }

        return resolved.ToList();
    }

    internal async Task LogActivityAsync(
        string name,
        string type,
        Guid userId,
        string? overview,
        Microsoft.Extensions.Logging.LogLevel severity)
    {
        try
        {
            var entry = new ActivityLog(name, type, userId)
            {
                Overview = overview,
                LogSeverity = severity
            };
            await _activityManager.CreateAsync(entry).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to write activity log entry '{Name}'", name);
        }
    }
}
