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

    public async Task ApplyRoleMappingsAsync(
        Guid userId,
        string[] userRoles,
        string[] entitlements,
        string providerId)
    {
        var config = _configProvider.GetConfiguration();

        var user = _userManager.GetUserById(userId);
        if (user == null)
        {
            _logger.LogWarning("User {UserId} not found for RBAC application", userId);
            return;
        }

        var preview = ComputePermissions(userRoles, entitlements, providerId, config);

        if (preview.MatchedGrantMappings.Length == 0 && !preview.ParsedEntitlements.Any())
        {
            _logger.LogInformation(
                "No role mappings or entitlements matched for user {Username} (roles: [{Roles}])",
                user.Username, string.Join(", ", userRoles));
            return;
        }

        ApplyToUser(user, preview);
        await _userManager.UpdateUserAsync(user).ConfigureAwait(false);

        string adminStr = preview.IsAdmin?.ToString() ?? "unchanged";
        string libsStr = preview.EnableAllLibraries switch
        {
            true => "ALL",
            false => (preview.Libraries?.Count ?? 0).ToString(),
            null => "unchanged",
        };

        _logger.LogInformation(
            "Applied RBAC for user {Username}: admin={IsAdmin}, libraries={Libraries}, " +
            "grants=[{Grants}], denies=[{Denies}], entitlements={EntCount}",
            user.Username,
            adminStr,
            libsStr,
            string.Join(", ", preview.MatchedGrantMappings),
            string.Join(", ", preview.MatchedDenyMappings),
            entitlements.Length);

        await LogActivityAsync(
            "OIDC RBAC permissions updated",
            "OidcPermissionsChanged",
            userId,
            $"Roles: {string.Join(", ", userRoles)}. Admin: {adminStr}.",
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

    private void ApplyToUser(Jellyfin.Database.Implementations.Entities.User user, PermissionPreview p)
    {
        void Apply(PermissionKind kind, bool? value)
        {
            if (value.HasValue) user.SetPermission(kind, value.Value);
        }

        Apply(PermissionKind.IsAdministrator, p.IsAdmin);
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
            _logger.LogDebug(ex, "Failed to write activity log entry '{Name}'", name);
        }
    }
}
