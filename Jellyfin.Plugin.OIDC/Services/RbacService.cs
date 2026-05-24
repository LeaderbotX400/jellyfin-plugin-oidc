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

        _logger.LogInformation(
            "Applied RBAC for user {Username}: admin={IsAdmin}, libraries={Libraries}, " +
            "grants=[{Grants}], denies=[{Denies}], entitlements={EntCount}",
            user.Username,
            preview.IsAdmin,
            preview.EnableAllLibraries ? "ALL" : preview.Libraries.Count.ToString(),
            string.Join(", ", preview.MatchedGrantMappings),
            string.Join(", ", preview.MatchedDenyMappings),
            entitlements.Length);

        await LogActivityAsync(
            "OIDC RBAC permissions updated",
            "OidcPermissionsChanged",
            userId,
            $"Roles: {string.Join(", ", userRoles)}. Admin: {preview.IsAdmin}.",
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
        var allMatching = config.RoleMappings
            .Where(m =>
                (string.IsNullOrEmpty(m.ProviderId) ||
                 string.Equals(m.ProviderId, providerId, StringComparison.OrdinalIgnoreCase)) &&
                userRoles.Contains(m.RoleName, StringComparer.OrdinalIgnoreCase))
            .OrderByDescending(m => m.Priority)
            .ToList();

        var grantMappings = allMatching.Where(m => !m.IsExplicitDeny).ToList();
        var denyMappings = allMatching.Where(m => m.IsExplicitDeny).ToList();

        if (grantMappings.Count == 0 && !string.IsNullOrEmpty(config.DefaultRoleName))
        {
            var def = config.RoleMappings.FirstOrDefault(m =>
                !m.IsExplicitDeny &&
                string.Equals(m.RoleName, config.DefaultRoleName, StringComparison.OrdinalIgnoreCase));
            if (def != null) grantMappings.Add(def);
        }

        var merged = grantMappings.Count > 0 ? MergeMappings(grantMappings) : new RoleMapping();
        var deny = denyMappings.Count > 0 ? MergeMappings(denyMappings) : null;

        var provider = config.Providers.FirstOrDefault(p =>
            string.Equals(p.ProviderId, providerId, StringComparison.OrdinalIgnoreCase));
        var entSet = (provider?.EnableEntitlements == true)
            ? EntitlementParser.Parse(entitlements, provider.EntitlementPrefix)
            : new EntitlementSet();

        // OR grants, then apply deny override
        bool isAdmin = (merged.IsAdmin || entSet.IsAdmin) && !(deny?.IsAdmin ?? false);
        bool playback = (merged.EnableMediaPlayback || entSet.EnableMediaPlayback) && !(deny?.EnableMediaPlayback ?? false);
        bool remote = (merged.EnableRemoteAccess || entSet.EnableRemoteAccess) && !(deny?.EnableRemoteAccess ?? false);
        bool transcode = (merged.EnableTranscoding || entSet.EnableTranscoding) && !(deny?.EnableTranscoding ?? false);
        bool liveTv = (merged.EnableLiveTv || entSet.EnableLiveTv) && !(deny?.EnableLiveTv ?? false);
        bool liveTvMgmt = (merged.EnableLiveTvManagement || entSet.EnableLiveTvManagement) && !(deny?.EnableLiveTvManagement ?? false);
        bool delete = (merged.EnableContentDeletion || entSet.EnableContentDeletion) && !(deny?.EnableContentDeletion ?? false);
        bool collections = (merged.EnableCollectionManagement || entSet.EnableCollectionManagement) && !(deny?.EnableCollectionManagement ?? false);
        bool subtitles = (merged.EnableSubtitleManagement || entSet.EnableSubtitleManagement) && !(deny?.EnableSubtitleManagement ?? false);
        bool download = (merged.EnableDownload || entSet.EnableDownload) && !(deny?.EnableDownload ?? false);
        bool syncplayHost = (merged.EnableSyncplayGroupCreation || entSet.EnableSyncplayGroupCreation) && !(deny?.EnableSyncplayGroupCreation ?? false);
        bool syncplay = ((merged.EnableSyncplay || entSet.EnableSyncplay) || syncplayHost) && !(deny?.EnableSyncplay ?? false);
        bool allLibs = (merged.EnableAllLibraries || entSet.EnableAllLibraries) && !(deny?.EnableAllLibraries ?? false);

        var libraryNames = merged.LibraryNames
            .Union(entSet.LibraryNames, StringComparer.OrdinalIgnoreCase)
            .ToList();
        var libraryIds = merged.LibraryIds.ToList();

        int? maxRating = null;
        if (merged.MaxParentalRating.HasValue || entSet.MaxParentalRating.HasValue)
        {
            maxRating = Math.Max(merged.MaxParentalRating ?? 0, entSet.MaxParentalRating ?? 0);
        }

        return new PermissionPreview(
            IsAdmin: isAdmin,
            EnableMediaPlayback: playback,
            EnableRemoteAccess: remote,
            EnableTranscoding: transcode,
            EnableLiveTv: liveTv,
            EnableLiveTvManagement: liveTvMgmt,
            EnableContentDeletion: delete,
            EnableCollectionManagement: collections,
            EnableSubtitleManagement: subtitles,
            EnableDownload: download,
            EnableSyncplay: syncplay,
            EnableSyncplayGroupCreation: syncplayHost,
            EnableAllLibraries: allLibs,
            Libraries: allLibs ? new List<string>() : ResolveLibraryIds(libraryIds, libraryNames),
            MaxParentalRating: maxRating,
            MatchedGrantMappings: grantMappings.Select(m => m.RoleName).ToArray(),
            MatchedDenyMappings: denyMappings.Select(m => m.RoleName).ToArray(),
            ParsedEntitlements: entitlements);
    }

    private void ApplyToUser(Jellyfin.Database.Implementations.Entities.User user, PermissionPreview p)
    {
        user.SetPermission(PermissionKind.IsAdministrator, p.IsAdmin);
        user.SetPermission(PermissionKind.EnableMediaPlayback, p.EnableMediaPlayback);
        user.SetPermission(PermissionKind.EnableRemoteAccess, p.EnableRemoteAccess);
        user.SetPermission(PermissionKind.EnableAudioPlaybackTranscoding, p.EnableTranscoding);
        user.SetPermission(PermissionKind.EnableVideoPlaybackTranscoding, p.EnableTranscoding);
        user.SetPermission(PermissionKind.EnableLiveTvAccess, p.EnableLiveTv);
        user.SetPermission(PermissionKind.EnableLiveTvManagement, p.EnableLiveTvManagement);
        user.SetPermission(PermissionKind.EnableContentDeletion, p.EnableContentDeletion);
        user.SetPermission(PermissionKind.EnableCollectionManagement, p.EnableCollectionManagement);
        user.SetPermission(PermissionKind.EnableSubtitleManagement, p.EnableSubtitleManagement);
        user.SetPermission(PermissionKind.EnableContentDownloading, p.EnableDownload);

        user.SyncPlayAccess = p.EnableSyncplayGroupCreation
            ? SyncPlayAccess.CreateAndJoinGroups
            : p.EnableSyncplay
                ? SyncPlayAccess.JoinGroups
                : SyncPlayAccess.None;

        if (p.EnableAllLibraries)
        {
            user.SetPermission(PermissionKind.EnableAllFolders, true);
        }
        else
        {
            user.SetPermission(PermissionKind.EnableAllFolders, false);
            user.SetPreference(PreferenceKind.EnabledFolders, p.Libraries.ToArray());
        }

        if (p.MaxParentalRating.HasValue)
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

    private static RoleMapping MergeMappings(List<RoleMapping> mappings)
    {
        return new RoleMapping
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
            EnableSyncplayGroupCreation = mappings.Any(m => m.EnableSyncplayGroupCreation),
            MaxParentalRating = mappings
                .Where(m => m.MaxParentalRating.HasValue)
                .Select(m => m.MaxParentalRating!.Value)
                .DefaultIfEmpty()
                .Max(),
            LibraryIds = mappings.SelectMany(m => m.LibraryIds)
                .Distinct(StringComparer.OrdinalIgnoreCase).ToList(),
            LibraryNames = mappings.SelectMany(m => m.LibraryNames)
                .Distinct(StringComparer.OrdinalIgnoreCase).ToList()
        };
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
