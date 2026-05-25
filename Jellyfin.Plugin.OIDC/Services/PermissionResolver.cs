using System;
using System.Collections.Generic;
using System.Linq;
using Jellyfin.Plugin.OIDC.Configuration;

namespace Jellyfin.Plugin.OIDC.Services;

/// <summary>
/// Pure-function permission resolver. Computes a <see cref="PermissionPreview"/> from roles,
/// entitlements, and the plugin configuration without touching any Jellyfin services. Library
/// name → id resolution is delegated via a callback so this class stays free of
/// <c>ILibraryManager</c> and can be exercised in isolated unit tests.
/// </summary>
/// <summary>
/// Minimal config view consumed by <see cref="PermissionResolver"/>. Plain POCO so unit tests can
/// construct one without pulling in <c>MediaBrowser.Model</c> (which <see cref="PluginConfiguration"/>
/// inherits from via <c>BasePluginConfiguration</c>).
/// </summary>
public sealed class ResolverConfig
{
    public List<RoleMapping> RoleMappings { get; set; } = new();
    public List<OidcProviderConfig> Providers { get; set; } = new();
    public string DefaultRoleName { get; set; } = string.Empty;
    public RbacBehaviorMode RbacBehavior { get; set; } = RbacBehaviorMode.EntitlementsAuthoritative;

    public static ResolverConfig From(PluginConfiguration cfg) => new()
    {
        RoleMappings = cfg.RoleMappings,
        Providers = cfg.Providers,
        DefaultRoleName = cfg.DefaultRoleName,
        RbacBehavior = cfg.RbacBehavior,
    };
}

public static class PermissionResolver
{
    public static PermissionPreview Resolve(
        string[] userRoles,
        string[] entitlements,
        string providerId,
        PluginConfiguration config,
        Func<List<string>, List<string>, List<string>>? resolveLibraryIds = null)
        => Resolve(userRoles, entitlements, providerId, ResolverConfig.From(config), resolveLibraryIds);

    public static PermissionPreview Resolve(
        string[] userRoles,
        string[] entitlements,
        string providerId,
        ResolverConfig config,
        Func<List<string>, List<string>, List<string>>? resolveLibraryIds = null)
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

        // When no grant mappings matched, fall back to an all-false RoleMapping rather than the
        // default-constructed one — the latter has EnableMediaPlayback/RemoteAccess/Transcoding=true
        // (UI defaults for new mappings), which would otherwise spuriously grant those permissions
        // to users with no matching mapping.
        var merged = grantMappings.Count > 0 ? MergeMappings(grantMappings) : EmptyMapping();
        var deny = denyMappings.Count > 0 ? MergeMappings(denyMappings) : null;

        var provider = config.Providers.FirstOrDefault(p =>
            string.Equals(p.ProviderId, providerId, StringComparison.OrdinalIgnoreCase));
        var entSet = (provider?.EnableEntitlements == true)
            ? EntitlementParser.Parse(entitlements, provider.EntitlementPrefix)
            : new EntitlementSet();

        // Respect-existing mode only takes effect in the role-only path; whenever entitlements appear,
        // they are authoritative (matching the default mode).
        bool respectExisting =
            config.RbacBehavior == RbacBehaviorMode.RespectExistingWhenUnspecified && !entSet.HasAny;

        bool? Resolve(bool grant, bool entitlement, bool? denyOpinion)
        {
            if (denyOpinion == true) return false;
            if (entitlement) return true;
            if (grant) return true;
            return respectExisting ? (bool?)null : false;
        }

        var isAdmin = Resolve(merged.IsAdmin, entSet.IsAdmin, deny?.IsAdmin);
        // Entitlement-only permissions (no parallel field in RoleMapping). grant=false always.
        var isDisabled = Resolve(false, entSet.IsDisabled, false);
        var isHidden = Resolve(false, entSet.IsHidden, false);
        var syncTranscode = Resolve(false, entSet.EnableSyncTranscoding, false);
        var forceRemoteTranscode = Resolve(false, entSet.ForceRemoteSourceTranscoding, false);
        var remux = Resolve(false, entSet.EnablePlaybackRemuxing, false);
        var conversion = Resolve(false, entSet.EnableMediaConversion, false);
        var lyric = Resolve(false, entSet.EnableLyricManagement, false);
        var allChannels = Resolve(false, entSet.EnableAllChannels, false);
        var allDevices = Resolve(false, entSet.EnableAllDevices, false);
        var sharedDevice = Resolve(false, entSet.EnableSharedDeviceControl, false);
        var remoteControl = Resolve(false, entSet.EnableRemoteControlOfOtherUsers, false);
        var publicSharing = Resolve(false, entSet.EnablePublicSharing, false);

        var playback = Resolve(merged.EnableMediaPlayback, entSet.EnableMediaPlayback, deny?.EnableMediaPlayback);
        var remote = Resolve(merged.EnableRemoteAccess, entSet.EnableRemoteAccess, deny?.EnableRemoteAccess);
        var transcode = Resolve(merged.EnableTranscoding, entSet.EnableTranscoding, deny?.EnableTranscoding);
        var liveTv = Resolve(merged.EnableLiveTv, entSet.EnableLiveTv, deny?.EnableLiveTv);
        var liveTvMgmt = Resolve(merged.EnableLiveTvManagement, entSet.EnableLiveTvManagement, deny?.EnableLiveTvManagement);
        var delete = Resolve(merged.EnableContentDeletion, entSet.EnableContentDeletion, deny?.EnableContentDeletion);
        var collections = Resolve(merged.EnableCollectionManagement, entSet.EnableCollectionManagement, deny?.EnableCollectionManagement);
        var subtitles = Resolve(merged.EnableSubtitleManagement, entSet.EnableSubtitleManagement, deny?.EnableSubtitleManagement);
        var download = Resolve(merged.EnableDownload, entSet.EnableDownload, deny?.EnableDownload);
        var syncplayHost = Resolve(merged.EnableSyncplayGroupCreation, entSet.EnableSyncplayGroupCreation, deny?.EnableSyncplayGroupCreation);
        bool syncplayGrantedAnywhere =
            merged.EnableSyncplay || merged.EnableSyncplayGroupCreation ||
            entSet.EnableSyncplay || entSet.EnableSyncplayGroupCreation;
        var syncplay = Resolve(syncplayGrantedAnywhere, false, deny?.EnableSyncplay);

        bool libraryOpined =
            merged.EnableAllLibraries || entSet.EnableAllLibraries ||
            merged.LibraryNames.Count > 0 || merged.LibraryIds.Count > 0 ||
            entSet.LibraryNames.Count > 0 ||
            (deny?.EnableAllLibraries ?? false);

        bool? allLibs;
        List<string>? libraries;
        if (respectExisting && !libraryOpined)
        {
            allLibs = null;
            libraries = null;
        }
        else
        {
            var allLibsResolved =
                (merged.EnableAllLibraries || entSet.EnableAllLibraries) &&
                !(deny?.EnableAllLibraries ?? false);
            allLibs = allLibsResolved;
            if (allLibsResolved)
            {
                libraries = new List<string>();
            }
            else
            {
                var libraryNames = merged.LibraryNames
                    .Union(entSet.LibraryNames, StringComparer.OrdinalIgnoreCase)
                    .ToList();
                var libraryIds = merged.LibraryIds.ToList();
                libraries = resolveLibraryIds != null
                    ? resolveLibraryIds(libraryIds, libraryNames)
                    : libraryIds;
            }
        }

        int? maxRating = null;
        bool clearRating = entSet.ClearMaxParentalRating;
        if (!clearRating &&
            (merged.MaxParentalRating.HasValue || entSet.MaxParentalRating.HasValue))
        {
            maxRating = Math.Max(merged.MaxParentalRating ?? 0, entSet.MaxParentalRating ?? 0);
        }

        return new PermissionPreview(
            IsAdmin: isAdmin,
            IsDisabled: isDisabled,
            IsHidden: isHidden,
            EnableMediaPlayback: playback,
            EnableRemoteAccess: remote,
            EnableTranscoding: transcode,
            EnableSyncTranscoding: syncTranscode,
            ForceRemoteSourceTranscoding: forceRemoteTranscode,
            EnablePlaybackRemuxing: remux,
            EnableMediaConversion: conversion,
            EnableLiveTv: liveTv,
            EnableLiveTvManagement: liveTvMgmt,
            EnableContentDeletion: delete,
            EnableCollectionManagement: collections,
            EnableSubtitleManagement: subtitles,
            EnableLyricManagement: lyric,
            EnableDownload: download,
            EnableSyncplay: syncplay,
            EnableSyncplayGroupCreation: syncplayHost,
            EnableAllLibraries: allLibs,
            EnableAllChannels: allChannels,
            EnableAllDevices: allDevices,
            EnableSharedDeviceControl: sharedDevice,
            EnableRemoteControlOfOtherUsers: remoteControl,
            EnablePublicSharing: publicSharing,
            Libraries: libraries,
            MaxParentalRating: maxRating,
            ClearMaxParentalRating: clearRating,
            MaxParentalRatingSub: entSet.MaxParentalRatingSub,
            ClearMaxParentalRatingSub: entSet.ClearMaxParentalRatingSub,
            RemoteClientBitrateLimit: entSet.RemoteClientBitrateLimit,
            ClearRemoteClientBitrateLimit: entSet.ClearRemoteClientBitrateLimit,
            MaxActiveSessions: entSet.MaxActiveSessions,
            LoginAttemptsBeforeLockout: entSet.LoginAttemptsBeforeLockout,
            ClearLoginAttemptsBeforeLockout: entSet.ClearLoginAttemptsBeforeLockout,
            MatchedGrantMappings: grantMappings.Select(m => m.RoleName).ToArray(),
            MatchedDenyMappings: denyMappings.Select(m => m.RoleName).ToArray(),
            ParsedEntitlements: entitlements);
    }

    private static RoleMapping EmptyMapping() => new()
    {
        EnableMediaPlayback = false,
        EnableRemoteAccess = false,
        EnableTranscoding = false,
    };

    internal static RoleMapping MergeMappings(List<RoleMapping> mappings) => new()
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
        MaxParentalRating = mappings.Any(m => m.MaxParentalRating.HasValue)
            ? mappings.Where(m => m.MaxParentalRating.HasValue).Max(m => m.MaxParentalRating!.Value)
            : (int?)null,
        LibraryIds = mappings.SelectMany(m => m.LibraryIds)
            .Distinct(StringComparer.OrdinalIgnoreCase).ToList(),
        LibraryNames = mappings.SelectMany(m => m.LibraryNames)
            .Distinct(StringComparer.OrdinalIgnoreCase).ToList()
    };
}
