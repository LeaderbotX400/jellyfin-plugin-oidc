using System.Collections.Generic;

namespace Jellyfin.Plugin.OIDC.Services;

/// <summary>Resolved effective permissions for a user, used by the preview endpoint and deny-mapping tests.</summary>
public sealed record PermissionPreview(
    bool IsAdmin,
    bool EnableMediaPlayback,
    bool EnableRemoteAccess,
    bool EnableTranscoding,
    bool EnableLiveTv,
    bool EnableLiveTvManagement,
    bool EnableContentDeletion,
    bool EnableCollectionManagement,
    bool EnableSubtitleManagement,
    bool EnableDownload,
    bool EnableSyncplay,
    bool EnableSyncplayGroupCreation,
    bool EnableAllLibraries,
    List<string> Libraries,
    int? MaxParentalRating,
    string[] MatchedGrantMappings,
    string[] MatchedDenyMappings,
    string[] ParsedEntitlements);
