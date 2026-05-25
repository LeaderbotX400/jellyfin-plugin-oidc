using System.Collections.Generic;

namespace Jellyfin.Plugin.OIDC.Services;

/// <summary>
/// Resolved effective permissions for a user, used by the preview endpoint and deny-mapping tests.
/// Nullable boolean fields use the convention: <c>null</c> means "no opinion — leave the user's
/// existing Jellyfin value untouched". Non-null values are written to the user.
/// In <see cref="Configuration.RbacBehaviorMode.EntitlementsAuthoritative"/> mode every field is
/// concrete (non-null); the nullable path is only exercised in
/// <see cref="Configuration.RbacBehaviorMode.RespectExistingWhenUnspecified"/> when entitlements
/// are absent.
/// </summary>
public sealed record PermissionPreview(
    bool? IsAdmin,
    bool? EnableMediaPlayback,
    bool? EnableRemoteAccess,
    bool? EnableTranscoding,
    bool? EnableLiveTv,
    bool? EnableLiveTvManagement,
    bool? EnableContentDeletion,
    bool? EnableCollectionManagement,
    bool? EnableSubtitleManagement,
    bool? EnableDownload,
    bool? EnableSyncplay,
    bool? EnableSyncplayGroupCreation,
    bool? EnableAllLibraries,
    /// <summary>Library IDs to enable when <see cref="EnableAllLibraries"/> is false. Null = no library opinion (leave user's existing libraries untouched).</summary>
    List<string>? Libraries,
    /// <summary>Numeric max parental rating to set, or null if not opined. See <see cref="ClearMaxParentalRating"/> for the explicit "no limit" case.</summary>
    int? MaxParentalRating,
    /// <summary>True when an entitlement asked to clear the user's MaxParentalRatingScore to null (no limit). Takes precedence over <see cref="MaxParentalRating"/>.</summary>
    bool ClearMaxParentalRating,
    string[] MatchedGrantMappings,
    string[] MatchedDenyMappings,
    string[] ParsedEntitlements);
