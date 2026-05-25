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
    bool? IsDisabled,
    bool? IsHidden,
    bool? EnableMediaPlayback,
    bool? EnableRemoteAccess,
    bool? EnableTranscoding,
    bool? EnableSyncTranscoding,
    bool? ForceRemoteSourceTranscoding,
    bool? EnablePlaybackRemuxing,
    bool? EnableMediaConversion,
    bool? EnableLiveTv,
    bool? EnableLiveTvManagement,
    bool? EnableContentDeletion,
    bool? EnableCollectionManagement,
    bool? EnableSubtitleManagement,
    bool? EnableLyricManagement,
    bool? EnableDownload,
    bool? EnableSyncplay,
    bool? EnableSyncplayGroupCreation,
    bool? EnableAllLibraries,
    bool? EnableAllChannels,
    bool? EnableAllDevices,
    bool? EnableSharedDeviceControl,
    bool? EnableRemoteControlOfOtherUsers,
    bool? EnablePublicSharing,
    List<string>? Libraries,
    int? MaxParentalRating,
    bool ClearMaxParentalRating,
    int? MaxParentalRatingSub,
    bool ClearMaxParentalRatingSub,
    int? RemoteClientBitrateLimit,
    bool ClearRemoteClientBitrateLimit,
    int? MaxActiveSessions,
    int? LoginAttemptsBeforeLockout,
    bool ClearLoginAttemptsBeforeLockout,
    string[] MatchedGrantMappings,
    string[] MatchedDenyMappings,
    string[] ParsedEntitlements);
