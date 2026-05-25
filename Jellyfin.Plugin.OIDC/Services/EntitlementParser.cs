using System;
using System.Collections.Generic;

namespace Jellyfin.Plugin.OIDC.Services;

/// <summary>
/// Represents permissions explicitly expressed by IdP entitlement claims.
/// Null properties mean "not expressed" — fall through to role-mapping result.
/// </summary>
public class EntitlementSet
{
    public bool IsAdmin { get; set; }
    public bool IsDisabled { get; set; }
    public bool IsHidden { get; set; }
    public bool EnableMediaPlayback { get; set; }
    public bool EnableRemoteAccess { get; set; }
    public bool EnableTranscoding { get; set; }
    public bool EnableSyncTranscoding { get; set; }
    public bool ForceRemoteSourceTranscoding { get; set; }
    public bool EnablePlaybackRemuxing { get; set; }
    public bool EnableMediaConversion { get; set; }
    public bool EnableLiveTv { get; set; }
    public bool EnableLiveTvManagement { get; set; }
    public bool EnableContentDeletion { get; set; }
    public bool EnableCollectionManagement { get; set; }
    public bool EnableSubtitleManagement { get; set; }
    public bool EnableLyricManagement { get; set; }
    public bool EnableDownload { get; set; }
    public bool EnableSyncplay { get; set; }
    public bool EnableSyncplayGroupCreation { get; set; }
    public bool EnableAllLibraries { get; set; }
    public bool EnableAllChannels { get; set; }
    public bool EnableAllDevices { get; set; }
    public bool EnableSharedDeviceControl { get; set; }
    public bool EnableRemoteControlOfOtherUsers { get; set; }
    public bool EnablePublicSharing { get; set; }
    public HashSet<string> LibraryNames { get; } = new(StringComparer.OrdinalIgnoreCase);
    public int? MaxParentalRating { get; set; }

    /// <summary>
    /// True when an entitlement explicitly removed any parental-rating limit
    /// (e.g. <c>jellyfin:rating:unlimited</c>). Causes the user's MaxParentalRatingScore
    /// to be set to null. Takes precedence over numeric rating tokens.
    /// </summary>
    public bool ClearMaxParentalRating { get; set; }

    public int? MaxParentalRatingSub { get; set; }
    public bool ClearMaxParentalRatingSub { get; set; }

    /// <summary>Remote client bitrate limit in kbps. Highest claim wins.</summary>
    public int? RemoteClientBitrateLimit { get; set; }
    public bool ClearRemoteClientBitrateLimit { get; set; }

    /// <summary>Max active sessions. 0 means unlimited in Jellyfin.</summary>
    public int? MaxActiveSessions { get; set; }

    /// <summary>Login attempts before lockout. Null means unlimited.</summary>
    public int? LoginAttemptsBeforeLockout { get; set; }
    public bool ClearLoginAttemptsBeforeLockout { get; set; }

    public bool HasAny { get; private set; }

    internal void MarkHasAny() => HasAny = true;
}

/// <summary>
/// Parses IdP entitlement strings (e.g. Authentik entitlements) into a <see cref="EntitlementSet"/>.
/// Default prefix is "jellyfin:" — e.g. "jellyfin:admin", "jellyfin:library:Movies".
/// </summary>
public static class EntitlementParser
{
    public static EntitlementSet Parse(string[] entitlements, string prefix)
    {
        if (string.IsNullOrEmpty(prefix))
        {
            prefix = "jellyfin:";
        }

        // IMPORTANT: The prefix match uses OrdinalIgnoreCase, and the token is extracted
        // using raw byte index (raw[prefix.Length..]). This is correct ONLY when the
        // prefix is entirely ASCII — because OrdinalIgnoreCase case-folds ASCII without
        // changing byte lengths (A-Z ↔ a-z differ only in bit 5, always same byte count).
        // If a non-ASCII prefix were configured, the substring index could be wrong.
        // We document and enforce this: the EntitlementPrefix config field is expected to
        // be ASCII (e.g. "jellyfin:", "myapp:"). Non-ASCII prefixes will produce
        // unexpected behavior and are not supported. See unit tests for a non-ASCII case.

        var set = new EntitlementSet();

        foreach (var raw in entitlements)
        {
            if (!raw.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var token = raw[prefix.Length..].ToLowerInvariant();
            set.MarkHasAny();

            switch (token)
            {
                case "admin":
                    set.IsAdmin = true;
                    break;
                case "disabled":
                    set.IsDisabled = true;
                    break;
                case "hidden":
                    set.IsHidden = true;
                    break;
                case "playback":
                    set.EnableMediaPlayback = true;
                    break;
                case "remote":
                    set.EnableRemoteAccess = true;
                    break;
                case "transcoding":
                    set.EnableTranscoding = true;
                    break;
                case "transcoding:sync":
                    set.EnableSyncTranscoding = true;
                    break;
                case "transcoding:force-remote":
                    set.ForceRemoteSourceTranscoding = true;
                    break;
                case "remux":
                    set.EnablePlaybackRemuxing = true;
                    break;
                case "conversion":
                    set.EnableMediaConversion = true;
                    break;
                case "livetv":
                    set.EnableLiveTv = true;
                    break;
                case "livetv:manage":
                    set.EnableLiveTv = true;
                    set.EnableLiveTvManagement = true;
                    break;
                case "content:delete":
                    set.EnableContentDeletion = true;
                    break;
                case "collection:manage":
                    set.EnableCollectionManagement = true;
                    break;
                case "subtitle:manage":
                    set.EnableSubtitleManagement = true;
                    break;
                case "lyric:manage":
                    set.EnableLyricManagement = true;
                    break;
                case "download":
                    set.EnableDownload = true;
                    break;
                case "syncplay":
                    set.EnableSyncplay = true;
                    break;
                case "syncplay:host":
                    set.EnableSyncplay = true;
                    set.EnableSyncplayGroupCreation = true;
                    break;
                case "library:all":
                    set.EnableAllLibraries = true;
                    break;
                case "channels:all":
                    set.EnableAllChannels = true;
                    break;
                case "devices:all":
                    set.EnableAllDevices = true;
                    break;
                case "devices:shared-control":
                    set.EnableSharedDeviceControl = true;
                    break;
                case "remote-control":
                    set.EnableRemoteControlOfOtherUsers = true;
                    break;
                case "public-sharing":
                    set.EnablePublicSharing = true;
                    break;
                default:
                    if (token.StartsWith("library:", StringComparison.OrdinalIgnoreCase))
                    {
                        var libraryName = raw[(prefix.Length + "library:".Length)..];
                        if (!string.IsNullOrEmpty(libraryName))
                        {
                            set.LibraryNames.Add(libraryName);
                        }
                    }
                    else if (token.StartsWith("rating:sub:", StringComparison.OrdinalIgnoreCase))
                    {
                        var val = token["rating:sub:".Length..];
                        if (val is "unlimited" or "none" or "max")
                        {
                            set.ClearMaxParentalRatingSub = true;
                        }
                        else if (int.TryParse(val, out var n))
                        {
                            if (!set.MaxParentalRatingSub.HasValue || n > set.MaxParentalRatingSub.Value)
                            {
                                set.MaxParentalRatingSub = n;
                            }
                        }
                    }
                    else if (token.StartsWith("rating:", StringComparison.OrdinalIgnoreCase))
                    {
                        var ratingStr = token["rating:".Length..];
                        if (ratingStr is "unlimited" or "none" or "max")
                        {
                            set.ClearMaxParentalRating = true;
                        }
                        else if (int.TryParse(ratingStr, out var rating))
                        {
                            // Take the most permissive (highest) rating if multiple specified
                            if (!set.MaxParentalRating.HasValue || rating > set.MaxParentalRating.Value)
                            {
                                set.MaxParentalRating = rating;
                            }
                        }
                    }
                    else if (token.StartsWith("bitrate:", StringComparison.OrdinalIgnoreCase))
                    {
                        var val = token["bitrate:".Length..];
                        if (val is "unlimited" or "none")
                        {
                            set.ClearRemoteClientBitrateLimit = true;
                        }
                        else if (int.TryParse(val, out var n))
                        {
                            // Highest cap wins (most permissive).
                            if (!set.RemoteClientBitrateLimit.HasValue || n > set.RemoteClientBitrateLimit.Value)
                            {
                                set.RemoteClientBitrateLimit = n;
                            }
                        }
                    }
                    else if (token.StartsWith("sessions:", StringComparison.OrdinalIgnoreCase))
                    {
                        var val = token["sessions:".Length..];
                        if (val is "unlimited" or "none")
                        {
                            // Jellyfin uses 0 to mean "no limit" for MaxActiveSessions.
                            set.MaxActiveSessions = 0;
                        }
                        else if (int.TryParse(val, out var n) && n >= 0)
                        {
                            // 0 = unlimited; higher numeric value wins, but 0 (unlimited) trumps all.
                            if (set.MaxActiveSessions != 0 &&
                                (!set.MaxActiveSessions.HasValue || n > set.MaxActiveSessions.Value))
                            {
                                set.MaxActiveSessions = n;
                            }
                        }
                    }
                    else if (token.StartsWith("login-attempts:", StringComparison.OrdinalIgnoreCase))
                    {
                        var val = token["login-attempts:".Length..];
                        if (val is "unlimited" or "none")
                        {
                            set.ClearLoginAttemptsBeforeLockout = true;
                        }
                        else if (int.TryParse(val, out var n) && n >= 0)
                        {
                            if (!set.LoginAttemptsBeforeLockout.HasValue || n > set.LoginAttemptsBeforeLockout.Value)
                            {
                                set.LoginAttemptsBeforeLockout = n;
                            }
                        }
                    }

                    break;
            }
        }

        return set;
    }
}
