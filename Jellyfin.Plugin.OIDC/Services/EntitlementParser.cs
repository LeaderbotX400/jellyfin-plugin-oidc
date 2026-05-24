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
    public bool EnableMediaPlayback { get; set; }
    public bool EnableRemoteAccess { get; set; }
    public bool EnableTranscoding { get; set; }
    public bool EnableLiveTv { get; set; }
    public bool EnableLiveTvManagement { get; set; }
    public bool EnableContentDeletion { get; set; }
    public bool EnableCollectionManagement { get; set; }
    public bool EnableSubtitleManagement { get; set; }
    public bool EnableDownload { get; set; }
    public bool EnableSyncplay { get; set; }
    public bool EnableSyncplayGroupCreation { get; set; }
    public bool EnableAllLibraries { get; set; }
    public HashSet<string> LibraryNames { get; } = new(StringComparer.OrdinalIgnoreCase);
    public int? MaxParentalRating { get; set; }

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
                case "playback":
                    set.EnableMediaPlayback = true;
                    break;
                case "remote":
                    set.EnableRemoteAccess = true;
                    break;
                case "transcoding":
                    set.EnableTranscoding = true;
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
                default:
                    if (token.StartsWith("library:", StringComparison.OrdinalIgnoreCase))
                    {
                        var libraryName = raw[(prefix.Length + "library:".Length)..];
                        if (!string.IsNullOrEmpty(libraryName))
                        {
                            set.LibraryNames.Add(libraryName);
                        }
                    }
                    else if (token.StartsWith("rating:", StringComparison.OrdinalIgnoreCase))
                    {
                        var ratingStr = token["rating:".Length..];
                        if (int.TryParse(ratingStr, out var rating))
                        {
                            // Take the most permissive (highest) rating if multiple specified
                            if (!set.MaxParentalRating.HasValue || rating > set.MaxParentalRating.Value)
                            {
                                set.MaxParentalRating = rating;
                            }
                        }
                    }

                    break;
            }
        }

        return set;
    }
}
