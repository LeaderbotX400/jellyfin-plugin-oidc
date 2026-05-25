using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Jellyfin.Plugin.OIDC.Services;

/// <summary>
/// Helpers for redacting IdP-supplied and PII values before they reach log sinks.
///
/// Policy (TASK-18):
///   Info  — no role-list contents, no claim values, no sub, no email.
///   Debug — redacted forms: role count, first-8-chars of sub, email domain.
///   Verbose/Trace — full values, only when <c>VerboseClaimLogging</c> is enabled in config.
/// </summary>
public static class LogRedaction
{
    /// <summary>
    /// Strips ASCII control characters (U+0000–U+001F and U+007F) from an IdP-supplied string,
    /// then caps the result at <paramref name="maxLen"/> characters.
    /// Prevents log-injection attacks from hostile <c>error_description</c> values, etc.
    /// </summary>
    public static string Sanitize(string? idpSupplied, int maxLen = 200)
    {
        if (string.IsNullOrEmpty(idpSupplied))
        {
            return string.Empty;
        }

        var sb = new StringBuilder(Math.Min(idpSupplied.Length, maxLen));
        foreach (var ch in idpSupplied)
        {
            // Strip all ASCII control characters: U+0000–U+001F (including NUL, CR, LF, TAB, ESC)
            // and U+007F (DEL). Use char.IsControl for completeness.
            if (char.IsControl(ch))
            {
                continue;
            }

            sb.Append(ch);
            if (sb.Length == maxLen)
            {
                break;
            }
        }

        return sb.ToString();
    }

    /// <summary>
    /// Returns the first 8 characters of the raw sub value, followed by "…".
    /// Safe to log at Debug level — uniquely identifies the subject in logs
    /// without exposing the full opaque identifier.
    /// </summary>
    public static string RedactSub(string? sub)
    {
        if (string.IsNullOrEmpty(sub))
        {
            return "(empty)";
        }

        return sub.Length <= 8 ? sub + "…" : sub[..8] + "…";
    }

    /// <summary>
    /// Returns "xxx@{domain}" form of an email address.
    /// Safe to log at Debug level — reveals the IdP domain without exposing the local part.
    /// </summary>
    public static string RedactEmail(string? email)
    {
        if (string.IsNullOrEmpty(email))
        {
            return "(empty)";
        }

        var atIdx = email.LastIndexOf('@');
        if (atIdx < 0)
        {
            return "xxx@(unknown)";
        }

        return "xxx@" + email[(atIdx + 1)..];
    }

    /// <summary>
    /// When <paramref name="verboseLogging"/> is false (default), returns only the count.
    /// When true, returns the full list joined with ", ".
    /// </summary>
    public static string RedactRoles(IEnumerable<string> roles, bool verboseLogging = false)
    {
        var arr = roles as string[] ?? roles.ToArray();
        if (verboseLogging)
        {
            return $"[{string.Join(", ", arr)}]";
        }

        return $"(count={arr.Length})";
    }
}
