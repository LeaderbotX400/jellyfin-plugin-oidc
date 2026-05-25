using System;

namespace Jellyfin.Plugin.OIDC.Services;

/// <summary>
/// Shared URL safety checks for OIDC endpoints (authority, JWKS, token, authorize).
/// MITM on plain HTTP delivers attacker-controlled JWKS → arbitrary token forgery,
/// so every URL we fetch over the wire goes through here.
/// </summary>
public static class SecurityValidation
{
    /// <summary>
    /// Throws <see cref="InvalidOperationException"/> if <paramref name="url"/> is not safe to fetch.
    /// "Safe" means HTTPS, OR (HTTP AND localhost AND <paramref name="allowInsecure"/> is true).
    /// </summary>
    /// <param name="url">The URL to validate. Null/empty is treated as invalid.</param>
    /// <param name="allowInsecure">Per-provider <c>AllowInsecureAuthority</c> flag.</param>
    /// <param name="paramName">Field name to surface in the error message.</param>
    public static void EnsureSecureUrl(string? url, bool allowInsecure, string paramName)
    {
        if (string.IsNullOrWhiteSpace(url))
        {
            throw new InvalidOperationException($"{paramName} is required");
        }

        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
        {
            throw new InvalidOperationException($"{paramName} must be an absolute URL: {url}");
        }

        if (uri.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        if (uri.Scheme.Equals(Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase))
        {
            if (allowInsecure && IsLoopback(uri.Host))
            {
                return;
            }

            throw new InvalidOperationException(
                $"{paramName} must use HTTPS (got {uri.Scheme}://{uri.Host}). " +
                "To allow plain HTTP for a localhost dev IdP, enable AllowInsecureAuthority on the provider.");
        }

        throw new InvalidOperationException(
            $"{paramName} scheme '{uri.Scheme}' is not supported; only https:// (or http:// to localhost with AllowInsecureAuthority) is permitted.");
    }

    /// <summary>Returns true for hosts we consider loopback for the dev-only HTTP bypass.</summary>
    public static bool IsLoopback(string host)
    {
        if (string.IsNullOrEmpty(host)) return false;
        return host.Equals("localhost", StringComparison.OrdinalIgnoreCase)
            || host.Equals("127.0.0.1", StringComparison.Ordinal)
            || host.Equals("::1", StringComparison.Ordinal)
            || host.Equals("[::1]", StringComparison.Ordinal);
    }
}
