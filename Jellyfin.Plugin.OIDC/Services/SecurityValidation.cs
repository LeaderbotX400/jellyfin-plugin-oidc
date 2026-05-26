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

    /// <summary>
    /// Throws if the discovered endpoint URL is not on the same scheme+host+port as the authority.
    /// Defense against a malicious/compromised discovery document that points endpoints at attacker
    /// hosts. We intentionally do NOT require a shared path prefix — many real IdPs (Authentik,
    /// AWS Cognito, etc.) serve sibling endpoints from a different path than the issuer.
    /// </summary>
    public static void EnsureSameHost(string? authorityUrl, string? endpointUrl, string paramName)
    {
        if (string.IsNullOrWhiteSpace(endpointUrl))
        {
            return; // optional endpoints (e.g. JWKS) are validated separately for presence
        }

        if (!Uri.TryCreate(authorityUrl, UriKind.Absolute, out var authority)
            || !Uri.TryCreate(endpointUrl, UriKind.Absolute, out var endpoint))
        {
            throw new InvalidOperationException(
                $"Cannot validate {paramName}: authority or endpoint is not a valid absolute URL");
        }

        if (!string.Equals(authority.Scheme, endpoint.Scheme, StringComparison.OrdinalIgnoreCase)
            || !string.Equals(authority.Host, endpoint.Host, StringComparison.OrdinalIgnoreCase)
            || authority.Port != endpoint.Port)
        {
            throw new InvalidOperationException(
                $"Discovery document {paramName} ({endpoint.Scheme}://{endpoint.Authority}) " +
                $"is not on the same host as the authority ({authority.Scheme}://{authority.Authority}). " +
                "This usually indicates a misconfigured or malicious IdP. " +
                "If your IdP legitimately uses a different host, this is not supported.");
        }
    }

    /// <summary>
    /// Normalizes an admin-supplied authority URL. Strips an accidentally-included
    /// <c>/.well-known/openid-configuration</c> suffix (with or without trailing slash) and any
    /// trailing slash. The result is the issuer base URL that IdentityModel expects.
    /// </summary>
    public static string NormalizeAuthority(string? authority)
    {
        if (string.IsNullOrWhiteSpace(authority)) return authority ?? string.Empty;
        var s = authority.Trim();
        const string wellKnown = "/.well-known/openid-configuration";
        if (s.EndsWith(wellKnown + "/", StringComparison.OrdinalIgnoreCase))
        {
            s = s[..^(wellKnown.Length + 1)];
        }
        else if (s.EndsWith(wellKnown, StringComparison.OrdinalIgnoreCase))
        {
            s = s[..^wellKnown.Length];
        }
        return s.TrimEnd('/');
    }
}
