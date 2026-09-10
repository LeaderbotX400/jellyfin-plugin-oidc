using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

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
    /// Returns true when <paramref name="address"/> is on a network the server must never be
    /// tricked into fetching from. Used for URLs whose host is chosen by the IdP (or, on IdPs
    /// where users edit their own profile, effectively by the end user) rather than by an admin.
    ///
    /// <see cref="IsLoopback"/> is a literal hostname check for the dev-HTTP bypass and is NOT a
    /// substitute for this: it does not see through DNS, and it does not cover private, link-local
    /// or carrier-NAT ranges. The classic target this blocks is the cloud instance-metadata
    /// endpoint at 169.254.169.254.
    /// </summary>
    public static bool IsBlockedAddress(IPAddress address)
    {
        ArgumentNullException.ThrowIfNull(address);

        // Unwrap ::ffff:a.b.c.d so an IPv4 range check below actually sees the IPv4 address.
        if (address.IsIPv4MappedToIPv6)
        {
            address = address.MapToIPv4();
        }

        if (IPAddress.IsLoopback(address)
            || address.Equals(IPAddress.Any)
            || address.Equals(IPAddress.IPv6Any))
        {
            return true;
        }

        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            var o = address.GetAddressBytes();
            return o[0] == 0                                        // 0.0.0.0/8 "this network"
                || o[0] == 10                                       // 10.0.0.0/8 private
                || (o[0] == 100 && o[1] >= 64 && o[1] <= 127)       // 100.64.0.0/10 carrier NAT
                || (o[0] == 169 && o[1] == 254)                     // 169.254.0.0/16 link-local (metadata)
                || (o[0] == 172 && o[1] >= 16 && o[1] <= 31)        // 172.16.0.0/12 private
                || (o[0] == 192 && o[1] == 168)                     // 192.168.0.0/16 private
                || (o[0] == 192 && o[1] == 0 && o[2] == 0)          // 192.0.0.0/24 IETF protocol
                || (o[0] == 198 && (o[1] & 0xFE) == 18)             // 198.18.0.0/15 benchmarking
                || o[0] >= 224;                                     // multicast + reserved/broadcast
        }

        if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            if (address.IsIPv6LinkLocal || address.IsIPv6SiteLocal || address.IsIPv6Multicast)
            {
                return true;
            }

            // fc00::/7 unique local addresses — no BCL predicate for these.
            return (address.GetAddressBytes()[0] & 0xFE) == 0xFC;
        }

        // Anything that is neither IPv4 nor IPv6 is not something we should be dialling.
        return true;
    }

    /// <summary>
    /// Resolves <paramref name="uri"/>'s host and returns the single address the caller must pin
    /// the connection to. Throws <see cref="InvalidOperationException"/> if the host does not
    /// resolve or if ANY returned address is blocked by <see cref="IsBlockedAddress"/>.
    ///
    /// Rejecting on *any* blocked address rather than filtering to the allowed ones is deliberate:
    /// a host that resolves to both a public and a private address is a DNS-rebinding setup, not a
    /// dual-homed service we want to reach. Returning one pinned address (rather than re-resolving
    /// at connect time) is what closes the TOCTOU window between this check and the socket.
    /// </summary>
    /// <param name="uri">The URL whose host should be resolved.</param>
    /// <param name="resolver">Injectable DNS lookup; defaults to <see cref="Dns.GetHostAddressesAsync(string, CancellationToken)"/>.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public static async Task<IPAddress> ResolveAndValidateAsync(
        Uri uri,
        Func<string, CancellationToken, Task<IPAddress[]>>? resolver = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(uri);

        resolver ??= static (host, ct) => Dns.GetHostAddressesAsync(host, ct);

        IPAddress[] addresses;
        try
        {
            addresses = await resolver(uri.Host, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception e) when (e is SocketException or ArgumentException)
        {
            throw new InvalidOperationException($"Could not resolve host '{uri.Host}'", e);
        }

        if (addresses.Length == 0)
        {
            throw new InvalidOperationException($"Host '{uri.Host}' resolved to no addresses");
        }

        foreach (var address in addresses)
        {
            if (IsBlockedAddress(address))
            {
                throw new InvalidOperationException(
                    $"Host '{uri.Host}' resolves to a non-public address ({address}); refusing to fetch. " +
                    "This is an SSRF guard — the URL came from the identity provider, not from an administrator.");
            }
        }

        return addresses[0];
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
