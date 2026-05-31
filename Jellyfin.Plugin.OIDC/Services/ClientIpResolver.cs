using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.OIDC.Services;

/// <summary>
/// Resolves the effective client IP from an inbound HTTP request, honoring
/// <c>X-Forwarded-For</c> / <c>X-Real-IP</c> only when the immediate TCP peer is in the
/// admin-configured trusted-proxy list.
///
/// Why the gate: anyone can send <c>X-Forwarded-For: 1.2.3.4</c>. If we trusted the header
/// unconditionally, an attacker would bypass the per-IP rate limit by sending a fresh fake
/// IP on every request. The trusted-proxy CIDR list pins the trust boundary at the reverse
/// proxy(es) the operator actually deploys behind.
///
/// XFF parsing walks right-to-left, skipping any IP that is itself a trusted proxy. This is
/// the standard pattern (see ASP.NET Core's ForwardedHeadersMiddleware): the rightmost
/// non-proxy IP is the real client. Falls back to <c>X-Real-IP</c> when XFF is absent.
/// </summary>
public static class ClientIpResolver
{
    /// <summary>
    /// Returns the client IP to use for rate-limiting / logging. Never throws; on any parse
    /// failure or untrusted peer, returns the raw <see cref="ConnectionInfo.RemoteIpAddress"/>.
    /// </summary>
    public static IPAddress? Resolve(
        HttpContext httpContext,
        bool trustForwardedHeaders,
        IReadOnlyList<IPNetwork> trustedProxies,
        ILogger? logger = null)
    {
        var remote = httpContext.Connection.RemoteIpAddress;
        if (!trustForwardedHeaders || trustedProxies.Count == 0 || remote == null)
        {
            return remote;
        }

        // The peer must itself be a trusted proxy before we honor any forwarded headers.
        // This is the load-bearing anti-spoof check.
        if (!IsInAny(remote, trustedProxies))
        {
            return remote;
        }

        // X-Forwarded-For: client, proxy1, proxy2. Walk right-to-left, skip trusted hops.
        var xff = httpContext.Request.Headers["X-Forwarded-For"].ToString();
        if (!string.IsNullOrWhiteSpace(xff))
        {
            var hops = xff.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            for (var i = hops.Length - 1; i >= 0; i--)
            {
                if (!TryParseIp(hops[i], out var hop)) continue;
                if (!IsInAny(hop, trustedProxies)) return hop;
            }
            // Whole chain was trusted proxies — fall through to X-Real-IP / remote.
        }

        var xRealIp = httpContext.Request.Headers["X-Real-IP"].ToString();
        if (!string.IsNullOrWhiteSpace(xRealIp) && TryParseIp(xRealIp, out var real))
        {
            return real;
        }

        return remote;
    }

    /// <summary>
    /// Parses a list of CIDR strings into <see cref="IPNetwork"/>. Invalid entries are
    /// dropped with a warning — a single typo in the admin UI must not break the resolver.
    /// </summary>
    public static IReadOnlyList<IPNetwork> ParseCidrs(IEnumerable<string> cidrs, ILogger? logger = null)
    {
        var result = new List<IPNetwork>();
        foreach (var c in cidrs)
        {
            if (string.IsNullOrWhiteSpace(c)) continue;
            var trimmed = c.Trim();
            if (IPNetwork.TryParse(trimmed, out var net))
            {
                result.Add(net);
            }
            else
            {
                logger?.LogWarning("Ignoring malformed trusted-proxy CIDR: {Cidr}", trimmed);
            }
        }
        return result;
    }

    private static bool IsInAny(IPAddress ip, IReadOnlyList<IPNetwork> ranges)
    {
        // Normalize ::ffff:a.b.c.d so a v4 CIDR can match a v4-mapped v6 form.
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        for (var i = 0; i < ranges.Count; i++)
        {
            if (ranges[i].Contains(ip)) return true;
        }
        return false;
    }

    private static bool TryParseIp(string s, out IPAddress ip)
    {
        // Forwarded headers may carry "ip:port" (RFC 7239-ish proxies) — strip the port.
        // Also strip brackets around v6 ("[::1]:443").
        var trimmed = s.Trim();
        if (trimmed.StartsWith('['))
        {
            var end = trimmed.IndexOf(']');
            if (end > 0) trimmed = trimmed[1..end];
        }
        else if (trimmed.Count(c => c == ':') == 1)
        {
            // single colon = v4:port, strip the port.
            trimmed = trimmed[..trimmed.IndexOf(':')];
        }
        return IPAddress.TryParse(trimmed, out ip!);
    }
}
