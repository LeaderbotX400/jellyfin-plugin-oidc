using System.Collections.Generic;
using System.Net;
using Jellyfin.Plugin.OIDC.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Jellyfin.Plugin.OIDC.Tests;

/// <summary>
/// Adversarial tests for <see cref="ClientIpResolver"/>. The headline threat: an attacker
/// hits the public callback directly, sends <c>X-Forwarded-For: 1.2.3.4</c>, and rotates
/// the spoofed IP per request to dodge the per-IP rate limiter. The trusted-proxy gate
/// is the load-bearing defense; these tests pin that behavior down.
/// </summary>
public class ClientIpResolverTests
{
    private static HttpContext Ctx(string remote, params (string Name, string Value)[] headers)
    {
        var ctx = new DefaultHttpContext();
        ctx.Connection.RemoteIpAddress = IPAddress.Parse(remote);
        foreach (var (n, v) in headers)
        {
            ctx.Request.Headers[n] = v;
        }
        return ctx;
    }

    private static IReadOnlyList<IPNetwork> Cidrs(params string[] cidrs)
        => ClientIpResolver.ParseCidrs(cidrs, NullLogger.Instance);

    // ── Anti-spoofing ──────────────────────────────────────────────────────

    [Fact]
    public void XffIgnored_WhenTrustForwardedHeadersFalse()
    {
        // Even with a trusted peer, an admin who hasn't opted in must not get header trust.
        var ctx = Ctx("10.0.0.5", ("X-Forwarded-For", "1.2.3.4"));
        var ip = ClientIpResolver.Resolve(ctx, trustForwardedHeaders: false, Cidrs("10.0.0.0/8"));
        Assert.Equal(IPAddress.Parse("10.0.0.5"), ip);
    }

    [Fact]
    public void XffIgnored_WhenTrustedProxyListEmpty()
    {
        // Fail-closed: TrustForwardedHeaders=true but no CIDRs configured = ignore headers.
        var ctx = Ctx("10.0.0.5", ("X-Forwarded-For", "1.2.3.4"));
        var ip = ClientIpResolver.Resolve(ctx, trustForwardedHeaders: true, Cidrs());
        Assert.Equal(IPAddress.Parse("10.0.0.5"), ip);
    }

    [Fact]
    public void XffIgnored_WhenPeerIsNotTrustedProxy()
    {
        // The headline spoof test: attacker connects directly from the public internet,
        // sends a forged XFF. We MUST return the real remote, not the spoofed value,
        // otherwise the rate limiter is trivially bypassable.
        var ctx = Ctx("203.0.113.99", ("X-Forwarded-For", "1.2.3.4"));
        var ip = ClientIpResolver.Resolve(ctx, trustForwardedHeaders: true, Cidrs("10.0.0.0/8"));
        Assert.Equal(IPAddress.Parse("203.0.113.99"), ip);
    }

    // ── Happy path: trusted proxy ──────────────────────────────────────────

    [Fact]
    public void SingleProxy_ReturnsClientFromXff()
    {
        var ctx = Ctx("10.0.0.5", ("X-Forwarded-For", "198.51.100.7"));
        var ip = ClientIpResolver.Resolve(ctx, true, Cidrs("10.0.0.0/8"));
        Assert.Equal(IPAddress.Parse("198.51.100.7"), ip);
    }

    [Fact]
    public void ChainedProxies_SkipsTrustedHopsRightToLeft()
    {
        // XFF: client, edge_proxy, internal_proxy
        // Connection from internal_proxy (10.0.0.5). Trusted list covers both proxies.
        // Real client is the leftmost untrusted hop.
        var ctx = Ctx("10.0.0.5", ("X-Forwarded-For", "198.51.100.7, 10.0.1.20, 10.0.0.5"));
        var ip = ClientIpResolver.Resolve(ctx, true, Cidrs("10.0.0.0/8"));
        Assert.Equal(IPAddress.Parse("198.51.100.7"), ip);
    }

    [Fact]
    public void ChainedProxies_StopsAtFirstUntrustedFromRight()
    {
        // If a non-trusted IP appears mid-chain, we treat IT as the client. A proxy
        // beyond it could itself be attacker-controlled appending fake hops.
        var ctx = Ctx("10.0.0.5", ("X-Forwarded-For", "1.1.1.1, 203.0.113.7, 10.0.0.5"));
        var ip = ClientIpResolver.Resolve(ctx, true, Cidrs("10.0.0.0/8"));
        // Rightmost non-trusted = 203.0.113.7 (1.1.1.1 is past it and untrusted but to
        // the LEFT — it could be attacker-injected, must not be trusted).
        Assert.Equal(IPAddress.Parse("203.0.113.7"), ip);
    }

    [Fact]
    public void AllHopsTrusted_FallsBackToXRealIp()
    {
        var ctx = Ctx("10.0.0.5",
            ("X-Forwarded-For", "10.0.0.1, 10.0.0.2"),
            ("X-Real-IP", "198.51.100.42"));
        var ip = ClientIpResolver.Resolve(ctx, true, Cidrs("10.0.0.0/8"));
        Assert.Equal(IPAddress.Parse("198.51.100.42"), ip);
    }

    [Fact]
    public void NoXff_UsesXRealIp()
    {
        var ctx = Ctx("10.0.0.5", ("X-Real-IP", "198.51.100.99"));
        var ip = ClientIpResolver.Resolve(ctx, true, Cidrs("10.0.0.0/8"));
        Assert.Equal(IPAddress.Parse("198.51.100.99"), ip);
    }

    [Fact]
    public void XRealIp_IgnoredWhenPeerUntrusted()
    {
        var ctx = Ctx("203.0.113.99", ("X-Real-IP", "1.2.3.4"));
        var ip = ClientIpResolver.Resolve(ctx, true, Cidrs("10.0.0.0/8"));
        Assert.Equal(IPAddress.Parse("203.0.113.99"), ip);
    }

    // ── Malformed input ────────────────────────────────────────────────────

    [Fact]
    public void MalformedXff_FallsThroughToRemote()
    {
        var ctx = Ctx("10.0.0.5", ("X-Forwarded-For", "not-an-ip, also-garbage"));
        var ip = ClientIpResolver.Resolve(ctx, true, Cidrs("10.0.0.0/8"));
        Assert.Equal(IPAddress.Parse("10.0.0.5"), ip);
    }

    [Fact]
    public void XffWithPortSuffix_StripsPort()
    {
        // RFC 7239-ish proxies sometimes append ":port"
        var ctx = Ctx("10.0.0.5", ("X-Forwarded-For", "198.51.100.7:54321"));
        var ip = ClientIpResolver.Resolve(ctx, true, Cidrs("10.0.0.0/8"));
        Assert.Equal(IPAddress.Parse("198.51.100.7"), ip);
    }

    [Fact]
    public void XffWithBracketedV6_ParsesAddress()
    {
        var ctx = Ctx("10.0.0.5", ("X-Forwarded-For", "[2001:db8::1]:443"));
        var ip = ClientIpResolver.Resolve(ctx, true, Cidrs("10.0.0.0/8"));
        Assert.Equal(IPAddress.Parse("2001:db8::1"), ip);
    }

    [Fact]
    public void EmptyXffHeader_FallsThroughCleanly()
    {
        var ctx = Ctx("10.0.0.5", ("X-Forwarded-For", ""));
        var ip = ClientIpResolver.Resolve(ctx, true, Cidrs("10.0.0.0/8"));
        Assert.Equal(IPAddress.Parse("10.0.0.5"), ip);
    }

    [Fact]
    public void XffWithExtraWhitespace_TrimsCorrectly()
    {
        var ctx = Ctx("10.0.0.5", ("X-Forwarded-For", "  198.51.100.7  ,  10.0.0.5  "));
        var ip = ClientIpResolver.Resolve(ctx, true, Cidrs("10.0.0.0/8"));
        Assert.Equal(IPAddress.Parse("198.51.100.7"), ip);
    }

    // ── IPv6 / mapping ─────────────────────────────────────────────────────

    [Fact]
    public void Ipv6Proxy_TrustedByV6Cidr()
    {
        var ctx = Ctx("2001:db8::5", ("X-Forwarded-For", "2001:beef::1"));
        var ip = ClientIpResolver.Resolve(ctx, true, Cidrs("2001:db8::/32"));
        Assert.Equal(IPAddress.Parse("2001:beef::1"), ip);
    }

    [Fact]
    public void V4MappedV6Peer_MatchesV4Cidr()
    {
        // Kestrel sometimes presents v4 connections as ::ffff:10.0.0.5
        var ctx = Ctx("::ffff:10.0.0.5", ("X-Forwarded-For", "198.51.100.42"));
        var ip = ClientIpResolver.Resolve(ctx, true, Cidrs("10.0.0.0/8"));
        Assert.Equal(IPAddress.Parse("198.51.100.42"), ip);
    }

    // ── CIDR parsing ───────────────────────────────────────────────────────

    [Fact]
    public void ParseCidrs_DropsInvalidEntries()
    {
        var nets = ClientIpResolver.ParseCidrs(
            new[] { "10.0.0.0/8", "not-a-cidr", "  ", "192.168.0.0/16" },
            NullLogger.Instance);
        Assert.Equal(2, nets.Count);
    }

    [Fact]
    public void ParseCidrs_AcceptsSingleHostMask()
    {
        var nets = ClientIpResolver.ParseCidrs(new[] { "127.0.0.1/32", "::1/128" }, NullLogger.Instance);
        Assert.Equal(2, nets.Count);
    }

    // ── No headers at all ──────────────────────────────────────────────────

    [Fact]
    public void NoForwardedHeaders_TrustedPeerReturnsRemote()
    {
        var ctx = Ctx("10.0.0.5");
        var ip = ClientIpResolver.Resolve(ctx, true, Cidrs("10.0.0.0/8"));
        Assert.Equal(IPAddress.Parse("10.0.0.5"), ip);
    }

    [Fact]
    public void NullRemote_ReturnsNull()
    {
        var ctx = new DefaultHttpContext();
        // RemoteIpAddress left null
        var ip = ClientIpResolver.Resolve(ctx, true, Cidrs("10.0.0.0/8"));
        Assert.Null(ip);
    }

    // ── ResolveScheme / ResolveHost adversarial tests ──────────────────────
    // Security constraint: an untrusted peer sending X-Forwarded-Host: evil.com
    // must NEVER influence the redirect_uri — that would let an attacker make
    // legitimate users send their OIDC code to the attacker's domain.

    private static HttpContext SchemeHostCtx(
        string remote,
        string scheme,
        string host,
        params (string Name, string Value)[] headers)
    {
        var ctx = new DefaultHttpContext();
        ctx.Connection.RemoteIpAddress = IPAddress.Parse(remote);
        ctx.Request.Scheme = scheme;
        ctx.Request.Host = new HostString(host);
        foreach (var (n, v) in headers)
        {
            ctx.Request.Headers[n] = v;
        }
        return ctx;
    }

    [Fact]
    public void XffProto_IgnoredWhenPeerUntrusted()
    {
        // Attacker connects directly from public internet and sends X-Forwarded-Proto: https.
        // Must return the real Request.Scheme, not the spoofed value.
        var ctx = SchemeHostCtx("203.0.113.99", "http", "internal.local",
            ("X-Forwarded-Proto", "https"));
        var scheme = ClientIpResolver.ResolveScheme(ctx, trustForwardedHeaders: true, Cidrs("10.0.0.0/8"));
        Assert.Equal("http", scheme);
    }

    [Fact]
    public void XffHost_IgnoredWhenPeerUntrusted()
    {
        // Attacker connects directly from public internet and sends X-Forwarded-Host: evil.example.com.
        // Must return the real Request.Host, not the spoofed value.
        var ctx = SchemeHostCtx("203.0.113.99", "http", "real.example.com",
            ("X-Forwarded-Host", "evil.example.com"));
        var host = ClientIpResolver.ResolveHost(ctx, trustForwardedHeaders: true, Cidrs("10.0.0.0/8"));
        Assert.Equal("real.example.com", host);
    }

    [Fact]
    public void XffProto_TrustedPeer_Honored()
    {
        // Peer is a trusted proxy — X-Forwarded-Proto must be returned.
        var ctx = SchemeHostCtx("10.0.0.5", "http", "internal.local",
            ("X-Forwarded-Proto", "https"));
        var scheme = ClientIpResolver.ResolveScheme(ctx, trustForwardedHeaders: true, Cidrs("10.0.0.0/8"));
        Assert.Equal("https", scheme);
    }

    [Fact]
    public void XffHost_TrustedPeer_Honored()
    {
        // Peer is a trusted proxy — X-Forwarded-Host must be returned.
        var ctx = SchemeHostCtx("10.0.0.5", "http", "internal.local",
            ("X-Forwarded-Host", "jellyfin.example.com"));
        var host = ClientIpResolver.ResolveHost(ctx, trustForwardedHeaders: true, Cidrs("10.0.0.0/8"));
        Assert.Equal("jellyfin.example.com", host);
    }

    [Fact]
    public void XffHost_CommaSeparated_TakesLeftmost()
    {
        // X-Forwarded-Host may be comma-separated when multiple proxies append. The leftmost
        // entry is the original client-facing host; rightmost entries are intermediate proxies.
        var ctx = SchemeHostCtx("10.0.0.5", "http", "internal.local",
            ("X-Forwarded-Host", "real.example.com, internal.local"));
        var host = ClientIpResolver.ResolveHost(ctx, trustForwardedHeaders: true, Cidrs("10.0.0.0/8"));
        Assert.Equal("real.example.com", host);
    }

    [Fact]
    public void XffProto_FlagOff_Ignored()
    {
        // TrustForwardedHeaders=false: even a trusted peer with the header present must not
        // influence the resolved scheme — the admin has not opted in.
        var ctx = SchemeHostCtx("10.0.0.5", "http", "internal.local",
            ("X-Forwarded-Proto", "https"));
        var scheme = ClientIpResolver.ResolveScheme(ctx, trustForwardedHeaders: false, Cidrs("10.0.0.0/8"));
        Assert.Equal("http", scheme);
    }
}
