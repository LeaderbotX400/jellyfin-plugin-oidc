using System;
using System.Net;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Jellyfin.Plugin.OIDC.Services;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Xunit;

namespace Jellyfin.Plugin.OIDC.Tests;

public class OidcDiscoveryCacheTests
{
    [Fact]
    public async Task GetAsync_HttpAuthority_NoOptIn_Throws()
    {
        var cache = new OidcDiscoveryCache(MakeFactory(_ => string.Empty), NullLogger<OidcDiscoveryCache>.Instance);

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            cache.GetAsync("http://idp.example", allowInsecureAuthority: false));
    }

    [Fact]
    public async Task GetAsync_HttpAuthority_NonLocalhostWithOptIn_StillThrows()
    {
        var cache = new OidcDiscoveryCache(MakeFactory(_ => string.Empty), NullLogger<OidcDiscoveryCache>.Instance);

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            cache.GetAsync("http://idp.example", allowInsecureAuthority: true));
    }

    [Fact]
    public async Task GetAsync_HttpLocalhostWithOptIn_Allowed()
    {
        var authority = "http://localhost:12345";
        var cache = new OidcDiscoveryCache(MakeFactory(req => BuildDiscoveryJson(authority)),
            NullLogger<OidcDiscoveryCache>.Instance, allowEndpointMismatch: true);

        var doc = await cache.GetAsync(authority, allowInsecureAuthority: true);

        Assert.False(doc.IsError);
        Assert.Equal(authority, doc.Issuer);
    }

    [Fact]
    public async Task GetAsync_HttpsAuthority_Allowed()
    {
        var authority = "https://idp.example";
        var cache = new OidcDiscoveryCache(MakeFactory(req => BuildDiscoveryJson(authority)),
            NullLogger<OidcDiscoveryCache>.Instance);

        var doc = await cache.GetAsync(authority);

        Assert.False(doc.IsError);
    }

    [Fact]
    public async Task GetAsync_EndpointHostMismatch_RejectedByDefault()
    {
        // Authority and endpoints point at different hosts → SecurityValidation.EnsureSameHost rejects.
        var authority = "https://idp.example";
        var cache = new OidcDiscoveryCache(MakeFactory(req => BuildDiscoveryJson(authority, tokenHost: "https://attacker.example")),
            NullLogger<OidcDiscoveryCache>.Instance);

        await Assert.ThrowsAsync<System.InvalidOperationException>(() => cache.GetAsync(authority));
    }

    [Fact]
    public async Task GetAsync_EndpointDifferentPathSameHost_Accepted()
    {
        // Real-world IdPs like Authentik serve endpoints at sibling paths of the issuer:
        // issuer = https://idp.example/application/o/<slug>/  (in BuildDiscoveryJson the issuer
        // matches the authority root). Authorize/token at https://idp.example/application/o/authorize/
        // are on the same host — must be accepted (was rejected by IdentityModel's path-prefix
        // ValidateEndpoints before; now we host-check ourselves).
        var authority = "https://idp.example";
        var cache = new OidcDiscoveryCache(
            MakeFactory(req => BuildDiscoveryJson(authority, tokenHost: "https://idp.example/application/o")),
            NullLogger<OidcDiscoveryCache>.Instance);

        var doc = await cache.GetAsync(authority);
        Assert.False(doc.IsError);
    }

    [Theory]
    [InlineData("https://idp.example/.well-known/openid-configuration")]
    [InlineData("https://idp.example/.well-known/openid-configuration/")]
    [InlineData("https://idp.example/")]
    public async Task GetAsync_NormalizesDiscoverySuffixAndTrailingSlash(string authorityAsTyped)
    {
        // Admins commonly paste the full discovery URL. Strip the suffix and any trailing /.
        var cache = new OidcDiscoveryCache(
            MakeFactory(req => BuildDiscoveryJson("https://idp.example")),
            NullLogger<OidcDiscoveryCache>.Instance,
            allowEndpointMismatch: true);

        var doc = await cache.GetAsync(authorityAsTyped);
        Assert.False(doc.IsError);
    }

    [Fact]
    public void Dispose_ReleasesSemaphores_NoObjectDisposedOnSubsequentDispose()
    {
        // Verify that Dispose completes without error and that a second Dispose is idempotent.
        var cache = new OidcDiscoveryCache(
            MakeFactory(_ => string.Empty),
            NullLogger<OidcDiscoveryCache>.Instance);

        cache.Dispose();

        // Second dispose must not throw
        var ex = Record.Exception(() => cache.Dispose());
        Assert.Null(ex);
    }

    [Fact]
    public async Task Dispose_SubsequentGetAsync_Throws()
    {
        var cache = new OidcDiscoveryCache(
            MakeFactory(_ => BuildDiscoveryJson("https://idp.example")),
            NullLogger<OidcDiscoveryCache>.Instance);

        cache.Dispose();

        await Assert.ThrowsAsync<ObjectDisposedException>(() =>
            cache.GetAsync("https://idp.example"));
    }

    [Fact]
    public async Task GetAsync_MultipleAuthorities_IsolatedConcurrency()
    {
        // Ensures that two authorities don't deadlock when they might share the same stripe.
        // Both must complete successfully.
        var authority1 = "https://idp1.example";
        var authority2 = "https://idp2.example";

        var cache = new OidcDiscoveryCache(
            MakeFactory(req =>
            {
                var url = req.RequestUri?.ToString() ?? string.Empty;
                var authority = url.Contains("idp1") ? authority1 : authority2;
                return BuildDiscoveryJson(authority);
            }),
            NullLogger<OidcDiscoveryCache>.Instance);

        var t1 = cache.GetAsync(authority1);
        var t2 = cache.GetAsync(authority2);

        var results = await Task.WhenAll(t1, t2);

        Assert.False(results[0].IsError);
        Assert.False(results[1].IsError);
    }

    [Fact]
    public async Task GetAsync_SecondCall_ReturnsCached()
    {
        // IdentityModel's GetDiscoveryDocumentAsync fetches both the discovery document and the
        // jwks_uri during its first call, so the first GetAsync causes multiple HTTP requests.
        // The second GetAsync must produce zero additional requests (pure cache hit).
        var authority = "https://idp.example";
        int fetchCount = 0;
        var cache = new OidcDiscoveryCache(
            MakeFactory(_ =>
            {
                Interlocked.Increment(ref fetchCount);
                return BuildDiscoveryJson(authority);
            }),
            NullLogger<OidcDiscoveryCache>.Instance);

        await cache.GetAsync(authority);
        var afterFirst = fetchCount;

        await cache.GetAsync(authority);
        var afterSecond = fetchCount;

        // Second call must not have issued any new HTTP requests.
        Assert.Equal(afterFirst, afterSecond);
        Assert.True(afterFirst >= 1, "First call should have issued at least one HTTP request");
    }

    [Fact]
    public async Task Invalidate_ForcesRefetch()
    {
        // After Invalidate, the next GetAsync must issue new HTTP requests rather than returning
        // the stale cached entry.
        var authority = "https://idp.example";
        int fetchCount = 0;
        var cache = new OidcDiscoveryCache(
            MakeFactory(_ =>
            {
                Interlocked.Increment(ref fetchCount);
                return BuildDiscoveryJson(authority);
            }),
            NullLogger<OidcDiscoveryCache>.Instance);

        await cache.GetAsync(authority);
        var afterFirst = fetchCount;

        cache.Invalidate(authority);

        await cache.GetAsync(authority);
        var afterSecond = fetchCount;

        // After invalidation a fresh fetch must have occurred.
        Assert.True(afterSecond > afterFirst,
            $"Expected more requests after Invalidate; got {afterFirst} then {afterSecond}");
    }

    private static string BuildDiscoveryJson(string authority, string? tokenHost = null)
    {
        var host = tokenHost ?? authority;
        return JsonSerializer.Serialize(new
        {
            issuer = authority,
            authorization_endpoint = $"{host}/authorize",
            token_endpoint = $"{host}/token",
            jwks_uri = $"{host}/jwks",
            response_types_supported = new[] { "code" },
            subject_types_supported = new[] { "public" },
            id_token_signing_alg_values_supported = new[] { "RS256" }
        });
    }

    private static IHttpClientFactory MakeFactory(Func<HttpRequestMessage, string> respond)
    {
        var factory = new Mock<IHttpClientFactory>();
        factory.Setup(f => f.CreateClient("OidcPlugin"))
               .Returns(new HttpClient(new RouterHandler(respond)));
        return factory.Object;
    }

    private sealed class RouterHandler(Func<HttpRequestMessage, string> respond) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            var body = respond(request);
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(body)
            });
        }
    }
}
