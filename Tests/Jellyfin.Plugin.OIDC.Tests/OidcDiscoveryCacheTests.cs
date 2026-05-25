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
        // Authority and endpoints point at different hosts — IdentityModel's ValidateEndpoints catches this.
        var authority = "https://idp.example";
        var cache = new OidcDiscoveryCache(MakeFactory(req => BuildDiscoveryJson(authority, tokenHost: "https://attacker.example")),
            NullLogger<OidcDiscoveryCache>.Instance);

        var doc = await cache.GetAsync(authority);
        Assert.True(doc.IsError);
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
