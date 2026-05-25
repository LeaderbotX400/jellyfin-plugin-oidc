using System;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Jellyfin.Plugin.OIDC.Services;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Xunit;

namespace Jellyfin.Plugin.OIDC.Tests;

public class JwksCacheTests
{
    // Minimal valid JWKS JSON for testing
    private const string SampleJwks = """{"keys":[{"kty":"RSA","kid":"1","use":"sig","n":"sampleN","e":"AQAB"}]}""";

    private static JwksCache CreateCache(string jwksJson = SampleJwks)
    {
        var handler = new FakeHttpHandler(jwksJson);
        var factory = new Mock<IHttpClientFactory>();
        factory.Setup(f => f.CreateClient("OidcPlugin"))
               .Returns(new HttpClient(handler) { BaseAddress = new Uri("http://localhost") });
        return new JwksCache(factory.Object, NullLogger<JwksCache>.Instance);
    }

    [Fact]
    public async Task GetKeysAsync_FirstCall_FetchesFromRemote()
    {
        var cache = CreateCache();
        var keys = await cache.GetKeysAsync("http://idp/jwks");
        Assert.NotNull(keys);
    }

    [Fact]
    public async Task GetKeysAsync_SecondCall_ReturnsCachedResult()
    {
        var handler = new CountingHttpHandler(SampleJwks);
        var factory = new Mock<IHttpClientFactory>();
        factory.Setup(f => f.CreateClient("OidcPlugin"))
               .Returns(new HttpClient(handler));
        var cache = new JwksCache(factory.Object, NullLogger<JwksCache>.Instance);

        await cache.GetKeysAsync("http://idp/jwks");
        await cache.GetKeysAsync("http://idp/jwks");

        Assert.Equal(1, handler.RequestCount);
    }

    [Fact]
    public async Task GetKeysAsync_AfterInvalidate_FetchesAgain()
    {
        var handler = new CountingHttpHandler(SampleJwks);
        var factory = new Mock<IHttpClientFactory>();
        factory.Setup(f => f.CreateClient("OidcPlugin"))
               .Returns(new HttpClient(handler));
        var cache = new JwksCache(factory.Object, NullLogger<JwksCache>.Instance);

        await cache.GetKeysAsync("http://idp/jwks");
        cache.Invalidate("http://idp/jwks");
        await cache.GetKeysAsync("http://idp/jwks");

        Assert.Equal(2, handler.RequestCount);
    }

    [Fact]
    public async Task GetKeysAsync_DifferentUris_FetchedSeparately()
    {
        var handler = new CountingHttpHandler(SampleJwks);
        var factory = new Mock<IHttpClientFactory>();
        factory.Setup(f => f.CreateClient("OidcPlugin"))
               .Returns(new HttpClient(handler));
        var cache = new JwksCache(factory.Object, NullLogger<JwksCache>.Instance);

        await cache.GetKeysAsync("http://idp1/jwks");
        await cache.GetKeysAsync("http://idp2/jwks");

        Assert.Equal(2, handler.RequestCount);
    }

    [Fact]
    public async Task RefreshAsync_RateLimited_FetchesOnce()
    {
        // Two consecutive misses (≈"unknown kid" recovery attempts) within the gate window
        // must result in only one network refresh.
        var handler = new CountingHttpHandler(SampleJwks);
        var factory = new Mock<IHttpClientFactory>();
        factory.Setup(f => f.CreateClient("OidcPlugin"))
               .Returns(new HttpClient(handler));
        var cache = new JwksCache(factory.Object, NullLogger<JwksCache>.Instance, TimeSpan.FromMinutes(5));

        await cache.RefreshAsync("http://idp/jwks");
        await cache.RefreshAsync("http://idp/jwks");

        Assert.Equal(1, handler.RequestCount);
    }

    [Fact]
    public async Task RefreshAsync_AfterGate_FetchesAgain()
    {
        var handler = new CountingHttpHandler(SampleJwks);
        var factory = new Mock<IHttpClientFactory>();
        factory.Setup(f => f.CreateClient("OidcPlugin"))
               .Returns(new HttpClient(handler));
        // Zero-length gate → every Refresh call should hit the wire.
        var cache = new JwksCache(factory.Object, NullLogger<JwksCache>.Instance, TimeSpan.Zero);

        await cache.RefreshAsync("http://idp/jwks");
        await Task.Delay(20);
        await cache.RefreshAsync("http://idp/jwks");

        Assert.Equal(2, handler.RequestCount);
    }

    [Fact]
    public async Task GetKeysAsync_ConcurrentCalls_FetchOnce()
    {
        var handler = new CountingHttpHandler(SampleJwks, delayMs: 50);
        var factory = new Mock<IHttpClientFactory>();
        factory.Setup(f => f.CreateClient("OidcPlugin"))
               .Returns(new HttpClient(handler));
        var cache = new JwksCache(factory.Object, NullLogger<JwksCache>.Instance);

        var tasks = new Task[10];
        for (var i = 0; i < tasks.Length; i++)
        {
            tasks[i] = cache.GetKeysAsync("http://idp/jwks");
        }

        await Task.WhenAll(tasks);

        // Due to locking, should only fetch once
        Assert.Equal(1, handler.RequestCount);
    }

    // ── Fake HTTP handlers ────────────────────────────────────────────────────

    private sealed class FakeHttpHandler(string response) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken ct)
        {
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(response)
            });
        }
    }

    private sealed class CountingHttpHandler(string response, int delayMs = 0) : HttpMessageHandler
    {
        private int _count;
        public int RequestCount => _count;

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken ct)
        {
            Interlocked.Increment(ref _count);
            if (delayMs > 0)
            {
                await Task.Delay(delayMs, ct);
            }

            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(response)
            };
        }
    }
}
