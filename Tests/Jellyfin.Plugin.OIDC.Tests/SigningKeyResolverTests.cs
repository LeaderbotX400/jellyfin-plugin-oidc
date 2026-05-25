using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Jellyfin.Plugin.OIDC.Services;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.IdentityModel.Tokens;
using Moq;
using Xunit;

namespace Jellyfin.Plugin.OIDC.Tests;

public class SigningKeyResolverTests
{
    private const string Issuer = "https://idp.example";
    private const string Audience = "client-1";
    private const string ClientSecret = "shared-secret-which-is-plenty-long-for-hmac-256-signing";

    [Fact]
    public async Task ResolveAsync_HsTokenNotInAllowlist_Throws()
    {
        var token = MintHs256("kid-irrelevant");
        var jwksCache = MakeCache("""{"keys":[]}""");

        var ex = await Assert.ThrowsAsync<SecurityTokenInvalidSignatureException>(() =>
            SigningKeyResolver.ResolveAsync(token, ClientSecret, "http://idp/jwks", jwksCache,
                new[] { "RS256", "ES256" }));
        Assert.Contains("not in", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task ResolveAsync_HsTokenInAllowlist_ReturnsSymmetricKey()
    {
        var token = MintHs256("kid-irrelevant");
        var jwksCache = MakeCache("""{"keys":[]}""");

        var keys = await SigningKeyResolver.ResolveAsync(token, ClientSecret, "http://idp/jwks", jwksCache,
            new[] { "HS256" });

        Assert.Single(keys);
        Assert.IsType<SymmetricSecurityKey>(keys[0]);
    }

    [Fact]
    public async Task ResolveAsync_RsTokenKnownKid_ReturnsJwksKeys()
    {
        using var rsa = RSA.Create(2048);
        const string kid = "rsa-1";
        var token = MintRs256(rsa, kid);
        var jwksCache = MakeCache(BuildJwks(rsa, kid));

        var keys = await SigningKeyResolver.ResolveAsync(token, ClientSecret, "http://idp/jwks", jwksCache,
            new[] { "RS256" });

        Assert.NotEmpty(keys);
    }

    [Fact]
    public async Task ResolveAsync_RsTokenUnknownKid_TriggersRefreshThenSucceeds()
    {
        // Initial JWKS lacks the token's kid; second fetch returns a JWKS that contains it.
        using var rsa = RSA.Create(2048);
        const string kid = "rotated-key";
        var token = MintRs256(rsa, kid);

        var handler = new SequentialHandler(new[]
        {
            """{"keys":[]}""",
            BuildJwks(rsa, kid)
        });
        var jwksCache = MakeCacheFromHandler(handler);

        var keys = await SigningKeyResolver.ResolveAsync(token, ClientSecret, "http://idp/jwks", jwksCache,
            new[] { "RS256" });

        Assert.Equal(2, handler.RequestCount);
        Assert.NotEmpty(keys);
    }

    [Fact]
    public async Task ResolveAsync_RsTokenUnknownKidAfterRefresh_RefreshesOnceAndReturnsEmptyKeySet()
    {
        // IdP never serves the token's kid. Resolver should refresh exactly once (not loop forever)
        // and return the cached keys; the caller's validation will then fail cleanly.
        using var rsa = RSA.Create(2048);
        var token = MintRs256(rsa, "ghost-kid");

        var handler = new SequentialHandler(new[]
        {
            """{"keys":[]}""",
            """{"keys":[]}"""
        });
        var jwksCache = MakeCacheFromHandler(handler);

        var keys = await SigningKeyResolver.ResolveAsync(token, ClientSecret, "http://idp/jwks", jwksCache,
            new[] { "RS256" });

        Assert.Equal(2, handler.RequestCount); // one for GetKeysAsync, one for RefreshAsync
        Assert.Empty(keys);
    }

    [Fact]
    public async Task ResolveAsync_EmptyAllowlist_Throws()
    {
        var token = MintHs256("kid-irrelevant");
        var jwksCache = MakeCache("""{"keys":[]}""");

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            SigningKeyResolver.ResolveAsync(token, ClientSecret, "http://idp/jwks", jwksCache,
                Array.Empty<string>()));
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private static string MintHs256(string kid)
    {
        var creds = new SigningCredentials(
            new SymmetricSecurityKey(Encoding.UTF8.GetBytes(ClientSecret)),
            SecurityAlgorithms.HmacSha256);
        var jwt = new JwtSecurityToken(
            issuer: Issuer, audience: Audience,
            claims: new[] { new Claim("sub", "u-1") },
            notBefore: DateTime.UtcNow.AddMinutes(-1),
            expires: DateTime.UtcNow.AddMinutes(5),
            signingCredentials: creds);
        jwt.Header["kid"] = kid;
        return new JwtSecurityTokenHandler().WriteToken(jwt);
    }

    private static string MintRs256(RSA rsa, string kid)
    {
        var key = new RsaSecurityKey(rsa) { KeyId = kid };
        var creds = new SigningCredentials(key, SecurityAlgorithms.RsaSha256);
        var jwt = new JwtSecurityToken(
            issuer: Issuer, audience: Audience,
            claims: new[] { new Claim("sub", "u-1") },
            notBefore: DateTime.UtcNow.AddMinutes(-1),
            expires: DateTime.UtcNow.AddMinutes(5),
            signingCredentials: creds);
        return new JwtSecurityTokenHandler().WriteToken(jwt);
    }

    private static string BuildJwks(RSA rsa, string kid)
    {
        var jwk = JsonWebKeyConverter.ConvertFromRSASecurityKey(new RsaSecurityKey(rsa) { KeyId = kid });
        jwk.Use = "sig";
        jwk.Alg = "RS256";
        return JsonSerializer.Serialize(new { keys = new[] { jwk } });
    }

    private static JwksCache MakeCache(string jwksJson) =>
        MakeCacheFromHandler(new ConstantHandler(jwksJson));

    private static JwksCache MakeCacheFromHandler(HttpMessageHandler handler)
    {
        var factory = new Mock<IHttpClientFactory>();
        factory.Setup(f => f.CreateClient("OidcPlugin"))
               .Returns(new HttpClient(handler));
        // Zero refresh-gate so test-side back-to-back refreshes aren't rate-limited.
        return new JwksCache(factory.Object, NullLogger<JwksCache>.Instance, TimeSpan.Zero);
    }

    private sealed class ConstantHandler(string body) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
            => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(body) });
    }

    private sealed class SequentialHandler : HttpMessageHandler
    {
        private readonly Queue<string> _responses;
        private int _count;
        public int RequestCount => _count;

        public SequentialHandler(IEnumerable<string> responses)
        {
            _responses = new Queue<string>(responses);
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Interlocked.Increment(ref _count);
            var body = _responses.Count > 0 ? _responses.Dequeue() : """{"keys":[]}""";
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(body) });
        }
    }
}
