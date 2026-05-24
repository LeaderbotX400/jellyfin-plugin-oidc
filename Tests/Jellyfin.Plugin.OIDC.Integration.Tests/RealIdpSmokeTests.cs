using System;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http;
using System.Threading.Tasks;
using IdentityModel.Client;
using Jellyfin.Plugin.OIDC.Services;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Jellyfin.Plugin.OIDC.Integration.Tests;

/// <summary>
/// Smoke tests that hit a real OIDC provider over the network. Skipped unless the required
/// environment variables are set, so they never run in CI by accident:
///   OIDC_SMOKE_AUTHORITY      — e.g. https://auth.example.com/application/o/myapp/
///   OIDC_SMOKE_CLIENT_ID
///   OIDC_SMOKE_CLIENT_SECRET
///   OIDC_SMOKE_USERNAME       — for the ROPC grant
///   OIDC_SMOKE_PASSWORD
/// </summary>
public sealed class RealIdpSmokeTests
{
    private static (string Authority, string ClientId, string ClientSecret, string Username, string Password)? GetCreds()
    {
        var auth = Environment.GetEnvironmentVariable("OIDC_SMOKE_AUTHORITY");
        var cid = Environment.GetEnvironmentVariable("OIDC_SMOKE_CLIENT_ID");
        var cs = Environment.GetEnvironmentVariable("OIDC_SMOKE_CLIENT_SECRET");
        var u = Environment.GetEnvironmentVariable("OIDC_SMOKE_USERNAME");
        var p = Environment.GetEnvironmentVariable("OIDC_SMOKE_PASSWORD");
        if (string.IsNullOrEmpty(auth) || string.IsNullOrEmpty(cid) || string.IsNullOrEmpty(cs)
            || string.IsNullOrEmpty(u) || string.IsNullOrEmpty(p))
        {
            return null;
        }

        return (auth, cid, cs, u, p);
    }

    [Fact]
    public async Task RealIdp_PasswordGrant_TokenValidatesAndClaimsExtract()
    {
        var creds = GetCreds();
        if (creds == null)
        {
            // Skip silently when env vars aren't set
            return;
        }

        var (authority, clientId, clientSecret, username, password) = creds.Value;
        var httpClient = new HttpClient();

        // 1. Fetch discovery — proves authority is reachable + parseable
        var disco = await httpClient.GetDiscoveryDocumentAsync(new DiscoveryDocumentRequest
        {
            Address = authority,
            Policy = new DiscoveryPolicy { ValidateIssuerName = true, ValidateEndpoints = false }
        });
        Assert.False(disco.IsError, $"Discovery failed: {disco.Error}");

        // 2. ROPC grant — only test path that doesn't need a browser. Many IdPs disable
        //    this in prod; smoke tests rely on a dedicated test client that allows it.
        var tokenResponse = await httpClient.RequestPasswordTokenAsync(new PasswordTokenRequest
        {
            Address = disco.TokenEndpoint,
            ClientId = clientId,
            ClientSecret = clientSecret,
            UserName = username,
            Password = password,
            Scope = "openid profile email"
        });
        Assert.False(tokenResponse.IsError, $"Token request failed: {tokenResponse.Error} - {tokenResponse.ErrorDescription}");
        Assert.NotNull(tokenResponse.IdentityToken);

        // 3. Resolve signing keys via our plugin code (detects HS256 vs RS256 from token header)
        var jwksCache = new JwksCache(new FakeHttpClientFactory(), NullLogger<JwksCache>.Instance);
        SecurityKey[] keys = await SigningKeyResolver.ResolveAsync(
            tokenResponse.IdentityToken!, clientSecret, disco.JwksUri, jwksCache);
        Assert.NotEmpty(keys);

        // 4. Validate the ID token signature + claims using the same validation params as the plugin
        var handler = new JwtSecurityTokenHandler();
        handler.ValidateToken(tokenResponse.IdentityToken!, new TokenValidationParameters
        {
            ValidIssuer = disco.Issuer,
            ValidAudience = clientId,
            IssuerSigningKeys = keys,
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            RequireSignedTokens = true,
            ClockSkew = TimeSpan.FromSeconds(30)
        }, out var validated);

        var jwt = (JwtSecurityToken)validated;

        // 5. Exercise the actual claim parser the plugin uses end-to-end
        var sub = ClaimParser.ExtractClaim(jwt, "sub");
        var preferredUsername = ClaimParser.ExtractClaim(jwt, "preferred_username");
        Assert.NotEmpty(sub);

        // Print observed claim shape so a human can sanity-check
        var claimSummary = string.Join(", ", jwt.Claims.Select(c => $"{c.Type}={Truncate(c.Value, 40)}"));
        Console.WriteLine($"[smoke] alg={jwt.Header.Alg} iss={jwt.Issuer} sub={sub} preferred_username={preferredUsername}");
        Console.WriteLine($"[smoke] all claims: {claimSummary}");
    }

    private static string Truncate(string s, int max) => s.Length <= max ? s : s.Substring(0, max) + "…";
}
