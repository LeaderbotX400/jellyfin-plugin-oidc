using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.IdentityModel.Tokens;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;
using WireMock.Server;
using Xunit;

namespace Jellyfin.Plugin.OIDC.Integration.Tests;

/// <summary>
/// xUnit fixture that boots a WireMock-based OpenID Connect Provider on a random port.
/// Exposes discovery, JWKS, and token endpoints; signs ID tokens with a generated RSA key.
/// One instance per test class (IClassFixture) so the IdP can be reused across cases.
/// </summary>
public sealed class MockIdpFixture : IAsyncLifetime
{
    public WireMockServer Server { get; private set; } = null!;
    public string Authority => Server.Url!;
    public string Issuer => Server.Url!;
    public string ClientId { get; } = "jellyfin-test-client";
    public string ClientSecret { get; } = "test-secret-needs-to-be-at-least-128-bits-for-hs256-signing";

    private RsaSecurityKey _signingKey = null!;
    public string KeyId { get; } = "test-key-1";

    public Task InitializeAsync()
    {
        Server = WireMockServer.Start();

        // Generate a stable RSA key for the lifetime of this fixture
        var rsa = RSA.Create(2048);
        _signingKey = new RsaSecurityKey(rsa) { KeyId = KeyId };

        // Discovery document
        var discovery = new
        {
            issuer = Issuer,
            authorization_endpoint = $"{Server.Url}/authorize",
            token_endpoint = $"{Server.Url}/token",
            jwks_uri = $"{Server.Url}/jwks",
            response_types_supported = new[] { "code", "id_token", "token id_token" },
            subject_types_supported = new[] { "public" },
            id_token_signing_alg_values_supported = new[] { "RS256" },
            scopes_supported = new[] { "openid", "profile", "email", "roles" },
            token_endpoint_auth_methods_supported = new[] { "client_secret_post", "client_secret_basic" }
        };

        Server.Given(Request.Create().WithPath("/.well-known/openid-configuration").UsingGet())
              .RespondWith(Response.Create()
                  .WithStatusCode(200)
                  .WithHeader("Content-Type", "application/json")
                  .WithBody(JsonSerializer.Serialize(discovery)));

        // JWKS endpoint
        var jwk = JsonWebKeyConverter.ConvertFromRSASecurityKey(_signingKey);
        jwk.Use = "sig";
        jwk.Alg = "RS256";
        var jwks = new { keys = new[] { jwk } };

        Server.Given(Request.Create().WithPath("/jwks").UsingGet())
              .RespondWith(Response.Create()
                  .WithStatusCode(200)
                  .WithHeader("Content-Type", "application/json")
                  .WithBody(JsonSerializer.Serialize(jwks)));

        return Task.CompletedTask;
    }

    public Task DisposeAsync()
    {
        Server?.Stop();
        Server?.Dispose();
        return Task.CompletedTask;
    }

    /// <summary>
    /// Stubs the /token endpoint to return a freshly signed ID token containing the supplied claims.
    /// Must be called per-test to set up the response for the upcoming code exchange.
    /// </summary>
    public string EnqueueTokenResponse(
        string sub,
        string? username = null,
        string? email = null,
        bool? emailVerified = null,
        IEnumerable<string>? roles = null,
        IEnumerable<string>? entitlements = null,
        string? nonce = null,
        bool useHmacSigning = false,
        IEnumerable<string>? amr = null,
        string? acr = null)
    {
        var claims = new List<Claim>
        {
            new("sub", sub),
            new("aud", ClientId),
            new("iss", Issuer)
        };
        if (username != null) claims.Add(new Claim("preferred_username", username));
        if (email != null) claims.Add(new Claim("email", email));
        if (emailVerified.HasValue) claims.Add(new Claim("email_verified", emailVerified.Value ? "true" : "false"));
        if (nonce != null) claims.Add(new Claim("nonce", nonce));
        if (roles != null)
        {
            foreach (var r in roles) claims.Add(new Claim("roles", r));
        }

        if (entitlements != null)
        {
            foreach (var e in entitlements) claims.Add(new Claim("entitlements", e));
        }

        if (amr != null)
        {
            foreach (var a in amr) claims.Add(new Claim("amr", a));
        }

        if (acr != null) claims.Add(new Claim("acr", acr));

        var creds = useHmacSigning
            ? new SigningCredentials(new SymmetricSecurityKey(Encoding.UTF8.GetBytes(ClientSecret)), SecurityAlgorithms.HmacSha256)
            : new SigningCredentials(_signingKey, SecurityAlgorithms.RsaSha256);
        var jwt = new JwtSecurityToken(
            issuer: Issuer,
            audience: ClientId,
            claims: claims,
            notBefore: DateTime.UtcNow.AddMinutes(-1),
            expires: DateTime.UtcNow.AddMinutes(5),
            signingCredentials: creds);
        var idToken = new JwtSecurityTokenHandler().WriteToken(jwt);

        var tokenResponse = new
        {
            access_token = "test-access-token",
            id_token = idToken,
            token_type = "Bearer",
            expires_in = 3600
        };

        // Reset and re-stub /token; per call so each test gets a fresh stub
        Server.Given(Request.Create().WithPath("/token").UsingPost())
              .RespondWith(Response.Create()
                  .WithStatusCode(200)
                  .WithHeader("Content-Type", "application/json")
                  .WithBody(JsonSerializer.Serialize(tokenResponse)));

        return idToken;
    }

    /// <summary>
    /// Signs a logout_token but addressed to a different audience than ours — used to
    /// test that the verifying controller rejects mismatched-signer tokens. The signature
    /// uses THIS fixture's key, so the audience side is the only thing that matters.
    /// </summary>
    public string CreateLogoutTokenForAudience(string sub, string audience)
    {
        return BuildLogoutToken(
            sub: sub,
            sid: null,
            audience: audience,
            issuer: Issuer,
            signingKey: _signingKey,
            algorithm: SecurityAlgorithms.RsaSha256,
            includeIat: true,
            includeJti: true,
            includeExp: true,
            iatOverride: null,
            jtiOverride: null);
    }

    /// <summary>Signs a logout_token suitable for OIDC back-channel logout (RFC 8935).</summary>
    public string CreateLogoutToken(
        string? sub,
        string? sid = null,
        bool includeIat = true,
        bool includeJti = true,
        bool includeExp = true,
        DateTime? iat = null,
        string? jti = null,
        bool includeNonce = false,
        string? issuerOverride = null,
        SecurityKey? signingKeyOverride = null,
        string? algorithmOverride = null)
    {
        return BuildLogoutToken(
            sub: sub,
            sid: sid,
            audience: ClientId,
            issuer: issuerOverride ?? Issuer,
            signingKey: signingKeyOverride ?? _signingKey,
            algorithm: algorithmOverride ?? SecurityAlgorithms.RsaSha256,
            includeIat: includeIat,
            includeJti: includeJti,
            includeExp: includeExp,
            iatOverride: iat,
            jtiOverride: jti,
            includeNonce: includeNonce);
    }

    private static string BuildLogoutToken(
        string? sub,
        string? sid,
        string audience,
        string issuer,
        SecurityKey signingKey,
        string algorithm,
        bool includeIat,
        bool includeJti,
        bool includeExp,
        DateTime? iatOverride,
        string? jtiOverride,
        bool includeNonce = false)
    {
        var events = new Dictionary<string, object>
        {
            ["http://schemas.openid.net/event/backchannel-logout"] = new { }
        };
        var claims = new List<Claim>
        {
            new("aud", audience),
            new("iss", issuer),
            new("events", JsonSerializer.Serialize(events), JsonClaimValueTypes.Json)
        };
        if (!string.IsNullOrEmpty(sub)) claims.Add(new Claim("sub", sub));
        if (!string.IsNullOrEmpty(sid)) claims.Add(new Claim("sid", sid));
        if (includeJti) claims.Add(new Claim("jti", jtiOverride ?? Guid.NewGuid().ToString("N")));
        if (includeIat)
        {
            var iat = iatOverride ?? DateTime.UtcNow;
            var iatUnix = new DateTimeOffset(DateTime.SpecifyKind(iat, DateTimeKind.Utc)).ToUnixTimeSeconds();
            claims.Add(new Claim("iat", iatUnix.ToString(), ClaimValueTypes.Integer64));
        }

        if (includeNonce) claims.Add(new Claim("nonce", Guid.NewGuid().ToString("N")));

        var creds = new SigningCredentials(signingKey, algorithm);
        var jwt = new JwtSecurityToken(
            issuer: issuer,
            audience: audience,
            claims: claims,
            notBefore: DateTime.UtcNow.AddMinutes(-1),
            expires: includeExp ? DateTime.UtcNow.AddMinutes(5) : null,
            signingCredentials: creds);
        return new JwtSecurityTokenHandler().WriteToken(jwt);
    }

    public RsaSecurityKey SigningKey => _signingKey;

    /// <summary>
    /// Stubs /token with an ID token that has NO roles and a signed JWT access token
    /// that carries the supplied <paramref name="accessTokenRoles"/>. Used to test
    /// the <c>RolesFromAccessToken</c> feature path.
    /// </summary>
    /// <param name="accessTokenSigningKey">
    /// Key to sign the access token. Pass <see langword="null"/> to use the IdP's
    /// canonical key (valid). Pass a different RSA key to simulate a wrong-key scenario.
    /// </param>
    public void EnqueueTokenResponseWithAccessTokenRoles(
        string sub,
        string username,
        string nonce,
        IEnumerable<string> accessTokenRoles,
        RsaSecurityKey? accessTokenSigningKey = null)
    {
        // ID token: no roles claim
        var idClaims = new List<Claim>
        {
            new("sub", sub),
            new("aud", ClientId),
            new("iss", Issuer),
            new("preferred_username", username),
            new("nonce", nonce)
        };
        var idCreds = new SigningCredentials(_signingKey, SecurityAlgorithms.RsaSha256);
        var idJwt = new JwtSecurityToken(
            issuer: Issuer,
            audience: ClientId,
            claims: idClaims,
            notBefore: DateTime.UtcNow.AddMinutes(-1),
            expires: DateTime.UtcNow.AddMinutes(5),
            signingCredentials: idCreds);
        var idToken = new JwtSecurityTokenHandler().WriteToken(idJwt);

        // Access token: carries roles, signed with the requested key
        var atKey = accessTokenSigningKey ?? _signingKey;
        var atClaims = new List<Claim>
        {
            new("sub", sub),
            new("iss", Issuer),
            new("aud", "resource-server")
        };
        foreach (var r in accessTokenRoles) atClaims.Add(new Claim("roles", r));

        var atCreds = new SigningCredentials(atKey, SecurityAlgorithms.RsaSha256);
        var atJwt = new JwtSecurityToken(
            issuer: Issuer,
            audience: "resource-server",
            claims: atClaims,
            notBefore: DateTime.UtcNow.AddMinutes(-1),
            expires: DateTime.UtcNow.AddMinutes(5),
            signingCredentials: atCreds);
        var accessToken = new JwtSecurityTokenHandler().WriteToken(atJwt);

        var tokenResponse = new
        {
            access_token = accessToken,
            id_token = idToken,
            token_type = "Bearer",
            expires_in = 3600
        };

        Server.Given(Request.Create().WithPath("/token").UsingPost())
              .RespondWith(Response.Create()
                  .WithStatusCode(200)
                  .WithHeader("Content-Type", "application/json")
                  .WithBody(JsonSerializer.Serialize(tokenResponse)));
    }
}
