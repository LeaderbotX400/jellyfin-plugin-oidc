using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;
using IdentityModel.Client;
using Jellyfin.Plugin.OIDC.Configuration;
using Jellyfin.Plugin.OIDC.Services;
using MediaBrowser.Controller.Session;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;

namespace Jellyfin.Plugin.OIDC.Api;

/// <summary>
/// Implements OIDC Back-Channel Logout (RFC 8935).
/// The IdP POSTs a signed logout_token when a user's session should be terminated.
/// </summary>
[ApiController]
[Route("sso/OIDC")]
public class OidcLogoutController : ControllerBase
{
    private const string BackChannelLogoutEventType = "http://schemas.openid.net/event/backchannel-logout";

    private static readonly TimeSpan IatSkew = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan ExpSkew = TimeSpan.FromMinutes(5);

    private readonly OidcUserStore _userStore;
    private readonly ISessionManager _sessionManager;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly JwksCache _jwksCache;
    private readonly OidcDiscoveryCache _discoveryCache;
    private readonly RbacService _rbacService;
    private readonly IPluginConfigProvider _configProvider;
    private readonly LogoutTokenReplayCache _replayCache;
    private readonly ILogger<OidcLogoutController> _logger;

    public OidcLogoutController(
        OidcUserStore userStore,
        ISessionManager sessionManager,
        IHttpClientFactory httpClientFactory,
        JwksCache jwksCache,
        OidcDiscoveryCache discoveryCache,
        RbacService rbacService,
        IPluginConfigProvider configProvider,
        LogoutTokenReplayCache replayCache,
        ILogger<OidcLogoutController> logger)
    {
        _userStore = userStore;
        _sessionManager = sessionManager;
        _httpClientFactory = httpClientFactory;
        _jwksCache = jwksCache;
        _discoveryCache = discoveryCache;
        _rbacService = rbacService;
        _configProvider = configProvider;
        _replayCache = replayCache;
        _logger = logger;
    }

    [HttpPost("backchannel-logout")]
    [Consumes("application/x-www-form-urlencoded")]
    public async Task<ActionResult> BackChannelLogout([FromForm] string logout_token)
    {
        if (string.IsNullOrEmpty(logout_token))
        {
            return BadRequest("logout_token is required");
        }

        var handler = new JwtSecurityTokenHandler();
        if (!handler.CanReadToken(logout_token))
        {
            _logger.LogWarning("Back-channel logout: received unreadable logout_token");
            return BadRequest("Invalid logout_token format");
        }

        JwtSecurityToken unvalidated;
        try
        {
            unvalidated = handler.ReadJwtToken(logout_token);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Back-channel logout: failed to read logout_token");
            return BadRequest("Invalid logout_token");
        }

        // ── Provider selection: match on BOTH iss and aud, not aud alone.
        // Otherwise an IdP with a matching aud (or a shared client_id across tenants) could
        // forge a logout for a different IdP's users that happen to share the same client_id.
        var unvalidatedIssuer = unvalidated.Issuer;
        if (string.IsNullOrEmpty(unvalidatedIssuer))
        {
            _logger.LogWarning("Back-channel logout: logout_token missing iss claim");
            return BadRequest("Invalid logout_token: missing iss");
        }

        var config = _configProvider.GetConfiguration();
        var unvalidatedAudiences = unvalidated.Audiences?.ToArray() ?? Array.Empty<string>();

        var candidateProviders = new List<(OidcProviderConfig Provider, DiscoveryDocumentResponse Disco)>();
        foreach (var p in config.Providers.Where(p => p.Enabled))
        {
            if (!unvalidatedAudiences.Contains(p.ClientId, StringComparer.Ordinal))
            {
                continue;
            }

            DiscoveryDocumentResponse disco;
            try
            {
                disco = await _discoveryCache.GetAsync(p.Authority, p.AllowInsecureAuthority).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Back-channel logout: discovery lookup threw for {Provider}", p.ProviderId);
                continue;
            }

            if (disco.IsError)
            {
                _logger.LogWarning(
                    "Back-channel logout: discovery error for {Provider}: {Error}",
                    p.ProviderId, disco.Error);
                continue;
            }

            if (string.Equals(disco.Issuer, unvalidatedIssuer, StringComparison.Ordinal))
            {
                candidateProviders.Add((p, disco));
            }
        }

        if (candidateProviders.Count == 0)
        {
            _logger.LogWarning(
                "Back-channel logout: no provider matched (iss={Issuer}, aud=[{Audiences}])",
                unvalidatedIssuer, string.Join(",", unvalidatedAudiences));
            return BadRequest("Unknown issuer or audience");
        }

        if (candidateProviders.Count > 1)
        {
            _logger.LogWarning(
                "Back-channel logout: ambiguous provider match for iss={Issuer} (matched {Count} providers)",
                unvalidatedIssuer, candidateProviders.Count);
            return BadRequest("Ambiguous provider match");
        }

        var provider = candidateProviders[0].Provider;
        var discovery = candidateProviders[0].Disco;

        SecurityKey[] signingKeys;
        try
        {
            signingKeys = await SigningKeyResolver.ResolveAsync(
                logout_token, provider.ClientSecret, discovery.JwksUri, _jwksCache,
                provider.AllowedSigningAlgorithms).ConfigureAwait(false);
        }
        catch (SecurityTokenException ex)
        {
            _logger.LogWarning(ex, "Back-channel logout: rejecting token (alg not allowed or related signing-key validation failure)");
            return BadRequest("Token signing validation failed");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Back-channel logout: failed to resolve signing keys");
            return StatusCode(502, "Failed to resolve signing keys");
        }

        var validationParameters = new TokenValidationParameters
        {
            ValidIssuer = discovery.Issuer,
            ValidAudience = provider.ClientId,
            IssuerSigningKeys = signingKeys,
            ValidAlgorithms = provider.AllowedSigningAlgorithms,
            ValidateIssuer = true,
            ValidateAudience = true,
            // We do our own lifetime check (RFC 8935 allows logout_tokens without exp).
            ValidateLifetime = false,
            ValidateIssuerSigningKey = true,
            RequireSignedTokens = true,
            LifetimeValidator = ValidateLogoutTokenLifetime,
            ClockSkew = TimeSpan.FromSeconds(30)
        };

        JwtSecurityToken validated;
        try
        {
            handler.ValidateToken(logout_token, validationParameters, out var validatedToken);
            validated = (JwtSecurityToken)validatedToken;
        }
        catch (SecurityTokenException ex)
        {
            _logger.LogWarning("Back-channel logout: token validation failed: {Message}", ex.Message);
            return BadRequest("Token validation failed");
        }

        // RFC 8935 §2.4: presence of `nonce` indicates an ID token, not a logout_token. MUST reject.
        if (validated.Claims.Any(c => c.Type == "nonce"))
        {
            _logger.LogWarning("Back-channel logout: rejected token containing nonce claim (likely an ID token)");
            return BadRequest("Invalid logout_token: nonce claim must not be present");
        }

        var eventsClaim = validated.Claims.FirstOrDefault(c => c.Type == "events")?.Value;
        if (string.IsNullOrEmpty(eventsClaim))
        {
            _logger.LogWarning("Back-channel logout: missing events claim");
            return BadRequest("Invalid logout_token: missing events claim");
        }

        try
        {
            using var doc = JsonDocument.Parse(eventsClaim);
            if (!doc.RootElement.TryGetProperty(BackChannelLogoutEventType, out _))
            {
                _logger.LogWarning("Back-channel logout: events claim does not contain logout event");
                return BadRequest("Invalid logout_token: wrong event type");
            }
        }
        catch (JsonException)
        {
            _logger.LogWarning("Back-channel logout: events claim is not valid JSON");
            return BadRequest("Invalid logout_token: malformed events claim");
        }

        // jti REQUIRED for replay protection (spec SHOULDs, we require for safety).
        var jti = validated.Claims.FirstOrDefault(c => c.Type == "jti")?.Value;
        if (string.IsNullOrEmpty(jti))
        {
            _logger.LogWarning("Back-channel logout: logout_token missing jti claim");
            return BadRequest("Invalid logout_token: missing jti");
        }

        // RFC 8935 §2.4: at-least-one of sub or sid must be present.
        var sub = validated.Claims.FirstOrDefault(c => c.Type == "sub")?.Value;
        var sid = validated.Claims.FirstOrDefault(c => c.Type == "sid")?.Value;
        if (string.IsNullOrEmpty(sub) && string.IsNullOrEmpty(sid))
        {
            _logger.LogWarning("Back-channel logout: logout_token missing both sub and sid claims");
            return BadRequest("Invalid logout_token: must contain sub or sid");
        }

        // Replay check AFTER signature/lifetime/claims validation succeeded. Putting it here means
        // we don't poison the cache with attacker-controlled jti values that wouldn't have been
        // accepted anyway.
        var expiresAt = validated.Payload.Expiration.HasValue
            ? DateTimeOffset.FromUnixTimeSeconds(validated.Payload.Expiration.Value)
            : DateTimeOffset.UtcNow.AddMinutes(5);
        if (!_replayCache.TryRegister(validated.Issuer, jti, expiresAt))
        {
            _logger.LogWarning(
                "Back-channel logout: replayed jti={Jti} for iss={Issuer}",
                jti, validated.Issuer);
            return BadRequest("Replayed logout_token");
        }

        // ── Resolve target user/session ─────────────────────────────────────
        OidcUserRecord? record = null;
        string revocationPath;

        if (!string.IsNullOrEmpty(sid))
        {
            record = await _userStore.GetBySidAsync(sid, provider.ProviderId).ConfigureAwait(false);
            revocationPath = "sid";
        }

        if (record == null && !string.IsNullOrEmpty(sub))
        {
            record = await _userStore.GetBySubAsync(sub, provider.ProviderId).ConfigureAwait(false);
            revocationPath = string.IsNullOrEmpty(sid) ? "sub" : "sid-fallback-sub";
        }
        else if (record != null && !string.IsNullOrEmpty(sid))
        {
            revocationPath = "sid";
        }
        else
        {
            revocationPath = "sub";
        }

        if (record == null)
        {
            _logger.LogInformation(
                "Back-channel logout: target not found (sub={Sub}, sid={Sid}, provider={Provider}) — ignoring",
                sub, sid, provider.ProviderId);
            return Ok();
        }

        try
        {
            // NOTE: Jellyfin's public ISessionManager only exposes RevokeUserTokens(userId, currentAccessToken),
            // which revokes ALL tokens for a user (the second arg is an exclusion of the caller's
            // own token, not a target session). So even when sid is present we currently must revoke
            // all sessions; the sid path is logged for audit and primed for future per-session API.
            await _sessionManager.RevokeUserTokens(record.UserId, null).ConfigureAwait(false);

            _logger.LogInformation(
                "Back-channel logout: revoked sessions for user {Username} (sub={Sub}, sid={Sid}, path={Path})",
                record.Username, sub, sid, revocationPath);

            await _rbacService.LogActivityAsync(
                $"OIDC back-channel logout: {record.Username}",
                "OidcBackChannelLogout",
                record.UserId,
                $"Provider: {provider.ProviderId}; path: {revocationPath}",
                Microsoft.Extensions.Logging.LogLevel.Information).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Back-channel logout: failed to revoke sessions for user {Username}", record.Username);
            return StatusCode(500, "Failed to revoke user sessions");
        }

        return Ok();
    }

    /// <summary>
    /// RFC 8935 lifetime rules: exp is optional, iat is REQUIRED. If exp is present, it must be
    /// in the future (allowing skew). iat must be within ±5 minutes of now (defends against
    /// long-stored tokens).
    /// </summary>
    private static bool ValidateLogoutTokenLifetime(
        DateTime? notBefore,
        DateTime? expires,
        SecurityToken securityToken,
        TokenValidationParameters parameters)
    {
        if (securityToken is not JwtSecurityToken jwt)
        {
            return false;
        }

        var iatUnix = jwt.Payload.IssuedAt;
        if (iatUnix == default)
        {
            throw new SecurityTokenInvalidLifetimeException("logout_token missing required iat claim");
        }

        var now = DateTime.UtcNow;
        var iat = iatUnix.ToUniversalTime();
        if (iat > now + IatSkew)
        {
            throw new SecurityTokenInvalidLifetimeException("logout_token iat is in the future");
        }

        if (iat < now - IatSkew)
        {
            throw new SecurityTokenInvalidLifetimeException("logout_token iat is too old");
        }

        if (expires.HasValue && expires.Value < now - ExpSkew)
        {
            throw new SecurityTokenExpiredException("logout_token has expired");
        }

        return true;
    }
}
