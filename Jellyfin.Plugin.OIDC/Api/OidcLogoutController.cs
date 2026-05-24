using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;
using IdentityModel.Client;
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

    private readonly OidcUserStore _userStore;
    private readonly ISessionManager _sessionManager;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly JwksCache _jwksCache;
    private readonly OidcDiscoveryCache _discoveryCache;
    private readonly RbacService _rbacService;
    private readonly IPluginConfigProvider _configProvider;
    private readonly ILogger<OidcLogoutController> _logger;

    public OidcLogoutController(
        OidcUserStore userStore,
        ISessionManager sessionManager,
        IHttpClientFactory httpClientFactory,
        JwksCache jwksCache,
        OidcDiscoveryCache discoveryCache,
        RbacService rbacService,
        IPluginConfigProvider configProvider,
        ILogger<OidcLogoutController> logger)
    {
        _userStore = userStore;
        _sessionManager = sessionManager;
        _httpClientFactory = httpClientFactory;
        _jwksCache = jwksCache;
        _discoveryCache = discoveryCache;
        _rbacService = rbacService;
        _configProvider = configProvider;
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

        var config = _configProvider.GetConfiguration();
        var audience = unvalidated.Audiences.FirstOrDefault();
        var provider = config.Providers.FirstOrDefault(p =>
            string.Equals(p.ClientId, audience, StringComparison.Ordinal) && p.Enabled);

        if (provider == null)
        {
            _logger.LogWarning(
                "Back-channel logout: no enabled provider found for aud={Audience}", audience);
            return BadRequest("Unknown audience");
        }

        var disco = await _discoveryCache.GetAsync(provider.Authority).ConfigureAwait(false);

        if (disco.IsError)
        {
            _logger.LogError(
                "Back-channel logout: discovery failed for provider {Provider}: {Error}",
                provider.ProviderId, disco.Error);
            return StatusCode(502, "Failed to contact identity provider");
        }

        SecurityKey[] signingKeys;
        try
        {
            signingKeys = await SigningKeyResolver.ResolveAsync(
                logout_token, provider.ClientSecret, disco.JwksUri, _jwksCache).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Back-channel logout: failed to resolve signing keys");
            return StatusCode(502, "Failed to resolve signing keys");
        }

        var validationParameters = new TokenValidationParameters
        {
            ValidIssuer = disco.Issuer,
            ValidAudience = provider.ClientId,
            IssuerSigningKeys = signingKeys,
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            RequireSignedTokens = true,
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

        var sub = validated.Claims.FirstOrDefault(c => c.Type == "sub")?.Value;
        if (string.IsNullOrEmpty(sub))
        {
            _logger.LogWarning("Back-channel logout: logout_token missing sub claim");
            return BadRequest("Invalid logout_token: missing sub claim");
        }

        var record = await _userStore.GetBySubAsync(sub, provider.ProviderId).ConfigureAwait(false);
        if (record == null)
        {
            _logger.LogInformation(
                "Back-channel logout: sub={Sub} not found in user store (provider={Provider}), ignoring",
                sub, provider.ProviderId);
            return Ok();
        }

        try
        {
            await _sessionManager.RevokeUserTokens(record.UserId, null).ConfigureAwait(false);
            _logger.LogInformation(
                "Back-channel logout: revoked sessions for user {Username} (sub={Sub})",
                record.Username, sub);

            await _rbacService.LogActivityAsync(
                $"OIDC back-channel logout: {record.Username}",
                "OidcBackChannelLogout",
                record.UserId,
                $"Provider: {provider.ProviderId}",
                Microsoft.Extensions.Logging.LogLevel.Information).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Back-channel logout: failed to revoke sessions for user {Username}", record.Username);
            return StatusCode(500, "Failed to revoke user sessions");
        }

        return Ok();
    }
}
