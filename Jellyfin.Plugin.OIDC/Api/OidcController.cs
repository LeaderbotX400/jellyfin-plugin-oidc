using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using IdentityModel;
using IdentityModel.Client;
using Jellyfin.Plugin.OIDC.Configuration;
using Jellyfin.Plugin.OIDC.Services;
using MediaBrowser.Common.Api;
using MediaBrowser.Controller.Library;
using MediaBrowser.Controller.Session;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace Jellyfin.Plugin.OIDC.Api;

[ApiController]
[Route("sso/OIDC")]
public class OidcController : ControllerBase
{
    private readonly StateManager _stateManager;
    private readonly UserSyncService _userSyncService;
    private readonly ISessionManager _sessionManager;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly JwksCache _jwksCache;
    private readonly OidcDiscoveryCache _discoveryCache;
    private readonly RbacService _rbacService;
    private readonly OidcUserStore _userStore;
    private readonly IUserManager _userManager;
    private readonly IPluginConfigProvider _configProvider;
    private readonly ILogger<OidcController> _logger;

    public OidcController(
        StateManager stateManager,
        UserSyncService userSyncService,
        ISessionManager sessionManager,
        IHttpClientFactory httpClientFactory,
        JwksCache jwksCache,
        OidcDiscoveryCache discoveryCache,
        RbacService rbacService,
        OidcUserStore userStore,
        IUserManager userManager,
        IPluginConfigProvider configProvider,
        ILogger<OidcController> logger)
    {
        _stateManager = stateManager;
        _userSyncService = userSyncService;
        _sessionManager = sessionManager;
        _httpClientFactory = httpClientFactory;
        _jwksCache = jwksCache;
        _discoveryCache = discoveryCache;
        _rbacService = rbacService;
        _userStore = userStore;
        _userManager = userManager;
        _configProvider = configProvider;
        _logger = logger;
    }

    [HttpGet("Start/{providerId}")]
    public async Task<ActionResult> Start(string providerId)
    {
        var provider = GetProvider(providerId);
        if (provider == null)
        {
            return NotFound($"Provider '{providerId}' not found or disabled");
        }

        var disco = await GetDiscoveryDocumentAsync(provider).ConfigureAwait(false);
        if (disco.IsError)
        {
            _logger.LogError("OIDC discovery failed for {Provider}: {Error}", providerId, disco.Error);
            return StatusCode(502, "Failed to contact identity provider");
        }

        var codeVerifier = CryptoRandom.CreateUniqueId(64);
        var codeChallenge = CreateCodeChallenge(codeVerifier);
        var nonce = CryptoRandom.CreateUniqueId(32);
        var redirectUri = BuildCallbackUri(providerId);

        var state = new OidcState
        {
            ProviderId = providerId,
            Nonce = nonce,
            CodeVerifier = codeVerifier,
            RedirectUri = redirectUri
        };

        var stateKey = _stateManager.StoreState(state);

        var authorizeUrl = new RequestUrl(disco.AuthorizeEndpoint!);
        var url = authorizeUrl.CreateAuthorizeUrl(
            clientId: provider.ClientId,
            responseType: OidcConstants.ResponseTypes.Code,
            scope: provider.Scopes,
            redirectUri: redirectUri,
            state: stateKey,
            nonce: nonce,
            codeChallenge: codeChallenge,
            codeChallengeMethod: OidcConstants.CodeChallengeMethods.Sha256,
            extra: ParseAdditionalParameters(provider.AdditionalParameters));

        return Redirect(url);
    }

    [HttpGet("Callback/{providerId}")]
    public async Task<ActionResult> Callback(string providerId, [FromQuery] string code, [FromQuery] string state)
    {
        if (string.IsNullOrEmpty(code) || string.IsNullOrEmpty(state))
        {
            var error = HttpContext.Request.Query["error"].FirstOrDefault();
            var errorDesc = HttpContext.Request.Query["error_description"].FirstOrDefault();
            _logger.LogWarning("OIDC callback error: {Error} - {Description}", error, errorDesc);
            return BadRequest($"Authentication failed: {error ?? "missing code or state"}");
        }

        var oidcState = _stateManager.ConsumeState(state);
        if (oidcState == null)
        {
            return BadRequest("Invalid or expired authentication state. Please try again.");
        }

        if (!string.Equals(oidcState.ProviderId, providerId, StringComparison.OrdinalIgnoreCase))
        {
            return BadRequest("Provider mismatch");
        }

        var provider = GetProvider(providerId);
        if (provider == null)
        {
            return NotFound($"Provider '{providerId}' not found");
        }

        var disco = await GetDiscoveryDocumentAsync(provider).ConfigureAwait(false);
        if (disco.IsError)
        {
            return StatusCode(502, "Failed to contact identity provider");
        }

        var httpClient = _httpClientFactory.CreateClient("OidcPlugin");
        var tokenResponse = await httpClient.RequestAuthorizationCodeTokenAsync(new AuthorizationCodeTokenRequest
        {
            Address = disco.TokenEndpoint,
            ClientId = provider.ClientId,
            ClientSecret = provider.ClientSecret,
            Code = code,
            RedirectUri = oidcState.RedirectUri,
            CodeVerifier = oidcState.CodeVerifier
        }).ConfigureAwait(false);

        if (tokenResponse.IsError)
        {
            _logger.LogError("Token exchange failed: {Error} {Description}",
                tokenResponse.Error, tokenResponse.ErrorDescription);
            return BadRequest("Token exchange failed. Check plugin logs for details.");
        }

        var tokenString = tokenResponse.IdentityToken;
        if (string.IsNullOrEmpty(tokenString))
        {
            _logger.LogError("Identity token missing in token response from provider {Provider}", providerId);
            return BadRequest("Identity token is missing");
        }

        var handler = new JwtSecurityTokenHandler();
        if (!handler.CanReadToken(tokenString))
        {
            return BadRequest("Could not read identity token");
        }

        SecurityKey[] signingKeys;
        try
        {
            signingKeys = await SigningKeyResolver.ResolveAsync(
                tokenString, provider.ClientSecret, disco.JwksUri, _jwksCache).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to resolve signing keys for provider {Provider}", providerId);
            return StatusCode(502, "Failed to resolve signing keys from identity provider");
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

        JwtSecurityToken idToken;
        try
        {
            handler.ValidateToken(tokenString, validationParameters, out var validatedToken);
            idToken = (JwtSecurityToken)validatedToken;
        }
        catch (SecurityTokenException ex)
        {
            _logger.LogWarning("ID token validation failed for provider {Provider}: {Message}", providerId, ex.Message);
            await _rbacService.LogActivityAsync(
                "OIDC login failed: token validation error",
                "OidcLoginFailure",
                Guid.Empty,
                ex.Message,
                Microsoft.Extensions.Logging.LogLevel.Warning).ConfigureAwait(false);
            return BadRequest("Token validation failed");
        }

        var nonceClaim = idToken.Claims.FirstOrDefault(c => c.Type == "nonce")?.Value;
        if (!string.IsNullOrEmpty(oidcState.Nonce) && nonceClaim != oidcState.Nonce)
        {
            _logger.LogWarning("Nonce mismatch in OIDC callback");
            return BadRequest("Token validation failed: nonce mismatch");
        }

        // A.1 — email_verified enforcement
        var emailVerifiedClaim = ClaimParser.ExtractClaim(idToken, "email_verified");
        var emailVerified = string.Equals(emailVerifiedClaim, "true", StringComparison.OrdinalIgnoreCase);
        var emailClaim = ClaimParser.ExtractClaim(idToken, provider.EmailClaim);

        if (provider.RequireEmailVerified)
        {
            if (!emailVerified)
            {
                _logger.LogWarning(
                    "OIDC login rejected: email_verified={Value} for provider {Provider}",
                    emailVerifiedClaim, providerId);
                return Unauthorized("Email address is not verified. Please verify your email with the identity provider.");
            }
        }

        var sub = ClaimParser.ExtractClaim(idToken, "sub");
        var username = ClaimParser.ExtractClaim(idToken, provider.UsernameClaim);
        if (string.IsNullOrEmpty(username))
        {
            username = sub;
        }

        if (string.IsNullOrEmpty(username))
        {
            return BadRequest("Could not determine username from token");
        }

        var displayName = ClaimParser.ExtractClaim(idToken, provider.DisplayNameClaim);

        // Extract roles; fall back to access token for non-standard IdPs
        var roles = ClaimParser.ExtractRoles(idToken, provider.RoleClaim);
        if (roles.Length == 0 && handler.CanReadToken(tokenResponse.AccessToken))
        {
            var accessToken = handler.ReadJwtToken(tokenResponse.AccessToken);
            roles = ClaimParser.ExtractRoles(accessToken, provider.RoleClaim);
        }

        // A.3 — apply claim transforms before role matching
        var rawRoles = roles;
        roles = ClaimParser.ApplyTransforms(roles, provider.RoleTransforms);

        var entitlements = provider.EnableEntitlements
            ? ClaimParser.ExtractRoles(idToken, provider.EntitlementClaim)
            : Array.Empty<string>();

        var transformCount = provider.RoleTransforms?.Count ?? 0;
        if (transformCount > 0 && !rawRoles.SequenceEqual(roles, StringComparer.Ordinal))
        {
            _logger.LogInformation(
                "OIDC auth successful: user={Username}, roles=[{Roles}] (raw=[{RawRoles}], transforms={TransformCount}), entitlements={EntitlementCount}, provider={Provider}",
                username, string.Join(", ", roles), string.Join(", ", rawRoles), transformCount, entitlements.Length, providerId);
        }
        else
        {
            _logger.LogInformation(
                "OIDC auth successful: user={Username}, roles=[{Roles}], entitlements={EntitlementCount}, provider={Provider}",
                username, string.Join(", ", roles), entitlements.Length, providerId);
        }

        var sessionToken = _stateManager.StoreAuthorizedSession(new AuthorizedSession
        {
            ProviderId = providerId,
            Username = username,
            DisplayName = displayName,
            Sub = sub,
            Roles = roles,
            Entitlements = entitlements,
            LinkUserId = oidcState.LinkingForUserId,
            Email = emailClaim,
            EmailVerified = emailVerified
        });

        return Content(BuildCallbackHtml(sessionToken, providerId), "text/html");
    }

    [HttpPost("Auth/{providerId}")]
    public async Task<ActionResult> Authenticate(
        string providerId,
        [FromBody] AuthenticateRequest request)
    {
        var session = _stateManager.ConsumeAuthorizedSession(request.Token);
        if (session == null)
        {
            return Unauthorized("Invalid or expired session token");
        }

        if (!string.Equals(session.ProviderId, providerId, StringComparison.OrdinalIgnoreCase))
        {
            return BadRequest("Provider mismatch");
        }

        try
        {
            // C.2 — handle account linking if this is a link flow
            if (session.LinkUserId.HasValue)
            {
                await _userStore.LinkAsync(session.LinkUserId.Value, session.Sub, providerId)
                    .ConfigureAwait(false);
                _logger.LogInformation(
                    "Linked user {UserId} to OIDC sub={Sub} provider={Provider}",
                    session.LinkUserId.Value, session.Sub, providerId);
                return Ok(new { Linked = true, Sub = session.Sub });
            }

            var userId = await _userSyncService.SyncUserAsync(
                session.Username,
                session.DisplayName,
                session.Sub,
                session.Roles,
                session.Entitlements,
                providerId,
                session.Email,
                session.EmailVerified).ConfigureAwait(false);

            var authRequest = new AuthenticationRequest
            {
                App = request.App ?? "Jellyfin Web",
                AppVersion = request.AppVersion ?? "0.0.0",
                DeviceId = request.DeviceId ?? Guid.NewGuid().ToString(),
                DeviceName = request.DeviceName ?? "OIDC",
                UserId = userId
            };

            var authResult = await _sessionManager.AuthenticateDirect(authRequest).ConfigureAwait(false);

            await _rbacService.LogActivityAsync(
                $"OIDC login: {session.Username}",
                "OidcLoginSuccess",
                userId,
                $"Provider: {providerId}",
                Microsoft.Extensions.Logging.LogLevel.Information).ConfigureAwait(false);

            return Ok(authResult);
        }
        catch (OidcUsernameCollisionException ex)
        {
            _logger.LogWarning(
                "OIDC login rejected: name collision for '{Username}' (provider={Provider})",
                ex.Username, providerId);
            await _rbacService.LogActivityAsync(
                $"OIDC login rejected: name collision for '{ex.Username}'",
                "OidcLoginNameCollision",
                Guid.Empty,
                $"Provider: {providerId}",
                Microsoft.Extensions.Logging.LogLevel.Warning).ConfigureAwait(false);
            return Conflict(new
            {
                error = "name_collision",
                message = ex.Message
            });
        }
        catch (OidcUserStoreUnavailableException ex)
        {
            _logger.LogError(ex, "OIDC user store is unavailable — login rejected for {Username}", session.Username);
            return StatusCode(503, "OIDC user store is unavailable due to file corruption. " +
                                   "An administrator must reset it via POST /sso/OIDC/Admin/UserStore/Reset.");
        }
        catch (InvalidOperationException ex)
        {
            _logger.LogWarning("User sync failed: {Message}", ex.Message);
            return Forbid();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Authentication failed for user {Username}", session.Username);
            return StatusCode(500, "Authentication failed");
        }
    }

    [HttpGet("Providers")]
    public ActionResult GetProviders()
    {
        var config = _configProvider.GetConfiguration();
        var providers = config.Providers
            .Where(p => p.Enabled)
            .Select(p => new
            {
                p.ProviderId,
                p.DisplayName,
                p.ButtonColor,
                p.ButtonIcon,
                StartUrl = $"{Request.Scheme}://{Request.Host}/sso/OIDC/Start/{p.ProviderId}"
            });

        return Ok(providers);
    }

    // ── Account linking endpoints ─────────────────────────────────────────────

    [HttpGet("link/start/{providerId}")]
    [Authorize]
    public async Task<ActionResult> LinkStart(string providerId)
    {
        var provider = GetProvider(providerId);
        if (provider == null)
        {
            return NotFound($"Provider '{providerId}' not found or disabled");
        }

        // Identify the currently authenticated Jellyfin user
        var jellyfinUserId = GetCurrentUserId();
        if (jellyfinUserId == null)
        {
            return Unauthorized("Could not determine current user");
        }

        var disco = await GetDiscoveryDocumentAsync(provider).ConfigureAwait(false);
        if (disco.IsError)
        {
            return StatusCode(502, "Failed to contact identity provider");
        }

        var codeVerifier = CryptoRandom.CreateUniqueId(64);
        var codeChallenge = CreateCodeChallenge(codeVerifier);
        var nonce = CryptoRandom.CreateUniqueId(32);
        var redirectUri = BuildCallbackUri(providerId);

        var stateKey = _stateManager.StoreState(new OidcState
        {
            ProviderId = providerId,
            Nonce = nonce,
            CodeVerifier = codeVerifier,
            RedirectUri = redirectUri,
            LinkingForUserId = jellyfinUserId.Value
        });

        var authorizeUrl = new RequestUrl(disco.AuthorizeEndpoint!);
        var url = authorizeUrl.CreateAuthorizeUrl(
            clientId: provider.ClientId,
            responseType: OidcConstants.ResponseTypes.Code,
            scope: provider.Scopes,
            redirectUri: redirectUri,
            state: stateKey,
            nonce: nonce,
            codeChallenge: codeChallenge,
            codeChallengeMethod: OidcConstants.CodeChallengeMethods.Sha256);

        return Redirect(url);
    }

    [HttpDelete("link/{providerId}")]
    [Authorize]
    public async Task<ActionResult> Unlink(string providerId)
    {
        var jellyfinUserId = GetCurrentUserId();
        if (jellyfinUserId == null)
        {
            return Unauthorized();
        }

        try
        {
            await _userStore.UnlinkAsync(jellyfinUserId.Value, providerId).ConfigureAwait(false);
        }
        catch (OidcUserStoreUnavailableException ex)
        {
            _logger.LogError(ex, "OIDC user store unavailable during Unlink for user {UserId}", jellyfinUserId.Value);
            return StatusCode(503, "OIDC user store is unavailable. Contact an administrator.");
        }

        _logger.LogInformation("Unlinked user {UserId} from provider {Provider}", jellyfinUserId.Value, providerId);
        return Ok();
    }

    [HttpGet("links")]
    [Authorize]
    public async Task<ActionResult> GetLinks()
    {
        var jellyfinUserId = GetCurrentUserId();
        if (jellyfinUserId == null)
        {
            return Unauthorized();
        }

        IReadOnlyList<(string ProviderId, string Sub)> links;
        try
        {
            links = await _userStore.GetLinksForUserAsync(jellyfinUserId.Value).ConfigureAwait(false);
        }
        catch (OidcUserStoreUnavailableException ex)
        {
            _logger.LogError(ex, "OIDC user store unavailable during GetLinks for user {UserId}", jellyfinUserId.Value);
            return StatusCode(503, "OIDC user store is unavailable. Contact an administrator.");
        }

        return Ok(links.Select(l => new { l.ProviderId, l.Sub }));
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private Guid? GetCurrentUserId()
    {
        var userIdClaim = User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value
                         ?? User.FindFirst("uid")?.Value
                         ?? User.FindFirst("sub")?.Value;
        if (Guid.TryParse(userIdClaim, out var userId))
        {
            return userId;
        }

        return null;
    }

    private OidcProviderConfig? GetProvider(string providerId)
    {
        return _configProvider.GetConfiguration().Providers
            .FirstOrDefault(p => string.Equals(p.ProviderId, providerId, StringComparison.OrdinalIgnoreCase)
                                 && p.Enabled);
    }

    private Task<DiscoveryDocumentResponse> GetDiscoveryDocumentAsync(OidcProviderConfig provider) =>
        _discoveryCache.GetAsync(provider.Authority);

    private string BuildCallbackUri(string providerId)
    {
        return $"{Request.Scheme}://{Request.Host}/sso/OIDC/Callback/{providerId}";
    }

    private static string CreateCodeChallenge(string codeVerifier)
    {
        using var sha256 = SHA256.Create();
        var hash = sha256.ComputeHash(Encoding.ASCII.GetBytes(codeVerifier));
        return Base64UrlEncoder.Encode(hash);
    }

    private static Parameters? ParseAdditionalParameters(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
        {
            return null;
        }

        var pairs = raw.Split('&', StringSplitOptions.RemoveEmptyEntries)
            .Select(p => p.Split('=', 2))
            .Where(p => p.Length == 2)
            .Select(p => new KeyValuePair<string, string>(
                Uri.UnescapeDataString(p[0].Trim()),
                Uri.UnescapeDataString(p[1].Trim())));

        return new Parameters(pairs);
    }

    private static string BuildCallbackHtml(string sessionToken, string providerId)
    {
        return $$"""
        <!DOCTYPE html>
        <html>
        <head><title>Authenticating...</title></head>
        <body>
        <h3>Completing authentication...</h3>
        <p id="status">Please wait...</p>
        <script>
        (function() {
            const token = '{{sessionToken}}';
            const providerId = '{{providerId}}';

            const deviceId = localStorage.getItem('_deviceId2') || crypto.randomUUID();
            localStorage.setItem('_deviceId2', deviceId);

            fetch('/sso/OIDC/Auth/' + providerId, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    Token: token,
                    DeviceId: deviceId,
                    DeviceName: navigator.userAgent.substring(0, 50),
                    App: 'Jellyfin Web',
                    AppVersion: '10.11.0'
                })
            })
            .then(function(r) {
                if (r.status === 409) {
                    return r.json().then(function(body) {
                        throw new Error(body && body.message ? body.message : 'Account collision');
                    });
                }
                if (!r.ok) throw new Error('Auth failed: ' + r.status);
                return r.json();
            })
            .then(function(auth) {
                // Link flow returns {Linked: true} instead of a session
                if (auth.Linked) {
                    document.getElementById('status').textContent = 'Account linked successfully!';
                    setTimeout(function() { window.close(); }, 2000);
                    return;
                }
                var credentials = {
                    Servers: [{
                        ManualAddress: window.location.origin,
                        AccessToken: auth.AccessToken,
                        UserId: auth.User.Id,
                        IsLocalUser: true
                    }]
                };
                localStorage.setItem('jellyfin_credentials', JSON.stringify(credentials));

                var user = {
                    Id: auth.User.Id,
                    ServerId: auth.ServerId,
                    AccessToken: auth.AccessToken
                };
                localStorage.setItem('_jellyfin_user_' + auth.ServerId, JSON.stringify(user));

                document.getElementById('status').textContent = 'Success! Redirecting...';
                window.location.href = '/';
            })
            .catch(function(err) {
                document.getElementById('status').textContent = 'Error: ' + err.message;
            });
        })();
        </script>
        </body>
        </html>
        """;
    }
}

public class AuthenticateRequest
{
    public string Token { get; set; } = string.Empty;
    public string? DeviceId { get; set; }
    public string? DeviceName { get; set; }
    public string? App { get; set; }
    public string? AppVersion { get; set; }
}
