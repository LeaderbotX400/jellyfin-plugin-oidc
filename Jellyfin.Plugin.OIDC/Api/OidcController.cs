using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using IdentityModel;
using IdentityModel.Client;
using Jellyfin.Plugin.OIDC;
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
    private readonly AuthorizationCodeCache _codeCache;
    private readonly CallbackRateLimiter _rateLimiter;
    private readonly ProfileImageService _profileImageService;
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
        AuthorizationCodeCache codeCache,
        CallbackRateLimiter rateLimiter,
        ProfileImageService profileImageService,
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
        _codeCache = codeCache;
        _rateLimiter = rateLimiter;
        _profileImageService = profileImageService;
        _logger = logger;
    }

    [HttpGet("Start/{providerId}")]
    public async Task<ActionResult> Start(string providerId)
    {
        if (!ProviderIdValidation.IsValid(providerId))
        {
            return BadRequest($"Invalid provider id (must be {ProviderIdValidation.CharsetDescription})");
        }

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

        // Issue a per-request CSRF token, store its SHA-256 hash in server-side state,
        // and emit the raw token as a strict cookie. The /Callback handler must read the
        // cookie back and prove possession before accepting the OIDC response — this prevents
        // login-CSRF (an attacker forcing a victim's browser to complete the attacker's flow).
        var csrfToken = StateManager.GenerateCsprngToken();
        var csrfHash = StateManager.HashToken(csrfToken);
        SetCsrfBindingCookie(providerId, csrfToken);

        var state = new OidcState
        {
            ProviderId = providerId,
            Nonce = nonce,
            CodeVerifier = codeVerifier,
            RedirectUri = redirectUri,
            CsrfBindingHash = csrfHash
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
        var cfg = _configProvider.GetConfiguration();
        var trustedProxies = ClientIpResolver.ParseCidrs(cfg.TrustedProxyCidrs, _logger);
        var remoteIp = ClientIpResolver.Resolve(HttpContext, cfg.TrustForwardedHeaders, trustedProxies, _logger);
        if (_rateLimiter.IsBanned(remoteIp, out var retryAfter))
        {
            Response.Headers["Retry-After"] = ((int)retryAfter.TotalSeconds).ToString(System.Globalization.CultureInfo.InvariantCulture);
            return StatusCode(429, "Too many failed authentication attempts. Try again later.");
        }

        if (string.IsNullOrEmpty(code) || string.IsNullOrEmpty(state))
        {
            var error = HttpContext.Request.Query["error"].FirstOrDefault();
            var errorDesc = HttpContext.Request.Query["error_description"].FirstOrDefault();
            // Sanitize IdP-supplied strings before logging to prevent log injection.
            _logger.LogWarning(
                "OIDC callback error: {Error} - {Description}",
                LogRedaction.Sanitize(error),
                LogRedaction.Sanitize(errorDesc));
            _rateLimiter.RecordFailure(remoteIp);
            return BadRequest($"Authentication failed: {error ?? "missing code or state"}");
        }

        var oidcState = _stateManager.ConsumeState(state);
        if (oidcState == null)
        {
            await _rbacService.LogActivityAsync(
                "OIDC callback rejected: invalid or expired state",
                "OidcLoginFailure", Guid.Empty, $"provider={providerId}",
                Microsoft.Extensions.Logging.LogLevel.Warning).ConfigureAwait(false);
            _rateLimiter.RecordFailure(remoteIp);
            return BadRequest("Invalid or expired authentication state. Please try again.");
        }

        if (!string.Equals(oidcState.ProviderId, providerId, StringComparison.OrdinalIgnoreCase))
        {
            await _rbacService.LogActivityAsync(
                "OIDC callback rejected: provider mismatch",
                "OidcLoginFailure", Guid.Empty,
                $"stateProvider={oidcState.ProviderId} urlProvider={providerId}",
                Microsoft.Extensions.Logging.LogLevel.Warning).ConfigureAwait(false);
            _rateLimiter.RecordFailure(remoteIp);
            return BadRequest("Provider mismatch");
        }

        // Defense-in-depth: one-time-use code guard. The IdP's token endpoint already
        // enforces this, but we add an in-process check to catch replays before any
        // token exchange network call is made.
        if (!_codeCache.TryConsume(code, providerId))
        {
            _logger.LogWarning("OIDC callback rejected: authorization code already used for provider {Provider}", providerId);
            await _rbacService.LogActivityAsync(
                "OIDC callback rejected: authorization code replay",
                "OidcLoginFailure", Guid.Empty, $"provider={providerId}",
                Microsoft.Extensions.Logging.LogLevel.Warning).ConfigureAwait(false);
            _rateLimiter.RecordFailure(remoteIp);
            return BadRequest("Authorization code has already been used");
        }

        // Verify the per-request CSRF cookie that /Start set. Missing or mismatched cookie
        // means this callback wasn't initiated by this browser session — reject.
        if (!VerifyAndClearCsrfBindingCookie(providerId, oidcState))
        {
            _logger.LogWarning("OIDC callback rejected: missing or invalid CSRF binding cookie for provider {Provider}", providerId);
            await _rbacService.LogActivityAsync(
                "OIDC callback rejected: CSRF binding cookie missing or invalid",
                "OidcLoginFailure", Guid.Empty, $"provider={providerId}",
                Microsoft.Extensions.Logging.LogLevel.Warning).ConfigureAwait(false);
            _rateLimiter.RecordFailure(remoteIp);
            return BadRequest("Authentication session not initiated by this browser. Please start sign-in again.");
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
                LogRedaction.Sanitize(tokenResponse.Error),
                LogRedaction.Sanitize(tokenResponse.ErrorDescription));
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
                tokenString, provider.ClientSecret, disco.JwksUri, _jwksCache,
                provider.AllowedSigningAlgorithms).ConfigureAwait(false);
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
            ValidAlgorithms = provider.AllowedSigningAlgorithms,
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
            _rateLimiter.RecordFailure(remoteIp);
            return BadRequest("Token validation failed");
        }

        // Nonce MUST be present AND match — no short-circuit for empty nonce.
        // OidcState.Nonce is required (always set in /Start and /LinkStart), so this
        // guard catches both a missing nonce claim and a value mismatch.
        var nonceClaim = idToken.Claims.FirstOrDefault(c => c.Type == "nonce")?.Value;
        if (string.IsNullOrEmpty(nonceClaim) || nonceClaim != oidcState.Nonce)
        {
            _logger.LogWarning("Nonce missing or mismatch in OIDC callback for provider {Provider}", providerId);
            _rateLimiter.RecordFailure(remoteIp);
            return BadRequest("Token validation failed: nonce mismatch");
        }

        // Optional AMR/ACR enforcement — require the IdP to have asserted MFA / a specific
        // assurance level. Skipped when both lists are empty (default).
        if (!EnforceAmrAcr(provider, idToken, providerId, out var amrAcrFailure))
        {
            await _rbacService.LogActivityAsync(
                $"OIDC login rejected: {amrAcrFailure}",
                "OidcLoginFailure",
                Guid.Empty,
                $"provider={providerId}",
                Microsoft.Extensions.Logging.LogLevel.Warning).ConfigureAwait(false);
            _rateLimiter.RecordFailure(remoteIp);
            return Unauthorized(amrAcrFailure);
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
                    LogRedaction.Sanitize(emailVerifiedClaim), providerId);
                await _rbacService.LogActivityAsync(
                    "OIDC login rejected: email_verified=false",
                    "OidcLoginFailure", Guid.Empty, $"provider={providerId}",
                    Microsoft.Extensions.Logging.LogLevel.Warning).ConfigureAwait(false);
                _rateLimiter.RecordFailure(remoteIp);
                return Unauthorized("Email address is not verified. Please verify your email with the identity provider.");
            }
        }

        var sub = ClaimParser.ExtractClaim(idToken, "sub");
        var sid = ClaimParser.ExtractClaim(idToken, "sid") ?? string.Empty;
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

        var pictureUrl = provider.SyncProfileImage
            ? await ResolvePictureUrlAsync(provider, disco, idToken, tokenResponse.AccessToken).ConfigureAwait(false)
            : null;

        // Extract roles; optionally fall back to a fully-validated access token.
        // The flag is off by default: access tokens are resource-server tokens and
        // their audience/signing may differ from the id_token, so reading them
        // without validation is a security risk.
        var roles = ClaimParser.ExtractRoles(idToken, provider.RoleClaim);
        if (roles.Length == 0 && provider.RolesFromAccessToken && handler.CanReadToken(tokenResponse.AccessToken))
        {
            // Validate the access token with the same signing keys + issuer as the id_token,
            // but skip audience validation because access-token aud is the resource server,
            // not the OIDC client_id.
            var atValidationParameters = new TokenValidationParameters
            {
                ValidIssuer = disco.Issuer,
                IssuerSigningKeys = signingKeys,
                ValidAlgorithms = provider.AllowedSigningAlgorithms,
                ValidateIssuer = true,
                ValidateAudience = false,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                RequireSignedTokens = true,
                ClockSkew = TimeSpan.FromSeconds(30)
            };
            try
            {
                handler.ValidateToken(tokenResponse.AccessToken, atValidationParameters, out var validatedAt);
                var validatedAccessToken = (JwtSecurityToken)validatedAt;
                roles = ClaimParser.ExtractRoles(validatedAccessToken, provider.RoleClaim);
            }
            // ArgumentException covers malformed/oversized tokens that CanReadToken does not
            // screen out (e.g. > MaximumTokenSizeInBytes); a bad access token must degrade to
            // zero roles, never fail the login.
            catch (Exception ex) when (ex is SecurityTokenException or ArgumentException)
            {
                _logger.LogWarning(
                    "Access token validation failed for provider {Provider}; skipping access-token roles: {Message}",
                    providerId,
                    LogRedaction.Sanitize(ex.Message));
            }
        }

        // A.3 — apply claim transforms before role matching
        var rawRoles = roles;
        roles = ClaimParser.ApplyTransforms(roles, provider.RoleTransforms, providerId, _logger);

        // Audit when transforms changed the role set — silent renames/drops are the #1
        // debug pain point ("user has no perms but their IdP shows the right groups").
        // Surfacing this in Jellyfin's activity log lets admins see it without reading container logs.
        if ((provider.RoleTransforms?.Count ?? 0) > 0 && !rawRoles.SequenceEqual(roles, StringComparer.Ordinal))
        {
            var dropped = rawRoles.Except(roles, StringComparer.OrdinalIgnoreCase).ToArray();
            var added = roles.Except(rawRoles, StringComparer.OrdinalIgnoreCase).ToArray();
            await _rbacService.LogActivityAsync(
                $"OIDC role transforms applied for {username}",
                "OidcRoleTransform",
                Guid.Empty,
                $"provider={providerId} dropped={LogRedaction.RedactRoles(dropped, true)} added={LogRedaction.RedactRoles(added, true)}",
                Microsoft.Extensions.Logging.LogLevel.Information).ConfigureAwait(false);
        }

        var entitlements = provider.EnableEntitlements
            ? ClaimParser.ExtractRoles(idToken, provider.EntitlementClaim)
            : Array.Empty<string>();

        var config = _configProvider.GetConfiguration();
        var verbose = config.VerboseClaimLogging;

        var transformCount = provider.RoleTransforms?.Count ?? 0;
        if (transformCount > 0 && !rawRoles.SequenceEqual(roles, StringComparer.Ordinal))
        {
            // Info: counts only. Debug adds sub-hash. Verbose: full values.
            _logger.LogInformation(
                "OIDC auth successful: user={Username}, roles={RoleCount} (transforms={TransformCount}), entitlements={EntitlementCount}, provider={Provider}",
                username, LogRedaction.RedactRoles(roles, verbose), transformCount, entitlements.Length, providerId);
            if (verbose)
            {
                _logger.LogDebug(
                    "OIDC auth (verbose): sub={Sub}, roles={Roles}, rawRoles={RawRoles}, provider={Provider}",
                    LogRedaction.RedactSub(sub), LogRedaction.RedactRoles(roles, true), LogRedaction.RedactRoles(rawRoles, true), providerId);
            }
            else
            {
                _logger.LogDebug(
                    "OIDC auth: sub={SubRedacted}, roles={RoleCount}, rawRoleCount={RawRoleCount}, provider={Provider}",
                    LogRedaction.RedactSub(sub), LogRedaction.RedactRoles(roles), LogRedaction.RedactRoles(rawRoles), providerId);
            }
        }
        else
        {
            _logger.LogInformation(
                "OIDC auth successful: user={Username}, roles={RoleCount}, entitlements={EntitlementCount}, provider={Provider}",
                username, LogRedaction.RedactRoles(roles, verbose), entitlements.Length, providerId);
            if (!verbose)
            {
                _logger.LogDebug(
                    "OIDC auth: sub={SubRedacted}, roles={RoleCount}, provider={Provider}",
                    LogRedaction.RedactSub(sub), LogRedaction.RedactRoles(roles), providerId);
            }
        }

        var sessionToken = _stateManager.StoreAuthorizedSession(new AuthorizedSession
        {
            ProviderId = providerId,
            Username = username,
            DisplayName = displayName,
            Sub = sub,
            Sid = sid,
            Roles = roles,
            Entitlements = entitlements,
            LinkUserId = oidcState.LinkingForUserId,
            Email = emailClaim,
            EmailVerified = emailVerified,
            PictureUrl = pictureUrl
        });

        _rateLimiter.RecordSuccess(remoteIp);
        SetCallbackSecurityHeaders();
        return Content(BuildCallbackHtml(sessionToken, providerId), "text/html");
    }

    /// <summary>
    /// Resolves the avatar URL for this login: the id_token's picture claim if present, otherwise
    /// the userinfo endpoint.
    ///
    /// The userinfo fallback is not optional in practice — Authentik, the IdP this repo ships an
    /// example for, exposes <c>picture</c> only from userinfo and never in the id_token. The
    /// endpoint comes from the cached discovery document and has already been pinned to the
    /// authority's origin by <see cref="OidcDiscoveryCache"/>, so this adds no new egress target.
    ///
    /// Returns null on any failure. An avatar is never worth failing a login over.
    /// </summary>
    private async Task<string?> ResolvePictureUrlAsync(
        OidcProviderConfig provider,
        DiscoveryDocumentResponse disco,
        JwtSecurityToken idToken,
        string? accessToken)
    {
        var fromIdToken = ClaimParser.ExtractClaim(idToken, provider.PictureClaim);
        if (!string.IsNullOrWhiteSpace(fromIdToken))
        {
            return fromIdToken;
        }

        if (string.IsNullOrEmpty(accessToken) || string.IsNullOrEmpty(disco.UserInfoEndpoint))
        {
            return null;
        }

        try
        {
            var httpClient = _httpClientFactory.CreateClient("OidcPlugin");
            var userInfo = await httpClient.GetUserInfoAsync(new UserInfoRequest
            {
                Address = disco.UserInfoEndpoint,
                Token = accessToken
            }).ConfigureAwait(false);

            if (userInfo.IsError)
            {
                _logger.LogDebug(
                    "Userinfo lookup for picture claim failed for provider {Provider}: {Error}",
                    provider.ProviderId,
                    LogRedaction.Sanitize(userInfo.Error));
                return null;
            }

            foreach (var claim in userInfo.Claims)
            {
                if (string.Equals(claim.Type, provider.PictureClaim, StringComparison.Ordinal))
                {
                    return claim.Value;
                }
            }

            return null;
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or InvalidOperationException)
        {
            _logger.LogDebug(ex, "Userinfo lookup for picture claim failed for provider {Provider}", provider.ProviderId);
            return null;
        }
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

            // After the session exists, so an avatar host that is slow or hostile cannot delay or
            // prevent the login itself. ApplyAsync never throws; its own 5s timeout bounds the
            // extra latency, and it makes no network call at all when the URL has not changed.
            await _profileImageService
                .ApplyAsync(userId, session.PictureUrl, providerId, HttpContext.RequestAborted)
                .ConfigureAwait(false);

            if (!string.IsNullOrEmpty(session.Sid))
            {
                await _userStore.RecordSidAsync(userId, session.Sid, authRequest.DeviceId)
                    .ConfigureAwait(false);
            }

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
        var trustedProxies = ClientIpResolver.ParseCidrs(config.TrustedProxyCidrs, _logger);
        var scheme = ClientIpResolver.ResolveScheme(HttpContext, config.TrustForwardedHeaders, trustedProxies);
        var host = ClientIpResolver.ResolveHost(HttpContext, config.TrustForwardedHeaders, trustedProxies);
        var providers = config.Providers
            .Where(p => p.Enabled)
            .Select(p => new
            {
                p.ProviderId,
                p.DisplayName,
                p.ButtonColor,
                p.ButtonIcon,
                StartUrl = $"{scheme}://{host}/sso/OIDC/Start/{p.ProviderId}"
            });

        return Ok(providers);
    }

    // ── Account linking endpoints ─────────────────────────────────────────────

    // Link flow uses POST (not GET) to defeat naive cross-site request forgery:
    // a malicious <img src="...link/start/..."> or top-level link cannot trigger this endpoint
    // without an attacker-controlled origin running JS that already passes [Authorize]'s
    // bearer token. We also require Content-Type: application/json so a cross-origin form POST
    // (which browsers WILL send without preflight for x-www-form-urlencoded / multipart /
    // text-plain) cannot reach it — only same-origin JS with the Jellyfin token works.
    //
    // Trade-off (documented per spec): a full anti-CSRF token-pair would be the gold standard,
    // but Jellyfin's auth token is delivered via header (not cookie) so it's already not
    // automatically attached cross-site. The POST + JSON-only requirement closes the remaining
    // hole — a victim browser cannot be tricked into completing a link-to-attacker-IdP flow.
    [HttpPost("link/start/{providerId}")]
    [Authorize]
    [Consumes("application/json")]
    public async Task<ActionResult> LinkStart(string providerId)
    {
        if (!ProviderIdValidation.IsValid(providerId))
        {
            return BadRequest($"Invalid provider id (must be {ProviderIdValidation.CharsetDescription})");
        }

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

        // Same CSRF-binding cookie as the login flow — the IdP redirect lands on /Callback,
        // which checks the cookie hash before honouring the state.
        var csrfToken = StateManager.GenerateCsprngToken();
        var csrfHash = StateManager.HashToken(csrfToken);
        SetCsrfBindingCookie(providerId, csrfToken);

        var stateKey = _stateManager.StoreState(new OidcState
        {
            ProviderId = providerId,
            Nonce = nonce,
            CodeVerifier = codeVerifier,
            RedirectUri = redirectUri,
            LinkingForUserId = jellyfinUserId.Value,
            CsrfBindingHash = csrfHash
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
        _discoveryCache.GetAsync(provider.Authority, provider.AllowInsecureAuthority);

    private string BuildCallbackUri(string providerId)
    {
        var cfg = _configProvider.GetConfiguration();
        var trustedProxies = ClientIpResolver.ParseCidrs(cfg.TrustedProxyCidrs, _logger);
        var scheme = ClientIpResolver.ResolveScheme(HttpContext, cfg.TrustForwardedHeaders, trustedProxies);
        var host = ClientIpResolver.ResolveHost(HttpContext, cfg.TrustForwardedHeaders, trustedProxies);
        return $"{scheme}://{host}/sso/OIDC/Callback/{providerId}";
    }

    // Validates the id_token's amr / acr claims against per-provider requirements.
    // Returns true when allowed; false with a user-facing reason when rejected.
    // Empty config lists short-circuit to allow (no enforcement).
    private bool EnforceAmrAcr(
        OidcProviderConfig provider,
        JwtSecurityToken idToken,
        string providerId,
        out string failureReason)
    {
        failureReason = string.Empty;

        var requiredAmr = provider.RequiredAmrValues;
        if (requiredAmr != null && requiredAmr.Count > 0)
        {
            var presentAmr = idToken.Claims
                .Where(c => c.Type == "amr")
                .Select(c => c.Value)
                .ToArray();
            var matched = presentAmr.Any(v =>
                requiredAmr.Any(r => string.Equals(r, v, StringComparison.OrdinalIgnoreCase)));
            if (!matched)
            {
                _logger.LogWarning(
                    "OIDC login rejected: required amr not satisfied for provider {Provider}. present={Present} required={Required}",
                    providerId,
                    LogRedaction.RedactRoles(presentAmr),
                    LogRedaction.RedactRoles(requiredAmr.ToArray()));
                failureReason = "Authentication did not satisfy required authentication method (amr).";
                return false;
            }
        }

        var requiredAcr = provider.RequiredAcrValues;
        if (requiredAcr != null && requiredAcr.Count > 0)
        {
            // acr is a single string per spec.
            var acr = ClaimParser.ExtractClaim(idToken, "acr");
            var matched = !string.IsNullOrEmpty(acr) &&
                requiredAcr.Any(r => string.Equals(r, acr, StringComparison.Ordinal));
            if (!matched)
            {
                _logger.LogWarning(
                    "OIDC login rejected: required acr not satisfied for provider {Provider}. present={Present}",
                    providerId,
                    LogRedaction.Sanitize(acr));
                failureReason = "Authentication did not satisfy required assurance level (acr).";
                return false;
            }
        }

        return true;
    }

    private static string CreateCodeChallenge(string codeVerifier)
    {
        // RFC 7636 §4.2: BASE64URL(SHA256(ASCII(code_verifier))).
        // CryptoRandom.CreateUniqueId only produces ASCII-safe characters, so UTF-8
        // and ASCII are equivalent here — but UTF-8 is spec-correct for the general case.
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(codeVerifier));
        return Base64UrlEncoder.Encode(hash);
    }

    // Keys that are owned by the OIDC protocol layer and must not be overridable via
    // AdditionalParameters — doing so could bypass security controls (e.g. redirecting to
    // an attacker redirect_uri, leaking the client_secret, or swapping the code_challenge).
    private static readonly HashSet<string> ReservedAuthorizeKeys = new(StringComparer.OrdinalIgnoreCase)
    {
        "redirect_uri", "client_id", "client_secret", "state", "nonce",
        "code_challenge", "code_challenge_method", "response_type", "scope"
    };

    /// <summary>
    /// Parses the provider's <c>AdditionalParameters</c> field into a <see cref="Parameters"/> map.
    /// Throws <see cref="InvalidOperationException"/> if any key is reserved by the OIDC protocol.
    /// This is also enforced at config-save time via <see cref="ProviderConfigValidator"/>.
    /// </summary>
    internal static Parameters? ParseAdditionalParameters(string? raw)
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
                Uri.UnescapeDataString(p[1].Trim())))
            .ToList();

        foreach (var kv in pairs)
        {
            if (ReservedAuthorizeKeys.Contains(kv.Key))
            {
                throw new InvalidOperationException(
                    $"AdditionalParameters contains reserved key '{kv.Key}'. " +
                    "This key is controlled by the OIDC protocol and cannot be overridden.");
            }
        }

        return new Parameters(pairs);
    }

    // Cookie configuration:
    //   * On HTTPS we use the `__Host-` prefix — browsers enforce Secure + Path=/ + no Domain,
    //     making cookie injection from a sibling subdomain impossible.
    //   * On plain HTTP (dev only) the `__Host-` prefix would be rejected by the browser
    //     because Secure must be set, so we drop the prefix. This is documented in README and
    //     is acceptable because the entire login flow is already insecure over HTTP.
    private const string CsrfCookieSuffix = "oidc-csrf";

    private string GetCsrfCookieName(string providerId)
    {
        // Provider id charset is validated (A-Za-z0-9_-) so safe to splice into a cookie name.
        var prefix = Request.IsHttps ? "__Host-" : string.Empty;
        return $"{prefix}{CsrfCookieSuffix}-{providerId}";
    }

    private void SetCsrfBindingCookie(string providerId, string token)
    {
        var opts = new Microsoft.AspNetCore.Http.CookieOptions
        {
            HttpOnly = true,
            Secure = Request.IsHttps,
            SameSite = Microsoft.AspNetCore.Http.SameSiteMode.Lax,
            Path = "/",
            // Lifetime mirrors the server-side state expiry. The cookie is single-use; the
            // /Callback handler clears it on success or on hash mismatch.
            MaxAge = TimeSpan.FromMinutes(10)
        };
        Response.Cookies.Append(GetCsrfCookieName(providerId), token, opts);
    }

    private bool VerifyAndClearCsrfBindingCookie(string providerId, OidcState state)
    {
        var cookieName = GetCsrfCookieName(providerId);
        var present = Request.Cookies.TryGetValue(cookieName, out var raw);

        // Always clear the cookie post-callback so a stale token can't be replayed.
        var clearOpts = new Microsoft.AspNetCore.Http.CookieOptions
        {
            HttpOnly = true,
            Secure = Request.IsHttps,
            SameSite = Microsoft.AspNetCore.Http.SameSiteMode.Lax,
            Path = "/"
        };
        Response.Cookies.Delete(cookieName, clearOpts);

        if (state.CsrfBindingHash == null)
        {
            // No binding was issued (legacy state path or test). Reject to be safe.
            return false;
        }

        if (!present || string.IsNullOrEmpty(raw))
        {
            return false;
        }

        var presented = StateManager.HashToken(raw!);
        return CryptographicOperations.FixedTimeEquals(presented, state.CsrfBindingHash);
    }

    private void SetCallbackSecurityHeaders()
    {
        // The callback HTML must run a small bootstrap script that hands the session token
        // back to /Auth and writes Jellyfin's localStorage credentials. We pin everything else
        // off (no <img>, no external CSS, no XHR to other origins). The 'unsafe-inline' on
        // script-src is regrettable but mandated by Jellyfin's plugin embedding model — we
        // cannot ship a separate JS file with a hash-pinned <script src>. Defense-in-depth
        // here is the value-side hardening: every interpolation is JSON-encoded and the
        // provider id charset is validated at config-save time.
        Response.Headers["Content-Security-Policy"] =
            "default-src 'none'; script-src 'unsafe-inline'; connect-src 'self'; style-src 'unsafe-inline'; frame-ancestors 'none'";
        Response.Headers["X-Content-Type-Options"] = "nosniff";
        Response.Headers["Referrer-Policy"] = "no-referrer";
        Response.Headers["X-Frame-Options"] = "DENY";
    }

    private static string BuildCallbackHtml(string sessionToken, string providerId)
    {
        // Every value that crosses into the <script> body is JSON-encoded. JsonSerializer
        // produces a valid JS string literal (single tokens like </script> are escaped as
        // </script>, etc.). This is the defence even if a provider id with hostile
        // characters somehow bypassed the regex at the config layer.
        var encodedToken = JsonSerializer.Serialize(sessionToken);
        var encodedProvider = JsonSerializer.Serialize(providerId);
        // Use the actual plugin version rather than a hardcoded string so Jellyfin's
        // session table shows the real plugin version. Falls back to "0.0.0" when
        // running outside the Jellyfin host (e.g. unit tests).
        var appVersion = OidcPlugin.Instance?.Version?.ToString() ?? "0.0.0";
        var encodedVersion = JsonSerializer.Serialize(appVersion);
        return $$"""
        <!DOCTYPE html>
        <html>
        <head><title>Authenticating...</title></head>
        <body>
        <h3>Completing authentication...</h3>
        <p id="status">Please wait...</p>
        <script>
        (function() {
            const token = {{encodedToken}};
            const providerId = {{encodedProvider}};

            // crypto.randomUUID() is secure-context only. A Jellyfin served over plain HTTP at a
            // non-localhost address — a LAN install on http://10.0.0.5:8096, say — has no secure
            // context, randomUUID is undefined, and this line used to throw and strand the login
            // on "Completing authentication...". crypto.getRandomValues has no such restriction.
            function newDeviceId() {
                if (crypto && typeof crypto.randomUUID === 'function') {
                    return crypto.randomUUID();
                }
                if (crypto && typeof crypto.getRandomValues === 'function') {
                    const b = new Uint8Array(16);
                    crypto.getRandomValues(b);
                    b[6] = (b[6] & 0x0f) | 0x40;  // version 4
                    b[8] = (b[8] & 0x3f) | 0x80;  // variant 10x
                    const h = Array.from(b, x => x.toString(16).padStart(2, '0')).join('');
                    return h.slice(0, 8) + '-' + h.slice(8, 12) + '-' + h.slice(12, 16) + '-' +
                           h.slice(16, 20) + '-' + h.slice(20);
                }
                // Last resort: this is a device label for the session list, not a secret.
                return 'oidc-' + Date.now().toString(16) + '-' + Math.random().toString(16).slice(2, 10);
            }

            const deviceId = localStorage.getItem('_deviceId2') || newDeviceId();
            localStorage.setItem('_deviceId2', deviceId);

            fetch('/sso/OIDC/Auth/' + encodeURIComponent(providerId), {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    Token: token,
                    DeviceId: deviceId,
                    DeviceName: navigator.userAgent.substring(0, 50),
                    App: 'Jellyfin Web',
                    AppVersion: {{encodedVersion}}
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
