using System;
using System.Linq;
using System.Threading.Tasks;
using Jellyfin.Plugin.OIDC;
using Jellyfin.Plugin.OIDC.Configuration;
using Jellyfin.Plugin.OIDC.Saml;
using Jellyfin.Plugin.OIDC.Services;
using MediaBrowser.Controller.Session;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.OIDC.Api;

[ApiController]
[Route("sso/SAML")]
public class SamlController : ControllerBase
{
    /// <summary>
    /// Cap on the base64 SAMLResponse form field. 256 KB easily accommodates legitimate IdP
    /// responses (typically &lt;20 KB) and well-padded enterprise responses, while refusing
    /// the multi-MB blobs an attacker would use to force expensive XML parsing or signature
    /// verification work.
    /// </summary>
    private const int MaxSamlResponseBytes = 256 * 1024;

    /// <summary>Cap on RelayState — only a few KB are ever legitimate.</summary>
    private const int MaxRelayStateBytes = 8 * 1024;

    private const string TransientNameIdFormat = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient";

    private readonly UserSyncService _userSyncService;
    private readonly StateManager _stateManager;
    private readonly ISessionManager _sessionManager;
    private readonly RbacService _rbacService;
    private readonly IPluginConfigProvider _configProvider;
    private readonly SamlAssertionReplayCache _replayCache;
    private readonly ILogger<SamlController> _logger;

    public SamlController(
        UserSyncService userSyncService,
        StateManager stateManager,
        ISessionManager sessionManager,
        RbacService rbacService,
        IPluginConfigProvider configProvider,
        SamlAssertionReplayCache replayCache,
        ILogger<SamlController> logger)
    {
        _userSyncService = userSyncService;
        _stateManager = stateManager;
        _sessionManager = sessionManager;
        _rbacService = rbacService;
        _configProvider = configProvider;
        _replayCache = replayCache;
        _logger = logger;
    }

    /// <summary>Initiates SP-initiated SAML SSO (HTTP-Redirect binding).</summary>
    [HttpGet("Start/{providerId}")]
    public ActionResult Start(string providerId)
    {
        var provider = GetProvider(providerId);
        if (provider == null)
        {
            return NotFound($"SAML provider '{providerId}' not found or disabled");
        }

        var requestId = "_" + Guid.NewGuid().ToString("N");
        var acsUrl = BuildAcsUrl(providerId);

        // Store requestId in state so ACS can validate InResponseTo + relay state (CSRF protection).
        // The relayState key returned to the IdP is opaque; on POST-back we look up the stashed
        // request ID and compare it against the response's InResponseTo to defeat replay/CSRF.
        var stateKey = _stateManager.StoreState(new OidcState
        {
            ProviderId = "saml:" + providerId,
            Nonce = requestId,
            CodeVerifier = string.Empty,
            RedirectUri = acsUrl,
            // Login-CSRF binding. It cannot be checked at the ACS, a cross-site POST that a
            // SameSite=Lax cookie does not ride, so it travels with the session to /Auth — a
            // same-origin fetch from the callback page — and is verified there.
            CsrfBindingHash = BrowserBindingCookie.Issue(Request, Response, BindingKey(provider))
        }, StateManager.ClientKeyFor(ClientAddress()));

        if (stateKey is null)
        {
            return StatusCode(503, "Too many sign-ins in progress. Try again in a few minutes.");
        }

        var redirectUrl = SamlRequest.BuildRedirectUrl(provider, acsUrl, requestId, relayState: stateKey);
        return Redirect(redirectUrl);
    }

    /// <summary>Assertion Consumer Service endpoint (HTTP-POST binding).</summary>
    [HttpPost("ACS/{providerId}")]
    [Consumes("application/x-www-form-urlencoded")]
    public async Task<ActionResult> AssertionConsumerService(
        string providerId,
        [FromForm(Name = "SAMLResponse")] string samlResponse,
        [FromForm(Name = "RelayState")] string? relayState)
    {
        var provider = GetProvider(providerId);
        if (provider == null)
        {
            return NotFound($"SAML provider '{providerId}' not found or disabled");
        }

        if (string.IsNullOrEmpty(samlResponse))
        {
            return BadRequest("Missing SAMLResponse");
        }

        // Size caps — cheap rejection before we burn cycles on base64 decode + XML parse +
        // signature verification. The IdP-side limit is the raw base64 length; the XML parser
        // applies its own MaxCharactersInDocument cap on the decoded payload.
        if (samlResponse.Length > MaxSamlResponseBytes)
        {
            _logger.LogWarning(
                "SAML: rejected oversized SAMLResponse ({Length} > {Cap} bytes, provider={Provider})",
                samlResponse.Length, MaxSamlResponseBytes, providerId);
            return BadRequest("SAMLResponse exceeds maximum allowed size.");
        }

        if (relayState != null && relayState.Length > MaxRelayStateBytes)
        {
            _logger.LogWarning(
                "SAML: rejected oversized RelayState ({Length} > {Cap} bytes, provider={Provider})",
                relayState.Length, MaxRelayStateBytes, providerId);
            return BadRequest("RelayState exceeds maximum allowed size.");
        }

        // RelayState is the only CSRF binding to a real SP-initiated request. Treat absence as a
        // policy decision: when AllowIdpInitiated=false, no RelayState means no in-flight request,
        // which means we must reject. When AllowIdpInitiated=true, missing RelayState is fine —
        // the ExpectedInResponseTo stays null and the response's InResponseTo (if any) must also
        // be absent.
        string? expectedInResponseTo = null;
        byte[]? csrfBindingHash = null;
        if (!string.IsNullOrEmpty(relayState))
        {
            var samlState = _stateManager.ConsumeState(relayState);
            if (samlState == null
                || !string.Equals(samlState.ProviderId, "saml:" + provider.Id, StringComparison.OrdinalIgnoreCase))
            {
                return BadRequest("Invalid or expired relay state. Please try again.");
            }
            expectedInResponseTo = samlState.Nonce;
            csrfBindingHash = samlState.CsrfBindingHash;
        }
        else if (!provider.AllowIdpInitiated)
        {
            _logger.LogWarning(
                "SAML: rejecting response without RelayState (IdP-initiated SSO disabled for provider={Provider})",
                providerId);
            return BadRequest("Missing RelayState; IdP-initiated SSO is disabled for this provider.");
        }

        var context = new SamlResponseValidationContext
        {
            AcsUrl = BuildAcsUrl(providerId),
            ExpectedInResponseTo = expectedInResponseTo
        };

        Saml.ParsedSamlAssertion assertion;
        try
        {
            assertion = SamlResponse.Parse(samlResponse, provider, context, _logger);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "SAML: assertion validation failed for provider {Provider}", providerId);
            await _rbacService.LogActivityAsync(
                "SAML login failed: assertion validation error",
                "SamlLoginFailure",
                Guid.Empty,
                ex.Message,
                Microsoft.Extensions.Logging.LogLevel.Warning).ConfigureAwait(false);
            return BadRequest("SAML assertion validation failed");
        }

        // Replay protection — refuse to consume the same AssertionID twice within its validity
        // window. Without this, an attacker who captures a valid POST can re-submit it until
        // NotOnOrAfter elapses.
        if (!_replayCache.TryRegister(assertion.Issuer, assertion.AssertionId, assertion.NotOnOrAfter))
        {
            await _rbacService.LogActivityAsync(
                "SAML login failed: replayed assertion",
                "SamlLoginFailure",
                Guid.Empty,
                $"AssertionID={assertion.AssertionId}",
                Microsoft.Extensions.Logging.LogLevel.Warning).ConfigureAwait(false);
            return BadRequest("SAML assertion has already been consumed (replay).");
        }

        // NameID is the identity key — accounts are linked on "saml:{provider}:{NameID}". Without
        // one, every such assertion would share the key "saml:{provider}:" and log into whichever
        // account claimed it first. It must also be persistent: a transient NameID changes on every
        // login and can never resolve to the same account twice.
        if (string.IsNullOrWhiteSpace(assertion.NameId))
        {
            _logger.LogWarning("SAML: rejecting assertion with no NameID (provider={Provider})", providerId);
            return BadRequest("SAML assertion has no NameID; configure the IdP to send a persistent NameID.");
        }

        if (string.Equals(assertion.NameIdFormat, TransientNameIdFormat, StringComparison.Ordinal))
        {
            _logger.LogWarning("SAML: rejecting transient NameID (provider={Provider})", providerId);
            return BadRequest("SAML assertion uses a transient NameID; configure the IdP to send a persistent NameID.");
        }

        // Resolve username: named attribute takes precedence over NameID
        var username = assertion.NameId;
        if (!string.Equals(provider.UsernameClaim, "NameID", StringComparison.OrdinalIgnoreCase) &&
            assertion.Attributes.TryGetValue(provider.UsernameClaim, out var attrValues) &&
            attrValues.Length > 0)
        {
            username = attrValues[0];
        }

        if (string.IsNullOrEmpty(username))
        {
            return BadRequest("Could not determine username from SAML assertion");
        }

        var verbose = _configProvider.GetConfiguration().VerboseClaimLogging;
        _logger.LogInformation(
            "SAML auth successful: user={Username}, roles={Roles}, provider={Provider}",
            username, LogRedaction.RedactRoles(assertion.Roles, verbose), providerId);

        var sessionToken = _stateManager.StoreAuthorizedSession(new AuthorizedSession
        {
            ProviderId = "saml:" + providerId,
            Username = username,
            Sub = assertion.NameId,
            Roles = assertion.Roles,
            Entitlements = Array.Empty<string>(),
            CsrfBindingHash = csrfBindingHash
        });

        SsoPages.SetSecurityHeaders(Response);
        return Content(
            SsoPages.BuildCompletionHtml(
                sessionToken,
                SsoPages.ServerBase(Request) + "/sso/SAML/Auth/" + providerId,
                SsoPages.ServerBase(Request) + "/",
                "Completing SAML authentication..."),
            "text/html");
    }

    /// <summary>Completes SAML authentication by exchanging the session token for a Jellyfin auth token.</summary>
    [HttpPost("Auth/{providerId}")]
    public async Task<ActionResult> Authenticate(string providerId, [FromBody] AuthenticateRequest request)
    {
        var session = _stateManager.ConsumeAuthorizedSession(request.Token);
        if (session == null)
        {
            return Unauthorized("Invalid or expired session token");
        }

        var expectedProviderId = "saml:" + providerId;
        if (!string.Equals(session.ProviderId, expectedProviderId, StringComparison.OrdinalIgnoreCase))
        {
            return BadRequest("Provider mismatch");
        }

        // SP-initiated flows must finish in the browser that started them. Without this, an
        // attacker could complete their own SAML login and have the victim's browser POST the
        // response, signing the victim into the attacker's account (login-CSRF). IdP-initiated
        // flows carry no binding: they have no /Start, which is why AllowIdpInitiated is opt-in.
        var provider = GetProvider(providerId);
        if (provider is null)
        {
            return NotFound($"SAML provider '{providerId}' not found or disabled");
        }

        if (session.CsrfBindingHash is not null
            && !BrowserBindingCookie.VerifyAndClear(Request, Response, BindingKey(provider), session.CsrfBindingHash))
        {
            _logger.LogWarning("SAML login rejected: browser binding cookie missing or invalid (provider={Provider})", providerId);
            await _rbacService.LogActivityAsync(
                "SAML login rejected: browser binding cookie missing or invalid",
                "SamlLoginFailure", Guid.Empty, $"provider={providerId}",
                Microsoft.Extensions.Logging.LogLevel.Warning).ConfigureAwait(false);
            return BadRequest("Authentication session not initiated by this browser. Please start sign-in again.");
        }

        try
        {
            var userId = await _userSyncService.SyncUserAsync(
                session.Username,
                session.DisplayName,
                session.Sub,
                session.Roles,
                session.Entitlements,
                session.ProviderId).ConfigureAwait(false);

            // Mint a real Jellyfin session so the callback page can store working credentials.
            // Mirrors OidcController.Authenticate's AuthenticateDirect wiring exactly.
            var authRequest = new AuthenticationRequest
            {
                App = request.App ?? "Jellyfin Web",
                AppVersion = request.AppVersion ?? "0.0.0",
                DeviceId = request.DeviceId ?? Guid.NewGuid().ToString(),
                DeviceName = request.DeviceName ?? "SAML",
                UserId = userId
            };

            var authResult = await _sessionManager.AuthenticateDirect(authRequest).ConfigureAwait(false);

            await _rbacService.LogActivityAsync(
                $"SAML login: {session.Username}",
                "SamlLoginSuccess",
                userId,
                $"Provider: {providerId}",
                Microsoft.Extensions.Logging.LogLevel.Information).ConfigureAwait(false);

            return Ok(authResult);
        }
        catch (OidcUsernameCollisionException ex)
        {
            _logger.LogWarning(
                "SAML login rejected: name collision for '{Username}' (provider={Provider})",
                ex.Username, providerId);
            return Conflict(new
            {
                error = "name_collision",
                message = ex.Message
            });
        }
        catch (OidcUserDisabledException ex)
        {
            _logger.LogWarning(
                "SAML login rejected: account '{Username}' is disabled (provider={Provider})",
                ex.Username, providerId);
            await _rbacService.LogActivityAsync(
                $"SAML login rejected: account '{ex.Username}' is disabled",
                "SamlLoginDisabledUser",
                Guid.Empty,
                $"Provider: {providerId}",
                Microsoft.Extensions.Logging.LogLevel.Warning).ConfigureAwait(false);
            return StatusCode(403, new { error = "account_disabled", message = "This account is disabled." });
        }
        catch (InvalidOperationException ex)
        {
            _logger.LogWarning("SAML user sync failed: {Message}", ex.Message);
            return Forbid();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "SAML authentication failed for user {Username}", session.Username);
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
        var basePath = SsoPages.ServerBase(Request);
        var providers = config.SamlProviders
            .Where(p => p.Enabled)
            .Select(p => new
            {
                p.Id,
                p.DisplayName,
                p.ButtonColor,
                StartUrl = $"{scheme}://{host}{basePath}/sso/SAML/Start/{p.Id}"
            });

        return Ok(providers);
    }

    /// <summary>The caller's address, honouring forwarded headers only from configured trusted proxies.</summary>
    private System.Net.IPAddress? ClientAddress()
    {
        var cfg = _configProvider.GetConfiguration();
        return ClientIpResolver.Resolve(
            HttpContext, cfg.TrustForwardedHeaders, ClientIpResolver.ParseCidrs(cfg.TrustedProxyCidrs, _logger), _logger);
    }

    private SamlProviderConfig? GetProvider(string providerId)
    {
        return _configProvider.GetConfiguration().SamlProviders
            .Find(p => string.Equals(p.Id, providerId, StringComparison.OrdinalIgnoreCase) && p.Enabled);
    }

    // The ACS URL is reverse-proxy aware so the AuthnRequest (in /Start) and the
    // Destination/Recipient validation (in /ACS) both compute the externally-visible URL the
    // IdP actually sees. Both call sites go through here, so they stay in lockstep.
    private string BuildAcsUrl(string providerId)
    {
        var cfg = _configProvider.GetConfiguration();
        var trustedProxies = ClientIpResolver.ParseCidrs(cfg.TrustedProxyCidrs, _logger);
        var scheme = ClientIpResolver.ResolveScheme(HttpContext, cfg.TrustForwardedHeaders, trustedProxies);
        var host = ClientIpResolver.ResolveHost(HttpContext, cfg.TrustForwardedHeaders, trustedProxies);
        return $"{scheme}://{host}{SsoPages.ServerBase(Request)}/sso/SAML/ACS/{providerId}";
    }

    /// <summary>
    /// Cookie key for the SAML browser binding. Uses the configured id (validated to
    /// [A-Za-z0-9_-]) rather than the URL segment, whose casing may differ between legs, and a
    /// "saml." prefix: "." cannot occur in a provider id, so no OIDC provider id (which the OIDC
    /// flow uses as its key) can ever produce the same cookie name.
    /// </summary>
    private static string BindingKey(SamlProviderConfig provider) => "saml." + provider.Id;
}
