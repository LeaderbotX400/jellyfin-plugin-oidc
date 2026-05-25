using System;
using System.Linq;
using System.Threading.Tasks;
using Jellyfin.Plugin.OIDC.Configuration;
using Jellyfin.Plugin.OIDC.Saml;
using Jellyfin.Plugin.OIDC.Services;
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

    private readonly UserSyncService _userSyncService;
    private readonly StateManager _stateManager;
    private readonly RbacService _rbacService;
    private readonly IPluginConfigProvider _configProvider;
    private readonly SamlAssertionReplayCache _replayCache;
    private readonly ILogger<SamlController> _logger;

    public SamlController(
        UserSyncService userSyncService,
        StateManager stateManager,
        RbacService rbacService,
        IPluginConfigProvider configProvider,
        SamlAssertionReplayCache replayCache,
        ILogger<SamlController> logger)
    {
        _userSyncService = userSyncService;
        _stateManager = stateManager;
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
            RedirectUri = acsUrl
        });

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
        if (!string.IsNullOrEmpty(relayState))
        {
            var samlState = _stateManager.ConsumeState(relayState);
            if (samlState == null)
            {
                return BadRequest("Invalid or expired relay state. Please try again.");
            }
            expectedInResponseTo = samlState.Nonce;
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

        _logger.LogInformation(
            "SAML auth successful: user={Username}, roles=[{Roles}], provider={Provider}",
            username, string.Join(", ", assertion.Roles), providerId);

        var sessionToken = _stateManager.StoreAuthorizedSession(new AuthorizedSession
        {
            ProviderId = "saml:" + providerId,
            Username = username,
            Sub = assertion.NameId,
            Roles = assertion.Roles,
            Entitlements = Array.Empty<string>()
        });

        return Content(BuildCallbackHtml(sessionToken, providerId), "text/html");
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

        try
        {
            var userId = await _userSyncService.SyncUserAsync(
                session.Username,
                session.DisplayName,
                session.Sub,
                session.Roles,
                session.Entitlements,
                session.ProviderId).ConfigureAwait(false);

            await _rbacService.LogActivityAsync(
                $"SAML login: {session.Username}",
                "SamlLoginSuccess",
                userId,
                $"Provider: {providerId}",
                Microsoft.Extensions.Logging.LogLevel.Information).ConfigureAwait(false);

            // Return minimal auth result for the JS to pick up
            return Ok(new { UserId = userId });
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
        var providers = config.SamlProviders
            .Where(p => p.Enabled)
            .Select(p => new
            {
                p.Id,
                p.DisplayName,
                p.ButtonColor,
                StartUrl = $"{Request.Scheme}://{Request.Host}/sso/SAML/Start/{p.Id}"
            });

        return Ok(providers);
    }

    private SamlProviderConfig? GetProvider(string providerId)
    {
        return _configProvider.GetConfiguration().SamlProviders
            .Find(p => string.Equals(p.Id, providerId, StringComparison.OrdinalIgnoreCase) && p.Enabled);
    }

    private string BuildAcsUrl(string providerId) =>
        $"{Request.Scheme}://{Request.Host}/sso/SAML/ACS/{providerId}";

    private static string BuildCallbackHtml(string sessionToken, string providerId)
    {
        return $$"""
        <!DOCTYPE html>
        <html>
        <head><title>Authenticating...</title></head>
        <body>
        <h3>Completing SAML authentication...</h3>
        <p id="status">Please wait...</p>
        <script>
        (function() {
            const token = '{{sessionToken}}';
            const providerId = '{{providerId}}';
            const deviceId = localStorage.getItem('_deviceId2') || crypto.randomUUID();
            localStorage.setItem('_deviceId2', deviceId);

            fetch('/sso/SAML/Auth/' + providerId, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ Token: token })
            })
            .then(function(r) { if (!r.ok) throw new Error('Auth failed: ' + r.status); return r.json(); })
            .then(function(result) {
                // SAML auth returns userId; use Jellyfin's standard login to get a full session
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
