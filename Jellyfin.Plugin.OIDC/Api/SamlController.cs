using System;
using System.Linq;
using System.Text.Json;
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
    private readonly UserSyncService _userSyncService;
    private readonly StateManager _stateManager;
    private readonly RbacService _rbacService;
    private readonly IPluginConfigProvider _configProvider;
    private readonly ILogger<SamlController> _logger;

    public SamlController(
        UserSyncService userSyncService,
        StateManager stateManager,
        RbacService rbacService,
        IPluginConfigProvider configProvider,
        ILogger<SamlController> logger)
    {
        _userSyncService = userSyncService;
        _stateManager = stateManager;
        _rbacService = rbacService;
        _configProvider = configProvider;
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

        // Store requestId in state so ACS can validate relay state (CSRF protection)
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

        // Validate relay state (anti-CSRF)
        if (!string.IsNullOrEmpty(relayState))
        {
            var samlState = _stateManager.ConsumeState(relayState);
            if (samlState == null)
            {
                return BadRequest("Invalid or expired relay state. Please try again.");
            }
        }

        Saml.ParsedSamlAssertion assertion;
        try
        {
            assertion = SamlResponse.Parse(samlResponse, provider, _logger);
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

        SetCallbackSecurityHeaders();
        return Content(BuildCallbackHtml(sessionToken, providerId), "text/html");
    }

    private void SetCallbackSecurityHeaders()
    {
        // See OidcController.SetCallbackSecurityHeaders for the full rationale on 'unsafe-inline'.
        Response.Headers["Content-Security-Policy"] =
            "default-src 'none'; script-src 'unsafe-inline'; connect-src 'self'; style-src 'unsafe-inline'";
        Response.Headers["X-Content-Type-Options"] = "nosniff";
        Response.Headers["Referrer-Policy"] = "no-referrer";
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
        // JSON-encode every value crossing into <script> — see OidcController.BuildCallbackHtml.
        var encodedToken = JsonSerializer.Serialize(sessionToken);
        var encodedProvider = JsonSerializer.Serialize(providerId);
        return $$"""
        <!DOCTYPE html>
        <html>
        <head><title>Authenticating...</title></head>
        <body>
        <h3>Completing SAML authentication...</h3>
        <p id="status">Please wait...</p>
        <script>
        (function() {
            const token = {{encodedToken}};
            const providerId = {{encodedProvider}};
            const deviceId = localStorage.getItem('_deviceId2') || crypto.randomUUID();
            localStorage.setItem('_deviceId2', deviceId);

            fetch('/sso/SAML/Auth/' + encodeURIComponent(providerId), {
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
