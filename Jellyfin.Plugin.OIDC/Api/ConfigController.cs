using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using IdentityModel.Client;
using Jellyfin.Plugin.OIDC.Configuration;
using Jellyfin.Plugin.OIDC.Services;
using MediaBrowser.Common.Api;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.OIDC.Api;

[ApiController]
[Route("sso/OIDC/Config")]
[Authorize(Policy = Policies.RequiresElevation)]
public class ConfigController : ControllerBase
{
    private readonly RbacService _rbacService;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly IPluginConfigProvider _configProvider;
    private readonly OidcUserStore _userStore;
    private readonly ILogger<ConfigController> _logger;

    public ConfigController(
        RbacService rbacService,
        IHttpClientFactory httpClientFactory,
        IPluginConfigProvider configProvider,
        OidcUserStore userStore,
        ILogger<ConfigController> logger)
    {
        _rbacService = rbacService;
        _httpClientFactory = httpClientFactory;
        _configProvider = configProvider;
        _userStore = userStore;
        _logger = logger;
    }

    /// <summary>
    /// Returns the plugin configuration with all secret fields replaced by
    /// <see cref="ConfigMasking.Sentinel"/>. The admin UI must use this
    /// endpoint instead of the standard /Plugins/{id}/Configuration route,
    /// which exposes secrets in plaintext.
    /// </summary>
    [HttpGet]
    public ActionResult<PluginConfiguration> GetConfig()
    {
        var config = _configProvider.GetConfiguration();
        return Ok(ConfigMasking.Mask(config));
    }

    /// <summary>
    /// Saves the plugin configuration. For each secret field, a value of
    /// <see cref="ConfigMasking.Sentinel"/> means "keep the existing secret";
    /// an empty string clears the secret; any other value overwrites it.
    /// </summary>
    [HttpPost]
    public ActionResult SaveConfig([FromBody] PluginConfiguration incoming)
    {
        var persisted = _configProvider.GetConfiguration();
        ConfigMasking.MergeSecrets(incoming, persisted);
        foreach (var p in incoming.Providers)
        {
            p.Authority = SecurityValidation.NormalizeAuthority(p.Authority);
        }

        try
        {
            _configProvider.SaveConfiguration(incoming);
        }
        catch (Exception ex) when (ex is InvalidOperationException or ArgumentException)
        {
            // OidcPlugin.UpdateConfiguration validates before persisting and throws with a
            // message written for the admin ("PictureAllowedHosts entry 'x' is not a bare
            // hostname", "signing algorithm 'foo' is unknown", …). Letting it escape produced
            // a bare 500 "Error processing request", so the admin saw that the save failed but
            // never why. Surface it as a 400 with the reason instead.
            _logger.LogWarning("Rejected plugin configuration save: {Message}", ex.Message);
            return BadRequest(new { error = "invalid_configuration", message = ex.Message });
        }

        return NoContent();
    }

    [HttpGet("Libraries")]
    public ActionResult<Dictionary<string, string>> GetLibraries()
    {
        return Ok(_rbacService.GetAvailableLibraries());
    }

    [HttpGet("PreviewPermissions")]
    public ActionResult PreviewPermissions(
        [FromQuery] string? providerId,
        [FromQuery] string? roles,
        [FromQuery] string? entitlements)
    {
        var roleArray = roles?.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                        ?? Array.Empty<string>();
        var entArray = entitlements?.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                       ?? Array.Empty<string>();

        var preview = _rbacService.PreviewPermissions(roleArray, entArray, providerId ?? string.Empty);
        return Ok(preview);
    }

    [HttpGet("Status")]
    public ActionResult GetStatus()
    {
        var config = _configProvider.GetConfiguration();
        return Ok(new
        {
            PluginVersion = OidcPlugin.Instance?.Version?.ToString() ?? "unknown",
            ProviderCount = config.Providers.Count,
            RoleMappingCount = config.RoleMappings.Count,
            EnabledProviders = config.Providers.Where(p => p.Enabled).Select(p => p.DisplayName).ToList()
        });
    }

    /// Validates a proposed configuration and returns any warnings. Does not save.
    /// Called automatically by the UI on every save to surface issues without blocking.
    /// </summary>
    [HttpPost("ValidateConfig")]
    public ActionResult ValidateConfig([FromBody] PluginConfiguration proposedConfig)
    {
        var warnings = new List<string>();

        if (proposedConfig?.Providers != null && proposedConfig.RoleMappings != null)
        {
            // Collect role names of all grant mappings that confer admin.
            var adminRoleNames = proposedConfig.RoleMappings
                .Where(m => !m.IsExplicitDeny && m.IsAdmin)
                .Select(m => m.RoleName)
                .ToHashSet(StringComparer.OrdinalIgnoreCase);

            foreach (var provider in proposedConfig.Providers)
            {
                foreach (var transform in provider.RoleTransforms ?? new List<ClaimTransform>())
                {
                    if (!string.IsNullOrWhiteSpace(transform.ToValue) &&
                        adminRoleNames.Contains(transform.ToValue))
                    {
                        var msg = $"Provider '{provider.ProviderId}': transform from='{transform.FromValue}' " +
                                  $"to='{transform.ToValue}' maps into an admin role mapping. " +
                                  $"Any IdP user with the '{transform.FromValue}' role will become a Jellyfin administrator.";
                        warnings.Add(msg);
                        _logger.LogWarning(
                            "Config warning: provider={Provider} transform from={From} to={To} targets admin role",
                            provider.ProviderId, transform.FromValue, transform.ToValue);
                    }
                }
            }
        }

        // SAML EntityId / IdpEntityId warnings — warn only, never block save.
        foreach (var saml in proposedConfig?.SamlProviders ?? new List<SamlProviderConfig>())
        {
            if (!saml.Enabled) continue;

            if (string.IsNullOrWhiteSpace(saml.EntityId))
            {
                warnings.Add(
                    $"SAML provider '{saml.Id}': SP EntityID is empty — audience validation will be SKIPPED for this provider.");
                _logger.LogWarning(
                    "Config warning: SAML provider={Provider} has empty EntityId — audience validation skipped",
                    saml.Id);
            }

            if (string.IsNullOrWhiteSpace(saml.IdpEntityId))
            {
                warnings.Add(
                    $"SAML provider '{saml.Id}': IdP EntityID is empty — issuer validation will be SKIPPED for this provider.");
                _logger.LogWarning(
                    "Config warning: SAML provider={Provider} has empty IdpEntityId — issuer validation skipped",
                    saml.Id);
            }
        }

        return Ok(new { Warnings = warnings });
    }

    /// <summary>
    /// Validates a candidate plugin configuration before the admin commits it. The UI calls this
    /// from its Save handler; the real save still goes through Jellyfin's standard plugin config
    /// API, where <see cref="OidcPlugin.UpdateConfiguration"/> enforces the same rules as a
    /// last line of defence. The primary thing being enforced here is the provider id charset —
    /// because provider ids are interpolated into URLs and (defence-in-depth) into JS string
    /// literals in the callback HTML.
    /// </summary>
    [HttpPost("Validate")]
    public ActionResult Validate([FromBody] PluginConfiguration config)
    {
        var errors = ValidateConfiguration(config);
        if (errors.Count > 0)
        {
            return BadRequest(new { Errors = errors });
        }

        return Ok(new { Valid = true });
    }

    internal static List<string> ValidateConfiguration(PluginConfiguration? config)
    {
        var errors = new List<string>();
        if (config == null)
        {
            errors.Add("Configuration body is required");
            return errors;
        }

        foreach (var p in config.Providers ?? new List<OidcProviderConfig>())
        {
            if (!ProviderIdValidation.IsValid(p.ProviderId))
            {
                errors.Add(
                    $"OIDC provider '{p.DisplayName}' has invalid ProviderId '{p.ProviderId}'. "
                    + $"Must be {ProviderIdValidation.CharsetDescription}.");
            }
        }

        foreach (var p in config.SamlProviders ?? new List<SamlProviderConfig>())
        {
            if (!ProviderIdValidation.IsValid(p.Id))
            {
                errors.Add(
                    $"SAML provider '{p.DisplayName}' has invalid Id '{p.Id}'. "
                    + $"Must be {ProviderIdValidation.CharsetDescription}.");
            }
        }

        return errors;
    }

    [HttpPost("TestProvider")]
    public async Task<ActionResult> TestProvider([FromBody] ProviderTestRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.Authority))
        {
            return Ok(new { Success = false, Error = "Authority URL is required" });
        }

        try
        {
            request.Authority = SecurityValidation.NormalizeAuthority(request.Authority);
            SecurityValidation.EnsureSecureUrl(request.Authority, request.AllowInsecureAuthority, "Authority");
        }
        catch (System.InvalidOperationException ex)
        {
            return Ok(new { Success = false, Error = ex.Message });
        }

        var httpClient = _httpClientFactory.CreateClient("OidcPlugin");
        var disco = await httpClient.GetDiscoveryDocumentAsync(new DiscoveryDocumentRequest
        {
            Address = request.Authority,
            Policy = new DiscoveryPolicy
            {
                ValidateIssuerName = true,
                ValidateEndpoints = false // host check below — see OidcDiscoveryCache for rationale
            }
        }).ConfigureAwait(false);

        if (disco.IsError)
        {
            return Ok(new
            {
                Success = false,
                Error = disco.Error,
                ErrorType = disco.ErrorType.ToString()
            });
        }

        try
        {
            SecurityValidation.EnsureSameHost(request.Authority, disco.TokenEndpoint, "token_endpoint");
            SecurityValidation.EnsureSameHost(request.Authority, disco.AuthorizeEndpoint, "authorization_endpoint");
            SecurityValidation.EnsureSameHost(request.Authority, disco.JwksUri, "jwks_uri");
        }
        catch (System.InvalidOperationException ex)
        {
            return Ok(new { Success = false, Error = ex.Message });
        }

        var requestedScopes = (request.Scopes ?? string.Empty)
            .Split(' ', System.StringSplitOptions.RemoveEmptyEntries);
        var supportedScopes = disco.ScopesSupported?.ToList() ?? new List<string>();
        var unsupportedScopes = supportedScopes.Count == 0
            ? new List<string>()
            : requestedScopes.Where(s => !supportedScopes.Contains(s)).ToList();

        return Ok(new
        {
            Success = true,
            Issuer = disco.Issuer,
            AuthorizationEndpoint = disco.AuthorizeEndpoint,
            TokenEndpoint = disco.TokenEndpoint,
            UserInfoEndpoint = disco.UserInfoEndpoint,
            JwksUri = disco.JwksUri,
            ScopesSupported = supportedScopes,
            UnsupportedRequestedScopes = unsupportedScopes
        });
    }

    /// <summary>
    /// Resets the OIDC user store after a corruption event.
    /// This clears all persisted user-store data and re-enables logins.
    /// Only call this after investigating the quarantined .corrupt-* file.
    /// Requires administrator privileges.
    /// </summary>
    [HttpPost("/sso/OIDC/Admin/UserStore/Reset")]
    public ActionResult ResetUserStore()
    {
        _logger.LogWarning("OidcUserStore admin reset requested by {User}", User.Identity?.Name ?? "unknown");
        _userStore.AdminReset();
        return Ok(new
        {
            Message = "OIDC user store has been reset. All previous sub→user links are cleared. " +
                      "Users will be re-linked on next login. Review the quarantined .corrupt-* file before proceeding."
        });
    }
}

public class ProviderTestRequest
{
    public string Authority { get; set; } = string.Empty;
    public string? Scopes { get; set; }

    /// <summary>Mirrors <c>OidcProviderConfig.AllowInsecureAuthority</c> so the admin UI can test localhost dev IdPs.</summary>
    public bool AllowInsecureAuthority { get; set; }
}
