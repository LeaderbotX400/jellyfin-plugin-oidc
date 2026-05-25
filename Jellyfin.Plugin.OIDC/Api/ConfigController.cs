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

namespace Jellyfin.Plugin.OIDC.Api;

[ApiController]
[Route("sso/OIDC/Config")]
[Authorize(Policy = Policies.RequiresElevation)]
public class ConfigController : ControllerBase
{
    private readonly RbacService _rbacService;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly IPluginConfigProvider _configProvider;

    public ConfigController(
        RbacService rbacService,
        IHttpClientFactory httpClientFactory,
        IPluginConfigProvider configProvider)
    {
        _rbacService = rbacService;
        _httpClientFactory = httpClientFactory;
        _configProvider = configProvider;
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
        _configProvider.SaveConfiguration(incoming);
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

    [HttpPost("TestProvider")]
    public async Task<ActionResult> TestProvider([FromBody] ProviderTestRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.Authority))
        {
            return Ok(new { Success = false, Error = "Authority URL is required" });
        }

        var httpClient = _httpClientFactory.CreateClient("OidcPlugin");
        var disco = await httpClient.GetDiscoveryDocumentAsync(new DiscoveryDocumentRequest
        {
            Address = request.Authority,
            Policy = new DiscoveryPolicy
            {
                ValidateIssuerName = true,
                ValidateEndpoints = false
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
}

public class ProviderTestRequest
{
    public string Authority { get; set; } = string.Empty;
    public string? Scopes { get; set; }
}
