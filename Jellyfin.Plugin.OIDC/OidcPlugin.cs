using System;
using System.Collections.Generic;
using Jellyfin.Plugin.OIDC.Configuration;
using Jellyfin.Plugin.OIDC.Services;
using MediaBrowser.Common.Configuration;
using MediaBrowser.Common.Plugins;
using MediaBrowser.Model.Plugins;
using MediaBrowser.Model.Serialization;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.OIDC;

public class OidcPlugin : BasePlugin<PluginConfiguration>, IHasWebPages
{
    private readonly ILogger<OidcPlugin> _log;

    public OidcPlugin(IApplicationPaths applicationPaths, IXmlSerializer xmlSerializer)
        : base(applicationPaths, xmlSerializer)
    {
        Instance = this;
        _log = LoggerFactory.Create(b => b.AddConsole()).CreateLogger<OidcPlugin>();

        // Run migration on initial load.
        RunMigration(Configuration);

        // Re-run after every config save (e.g. from the admin UI).
        ConfigurationChanged += (_, cfg) => RunMigration((PluginConfiguration)cfg);
    }

    /// <summary>
    /// Refuses to persist provider configs whose endpoints aren't HTTPS (unless the provider explicitly
    /// opts in to <c>AllowInsecureAuthority</c> + uses a loopback host). Catches misconfiguration at
    /// save time rather than at first login attempt.
    /// </summary>
    public override void UpdateConfiguration(BasePluginConfiguration configuration)
    {
        if (configuration is PluginConfiguration cfg)
        {
            foreach (var p in cfg.Providers)
            {
                if (!p.Enabled) continue;
                ProviderConfigValidator.ValidateOrThrow(p);
            }
        }

        base.UpdateConfiguration(configuration);
    }

    public static OidcPlugin? Instance { get; private set; }

    public override string Name => "OIDC RBAC";

    public override Guid Id => Guid.Parse("d4e5f6a7-b8c9-0d1e-2f3a-4b5c6d7e8f90");

    public override string Description => "Advanced OIDC authentication with role-based library access control";

    public IEnumerable<PluginPageInfo> GetPages()
    {
        var ns = GetType().Namespace;
        return new[]
        {
            new PluginPageInfo
            {
                Name = Name,
                EmbeddedResourcePath = $"{ns}.Configuration.configPage.html"
            },
            new PluginPageInfo
            {
                Name = "oidcrbacjs",
                EmbeddedResourcePath = $"{ns}.Configuration.oidcrbac.js"
            }
        };
    }

    private void RunMigration(PluginConfiguration cfg)
    {
        var migrated = ConfigMigration.MigrateDenyMappings(cfg.RoleMappings);
        foreach (var role in migrated)
        {
            _log.LogWarning(
                "OIDC RBAC migration (v0.1.3): deny mapping '{Role}' had legacy default-true values for " +
                "EnableMediaPlayback / EnableRemoteAccess / EnableTranscoding. " +
                "These have been cleared to null (no-op for deny). " +
                "Please review your deny mappings in the admin UI and explicitly enable the " +
                "permissions you want this deny rule to strip.",
                role);
        }
    }
}
