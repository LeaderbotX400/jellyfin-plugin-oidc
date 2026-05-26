using System;
using System.Collections.Generic;
using Jellyfin.Plugin.OIDC.Api;
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

        // Run the one-time legacy-deny migration on initial load only. The UI does not round-trip
        // the plugin-level sentinel, but System.Text.Json deserialization preserves it from the
        // persisted XML on every load, so the second startup sees MigratedDenyDefaultsV013=true
        // and skips. We intentionally do NOT re-run on ConfigurationChanged — doing so wiped
        // deliberately-set deny flags on every save (the UI cannot send a per-mapping sentinel).
        RunMigration(Configuration);
    }

    public static OidcPlugin? Instance { get; private set; }

    public override string Name => "OIDC RBAC";

    public override Guid Id => Guid.Parse("d4e5f6a7-b8c9-0d1e-2f3a-4b5c6d7e8f90");

    public override string Description => "Advanced OIDC authentication with role-based library access control";

    /// <summary>
    /// Defence-in-depth on every config save:
    ///   1. Reject configs with invalid provider ids (charset / length) — the web UI validates via
    ///      /sso/OIDC/Config/Validate, but a determined caller hitting the standard plugin config
    ///      endpoint directly would bypass that; this is the last line.
    ///   2. Refuse provider configs whose endpoints aren't HTTPS (unless that provider explicitly
    ///      opts in to <c>AllowInsecureAuthority</c> + uses a loopback host). Catches
    ///      misconfiguration at save time rather than at first login attempt.
    /// </summary>
    public override void UpdateConfiguration(BasePluginConfiguration configuration)
    {
        if (configuration is PluginConfiguration cfg)
        {
            var errors = ConfigController.ValidateConfiguration(cfg);
            if (errors.Count > 0)
            {
                throw new ArgumentException(
                    "Invalid plugin configuration: " + string.Join("; ", errors),
                    nameof(configuration));
            }

            foreach (var p in cfg.Providers)
            {
                if (!p.Enabled) continue;
                ProviderConfigValidator.ValidateOrThrow(p);
            }
        }

        base.UpdateConfiguration(configuration);
    }

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
        if (cfg.MigratedDenyDefaultsV013) return;

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

        cfg.MigratedDenyDefaultsV013 = true;
        SaveConfiguration(cfg);
    }
}
