using System;
using System.Collections.Generic;
using Jellyfin.Plugin.OIDC.Api;
using Jellyfin.Plugin.OIDC.Configuration;
using MediaBrowser.Common.Configuration;
using MediaBrowser.Common.Plugins;
using MediaBrowser.Model.Plugins;
using MediaBrowser.Model.Serialization;

namespace Jellyfin.Plugin.OIDC;

public class OidcPlugin : BasePlugin<PluginConfiguration>, IHasWebPages
{
    public OidcPlugin(IApplicationPaths applicationPaths, IXmlSerializer xmlSerializer)
        : base(applicationPaths, xmlSerializer)
    {
        Instance = this;
    }

    public static OidcPlugin? Instance { get; private set; }

    public override string Name => "OIDC RBAC";

    public override Guid Id => Guid.Parse("d4e5f6a7-b8c9-0d1e-2f3a-4b5c6d7e8f90");

    public override string Description => "Advanced OIDC authentication with role-based library access control";

    /// <summary>
    /// Defence-in-depth: reject any configuration that contains an invalid provider id
    /// (charset / length). The web UI also validates via /sso/OIDC/Config/Validate, but a
    /// determined caller hitting the standard plugin config endpoint directly would bypass that;
    /// this override is the last line.
    /// </summary>
    public override void UpdateConfiguration(BasePluginConfiguration configuration)
    {
        if (configuration is PluginConfiguration typed)
        {
            var errors = ConfigController.ValidateConfiguration(typed);
            if (errors.Count > 0)
            {
                throw new ArgumentException(
                    "Invalid plugin configuration: " + string.Join("; ", errors),
                    nameof(configuration));
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
}
