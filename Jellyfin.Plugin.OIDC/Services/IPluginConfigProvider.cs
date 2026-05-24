using Jellyfin.Plugin.OIDC.Configuration;

namespace Jellyfin.Plugin.OIDC.Services;

/// <summary>
/// Provides access to the plugin's runtime configuration.
/// Abstracted to allow injection in integration tests without a live Jellyfin host.
/// </summary>
public interface IPluginConfigProvider
{
    PluginConfiguration GetConfiguration();
}

/// <summary>Production implementation: reads from the Jellyfin plugin singleton.</summary>
public sealed class JellyfinPluginConfigProvider : IPluginConfigProvider
{
    public PluginConfiguration GetConfiguration() =>
        OidcPlugin.Instance?.Configuration ?? new PluginConfiguration();
}
