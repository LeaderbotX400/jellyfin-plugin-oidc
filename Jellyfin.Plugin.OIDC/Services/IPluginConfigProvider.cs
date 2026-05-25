using Jellyfin.Plugin.OIDC.Configuration;

namespace Jellyfin.Plugin.OIDC.Services;

/// <summary>
/// Provides access to the plugin's runtime configuration.
/// Abstracted to allow injection in integration tests without a live Jellyfin host.
/// </summary>
public interface IPluginConfigProvider
{
    PluginConfiguration GetConfiguration();

    /// <summary>Persists the supplied configuration (already secret-merged).</summary>
    void SaveConfiguration(PluginConfiguration config);
}

/// <summary>Production implementation: reads from and writes to the Jellyfin plugin singleton.</summary>
public sealed class JellyfinPluginConfigProvider : IPluginConfigProvider
{
    public PluginConfiguration GetConfiguration() =>
        OidcPlugin.Instance?.Configuration ?? new PluginConfiguration();

    public void SaveConfiguration(PluginConfiguration config)
    {
        if (OidcPlugin.Instance is null) return;
        OidcPlugin.Instance.UpdateConfiguration(config);
    }
}
