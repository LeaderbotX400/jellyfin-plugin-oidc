using MediaBrowser.Controller;
using MediaBrowser.Controller.Plugins;
using MediaBrowser.Model.Activity;
using MediaBrowser.Model.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.OIDC.Services;

public class ServiceRegistrator : IPluginServiceRegistrator
{
    public void RegisterServices(IServiceCollection serviceCollection, IServerApplicationHost applicationHost)
    {
        serviceCollection.AddSingleton<IPluginConfigProvider, JellyfinPluginConfigProvider>();
        serviceCollection.AddSingleton<StateManager>();
        serviceCollection.AddHostedService(sp => sp.GetRequiredService<StateManager>());
        serviceCollection.AddSingleton<OidcUserStore>(sp => new OidcUserStore(
            sp.GetRequiredService<ILogger<OidcUserStore>>(),
            sp.GetRequiredService<IActivityManager>()));
        serviceCollection.AddSingleton<JwksCache>();
        serviceCollection.AddSingleton<OidcDiscoveryCache>();
        serviceCollection.AddScoped<RbacService>();
        serviceCollection.AddScoped<UserSyncService>();
        serviceCollection.AddTransient<IScheduledTask, RbacResyncTask>();
    }
}
