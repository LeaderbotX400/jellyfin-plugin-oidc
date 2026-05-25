using MediaBrowser.Controller;
using MediaBrowser.Controller.Plugins;
using MediaBrowser.Model.Tasks;
using Microsoft.Extensions.DependencyInjection;

namespace Jellyfin.Plugin.OIDC.Services;

public class ServiceRegistrator : IPluginServiceRegistrator
{
    public void RegisterServices(IServiceCollection serviceCollection, IServerApplicationHost applicationHost)
    {
        serviceCollection.AddSingleton<IPluginConfigProvider, JellyfinPluginConfigProvider>();
        serviceCollection.AddSingleton<StateManager>();
        serviceCollection.AddHostedService(sp => sp.GetRequiredService<StateManager>());
        serviceCollection.AddSingleton<LogoutTokenReplayCache>();
        serviceCollection.AddHostedService(sp => sp.GetRequiredService<LogoutTokenReplayCache>());
        serviceCollection.AddSingleton<OidcUserStore>();
        serviceCollection.AddSingleton<JwksCache>();
        serviceCollection.AddSingleton<OidcDiscoveryCache>();
        serviceCollection.AddScoped<RbacService>();
        serviceCollection.AddScoped<UserSyncService>();
        serviceCollection.AddTransient<IScheduledTask, RbacResyncTask>();
    }
}
