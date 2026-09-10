using System;
using System.Net;
using System.Net.Http;
using Jellyfin.Plugin.OIDC.Auth;
using MediaBrowser.Controller;
using MediaBrowser.Controller.Authentication;
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
        // Surface OidcAuthProvider in Jellyfin's per-user "Authentication Provider" dropdown.
        // Without this, admins have no UI to migrate an existing local user to OIDC — the only
        // path is OIDC login + auto-link, which TASK-04 blocks by default for safety.
        serviceCollection.AddSingleton<IAuthenticationProvider, OidcAuthProvider>();

        serviceCollection.AddSingleton<IPluginConfigProvider, JellyfinPluginConfigProvider>();
        serviceCollection.AddSingleton<StateManager>();
        serviceCollection.AddHostedService(sp => sp.GetRequiredService<StateManager>());
        serviceCollection.AddSingleton<LogoutTokenReplayCache>();
        serviceCollection.AddHostedService(sp => sp.GetRequiredService<LogoutTokenReplayCache>());
        serviceCollection.AddSingleton<SamlAssertionReplayCache>();
        serviceCollection.AddHostedService(sp => sp.GetRequiredService<SamlAssertionReplayCache>());
        serviceCollection.AddSingleton<AuthorizationCodeCache>();
        serviceCollection.AddHostedService(sp => sp.GetRequiredService<AuthorizationCodeCache>());
        serviceCollection.AddSingleton<CallbackRateLimiter>();
        serviceCollection.AddHostedService(sp => sp.GetRequiredService<CallbackRateLimiter>());
        serviceCollection.AddSingleton<OidcUserStore>(sp => new OidcUserStore(
            sp.GetRequiredService<ILogger<OidcUserStore>>(),
            sp.GetRequiredService<IActivityManager>()));
        serviceCollection.AddSingleton<JwksCache>();
        serviceCollection.AddSingleton<OidcDiscoveryCache>();
        serviceCollection.AddScoped<RbacService>();
        serviceCollection.AddScoped<UserSyncService>();

        // The avatar fetcher builds its own HttpClient per request, pinned to the IP address the
        // SSRF guard just validated (see ProfileImageService.CreatePinnedClient). It deliberately
        // does not use IHttpClientFactory: a pooled client would reuse connections and re-resolve
        // DNS, which is exactly the TOCTOU the pinning exists to close. The factory is injected as
        // a delegate so tests can substitute a stub client.
        serviceCollection.AddSingleton<Func<IPAddress, HttpClient>>(_ => ProfileImageService.CreatePinnedClient);
        serviceCollection.AddScoped<ProfileImageService>();
        serviceCollection.AddTransient<IScheduledTask, RbacResyncTask>();
    }
}
