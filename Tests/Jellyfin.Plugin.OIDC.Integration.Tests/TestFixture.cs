using System;
using System.IO;
using System.Threading.Tasks;
using System.Web;
using Jellyfin.Plugin.OIDC.Api;
using Jellyfin.Plugin.OIDC.Configuration;
using Jellyfin.Plugin.OIDC.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging.Abstractions;

namespace Jellyfin.Plugin.OIDC.Integration.Tests;

/// <summary>Composes a fully-configured <see cref="OidcController"/> against the supplied IdP mock.</summary>
internal sealed class TestFixture
{
    public MockIdpFixture Idp { get; }
    public TestPluginConfigProvider ConfigProvider { get; } = new();
    public FakeUserStoreWrapper UserStore { get; } = new();
    public OidcUserStore OidcUserStore { get; }
    public OidcController Controller { get; }
    public SamlController SamlController { get; }
    public RbacService RbacService { get; }
    public JwksCache JwksCache { get; }
    public OidcDiscoveryCache DiscoveryCache { get; }
    public StateManager StateManager { get; }
    public LogoutTokenReplayCache ReplayCache { get; }

    public TestFixture(MockIdpFixture idp)
    {
        Idp = idp;

        var userManagerMock = FakeJellyfinFactory.CreateUserManager(UserStore.Inner);
        var sessionManagerMock = FakeJellyfinFactory.CreateSessionManager();
        var libraryManagerMock = FakeJellyfinFactory.CreateLibraryManager();
        var activityManagerMock = FakeJellyfinFactory.CreateActivityManager();
        var httpFactory = new FakeHttpClientFactory();

        OidcUserStore = new OidcUserStore(Path.Combine(Path.GetTempPath(), $"oidc-test-{Guid.NewGuid():N}.json"));
        JwksCache = new JwksCache(httpFactory, NullLogger<JwksCache>.Instance);
        DiscoveryCache = new OidcDiscoveryCache(httpFactory, NullLogger<OidcDiscoveryCache>.Instance);
        StateManager = new StateManager(NullLogger<StateManager>.Instance);
        ReplayCache = new LogoutTokenReplayCache(NullLogger<LogoutTokenReplayCache>.Instance);

        RbacService = new RbacService(
            userManagerMock.Object,
            libraryManagerMock.Object,
            activityManagerMock.Object,
            ConfigProvider,
            NullLogger<RbacService>.Instance);

        var userSyncService = new UserSyncService(
            userManagerMock.Object,
            RbacService,
            OidcUserStore,
            ConfigProvider,
            NullLogger<UserSyncService>.Instance);

        Controller = new OidcController(
            StateManager,
            userSyncService,
            sessionManagerMock.Object,
            httpFactory,
            JwksCache,
            DiscoveryCache,
            RbacService,
            OidcUserStore,
            userManagerMock.Object,
            ConfigProvider,
            NullLogger<OidcController>.Instance);

        Controller.ControllerContext = new ControllerContext
        {
            HttpContext = BuildHttpContext()
        };

        SamlController = new SamlController(
            userSyncService,
            StateManager,
            RbacService,
            ConfigProvider,
            NullLogger<SamlController>.Instance);
        SamlController.ControllerContext = new ControllerContext
        {
            HttpContext = BuildHttpContext()
        };
    }

    public OidcProviderConfig AddProvider()
    {
        var provider = new OidcProviderConfig
        {
            ProviderId = "testidp",
            DisplayName = "Test IdP",
            Authority = Idp.Authority,
            ClientId = Idp.ClientId,
            ClientSecret = Idp.ClientSecret,
            Scopes = "openid profile email roles",
            UsernameClaim = "preferred_username",
            RoleClaim = "roles",
            EntitlementClaim = "entitlements",
            DisplayNameClaim = "name",
            EnableEntitlements = true,
            Enabled = true
        };
        ConfigProvider.Configuration.Providers.Add(provider);
        ConfigProvider.Configuration.AutoCreateUsers = true;
        return provider;
    }

    /// <summary>
    /// Adds a SAML provider with no IdP certificate configured. SAML responses will be
    /// rejected by signature validation unless the caller assigns <c>IdpCertificate</c>
    /// and signs responses accordingly.
    /// </summary>
    public SamlProviderConfig AddSamlProvider(string id = "saml-test")
    {
        var provider = new SamlProviderConfig
        {
            Id = id,
            DisplayName = "Test SAML IdP",
            EntityId = "https://jellyfin.test",
            SsoUrl = "https://idp.example.com/sso/saml",
            IdpCertificate = string.Empty, // signature verification skipped
            UsernameClaim = "NameID",
            RoleClaim = "groups",
            Enabled = true
        };
        ConfigProvider.Configuration.SamlProviders.Add(provider);
        ConfigProvider.Configuration.AutoCreateUsers = true;
        return provider;
    }

    /// <summary>Drives the complete OIDC flow (Start → Callback → Authenticate) end-to-end.</summary>
    public async Task RunFullFlow(
        string username,
        string sub,
        string? email = null,
        bool? emailVerified = null,
        string[]? roles = null,
        string[]? entitlements = null,
        bool useHmacSigning = false)
    {
        var startResult = await Controller.Start("testidp");
        var redirect = (RedirectResult)startResult;
        var state = HttpUtility.ParseQueryString(new Uri(redirect.Url).Query)["state"]!;
        var nonce = HttpUtility.ParseQueryString(new Uri(redirect.Url).Query)["nonce"]!;

        Idp.EnqueueTokenResponse(
            sub: sub,
            username: username,
            email: email,
            emailVerified: emailVerified,
            roles: roles,
            entitlements: entitlements,
            nonce: nonce,
            useHmacSigning: useHmacSigning);

        var callbackResult = await Controller.Callback("testidp", code: "test-code", state: state);
        var content = (ContentResult)callbackResult;

        const string marker = "const token = '";
        var idx = content.Content!.IndexOf(marker, StringComparison.Ordinal);
        var startIdx = idx + marker.Length;
        var endIdx = content.Content.IndexOf('\'', startIdx);
        var token = content.Content.Substring(startIdx, endIdx - startIdx);

        await Controller.Authenticate("testidp", new AuthenticateRequest
        {
            Token = token,
            DeviceId = "test-dev"
        });
    }

    private static DefaultHttpContext BuildHttpContext()
    {
        var ctx = new DefaultHttpContext();
        ctx.Request.Scheme = "https";
        ctx.Request.Host = new HostString("jellyfin.test", 443);
        return ctx;
    }
}

/// <summary>Wraps the in-memory user store with a friendlier lookup API for assertions.</summary>
internal sealed class FakeUserStoreWrapper
{
    public FakeUserStore Inner { get; } = new();
    public Jellyfin.Database.Implementations.Entities.User? GetByName(string name) =>
        Inner.ByName.TryGetValue(name, out var id) ? Inner.ById[id] : null;
}
