using System;
using System.IO;
using System.Threading.Tasks;
using System.Web;
using Jellyfin.Plugin.OIDC.Api;
using Jellyfin.Plugin.OIDC.Configuration;
using Jellyfin.Plugin.OIDC.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using MediaBrowser.Model.Activity;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;

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
    public SamlAssertionReplayCache SamlReplayCache { get; }
    public AuthorizationCodeCache CodeCache { get; }
    public CallbackRateLimiter RateLimiter { get; }
    public Mock<IActivityManager> ActivityManagerMock { get; }

    public TestFixture(MockIdpFixture idp)
    {
        Idp = idp;

        var userManagerMock = FakeJellyfinFactory.CreateUserManager(UserStore.Inner);
        var sessionManagerMock = FakeJellyfinFactory.CreateSessionManager();
        var libraryManagerMock = FakeJellyfinFactory.CreateLibraryManager();
        var activityManagerMock = FakeJellyfinFactory.CreateActivityManager();
        ActivityManagerMock = activityManagerMock;
        var httpFactory = new FakeHttpClientFactory();

        OidcUserStore = new OidcUserStore(Path.Combine(Path.GetTempPath(), $"oidc-test-{Guid.NewGuid():N}.json"));
        JwksCache = new JwksCache(httpFactory, NullLogger<JwksCache>.Instance);
        DiscoveryCache = new OidcDiscoveryCache(httpFactory, NullLogger<OidcDiscoveryCache>.Instance);
        StateManager = new StateManager(NullLogger<StateManager>.Instance);
        ReplayCache = new LogoutTokenReplayCache(NullLogger<LogoutTokenReplayCache>.Instance);
        SamlReplayCache = new SamlAssertionReplayCache(NullLogger<SamlAssertionReplayCache>.Instance);
        CodeCache = new AuthorizationCodeCache(NullLogger<AuthorizationCodeCache>.Instance);
        RateLimiter = new CallbackRateLimiter(NullLogger<CallbackRateLimiter>.Instance);

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
            CodeCache,
            RateLimiter,
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
            SamlReplayCache,
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
            Enabled = true,
            // WireMock IdP serves plain HTTP on localhost; opt in to the dev-only bypass.
            AllowInsecureAuthority = true
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
            IdpEntityId = "https://idp.example.com",
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
        PropagateCookies(Controller);

        Idp.EnqueueTokenResponse(
            sub: sub,
            username: username,
            email: email,
            emailVerified: emailVerified,
            roles: roles,
            entitlements: entitlements,
            nonce: nonce,
            useHmacSigning: useHmacSigning);

        // Use a unique code per invocation so the one-time-use AuthorizationCodeCache
        // does not reject the second call in multi-RunFullFlow test scenarios.
        var code = $"test-code-{Guid.NewGuid():N}";
        var callbackResult = await Controller.Callback("testidp", code: code, state: state);
        var content = (ContentResult)callbackResult;
        var token = ExtractSessionTokenFromHtml(content.Content!);

        await Controller.Authenticate("testidp", new AuthenticateRequest
        {
            Token = token,
            DeviceId = "test-dev"
        });
    }

    /// <summary>
    /// Returns the raw callback HTML without completing /Auth. Used to assert on script
    /// content (e.g. AppVersion).
    /// </summary>
    public async Task<string> RunFullFlowAndGetCallbackHtml(string username, string sub, string[]? roles = null)
    {
        var startResult = await Controller.Start("testidp");
        var redirect = (RedirectResult)startResult;
        var state = HttpUtility.ParseQueryString(new Uri(redirect.Url).Query)["state"]!;
        var nonce = HttpUtility.ParseQueryString(new Uri(redirect.Url).Query)["nonce"]!;
        PropagateCookies(Controller);
        Idp.EnqueueTokenResponse(sub: sub, username: username, nonce: nonce, roles: roles);
        var code = $"html-code-{Guid.NewGuid():N}";
        var callbackResult = await Controller.Callback("testidp", code: code, state: state);
        return ((ContentResult)callbackResult).Content ?? string.Empty;
    }

    /// <summary>
    /// Copies Set-Cookie headers written by the previous response into the next request,
    /// so a chained controller call sees the browser-bound CSRF cookie.
    /// </summary>
    public static void PropagateCookies(Microsoft.AspNetCore.Mvc.ControllerBase controller)
    {
        var ctx = controller.ControllerContext.HttpContext;
        var setCookies = ctx.Response.Headers["Set-Cookie"];
        if (setCookies.Count == 0)
        {
            return;
        }

        // Parse name=value (drop attributes) from each Set-Cookie and merge into Request.Cookies.
        // Replace the whole HttpContext.Request.Cookies via the standard "Cookie" header.
        var existing = ctx.Request.Headers.TryGetValue("Cookie", out var cur)
            ? cur.ToString().Split("; ", StringSplitOptions.RemoveEmptyEntries).ToList()
            : new System.Collections.Generic.List<string>();

        foreach (var sc in setCookies)
        {
            if (string.IsNullOrEmpty(sc)) continue;
            var firstAttr = sc.Split(';')[0];
            if (string.IsNullOrWhiteSpace(firstAttr)) continue;
            var eq = firstAttr.IndexOf('=');
            if (eq < 0) continue;
            var name = firstAttr.Substring(0, eq);
            // If Set-Cookie expired the cookie (Max-Age=0 / Expires past), drop matching entry.
            if (sc.Contains("Max-Age=0") || sc.Contains("expires=Thu, 01 Jan 1970", StringComparison.OrdinalIgnoreCase))
            {
                existing.RemoveAll(c => c.StartsWith(name + "=", StringComparison.Ordinal));
                continue;
            }
            existing.RemoveAll(c => c.StartsWith(name + "=", StringComparison.Ordinal));
            existing.Add(firstAttr);
        }

        ctx.Request.Headers["Cookie"] = string.Join("; ", existing);
        ctx.Response.Headers.Remove("Set-Cookie");
    }

    /// <summary>
    /// Extracts the session token written into the callback HTML by either controller.
    /// The token is now JSON-encoded (double-quoted) — supports both forms in case of regression.
    /// </summary>
    public static string ExtractSessionTokenFromHtml(string html)
    {
        const string marker = "const token = ";
        var idx = html.IndexOf(marker, StringComparison.Ordinal);
        if (idx < 0) throw new InvalidOperationException("Token marker not found in callback HTML");
        var start = idx + marker.Length;
        var quote = html[start];
        if (quote != '"' && quote != '\'') throw new InvalidOperationException("Expected quoted token literal");
        var end = html.IndexOf(quote, start + 1);
        return html.Substring(start + 1, end - start - 1);
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
