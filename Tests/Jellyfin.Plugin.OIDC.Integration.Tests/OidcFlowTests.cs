using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Web;
using Jellyfin.Data;
using Jellyfin.Database.Implementations.Enums;
using Jellyfin.Plugin.OIDC.Api;
using Jellyfin.Plugin.OIDC.Configuration;
using Jellyfin.Plugin.OIDC.Services;
using MediaBrowser.Controller.Session;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Jellyfin.Plugin.OIDC.Integration.Tests;

/// <summary>
/// End-to-end OIDC flow tests against a live WireMock IdP.
/// Exercises the real <see cref="OidcController"/> with real HTTP, real JWT validation,
/// real JWKS fetch &amp; cache. Only Jellyfin domain services (IUserManager, ISessionManager,
/// IActivityManager, ILibraryManager) are mocked — everything else is the real plugin code.
/// </summary>
public sealed class OidcFlowTests : IClassFixture<MockIdpFixture>
{
    private const string ProviderId = "testidp";
    private readonly MockIdpFixture _idp;

    public OidcFlowTests(MockIdpFixture idp) => _idp = idp;

    [Fact]
    public async Task FullFlow_NewUser_GetsCreatedAndAuthenticated()
    {
        var fixture = new TestFixture(_idp);
        fixture.AddProvider();

        // Step 1: Start — drives the IdP authorize redirect and captures the state
        var startResult = await fixture.Controller.Start(ProviderId);
        var redirect = Assert.IsType<RedirectResult>(startResult);
        var stateValue = ExtractStateFromUrl(redirect.Url);
        var nonceValue = ExtractParamFromUrl(redirect.Url, "nonce");
        TestFixture.PropagateCookies(fixture.Controller);

        // Step 2: IdP "redirects back" — we drive the callback directly
        _idp.EnqueueTokenResponse(
            sub: "user-123",
            username: "alice",
            email: "alice@example.com",
            roles: new[] { "admin" },
            nonce: nonceValue);

        var callbackResult = await fixture.Controller.Callback(ProviderId, code: "test-code", state: stateValue);
        Assert.IsType<ContentResult>(callbackResult);

        // Step 3: Authenticate — exchange the session token for a Jellyfin session
        var sessionToken = ExtractSessionTokenFromCallbackHtml((ContentResult)callbackResult);
        var authResult = await fixture.Controller.Authenticate(
            ProviderId,
            new AuthenticateRequest { Token = sessionToken, DeviceId = "test-dev" });

        var ok = Assert.IsType<OkObjectResult>(authResult);
        var jellyfinAuth = Assert.IsType<MediaBrowser.Controller.Authentication.AuthenticationResult>(ok.Value);
        Assert.NotNull(jellyfinAuth.AccessToken);
        Assert.NotEqual(Guid.Empty, jellyfinAuth.User!.Id);

        // The new user must exist in our fake user store
        var user = fixture.UserStore.GetByName("alice");
        Assert.NotNull(user);
    }

    [Fact]
    public async Task FullFlow_AdminRole_PromotesUserToAdministrator()
    {
        var fixture = new TestFixture(_idp);
        fixture.ConfigProvider.Configuration.RoleMappings = new List<RoleMapping>
        {
            new() { RoleName = "admin", IsAdmin = true, EnableMediaPlayback = true }
        };
        fixture.AddProvider();

        await fixture.RunFullFlow("bob", "user-bob", roles: new[] { "admin" });

        var user = fixture.UserStore.GetByName("bob");
        Assert.NotNull(user);
        Assert.True(HasPermission(user!, PermissionKind.IsAdministrator));
    }

    [Fact]
    public async Task FullFlow_DenyMappingOverridesGrant()
    {
        var fixture = new TestFixture(_idp);
        fixture.ConfigProvider.Configuration.RoleMappings = new List<RoleMapping>
        {
            new() { RoleName = "admin", IsAdmin = true, EnableMediaPlayback = true },
            // Deny mapping: zero the always-default-true flags. The admin UI clears these
            // automatically when "Explicit Deny" is toggled on (see oidcrbac.js), but
            // tests construct RoleMapping directly so we must clear them by hand.
            new()
            {
                RoleName = "restricted",
                IsExplicitDeny = true,
                IsAdmin = true,
                EnableMediaPlayback = false,
                EnableRemoteAccess = false,
                EnableTranscoding = false
            }
        };
        fixture.AddProvider();

        await fixture.RunFullFlow("carol", "user-carol", roles: new[] { "admin", "restricted" });

        var user = fixture.UserStore.GetByName("carol");
        Assert.NotNull(user);
        Assert.False(HasPermission(user!, PermissionKind.IsAdministrator));
        Assert.True(HasPermission(user, PermissionKind.EnableMediaPlayback));
    }

    [Fact]
    public async Task Callback_EmailNotVerified_Returns401WhenRequireEmailVerifiedSet()
    {
        var fixture = new TestFixture(_idp);
        var provider = fixture.AddProvider();
        provider.RequireEmailVerified = true;

        var startResult = await fixture.Controller.Start(ProviderId);
        var redirect = Assert.IsType<RedirectResult>(startResult);
        var stateValue = ExtractStateFromUrl(redirect.Url);
        var nonceValue = ExtractParamFromUrl(redirect.Url, "nonce");
        TestFixture.PropagateCookies(fixture.Controller);

        _idp.EnqueueTokenResponse(
            sub: "user-x",
            username: "dave",
            email: "dave@example.com",
            emailVerified: false,
            nonce: nonceValue);

        var callbackResult = await fixture.Controller.Callback(ProviderId, code: "test-code", state: stateValue);
        Assert.IsType<UnauthorizedObjectResult>(callbackResult);
    }

    [Fact]
    public async Task Callback_EmailVerified_AllowsLoginWhenRequireEmailVerifiedSet()
    {
        var fixture = new TestFixture(_idp);
        var provider = fixture.AddProvider();
        provider.RequireEmailVerified = true;

        await fixture.RunFullFlow("eve", "user-eve", email: "eve@example.com", emailVerified: true);

        Assert.NotNull(fixture.UserStore.GetByName("eve"));
    }

    [Fact]
    public async Task FullFlow_Hs256SignedToken_ValidatesWithClientSecret()
    {
        // Some IdPs (e.g. Authentik with default OIDC provider settings) sign ID tokens
        // with HS256 + the client_secret as the key. JWKS is empty in that case.
        // This test proves the plugin can validate symmetric-signed tokens too.
        var fixture = new TestFixture(_idp);
        var provider = fixture.AddProvider();
        // HS256 is off by default in v0.x configs; this test explicitly opts in to mirror
        // an admin who knowingly enables symmetric signing for an Authentik-style IdP.
        provider.AllowedSigningAlgorithms = new List<string> { "HS256", "RS256" };

        await fixture.RunFullFlow("hmacuser", "sub-hmac", useHmacSigning: true);

        Assert.NotNull(fixture.UserStore.GetByName("hmacuser"));
    }

    [Fact]
    public async Task FullFlow_Hs256AgainstRsOnlyProvider_IsRejected()
    {
        // An attacker (or compromised client) that gets the client_secret can mint HS256 tokens.
        // If the provider's AllowedSigningAlgorithms only lists RS*/ES*/PS*, the controller must refuse.
        var fixture = new TestFixture(_idp);
        var provider = fixture.AddProvider(); // default allowlist excludes HS*

        var startResult = await fixture.Controller.Start(ProviderId);
        var redirect = (RedirectResult)startResult;
        var state = ExtractStateFromUrl(redirect.Url);
        var nonce = ExtractParamFromUrl(redirect.Url, "nonce");

        _idp.EnqueueTokenResponse(
            sub: "hostile",
            username: "hostile",
            nonce: nonce,
            useHmacSigning: true);

        var callbackResult = await fixture.Controller.Callback(ProviderId, code: "code", state: state);
        // The resolver throws SecurityTokenInvalidSignatureException → controller returns 502
        // ("Failed to resolve signing keys"). Either way: not OK, no user created.
        Assert.False(callbackResult is ContentResult, "Hostile HS256 token must not produce an auth content page");
        Assert.Null(fixture.UserStore.GetByName("hostile"));
    }

    [Fact]
    public async Task DiscoveryCaching_RepeatedLogins_FetchDiscoveryOnce()
    {
        var fixture = new TestFixture(_idp);
        fixture.AddProvider();

        var before = _idp.Server.LogEntries.Count(l =>
            l.RequestMessage?.AbsolutePath?.EndsWith("/.well-known/openid-configuration", StringComparison.Ordinal) == true);

        await fixture.RunFullFlow("u1", "sub-1");
        await fixture.RunFullFlow("u2", "sub-2");
        await fixture.RunFullFlow("u3", "sub-3");

        var after = _idp.Server.LogEntries.Count(l =>
            l.RequestMessage?.AbsolutePath?.EndsWith("/.well-known/openid-configuration", StringComparison.Ordinal) == true);

        // With OidcDiscoveryCache wired in, three logins should only fetch /.well-known/openid-configuration once.
        Assert.Equal(1, after - before);
    }

    [Fact]
    public async Task JwksCaching_DirectInvocation_FetchesOnce()
    {
        // Drives JwksCache through real HTTP against the WireMock IdP to verify
        // the cache + locking work in a live setting. Note: this does NOT measure
        // the controller's overall JWKS request count because IdentityModel.Client's
        // discovery validation independently fetches /jwks on every discovery call
        // (a separate caching opportunity tracked outside this test).
        var fixture = new TestFixture(_idp);
        var jwksUri = $"{_idp.Authority}/jwks";

        var before = _idp.Server.LogEntries.Count(l =>
            l.RequestMessage?.AbsolutePath?.EndsWith("/jwks", StringComparison.Ordinal) == true);

        await fixture.JwksCache.GetKeysAsync(jwksUri);
        await fixture.JwksCache.GetKeysAsync(jwksUri);
        await fixture.JwksCache.GetKeysAsync(jwksUri);

        var after = _idp.Server.LogEntries.Count(l =>
            l.RequestMessage?.AbsolutePath?.EndsWith("/jwks", StringComparison.Ordinal) == true);

        Assert.Equal(1, after - before);
    }

    [Fact]
    public async Task Callback_MissingNonce_ReturnsBadRequest()
    {
        // When the IdP omits the nonce claim entirely, the controller must reject.
        var fixture = new TestFixture(_idp);
        fixture.AddProvider();

        var startResult = await fixture.Controller.Start(ProviderId);
        var redirect = Assert.IsType<RedirectResult>(startResult);
        var stateValue = ExtractStateFromUrl(redirect.Url);
        TestFixture.PropagateCookies(fixture.Controller);

        // EnqueueTokenResponse without nonce: → no "nonce" claim in the ID token
        _idp.EnqueueTokenResponse(sub: "no-nonce-sub", username: "no-nonce-user");

        var callbackResult = await fixture.Controller.Callback(ProviderId, code: "code-no-nonce", state: stateValue);
        Assert.IsType<BadRequestObjectResult>(callbackResult);
    }

    [Fact]
    public async Task Callback_NonceMismatch_ReturnsBadRequest()
    {
        // When the IdP returns a nonce that doesn't match what we sent, the controller must reject.
        var fixture = new TestFixture(_idp);
        fixture.AddProvider();

        var startResult = await fixture.Controller.Start(ProviderId);
        var redirect = Assert.IsType<RedirectResult>(startResult);
        var stateValue = ExtractStateFromUrl(redirect.Url);
        TestFixture.PropagateCookies(fixture.Controller);

        // Deliberately supply a wrong nonce value
        _idp.EnqueueTokenResponse(sub: "mismatch-sub", username: "mismatch-user", nonce: "wrong-nonce-value");

        var callbackResult = await fixture.Controller.Callback(ProviderId, code: "code-nonce-mismatch", state: stateValue);
        Assert.IsType<BadRequestObjectResult>(callbackResult);
    }

    [Fact]
    public async Task Callback_CodeReplayAttack_SecondCallReturnsBadRequest()
    {
        // Using the same authorization code twice must be rejected by the in-process code cache.
        var fixture = new TestFixture(_idp);
        fixture.AddProvider();

        // First call — should succeed
        var startResult1 = await fixture.Controller.Start(ProviderId);
        var redirect1 = Assert.IsType<RedirectResult>(startResult1);
        var state1 = ExtractStateFromUrl(redirect1.Url);
        var nonce1 = ExtractParamFromUrl(redirect1.Url, "nonce");
        TestFixture.PropagateCookies(fixture.Controller);

        _idp.EnqueueTokenResponse(sub: "replay-sub", username: "replay-user", nonce: nonce1);
        var firstResult = await fixture.Controller.Callback(ProviderId, code: "replay-code", state: state1);
        Assert.IsType<ContentResult>(firstResult);

        // Second call with same code on a fresh state — must be rejected
        var startResult2 = await fixture.Controller.Start(ProviderId);
        var redirect2 = Assert.IsType<RedirectResult>(startResult2);
        var state2 = ExtractStateFromUrl(redirect2.Url);
        var nonce2 = ExtractParamFromUrl(redirect2.Url, "nonce");
        TestFixture.PropagateCookies(fixture.Controller);

        _idp.EnqueueTokenResponse(sub: "replay-sub", username: "replay-user", nonce: nonce2);
        var secondResult = await fixture.Controller.Callback(ProviderId, code: "replay-code", state: state2);
        Assert.IsType<BadRequestObjectResult>(secondResult);
    }

    [Fact]
    public async Task BuildCallbackHtml_AppVersionNotHardcoded()
    {
        // The callback HTML must embed a real plugin version or the fallback "0.0.0" —
        // not the old hardcoded "10.11.0" string.
        var fixture = new TestFixture(_idp);
        fixture.AddProvider();

        var html = await fixture.RunFullFlowAndGetCallbackHtml("version-user", "version-sub");

        // Must NOT contain the old hardcoded string
        Assert.DoesNotContain("10.11.0", html);
        // Must contain AppVersion in the fetch body
        Assert.Contains("AppVersion", html);
    }

    // ────────────────────────────────────────────────────────────────────────
    // Helpers
    // ────────────────────────────────────────────────────────────────────────

    private static bool HasPermission(Jellyfin.Database.Implementations.Entities.User user, PermissionKind kind) =>
        user.Permissions.FirstOrDefault(p => p.Kind == kind)?.Value ?? false;

    private static string ExtractStateFromUrl(string url) => ExtractParamFromUrl(url, "state");

    private static string ExtractParamFromUrl(string url, string name)
    {
        var query = HttpUtility.ParseQueryString(new Uri(url).Query);
        return query[name] ?? throw new InvalidOperationException($"Missing '{name}' in {url}");
    }

    private static string ExtractSessionTokenFromCallbackHtml(ContentResult content) =>
        TestFixture.ExtractSessionTokenFromHtml(content.Content ?? string.Empty);
}
