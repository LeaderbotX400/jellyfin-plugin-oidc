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
        fixture.AddProvider();

        await fixture.RunFullFlow("hmacuser", "sub-hmac", useHmacSigning: true);

        Assert.NotNull(fixture.UserStore.GetByName("hmacuser"));
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

    private static string ExtractSessionTokenFromCallbackHtml(ContentResult content)
    {
        var html = content.Content ?? string.Empty;
        const string marker = "const token = '";
        var idx = html.IndexOf(marker, StringComparison.Ordinal);
        Assert.True(idx >= 0, "Session token marker not found in callback HTML");
        var start = idx + marker.Length;
        var end = html.IndexOf('\'', start);
        return html.Substring(start, end - start);
    }
}
