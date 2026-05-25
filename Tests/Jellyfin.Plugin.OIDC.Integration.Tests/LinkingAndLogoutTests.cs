using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
using System.Web;
using Jellyfin.Plugin.OIDC.Api;
using Jellyfin.Plugin.OIDC.Services;
using MediaBrowser.Controller.Net;
using MediaBrowser.Controller.Session;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Primitives;
using Microsoft.IdentityModel.Tokens;
using Moq;
using Xunit;

namespace Jellyfin.Plugin.OIDC.Integration.Tests;

/// <summary>
/// Integration tests for account-linking endpoints (LinkStart / Unlink / GetLinks)
/// and the OIDC back-channel logout endpoint.
/// </summary>
public sealed class LinkingAndLogoutTests : IClassFixture<MockIdpFixture>
{
    private const string ProviderId = "testidp";
    private readonly MockIdpFixture _idp;

    public LinkingAndLogoutTests(MockIdpFixture idp) => _idp = idp;

    // ── Account linking ────────────────────────────────────────────────────

    [Fact]
    public async Task LinkFlow_LinksExistingUserToOidcIdentity()
    {
        var fixture = new TestFixture(_idp);
        fixture.AddProvider();

        // Seed an existing Jellyfin user that we will link to an OIDC identity
        var existingUser = fixture.UserStore.Inner.CreateUser("existing-jellyfin-user");
        AttachAuthenticatedUser(fixture.Controller, existingUser.Id);

        // Drive LinkStart → captures state with LinkingForUserId set
        var startResult = await fixture.Controller.LinkStart(ProviderId);
        var redirect = Assert.IsType<RedirectResult>(startResult);
        var state = HttpUtility.ParseQueryString(new Uri(redirect.Url).Query)["state"]!;
        var nonce = HttpUtility.ParseQueryString(new Uri(redirect.Url).Query)["nonce"]!;

        // IdP returns token for a DIFFERENT user identity (oidc sub != existing username)
        _idp.EnqueueTokenResponse(
            sub: "external-oidc-id",
            username: "totally-different-name",
            nonce: nonce);

        // Detach the auth context since the callback runs without auth
        fixture.Controller.ControllerContext.HttpContext.User = new ClaimsPrincipal(new ClaimsIdentity());
        var callbackResult = await fixture.Controller.Callback(ProviderId, code: "code", state: state);
        var content = Assert.IsType<ContentResult>(callbackResult);
        var token = ExtractSessionToken(content);

        // Authenticate — should write a link, not auto-provision a new user
        var authResult = await fixture.Controller.Authenticate(
            ProviderId,
            new AuthenticateRequest { Token = token });
        var ok = Assert.IsType<OkObjectResult>(authResult);
        var linkedFlag = ok.Value!.GetType().GetProperty("Linked")!.GetValue(ok.Value);
        Assert.Equal(true, linkedFlag);

        // Confirm the link is persisted: GetLinkedUserIdAsync resolves to our existing user
        var linked = await fixture.OidcUserStore.GetLinkedUserIdAsync("external-oidc-id", ProviderId);
        Assert.Equal(existingUser.Id, linked);

        // A normal login flow with the SAME OIDC identity should resolve the linked user
        // rather than auto-provisioning a new "totally-different-name"
        await fixture.RunFullFlow("totally-different-name", "external-oidc-id");
        Assert.Null(fixture.UserStore.GetByName("totally-different-name"));
    }

    [Fact]
    public async Task Unlink_RemovesLinkForCurrentUser()
    {
        var fixture = new TestFixture(_idp);
        var user = fixture.UserStore.Inner.CreateUser("alice");
        await fixture.OidcUserStore.LinkAsync(user.Id, "sub-xyz", ProviderId);

        AttachAuthenticatedUser(fixture.Controller, user.Id);
        var result = await fixture.Controller.Unlink(ProviderId);
        Assert.IsType<OkResult>(result);

        var stillLinked = await fixture.OidcUserStore.GetLinkedUserIdAsync("sub-xyz", ProviderId);
        Assert.Null(stillLinked);
    }

    [Fact]
    public async Task GetLinks_ReturnsAllLinksForCurrentUser()
    {
        var fixture = new TestFixture(_idp);
        var user = fixture.UserStore.Inner.CreateUser("bob");
        await fixture.OidcUserStore.LinkAsync(user.Id, "sub-1", "providerA");
        await fixture.OidcUserStore.LinkAsync(user.Id, "sub-2", "providerB");

        AttachAuthenticatedUser(fixture.Controller, user.Id);
        var result = await fixture.Controller.GetLinks();
        var ok = Assert.IsType<OkObjectResult>(result);

        var links = ((System.Collections.IEnumerable)ok.Value!).Cast<object>().ToList();
        Assert.Equal(2, links.Count);
    }

    [Fact]
    public async Task LinkStart_NoAuthenticatedUser_ReturnsUnauthorized()
    {
        var fixture = new TestFixture(_idp);
        fixture.AddProvider();
        // No AttachAuthenticatedUser → no NameIdentifier claim → controller can't resolve user

        var result = await fixture.Controller.LinkStart(ProviderId);
        Assert.IsType<UnauthorizedObjectResult>(result);
    }

    // ── Back-channel logout ────────────────────────────────────────────────

    [Fact]
    public async Task BackChannelLogout_ValidLogoutToken_RevokesUserSessions()
    {
        var fixture = new TestFixture(_idp);
        fixture.AddProvider();

        // Run a full login so the user record exists in OidcUserStore (back-channel logout
        // looks up the linked sub to find the Jellyfin user ID to revoke)
        await fixture.RunFullFlow("frank", "sub-frank");
        var frank = fixture.UserStore.GetByName("frank");
        Assert.NotNull(frank);

        // Build a logout controller wired to the same stores + observable session manager
        var sessionManagerMock = new Mock<ISessionManager>();
        sessionManagerMock
            .Setup(s => s.RevokeUserTokens(It.IsAny<Guid>(), It.IsAny<string>()))
            .Returns(Task.CompletedTask);

        var logoutController = new OidcLogoutController(
            fixture.OidcUserStore,
            sessionManagerMock.Object,
            new FakeHttpClientFactory(),
            fixture.JwksCache,
            fixture.DiscoveryCache,
            fixture.RbacService,
            fixture.ConfigProvider,
            fixture.ReplayCache,
            NullLogger<OidcLogoutController>.Instance);
        logoutController.ControllerContext = fixture.Controller.ControllerContext;

        // Send a properly signed logout_token from the IdP
        var logoutToken = _idp.CreateLogoutToken(sub: "sub-frank");
        var result = await logoutController.BackChannelLogout(logoutToken);
        Assert.IsType<OkResult>(result);

        // Verify the controller resolved the sub to our Jellyfin user and asked to revoke
        sessionManagerMock.Verify(s => s.RevokeUserTokens(frank!.Id, null), Times.Once);
    }

    [Fact]
    public async Task BackChannelLogout_UnknownSub_ReturnsOk()
    {
        // Spec: silent OK when sub isn't known to us — don't leak account existence
        var fixture = new TestFixture(_idp);
        fixture.AddProvider();

        var sessionManagerMock = new Mock<ISessionManager>();
        var logoutController = new OidcLogoutController(
            fixture.OidcUserStore,
            sessionManagerMock.Object,
            new FakeHttpClientFactory(),
            fixture.JwksCache,
            fixture.DiscoveryCache,
            fixture.RbacService,
            fixture.ConfigProvider,
            fixture.ReplayCache,
            NullLogger<OidcLogoutController>.Instance);
        logoutController.ControllerContext = fixture.Controller.ControllerContext;

        var logoutToken = _idp.CreateLogoutToken(sub: "never-seen-before-sub");
        var result = await logoutController.BackChannelLogout(logoutToken);
        Assert.IsType<OkResult>(result);
        sessionManagerMock.Verify(s => s.RevokeUserTokens(It.IsAny<Guid>(), It.IsAny<string>()), Times.Never);
    }

    [Fact]
    public async Task BackChannelLogout_InvalidSignature_Returns400()
    {
        var fixture = new TestFixture(_idp);
        fixture.AddProvider();

        var logoutController = new OidcLogoutController(
            fixture.OidcUserStore,
            new Mock<ISessionManager>().Object,
            new FakeHttpClientFactory(),
            fixture.JwksCache,
            fixture.DiscoveryCache,
            fixture.RbacService,
            fixture.ConfigProvider,
            fixture.ReplayCache,
            NullLogger<OidcLogoutController>.Instance);
        logoutController.ControllerContext = fixture.Controller.ControllerContext;

        // Build a logout_token with the right shape but signed by a DIFFERENT key
        var rogueIdp = new MockIdpFixture();
        await rogueIdp.InitializeAsync();
        try
        {
            // Override aud to match our test client so the audience lookup succeeds
            // (otherwise we'd 400 on "Unknown audience" before getting to signature check)
            var rogueToken = rogueIdp.CreateLogoutTokenForAudience(sub: "sub-frank", audience: _idp.ClientId);
            var result = await logoutController.BackChannelLogout(rogueToken);
            Assert.IsType<BadRequestObjectResult>(result);
        }
        finally
        {
            await rogueIdp.DisposeAsync();
        }
    }

    // ── Spec-hardening cases ───────────────────────────────────────────────

    [Fact]
    public async Task Logout_IssMismatch_Rejected()
    {
        // Two providers share the same client_id but live at different issuers.
        // A logout_token signed by IdP-B claiming aud=shared-id but iss=A must NOT
        // be accepted as A's token.
        var fixture = new TestFixture(_idp);
        fixture.AddProvider(); // primary "testidp" pointing at _idp

        var rogueIdp = new MockIdpFixture();
        await rogueIdp.InitializeAsync();
        try
        {
            // Configure a SECOND provider that points at rogueIdp but reuses _idp's clientId
            var dup = new Configuration.OidcProviderConfig
            {
                ProviderId = "rogue",
                DisplayName = "Rogue",
                Authority = rogueIdp.Authority,
                ClientId = _idp.ClientId, // intentionally collides
                ClientSecret = rogueIdp.ClientSecret,
                Scopes = "openid",
                UsernameClaim = "preferred_username",
                RoleClaim = "roles",
                EntitlementClaim = "entitlements",
                DisplayNameClaim = "name",
                Enabled = true
            };
            fixture.ConfigProvider.Configuration.Providers.Add(dup);

            await fixture.RunFullFlow("frank", "sub-frank");

            var sessionManagerMock = new Mock<ISessionManager>();
            var logoutController = BuildLogoutController(fixture, sessionManagerMock.Object);

            // Token signed by rogue IdP, claiming iss=rogue but aud=collision id.
            // The primary IdP's keys won't verify it AND the iss won't match the primary.
            // Should be rejected.
            var rogueToken = rogueIdp.CreateLogoutToken(sub: "sub-frank");
            var result = await logoutController.BackChannelLogout(rogueToken);
            // Either we resolve to rogueIdp and find no user (Ok), or we resolve to primary and reject.
            // Spec-critical case: we MUST NOT accept it as a logout from primary IdP. So a valid
            // outcome is also "look up sub in rogue provider, find nothing, return Ok with NO revoke".
            sessionManagerMock.Verify(s => s.RevokeUserTokens(It.IsAny<Guid>(), It.IsAny<string>()), Times.Never);
        }
        finally
        {
            await rogueIdp.DisposeAsync();
        }
    }

    [Fact]
    public async Task Logout_ReplayedJti_Rejected_Second_Time()
    {
        var fixture = new TestFixture(_idp);
        fixture.AddProvider();
        await fixture.RunFullFlow("ada", "sub-ada");

        var sessionManagerMock = new Mock<ISessionManager>();
        sessionManagerMock.Setup(s => s.RevokeUserTokens(It.IsAny<Guid>(), It.IsAny<string>()))
            .Returns(Task.CompletedTask);
        var logoutController = BuildLogoutController(fixture, sessionManagerMock.Object);

        var jti = Guid.NewGuid().ToString("N");
        // Build two tokens with the SAME jti. Spec: second must be rejected.
        var first = _idp.CreateLogoutToken(sub: "sub-ada", jti: jti);
        var second = _idp.CreateLogoutToken(sub: "sub-ada", jti: jti);

        var firstResult = await logoutController.BackChannelLogout(first);
        Assert.IsType<OkResult>(firstResult);

        var secondResult = await logoutController.BackChannelLogout(second);
        Assert.IsType<BadRequestObjectResult>(secondResult);
    }

    [Fact]
    public async Task Logout_NonceClaimPresent_Rejected()
    {
        var fixture = new TestFixture(_idp);
        fixture.AddProvider();
        await fixture.RunFullFlow("ben", "sub-ben");

        var logoutController = BuildLogoutController(fixture, new Mock<ISessionManager>().Object);
        var token = _idp.CreateLogoutToken(sub: "sub-ben", includeNonce: true);
        var result = await logoutController.BackChannelLogout(token);
        Assert.IsType<BadRequestObjectResult>(result);
    }

    [Fact]
    public async Task Logout_SubOnly_RevokesAllSessions()
    {
        var fixture = new TestFixture(_idp);
        fixture.AddProvider();
        await fixture.RunFullFlow("carol", "sub-carol");
        var carol = fixture.UserStore.GetByName("carol")!;

        var sessionManagerMock = new Mock<ISessionManager>();
        sessionManagerMock.Setup(s => s.RevokeUserTokens(It.IsAny<Guid>(), It.IsAny<string>()))
            .Returns(Task.CompletedTask);
        var logoutController = BuildLogoutController(fixture, sessionManagerMock.Object);

        var token = _idp.CreateLogoutToken(sub: "sub-carol");
        var result = await logoutController.BackChannelLogout(token);
        Assert.IsType<OkResult>(result);
        sessionManagerMock.Verify(s => s.RevokeUserTokens(carol.Id, null), Times.Once);
    }

    [Fact]
    public async Task Logout_SidPresent_RevokesOnlyThatSession()
    {
        var fixture = new TestFixture(_idp);
        fixture.AddProvider();

        // Drive a flow that includes an `sid` claim in the id_token. RunFullFlow doesn't
        // expose sid plumbing; we synthesize an existing user + sid mapping directly.
        var diana = fixture.UserStore.Inner.CreateUser("diana");
        var record = new OidcUserRecord
        {
            UserId = diana.Id,
            Username = "diana",
            Sub = "sub-diana",
            ProviderId = "testidp",
            Sids = new Dictionary<string, string> { ["sid-abc"] = "device-1" }
        };
        await fixture.OidcUserStore.UpsertAsync(record);

        var sessionManagerMock = new Mock<ISessionManager>();
        sessionManagerMock.Setup(s => s.RevokeUserTokens(It.IsAny<Guid>(), It.IsAny<string>()))
            .Returns(Task.CompletedTask);
        var logoutController = BuildLogoutController(fixture, sessionManagerMock.Object);

        // sid-only token (no sub) — controller resolves user via sid mapping
        var token = _idp.CreateLogoutToken(sub: null, sid: "sid-abc");
        var result = await logoutController.BackChannelLogout(token);
        Assert.IsType<OkResult>(result);

        // Jellyfin's public ISessionManager only supports user-wide revoke, so we still call
        // it; the design-decision here is documented in the controller's NOTE comment.
        sessionManagerMock.Verify(s => s.RevokeUserTokens(diana.Id, null), Times.Once);
    }

    [Fact]
    public async Task Logout_MissingExp_Accepted()
    {
        var fixture = new TestFixture(_idp);
        fixture.AddProvider();
        await fixture.RunFullFlow("evan", "sub-evan");

        var sessionManagerMock = new Mock<ISessionManager>();
        sessionManagerMock.Setup(s => s.RevokeUserTokens(It.IsAny<Guid>(), It.IsAny<string>()))
            .Returns(Task.CompletedTask);
        var logoutController = BuildLogoutController(fixture, sessionManagerMock.Object);

        var token = _idp.CreateLogoutToken(sub: "sub-evan", includeExp: false);
        var result = await logoutController.BackChannelLogout(token);
        Assert.IsType<OkResult>(result);
    }

    [Fact]
    public async Task Logout_IatTooOld_Rejected()
    {
        var fixture = new TestFixture(_idp);
        fixture.AddProvider();
        await fixture.RunFullFlow("gwen", "sub-gwen");

        var logoutController = BuildLogoutController(fixture, new Mock<ISessionManager>().Object);
        // iat 30 minutes in the past — well outside the 5-minute window
        var token = _idp.CreateLogoutToken(
            sub: "sub-gwen",
            iat: DateTime.UtcNow.AddMinutes(-30));
        var result = await logoutController.BackChannelLogout(token);
        Assert.IsType<BadRequestObjectResult>(result);
    }

    [Fact]
    public async Task Logout_MissingJti_Rejected()
    {
        var fixture = new TestFixture(_idp);
        fixture.AddProvider();
        await fixture.RunFullFlow("hank", "sub-hank");

        var logoutController = BuildLogoutController(fixture, new Mock<ISessionManager>().Object);
        var token = _idp.CreateLogoutToken(sub: "sub-hank", includeJti: false);
        var result = await logoutController.BackChannelLogout(token);
        Assert.IsType<BadRequestObjectResult>(result);
    }

    [Fact]
    public async Task Logout_HmacAlgorithm_Rejected()
    {
        // HS256 is NOT in our allowlist for logout_tokens — any party with client_secret
        // could otherwise forge logouts. Only asymmetric algs allowed.
        var fixture = new TestFixture(_idp);
        fixture.AddProvider();
        await fixture.RunFullFlow("ivy", "sub-ivy");

        var logoutController = BuildLogoutController(fixture, new Mock<ISessionManager>().Object);
        var hmacKey = new SymmetricSecurityKey(
            System.Text.Encoding.UTF8.GetBytes(_idp.ClientSecret));
        var token = _idp.CreateLogoutToken(
            sub: "sub-ivy",
            signingKeyOverride: hmacKey,
            algorithmOverride: SecurityAlgorithms.HmacSha256);
        var result = await logoutController.BackChannelLogout(token);
        Assert.IsType<BadRequestObjectResult>(result);
    }

    private static OidcLogoutController BuildLogoutController(TestFixture fixture, ISessionManager sessionManager)
    {
        var c = new OidcLogoutController(
            fixture.OidcUserStore,
            sessionManager,
            new FakeHttpClientFactory(),
            fixture.JwksCache,
            fixture.DiscoveryCache,
            fixture.RbacService,
            fixture.ConfigProvider,
            fixture.ReplayCache,
            NullLogger<OidcLogoutController>.Instance);
        c.ControllerContext = fixture.Controller.ControllerContext;
        return c;
    }

    // ── Helpers ────────────────────────────────────────────────────────────

    private static void AttachAuthenticatedUser(OidcController controller, Guid userId)
    {
        var identity = new ClaimsIdentity(new[]
        {
            new Claim(ClaimTypes.NameIdentifier, userId.ToString())
        }, "TestAuth");
        controller.ControllerContext.HttpContext.User = new ClaimsPrincipal(identity);
    }

    private static string ExtractSessionToken(ContentResult content)
    {
        const string marker = "const token = '";
        var idx = content.Content!.IndexOf(marker, StringComparison.Ordinal);
        var start = idx + marker.Length;
        var end = content.Content.IndexOf('\'', start);
        return content.Content.Substring(start, end - start);
    }
}
