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
using Moq;
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
    public async Task Callback_RequiredAmrMissing_Returns401()
    {
        var fixture = new TestFixture(_idp);
        var provider = fixture.AddProvider();
        provider.RequiredAmrValues = new List<string> { "mfa" };

        var startResult = await fixture.Controller.Start(ProviderId);
        var redirect = Assert.IsType<RedirectResult>(startResult);
        var stateValue = ExtractStateFromUrl(redirect.Url);
        var nonceValue = ExtractParamFromUrl(redirect.Url, "nonce");
        TestFixture.PropagateCookies(fixture.Controller);

        _idp.EnqueueTokenResponse(
            sub: "user-noamr",
            username: "noamr",
            nonce: nonceValue,
            amr: new[] { "pwd" });

        var callbackResult = await fixture.Controller.Callback(ProviderId, code: "test-code", state: stateValue);
        Assert.IsType<UnauthorizedObjectResult>(callbackResult);
    }

    [Fact]
    public async Task Callback_RequiredAmrPresent_AllowsLogin()
    {
        var fixture = new TestFixture(_idp);
        var provider = fixture.AddProvider();
        provider.RequiredAmrValues = new List<string> { "mfa", "otp" };

        var startResult = await fixture.Controller.Start(ProviderId);
        var redirect = Assert.IsType<RedirectResult>(startResult);
        var stateValue = ExtractStateFromUrl(redirect.Url);
        var nonceValue = ExtractParamFromUrl(redirect.Url, "nonce");
        TestFixture.PropagateCookies(fixture.Controller);

        _idp.EnqueueTokenResponse(
            sub: "user-mfa",
            username: "mfauser",
            nonce: nonceValue,
            amr: new[] { "pwd", "otp" });

        var callbackResult = await fixture.Controller.Callback(ProviderId, code: "test-code", state: stateValue);
        Assert.IsNotType<UnauthorizedObjectResult>(callbackResult);
    }

    [Fact]
    public async Task Callback_RequiredAmrNoClaimAtAll_Returns401()
    {
        // Token entirely lacks an amr claim. Must be rejected, not silently allowed.
        var fixture = new TestFixture(_idp);
        var provider = fixture.AddProvider();
        provider.RequiredAmrValues = new List<string> { "mfa" };

        var startResult = await fixture.Controller.Start(ProviderId);
        var redirect = Assert.IsType<RedirectResult>(startResult);
        var stateValue = ExtractStateFromUrl(redirect.Url);
        var nonceValue = ExtractParamFromUrl(redirect.Url, "nonce");
        TestFixture.PropagateCookies(fixture.Controller);

        _idp.EnqueueTokenResponse(
            sub: "user-noclaim", username: "noclaim", nonce: nonceValue);
        // No amr passed at all.

        var callbackResult = await fixture.Controller.Callback(ProviderId, code: "test-code", state: stateValue);
        Assert.IsType<UnauthorizedObjectResult>(callbackResult);
    }

    [Fact]
    public async Task Callback_RequiredAmr_CaseInsensitive_Allowed()
    {
        // RFC 8176 AMR values are case-insensitive in practice across IdPs;
        // we treat them so to avoid silent failures over casing differences.
        var fixture = new TestFixture(_idp);
        var provider = fixture.AddProvider();
        provider.RequiredAmrValues = new List<string> { "MFA" };

        var startResult = await fixture.Controller.Start(ProviderId);
        var redirect = Assert.IsType<RedirectResult>(startResult);
        var stateValue = ExtractStateFromUrl(redirect.Url);
        var nonceValue = ExtractParamFromUrl(redirect.Url, "nonce");
        TestFixture.PropagateCookies(fixture.Controller);

        _idp.EnqueueTokenResponse(
            sub: "user-case", username: "caseuser", nonce: nonceValue,
            amr: new[] { "mfa" });

        var callbackResult = await fixture.Controller.Callback(ProviderId, code: "test-code", state: stateValue);
        Assert.IsNotType<UnauthorizedObjectResult>(callbackResult);
    }

    [Fact]
    public async Task Callback_RequiredAcr_CaseSensitive_RejectsCaseChange()
    {
        // ACR values are spec'd as case-sensitive URIs. A casing mismatch must reject.
        var fixture = new TestFixture(_idp);
        var provider = fixture.AddProvider();
        provider.RequiredAcrValues = new List<string> { "urn:mace:incommon:iap:silver" };

        var startResult = await fixture.Controller.Start(ProviderId);
        var redirect = Assert.IsType<RedirectResult>(startResult);
        var stateValue = ExtractStateFromUrl(redirect.Url);
        var nonceValue = ExtractParamFromUrl(redirect.Url, "nonce");
        TestFixture.PropagateCookies(fixture.Controller);

        _idp.EnqueueTokenResponse(
            sub: "user-acrcase", username: "acrcase", nonce: nonceValue,
            acr: "URN:MACE:INCOMMON:IAP:SILVER");

        var callbackResult = await fixture.Controller.Callback(ProviderId, code: "test-code", state: stateValue);
        Assert.IsType<UnauthorizedObjectResult>(callbackResult);
    }

    [Fact]
    public async Task Callback_RequiredAmrAndAcr_BothMustPass()
    {
        // Both lists set: AMR matches but ACR doesn't → must reject.
        var fixture = new TestFixture(_idp);
        var provider = fixture.AddProvider();
        provider.RequiredAmrValues = new List<string> { "mfa" };
        provider.RequiredAcrValues = new List<string> { "high" };

        var startResult = await fixture.Controller.Start(ProviderId);
        var redirect = Assert.IsType<RedirectResult>(startResult);
        var stateValue = ExtractStateFromUrl(redirect.Url);
        var nonceValue = ExtractParamFromUrl(redirect.Url, "nonce");
        TestFixture.PropagateCookies(fixture.Controller);

        _idp.EnqueueTokenResponse(
            sub: "u", username: "u", nonce: nonceValue,
            amr: new[] { "mfa" }, acr: "low");

        var callbackResult = await fixture.Controller.Callback(ProviderId, code: "test-code", state: stateValue);
        Assert.IsType<UnauthorizedObjectResult>(callbackResult);
    }

    [Fact]
    public async Task Callback_AmrRejection_WritesAuditEntry()
    {
        // Regression guard: rejected logins MUST surface in Jellyfin's activity log,
        // otherwise admins have no way to see brute-force or misconfigured-IdP traffic.
        var fixture = new TestFixture(_idp);
        var provider = fixture.AddProvider();
        provider.RequiredAmrValues = new List<string> { "mfa" };

        var startResult = await fixture.Controller.Start(ProviderId);
        var redirect = Assert.IsType<RedirectResult>(startResult);
        var stateValue = ExtractStateFromUrl(redirect.Url);
        var nonceValue = ExtractParamFromUrl(redirect.Url, "nonce");
        TestFixture.PropagateCookies(fixture.Controller);

        _idp.EnqueueTokenResponse(
            sub: "u", username: "u", nonce: nonceValue, amr: new[] { "pwd" });

        await fixture.Controller.Callback(ProviderId, code: "test-code", state: stateValue);

        fixture.ActivityManagerMock.Verify(m => m.CreateAsync(
            It.Is<Jellyfin.Database.Implementations.Entities.ActivityLog>(
                a => a.Type == "OidcLoginFailure")),
            Times.AtLeastOnce);
    }

    [Fact]
    public async Task Callback_EmptyAmrConfig_DoesNotEnforce()
    {
        // Regression guard: empty config must be a no-op, even on tokens with no amr claim.
        var fixture = new TestFixture(_idp);
        fixture.AddProvider();

        await fixture.RunFullFlow("noamr-noconfig", "sub-noamr");
        Assert.NotNull(fixture.UserStore.GetByName("noamr-noconfig"));
    }

    [Fact]
    public async Task Callback_RequiredAcrMismatch_Returns401()
    {
        var fixture = new TestFixture(_idp);
        var provider = fixture.AddProvider();
        provider.RequiredAcrValues = new List<string> { "urn:mace:incommon:iap:silver" };

        var startResult = await fixture.Controller.Start(ProviderId);
        var redirect = Assert.IsType<RedirectResult>(startResult);
        var stateValue = ExtractStateFromUrl(redirect.Url);
        var nonceValue = ExtractParamFromUrl(redirect.Url, "nonce");
        TestFixture.PropagateCookies(fixture.Controller);

        _idp.EnqueueTokenResponse(
            sub: "user-acr",
            username: "acruser",
            nonce: nonceValue,
            acr: "urn:mace:incommon:iap:bronze");

        var callbackResult = await fixture.Controller.Callback(ProviderId, code: "test-code", state: stateValue);
        Assert.IsType<UnauthorizedObjectResult>(callbackResult);
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
    // WP-A: RolesFromAccessToken tests
    // ────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Callback_RolesOnlyInAccessToken_FlagOff_UserGetsNoRoles()
    {
        // Flag OFF (default): even if the access token carries roles, they must be ignored.
        var fixture = new TestFixture(_idp);
        fixture.ConfigProvider.Configuration.RoleMappings = new List<RoleMapping>
        {
            new() { RoleName = "atonly-role", IsAdmin = true, EnableMediaPlayback = true }
        };
        var provider = fixture.AddProvider();
        // Explicitly ensure flag is off (default)
        provider.RolesFromAccessToken = false;

        var startResult = await fixture.Controller.Start(ProviderId);
        var redirect = Assert.IsType<RedirectResult>(startResult);
        var stateValue = ExtractStateFromUrl(redirect.Url);
        var nonceValue = ExtractParamFromUrl(redirect.Url, "nonce");
        TestFixture.PropagateCookies(fixture.Controller);

        _idp.EnqueueTokenResponseWithAccessTokenRoles(
            sub: "at-flag-off-sub",
            username: "atflagoff",
            nonce: nonceValue,
            accessTokenRoles: new[] { "atonly-role" });

        var callbackResult = await fixture.Controller.Callback(ProviderId, code: "at-off-code", state: stateValue);
        Assert.IsType<ContentResult>(callbackResult);

        var sessionToken = ExtractSessionTokenFromCallbackHtml((ContentResult)callbackResult);
        await fixture.Controller.Authenticate(ProviderId, new AuthenticateRequest { Token = sessionToken, DeviceId = "dev-at-off" });

        var user = fixture.UserStore.GetByName("atflagoff");
        Assert.NotNull(user);
        // Flag was off so the access token roles should NOT have been applied → not admin
        Assert.False(HasPermission(user!, PermissionKind.IsAdministrator));
    }

    [Fact]
    public async Task Callback_RolesOnlyInAccessToken_FlagOn_ValidToken_UserGetsRoles()
    {
        // Flag ON + correctly signed access token: roles from access token must be applied.
        var fixture = new TestFixture(_idp);
        fixture.ConfigProvider.Configuration.RoleMappings = new List<RoleMapping>
        {
            new() { RoleName = "atonly-role", IsAdmin = true, EnableMediaPlayback = true }
        };
        var provider = fixture.AddProvider();
        provider.RolesFromAccessToken = true;

        var startResult = await fixture.Controller.Start(ProviderId);
        var redirect = Assert.IsType<RedirectResult>(startResult);
        var stateValue = ExtractStateFromUrl(redirect.Url);
        var nonceValue = ExtractParamFromUrl(redirect.Url, "nonce");
        TestFixture.PropagateCookies(fixture.Controller);

        // Access token signed with the IdP's canonical key → validation succeeds
        _idp.EnqueueTokenResponseWithAccessTokenRoles(
            sub: "at-flag-on-sub",
            username: "atflagon",
            nonce: nonceValue,
            accessTokenRoles: new[] { "atonly-role" });

        var callbackResult = await fixture.Controller.Callback(ProviderId, code: "at-on-code", state: stateValue);
        Assert.IsType<ContentResult>(callbackResult);

        var sessionToken = ExtractSessionTokenFromCallbackHtml((ContentResult)callbackResult);
        await fixture.Controller.Authenticate(ProviderId, new AuthenticateRequest { Token = sessionToken, DeviceId = "dev-at-on" });

        var user = fixture.UserStore.GetByName("atflagon");
        Assert.NotNull(user);
        // Flag was on and AT was valid → roles should be applied → admin
        Assert.True(HasPermission(user!, PermissionKind.IsAdministrator));
    }

    [Fact]
    public async Task Callback_RolesOnlyInAccessToken_FlagOn_WrongKey_LoginSucceedsNoRoles()
    {
        // Flag ON but access token signed with a DIFFERENT key → validation fails;
        // login must still succeed (graceful degradation) but no roles from AT.
        var fixture = new TestFixture(_idp);
        fixture.ConfigProvider.Configuration.RoleMappings = new List<RoleMapping>
        {
            new() { RoleName = "atonly-role", IsAdmin = true, EnableMediaPlayback = true }
        };
        var provider = fixture.AddProvider();
        provider.RolesFromAccessToken = true;

        var startResult = await fixture.Controller.Start(ProviderId);
        var redirect = Assert.IsType<RedirectResult>(startResult);
        var stateValue = ExtractStateFromUrl(redirect.Url);
        var nonceValue = ExtractParamFromUrl(redirect.Url, "nonce");
        TestFixture.PropagateCookies(fixture.Controller);

        // Generate a separate RSA key that the IdP's JWKS doesn't know about
        var wrongKey = new Microsoft.IdentityModel.Tokens.RsaSecurityKey(
            System.Security.Cryptography.RSA.Create(2048));

        _idp.EnqueueTokenResponseWithAccessTokenRoles(
            sub: "at-wrongkey-sub",
            username: "atwrongkey",
            nonce: nonceValue,
            accessTokenRoles: new[] { "atonly-role" },
            accessTokenSigningKey: wrongKey);

        var callbackResult = await fixture.Controller.Callback(ProviderId, code: "at-wrongkey-code", state: stateValue);
        // Login must still succeed — bad AT signature is non-fatal
        Assert.IsType<ContentResult>(callbackResult);

        var sessionToken = ExtractSessionTokenFromCallbackHtml((ContentResult)callbackResult);
        await fixture.Controller.Authenticate(ProviderId, new AuthenticateRequest { Token = sessionToken, DeviceId = "dev-at-wk" });

        var user = fixture.UserStore.GetByName("atwrongkey");
        Assert.NotNull(user);
        // AT validation failed → no roles → not admin
        Assert.False(HasPermission(user!, PermissionKind.IsAdministrator));
    }

    [Fact]
    public async Task Callback_SecurityHeaders_IncludeFrameProtection()
    {
        // The callback page must include X-Frame-Options: DENY and CSP frame-ancestors 'none'
        // to prevent clickjacking via iframe embedding.
        var fixture = new TestFixture(_idp);
        fixture.AddProvider();

        var startResult = await fixture.Controller.Start(ProviderId);
        var redirect = Assert.IsType<RedirectResult>(startResult);
        var stateValue = ExtractStateFromUrl(redirect.Url);
        var nonceValue = ExtractParamFromUrl(redirect.Url, "nonce");
        TestFixture.PropagateCookies(fixture.Controller);

        _idp.EnqueueTokenResponse(sub: "frame-sub", username: "frameuser", nonce: nonceValue);

        await fixture.Controller.Callback(ProviderId, code: "frame-code", state: stateValue);

        var headers = fixture.Controller.ControllerContext.HttpContext.Response.Headers;
        var xfo = headers["X-Frame-Options"].ToString();
        var csp = headers["Content-Security-Policy"].ToString();

        Assert.Equal("DENY", xfo);
        Assert.Contains("frame-ancestors 'none'", csp);
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
