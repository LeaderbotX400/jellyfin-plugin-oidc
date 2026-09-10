using System;
using System.Linq;
using System.Threading.Tasks;
using System.Web;
using Microsoft.AspNetCore.Mvc;
using Moq;
using Xunit;

namespace Jellyfin.Plugin.OIDC.Integration.Tests;

/// <summary>
/// Drives the Quick Connect bridge through the real OIDC flow against the WireMock IdP. The
/// branch selection in the callback is the crux of the whole feature and is exactly what the
/// implementation this was modelled on leaves untested.
/// </summary>
public class QuickConnectFlowTests : IClassFixture<MockIdpFixture>
{
    private readonly MockIdpFixture _idp;

    public QuickConnectFlowTests(MockIdpFixture idp) => _idp = idp;

    /// <summary>Runs Start → IdP → Callback and returns the callback's rendered HTML.</summary>
    private static async Task<string> RunToCallbackHtml(TestFixture fixture, bool quickConnect, string username)
    {
        var start = quickConnect
            ? await fixture.Controller.QuickConnectStart("testidp")
            : await fixture.Controller.Start("testidp");

        var redirect = Assert.IsType<RedirectResult>(start);
        var query = HttpUtility.ParseQueryString(new Uri(redirect.Url).Query);
        TestFixture.PropagateCookies(fixture.Controller);

        fixture.Idp.EnqueueTokenResponse(
            sub: "sub-" + username, username: username, nonce: query["nonce"]!);

        var callback = await fixture.Controller.Callback(
            "testidp", code: $"code-{Guid.NewGuid():N}", state: query["state"]!);

        return Assert.IsType<ContentResult>(callback).Content!;
    }

    [Fact]
    public async Task QuickConnectFlow_CallbackRendersTheCodeEntryPage()
    {
        var fixture = new TestFixture(_idp);
        fixture.AddProvider();

        var html = await RunToCallbackHtml(fixture, quickConnect: true, "qcuser");

        Assert.Contains("Enter your code", html, StringComparison.Ordinal);
        Assert.Contains("QuickConnect/Authorize", html, StringComparison.Ordinal);
        Assert.Contains("id=\"code\"", html, StringComparison.Ordinal);
    }

    /// <summary>
    /// The ordinary login flow must be completely unaffected — it still gets the session-establishing
    /// page, not the code form.
    /// </summary>
    [Fact]
    public async Task NormalFlow_StillRendersTheSessionPage()
    {
        var fixture = new TestFixture(_idp);
        fixture.AddProvider();

        var html = await RunToCallbackHtml(fixture, quickConnect: false, "webuser");

        Assert.Contains("jellyfin_credentials", html, StringComparison.Ordinal);
        Assert.DoesNotContain("QuickConnect/Authorize", html, StringComparison.Ordinal);
    }

    /// <summary>
    /// The bridge browser is a helper for signing in a television, not a device being signed in.
    /// Writing Jellyfin's credentials to its localStorage would leave a stray logged-in session
    /// on someone's phone.
    /// </summary>
    [Fact]
    public async Task QuickConnectPage_DoesNotPersistCredentialsInTheBrowser()
    {
        var fixture = new TestFixture(_idp);
        fixture.AddProvider();

        var html = await RunToCallbackHtml(fixture, quickConnect: true, "qcuser2");

        Assert.DoesNotContain("localStorage.setItem", html, StringComparison.Ordinal);
        Assert.DoesNotContain("jellyfin_credentials", html, StringComparison.Ordinal);
    }

    /// <summary>
    /// The code must never travel through the OIDC redirect — that is the device-code phishing
    /// vector this design exists to avoid.
    /// </summary>
    [Fact]
    public async Task QuickConnectStart_DoesNotPutAnyCodeInTheAuthorizeUrl()
    {
        var fixture = new TestFixture(_idp);
        fixture.AddProvider();

        var redirect = Assert.IsType<RedirectResult>(await fixture.Controller.QuickConnectStart("testidp"));
        var query = HttpUtility.ParseQueryString(new Uri(redirect.Url).Query);

        Assert.All(query.AllKeys, k =>
            Assert.DoesNotContain("code", (k ?? string.Empty).Replace("code_challenge", string.Empty, StringComparison.Ordinal), StringComparison.OrdinalIgnoreCase));

        // PKCE must still be present — the bridge reuses the login flow, it does not weaken it.
        Assert.NotNull(query["code_challenge"]);
        Assert.Equal("S256", query["code_challenge_method"]);
        Assert.NotNull(query["nonce"]);
        Assert.NotNull(query["state"]);
    }

    [Fact]
    public async Task QuickConnectStart_RejectsAnUnknownProvider()
    {
        var fixture = new TestFixture(_idp);
        fixture.AddProvider();

        Assert.IsType<NotFoundObjectResult>(await fixture.Controller.QuickConnectStart("nope"));
    }

    [Fact]
    public void Landing_ListsTheEnabledProvider()
    {
        var fixture = new TestFixture(_idp);
        fixture.AddProvider();

        var html = Assert.IsType<ContentResult>(fixture.Controller.QuickConnectLanding()).Content!;

        Assert.Contains("Start/testidp", html, StringComparison.Ordinal);
    }

    [Fact]
    public void Landing_ReportsQuickConnectBeingDisabledServerWide()
    {
        var fixture = new TestFixture(_idp);
        fixture.AddProvider();
        fixture.QuickConnectMock.SetupGet(q => q.IsEnabled).Returns(false);

        var html = Assert.IsType<ContentResult>(fixture.Controller.QuickConnectLanding()).Content!;

        Assert.Contains("Quick Connect is turned off", html, StringComparison.Ordinal);
    }

    /// <summary>Unauthenticated callers get 401 — the endpoint's whole security model.</summary>
    [Fact]
    public async Task Authorize_WithoutASession_IsUnauthorized()
    {
        var fixture = new TestFixture(_idp);
        fixture.AddProvider();

        var result = await fixture.Controller.QuickConnectAuthorize(
            new Jellyfin.Plugin.OIDC.Api.QuickConnectAuthorizeRequest { Code = "123456" });

        Assert.IsType<UnauthorizedObjectResult>(result);
        fixture.QuickConnectMock.Verify(
            q => q.AuthorizeRequest(It.IsAny<Guid>(), It.IsAny<string>()), Times.Never);
    }
}
