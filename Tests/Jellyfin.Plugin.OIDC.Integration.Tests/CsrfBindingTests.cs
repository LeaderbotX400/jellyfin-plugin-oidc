using System;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;
using Jellyfin.Plugin.OIDC.Api;
using Microsoft.AspNetCore.Mvc;
using Xunit;

namespace Jellyfin.Plugin.OIDC.Integration.Tests;

/// <summary>
/// TASK-06 verification: the OIDC /Callback handler must reject any request that doesn't
/// present the per-browser CSRF binding cookie issued at /Start. And LinkStart must be
/// POST-only (no GET) with JSON Content-Type required.
/// </summary>
public sealed class CsrfBindingTests : IClassFixture<MockIdpFixture>
{
    private const string ProviderId = "testidp";
    private readonly MockIdpFixture _idp;

    public CsrfBindingTests(MockIdpFixture idp) => _idp = idp;

    [Fact]
    public async Task Callback_WithoutCsrfCookie_IsRejected()
    {
        var fixture = new TestFixture(_idp);
        fixture.AddProvider();

        var startResult = await fixture.Controller.Start(ProviderId);
        var redirect = Assert.IsType<RedirectResult>(startResult);
        var state = HttpUtility.ParseQueryString(new Uri(redirect.Url).Query)["state"]!;
        var nonce = HttpUtility.ParseQueryString(new Uri(redirect.Url).Query)["nonce"]!;

        // DO NOT propagate cookies — simulate a cross-site forced callback.
        // Drop any Set-Cookie so Request.Cookies stays empty.
        fixture.Controller.ControllerContext.HttpContext.Response.Headers.Remove("Set-Cookie");

        _idp.EnqueueTokenResponse(sub: "u", username: "u", nonce: nonce);

        var callbackResult = await fixture.Controller.Callback(ProviderId, code: "code", state: state);
        var bad = Assert.IsType<BadRequestObjectResult>(callbackResult);
        Assert.Contains("session", (bad.Value as string ?? string.Empty), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Callback_WithCorrectCsrfCookie_Succeeds()
    {
        var fixture = new TestFixture(_idp);
        fixture.AddProvider();

        var startResult = await fixture.Controller.Start(ProviderId);
        var redirect = Assert.IsType<RedirectResult>(startResult);
        var state = HttpUtility.ParseQueryString(new Uri(redirect.Url).Query)["state"]!;
        var nonce = HttpUtility.ParseQueryString(new Uri(redirect.Url).Query)["nonce"]!;

        // Confirm /Start actually issued a Set-Cookie for the binding token
        var setCookie = fixture.Controller.ControllerContext.HttpContext.Response.Headers["Set-Cookie"].ToString();
        Assert.Contains("oidc-csrf", setCookie);
        Assert.Contains("httponly", setCookie, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("samesite=lax", setCookie, StringComparison.OrdinalIgnoreCase);
        // Test fixture uses https://jellyfin.test so __Host- prefix should be in play.
        Assert.Contains("__Host-", setCookie);

        TestFixture.PropagateCookies(fixture.Controller);

        _idp.EnqueueTokenResponse(sub: "csrf-ok", username: "csrf-ok", nonce: nonce);
        var callbackResult = await fixture.Controller.Callback(ProviderId, code: "code", state: state);
        Assert.IsType<ContentResult>(callbackResult);
    }

    [Fact]
    public async Task LinkStart_GetVerbIsNotBoundByController()
    {
        // LinkStart is now [HttpPost]. The runtime routing layer rejects a GET with 405,
        // but at the controller-method level we just verify the attribute is POST.
        var method = typeof(OidcController).GetMethod(nameof(OidcController.LinkStart));
        Assert.NotNull(method);
        var attrs = method!.GetCustomAttributes(typeof(Microsoft.AspNetCore.Mvc.HttpPostAttribute), inherit: false);
        Assert.NotEmpty(attrs);
        var hasGet = method.GetCustomAttributes(typeof(Microsoft.AspNetCore.Mvc.HttpGetAttribute), inherit: false);
        Assert.Empty(hasGet);
        // And it must require JSON Content-Type so cross-origin form posts can't reach it.
        var consumes = method.GetCustomAttributes(typeof(Microsoft.AspNetCore.Mvc.ConsumesAttribute), inherit: false);
        Assert.NotEmpty(consumes);
    }

    [Fact]
    public async Task LinkStart_PostFromAuthenticatedUser_Succeeds()
    {
        var fixture = new TestFixture(_idp);
        fixture.AddProvider();
        var user = fixture.UserStore.Inner.CreateUser("link-target");
        var identity = new ClaimsIdentity(
            new[] { new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()) }, "Test");
        fixture.Controller.ControllerContext.HttpContext.User = new ClaimsPrincipal(identity);

        var result = await fixture.Controller.LinkStart(ProviderId);
        Assert.IsType<RedirectResult>(result);
    }
}
