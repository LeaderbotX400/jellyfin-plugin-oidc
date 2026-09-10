using System;
using Jellyfin.Plugin.OIDC.Services;
using Xunit;

namespace Jellyfin.Plugin.OIDC.Tests;

/// <summary>
/// Covers the HTML rewriting in <see cref="LoginButtonInjectionMiddleware"/>. This patches a page
/// the plugin does not own, so the behaviour that matters most is what happens when the page is
/// not the shape we expect: it must degrade to "no button", never to a broken web UI.
/// </summary>
public sealed class LoginButtonInjectionTests
{
    private const string RealShell =
        "<!doctype html><html dir=\"ltr\"><head><meta charset=\"utf-8\">" +
        "<link rel=\"manifest\" href=\"manifest.json\"></head><body><div id=\"reactRoot\"></div></body></html>";

    [Fact]
    public void InsertsScriptImmediatelyAfterHead()
    {
        var result = LoginButtonInjectionMiddleware.Inject(RealShell);

        Assert.NotNull(result);
        Assert.Contains("<head><script id=\"oidc-sso-injected\"", result, StringComparison.Ordinal);
        Assert.Contains("src=\"../sso/OIDC/LoginButtons?v=", result, StringComparison.Ordinal);
        // Relative so it resolves correctly under a configured base URL without reading it.
        Assert.DoesNotContain("src=\"/sso/", result, StringComparison.Ordinal);
    }

    [Fact]
    public void PreservesTheOriginalDocument()
    {
        var result = LoginButtonInjectionMiddleware.Inject(RealShell)!;

        Assert.Contains("<div id=\"reactRoot\"></div>", result, StringComparison.Ordinal);
        Assert.Contains("<link rel=\"manifest\" href=\"manifest.json\">", result, StringComparison.Ordinal);
        Assert.StartsWith("<!doctype html>", result, StringComparison.Ordinal);
    }

    [Fact]
    public void FallsBackToBodyCloseWhenThereIsNoHead()
    {
        var result = LoginButtonInjectionMiddleware.Inject("<html><body><p>hi</p></body></html>");

        Assert.NotNull(result);
        Assert.Contains("oidc-sso-injected", result, StringComparison.Ordinal);
        Assert.Contains("</body>", result, StringComparison.Ordinal);
    }

    [Fact]
    public void FallsBackToBodyOpenWhenThereIsNoClosingBody()
    {
        var result = LoginButtonInjectionMiddleware.Inject("<html><body class=\"x\"><p>hi</p>");

        Assert.NotNull(result);
        Assert.Contains("oidc-sso-injected", result, StringComparison.Ordinal);
    }

    /// <summary>Null is the signal to serve the upstream bytes untouched.</summary>
    [Theory]
    [InlineData("")]
    [InlineData("not html at all")]
    [InlineData("{\"json\":true}")]
    public void ReturnsNullWhenThereIsNoInsertionPoint(string html)
        => Assert.Null(LoginButtonInjectionMiddleware.Inject(html));

    /// <summary>A proxy replaying our own output must not stack a second copy of the tag.</summary>
    [Fact]
    public void DoesNotInjectTwice()
    {
        var once = LoginButtonInjectionMiddleware.Inject(RealShell)!;
        var twice = LoginButtonInjectionMiddleware.Inject(once)!;

        Assert.Equal(once, twice);
        var first = twice.IndexOf("oidc-sso-injected", StringComparison.Ordinal);
        Assert.Equal(-1, twice.IndexOf("oidc-sso-injected", first + 1, StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("/web")]
    [InlineData("/web/")]
    [InlineData("/web/index.html")]
    [InlineData("/jellyfin/web")]          // behind a base URL
    [InlineData("/jellyfin/web/index.html")]
    [InlineData("/WEB/INDEX.HTML")]
    public void RecognisesTheShellPaths(string path)
        => Assert.True(LoginButtonInjectionMiddleware.IsIndexPath(path), path);

    [Theory]
    [InlineData("/web/main.jellyfin.bundle.js")]
    [InlineData("/web/manifest.json")]
    [InlineData("/System/Info/Public")]
    [InlineData("/sso/OIDC/LoginButtons")]
    [InlineData("/webhooks")]
    [InlineData("/")]
    public void IgnoresEverythingElse(string path)
        => Assert.False(LoginButtonInjectionMiddleware.IsIndexPath(path), path);
}
