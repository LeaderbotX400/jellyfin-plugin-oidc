using System;
using System.Collections.Generic;
using System.Threading;
using Jellyfin.Plugin.OIDC.Api;
using Jellyfin.Plugin.OIDC.Configuration;
using Jellyfin.Plugin.OIDC.Services;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Jellyfin.Plugin.OIDC.Tests;

/// <summary>
/// The Quick Connect landing page. It renders admin-supplied provider names and colours, so the
/// escaping matters as much as the content.
/// </summary>
public sealed class QuickConnectLandingHtmlTests
{
    private static OidcProviderConfig Provider(string id, string name, string colour = "#fd4b2d")
        => new() { ProviderId = id, DisplayName = name, ButtonColor = colour, Enabled = true };

    [Fact]
    public void ListsEachEnabledProviderWithARelativeStartLink()
    {
        var html = OidcController.BuildQuickConnectLandingHtml(
            new[] { Provider("authentik", "Authentik"), Provider("keycloak", "Keycloak") }, true);

        Assert.Contains("href=\"Start/authentik\"", html, StringComparison.Ordinal);
        Assert.Contains("href=\"Start/keycloak\"", html, StringComparison.Ordinal);
        Assert.Contains("Sign in with Authentik", html, StringComparison.Ordinal);
    }

    [Fact]
    public void SaysSoWhenQuickConnectIsDisabledServerWide()
    {
        var html = OidcController.BuildQuickConnectLandingHtml(new[] { Provider("a", "A") }, false);

        Assert.Contains("Quick Connect is turned off", html, StringComparison.Ordinal);
        Assert.DoesNotContain("href=\"Start/a\"", html, StringComparison.Ordinal);
    }

    [Fact]
    public void SaysSoWhenNoProvidersAreEnabled()
    {
        var html = OidcController.BuildQuickConnectLandingHtml(Array.Empty<OidcProviderConfig>(), true);

        Assert.Contains("No single sign-on providers are enabled", html, StringComparison.Ordinal);
    }

    /// <summary>DisplayName is admin free text and must not be able to close the tag it sits in.</summary>
    [Fact]
    public void EscapesHostileDisplayNames()
    {
        var html = OidcController.BuildQuickConnectLandingHtml(
            new[] { Provider("p1", "</a><script>alert(1)</script>") }, true);

        Assert.DoesNotContain("<script>alert(1)</script>", html, StringComparison.Ordinal);
        Assert.Contains("&lt;script&gt;", html, StringComparison.Ordinal);
    }

    /// <summary>
    /// ButtonColor is admin-supplied and unvalidated. It must stay inside one CSS property value —
    /// a value like <c>red;} body{display:none</c> must not be able to open a new rule.
    /// </summary>
    [Fact]
    public void EscapesHostileButtonColours()
    {
        var html = OidcController.BuildQuickConnectLandingHtml(
            new[] { Provider("p1", "P", "red\"><script>alert(1)</script>") }, true);

        Assert.DoesNotContain("<script>alert(1)</script>", html, StringComparison.Ordinal);
        Assert.Contains("&quot;", html, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("<b>", "&lt;b&gt;")]
    [InlineData("a&b", "a&amp;b")]
    [InlineData("\"q\"", "&quot;q&quot;")]
    [InlineData("it's", "it&#39;s")]
    [InlineData(null, "")]
    [InlineData("", "")]
    public void HtmlEncodeCoversTheDangerousCharacters(string? input, string expected)
        => Assert.Equal(expected, OidcController.HtmlEncode(input));
}

/// <summary>
/// The per-user wrong-code cap. This is the control the reference implementation lacks entirely,
/// and it is the only thing standing between a signed-in low-privilege user and grinding the
/// six-digit code space to hijack someone else's pending Quick Connect request.
/// </summary>
public sealed class QuickConnectAttemptLimiterTests
{
    private static QuickConnectAttemptLimiter Create()
        => new(NullLogger<QuickConnectAttemptLimiter>.Instance);

    [Fact]
    public void AllowsAttemptsUpToTheCap()
    {
        var limiter = Create();
        var user = Guid.NewGuid();

        for (var i = 0; i < QuickConnectAttemptLimiter.MaxFailures - 1; i++)
        {
            limiter.RecordFailure(user);
            Assert.False(limiter.IsBlocked(user, out _), $"blocked after {i + 1} failures");
        }
    }

    [Fact]
    public void BlocksOnceTheCapIsReached()
    {
        var limiter = Create();
        var user = Guid.NewGuid();

        for (var i = 0; i < QuickConnectAttemptLimiter.MaxFailures; i++)
        {
            limiter.RecordFailure(user);
        }

        Assert.True(limiter.IsBlocked(user, out var retryAfter));
        Assert.True(retryAfter > TimeSpan.Zero);
    }

    [Fact]
    public void AnUnknownUserIsNeverBlocked()
        => Assert.False(Create().IsBlocked(Guid.NewGuid(), out _));

    /// <summary>A correct code after some fumbling must not leave the user throttled.</summary>
    [Fact]
    public void SuccessClearsTheCounter()
    {
        var limiter = Create();
        var user = Guid.NewGuid();

        for (var i = 0; i < QuickConnectAttemptLimiter.MaxFailures; i++)
        {
            limiter.RecordFailure(user);
        }

        Assert.True(limiter.IsBlocked(user, out _));

        limiter.RecordSuccess(user);

        Assert.False(limiter.IsBlocked(user, out _));
    }

    /// <summary>
    /// Keyed by user, so one user exhausting their attempts must not deny service to anyone else —
    /// the flaw in throttling this by IP, where one NAT can starve a household.
    /// </summary>
    [Fact]
    public void OneUsersFailuresDoNotAffectAnother()
    {
        var limiter = Create();
        var noisy = Guid.NewGuid();
        var innocent = Guid.NewGuid();

        for (var i = 0; i < QuickConnectAttemptLimiter.MaxFailures * 2; i++)
        {
            limiter.RecordFailure(noisy);
        }

        Assert.True(limiter.IsBlocked(noisy, out _));
        Assert.False(limiter.IsBlocked(innocent, out _));
    }

    [Fact]
    public void PruneDropsNothingWhileTheWindowIsLive()
    {
        var limiter = Create();
        var user = Guid.NewGuid();

        for (var i = 0; i < QuickConnectAttemptLimiter.MaxFailures; i++)
        {
            limiter.RecordFailure(user);
        }

        limiter.Prune();

        Assert.True(limiter.IsBlocked(user, out _));
    }

    [Fact]
    public void ConcurrentFailuresAreCountedExactly()
    {
        var limiter = Create();
        var user = Guid.NewGuid();

        // The counter is lock-guarded; a lost update here would silently widen the cap.
        System.Threading.Tasks.Parallel.For(0, QuickConnectAttemptLimiter.MaxFailures, _ => limiter.RecordFailure(user));

        Assert.True(limiter.IsBlocked(user, out _));
    }
}

/// <summary>
/// State plumbing for the bridge. The reference implementation's own suite leaves this untested,
/// and the flag is the single thing that distinguishes the two flows.
/// </summary>
public sealed class QuickConnectStateTests : IDisposable
{
    private readonly StateManager _states = new(NullLogger<StateManager>.Instance);

    public void Dispose() => _states.Dispose();

    private static OidcState NewState(bool quickConnect) => new()
    {
        ProviderId = "p1",
        Nonce = "n",
        CodeVerifier = "v",
        RedirectUri = "https://jf.example/sso/OIDC/Callback/p1",
        QuickConnect = quickConnect
    };

    [Fact]
    public void QuickConnectFlagSurvivesTheRoundTrip()
    {
        var key = _states.StoreState(NewState(true));

        var restored = _states.ConsumeState(key);

        Assert.NotNull(restored);
        Assert.True(restored!.QuickConnect);
    }

    /// <summary>The normal login flow must never accidentally land on the code-entry page.</summary>
    [Fact]
    public void DefaultsToFalseForTheOrdinaryLoginFlow()
    {
        var key = _states.StoreState(NewState(false));

        Assert.False(_states.ConsumeState(key)!.QuickConnect);
    }

    [Fact]
    public void AuthorizedSessionCarriesNoQuickConnectCode()
    {
        // The code is never carried through the OIDC round trip — it is typed by the user
        // afterwards. If a Code/Secret field ever appears on AuthorizedSession, the deep-link
        // phishing vector this design exists to avoid has been reintroduced.
        var properties = typeof(AuthorizedSession).GetProperties();

        Assert.DoesNotContain(properties, p =>
            p.Name.Contains("Code", StringComparison.OrdinalIgnoreCase)
            || p.Name.Contains("Secret", StringComparison.OrdinalIgnoreCase));
    }
}
