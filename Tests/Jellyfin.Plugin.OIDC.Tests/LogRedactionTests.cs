using System.Linq;
using Jellyfin.Plugin.OIDC.Services;
using Xunit;

namespace Jellyfin.Plugin.OIDC.Tests;

public class LogRedactionTests
{
    // ── Sanitize ──────────────────────────────────────────────────────────────

    [Fact]
    public void Sanitize_Null_ReturnsEmpty()
    {
        Assert.Equal(string.Empty, LogRedaction.Sanitize(null));
    }

    [Fact]
    public void Sanitize_Empty_ReturnsEmpty()
    {
        Assert.Equal(string.Empty, LogRedaction.Sanitize(string.Empty));
    }

    [Fact]
    public void Sanitize_PlainString_PassesThrough()
    {
        Assert.Equal("hello world", LogRedaction.Sanitize("hello world"));
    }

    [Fact]
    public void Sanitize_StripsCR()
    {
        Assert.Equal("line1line2", LogRedaction.Sanitize("line1\rline2"));
    }

    [Fact]
    public void Sanitize_StripsLF()
    {
        Assert.Equal("line1line2", LogRedaction.Sanitize("line1\nline2"));
    }

    [Fact]
    public void Sanitize_StripsCRLF()
    {
        Assert.Equal("line1line2", LogRedaction.Sanitize("line1\r\nline2"));
    }

    [Fact]
    public void Sanitize_StripsControlChars()
    {
        // Verify that NUL (U+0000), TAB (U+0009), and ESC (U+001B) are all stripped.
        // Assert on the exact expected output rather than using DoesNotContain with
        // control characters, since xUnit's DoesNotContain uses culture-aware IndexOf
        // which can have unexpected behavior with zero-weight characters like NUL.
        var nul = new string(new char[] { '\0' });
        var tab = new string(new char[] { '\t' });
        var esc = new string(new char[] { '\u001B' });
        var input = "foo" + nul + "bar" + tab + "baz" + esc + "qux";
        var result = LogRedaction.Sanitize(input);
        // All control chars must be stripped; only printable chars remain.
        Assert.Equal("foobarbazqux", result);
        Assert.True(result.All(c => !char.IsControl(c)), "No control characters should remain");
    }

    [Fact]
    public void Sanitize_CapsAtDefaultMaxLen()
    {
        var input = new string('a', 300);
        var result = LogRedaction.Sanitize(input);
        Assert.Equal(200, result.Length);
    }

    [Fact]
    public void Sanitize_CapsAtCustomMaxLen()
    {
        var input = new string('x', 50);
        var result = LogRedaction.Sanitize(input, maxLen: 10);
        Assert.Equal(10, result.Length);
    }

    [Fact]
    public void Sanitize_LogInjectionPayload_IsNeutered()
    {
        // An attacker might try to inject fake log lines by ending the current line.
        var payload = "ok\nfake-log-entry: admin logged in";
        var result = LogRedaction.Sanitize(payload);
        Assert.DoesNotContain("\n", result);
        Assert.Equal("okfake-log-entry: admin logged in", result);
    }

    // ── RedactSub ──────────────────────────────────────────────────────────────

    [Fact]
    public void RedactSub_Null_ReturnsEmpty()
    {
        Assert.Equal("(empty)", LogRedaction.RedactSub(null));
    }

    [Fact]
    public void RedactSub_Empty_ReturnsEmpty()
    {
        Assert.Equal("(empty)", LogRedaction.RedactSub(string.Empty));
    }

    [Fact]
    public void RedactSub_LongSub_TruncatesAt8()
    {
        var result = LogRedaction.RedactSub("abcdefghij-some-more");
        Assert.Equal("abcdefgh…", result);
    }

    [Fact]
    public void RedactSub_ShortSub_AppendsEllipsis()
    {
        var result = LogRedaction.RedactSub("abc");
        Assert.Equal("abc…", result);
    }

    [Fact]
    public void RedactSub_DoesNotRevealFullValue()
    {
        var sub = "user-secret-12345";
        var result = LogRedaction.RedactSub(sub);
        Assert.DoesNotContain("secret-12345", result);
        Assert.Contains("…", result);
    }

    // ── RedactEmail ────────────────────────────────────────────────────────────

    [Fact]
    public void RedactEmail_Null_ReturnsEmpty()
    {
        Assert.Equal("(empty)", LogRedaction.RedactEmail(null));
    }

    [Fact]
    public void RedactEmail_Empty_ReturnsEmpty()
    {
        Assert.Equal("(empty)", LogRedaction.RedactEmail(string.Empty));
    }

    [Fact]
    public void RedactEmail_Normal_ReturnsXxxAtDomain()
    {
        Assert.Equal("xxx@example.com", LogRedaction.RedactEmail("alice@example.com"));
    }

    [Fact]
    public void RedactEmail_NoAtSign_ReturnsUnknownDomain()
    {
        Assert.Equal("xxx@(unknown)", LogRedaction.RedactEmail("notanemail"));
    }

    [Fact]
    public void RedactEmail_LocalPartNotRevealed()
    {
        var result = LogRedaction.RedactEmail("secretname@corp.example.org");
        Assert.DoesNotContain("secretname", result);
        Assert.Contains("corp.example.org", result);
    }

    // ── RedactRoles ────────────────────────────────────────────────────────────

    [Fact]
    public void RedactRoles_WithoutVerbose_ReturnsCountOnly()
    {
        var result = LogRedaction.RedactRoles(new[] { "admin", "user", "moderator" }, verboseLogging: false);
        Assert.Equal("(count=3)", result);
        Assert.DoesNotContain("admin", result);
        Assert.DoesNotContain("user", result);
    }

    [Fact]
    public void RedactRoles_WithVerbose_ReturnsFull()
    {
        var result = LogRedaction.RedactRoles(new[] { "admin", "user" }, verboseLogging: true);
        Assert.Contains("admin", result);
        Assert.Contains("user", result);
    }

    [Fact]
    public void RedactRoles_EmptyList_ReturnsCountZero()
    {
        var result = LogRedaction.RedactRoles(System.Array.Empty<string>(), verboseLogging: false);
        Assert.Equal("(count=0)", result);
    }

    [Fact]
    public void RedactRoles_DefaultIsNonVerbose()
    {
        var result = LogRedaction.RedactRoles(new[] { "admin" });
        Assert.Equal("(count=1)", result);
    }
}
