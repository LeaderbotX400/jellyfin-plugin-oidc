using System.Text.Json;
using Jellyfin.Plugin.OIDC.Configuration;
using Xunit;

namespace Jellyfin.Plugin.OIDC.Tests;

/// <summary>
/// Defence-in-depth verification for TASK-12: the callback HTML must JSON-encode every value
/// interpolated into <c>&lt;script&gt;</c>. We don't reach into the private BuildCallbackHtml —
/// instead we verify the encoding primitive (JsonSerializer.Serialize) produces a JS-safe
/// literal even for the hostile inputs we care about, and we verify the provider-id charset
/// regex itself rejects anything that could escape an inline-JS string literal in the first place.
/// </summary>
public class CallbackHtmlEscapingTests
{
    [Theory]
    [InlineData("</script><script>alert(1)</script>")]
    [InlineData("' + alert(1) + '")]
    [InlineData("\\u003c/script\\u003e")]
    public void JsonEncoding_NeverProducesUnescapedScriptCloseTag(string hostile)
    {
        // System.Text.Json by default escapes < > & ' so the result is safe to drop into <script>.
        var encoded = JsonSerializer.Serialize(hostile);

        Assert.StartsWith("\"", encoded);
        Assert.EndsWith("\"", encoded);
        Assert.DoesNotContain("</script>", encoded);
    }

    [Fact]
    public void JsonEncoding_HandlesUnicodeLineSeparators()
    {
        // U+2028 / U+2029 are JS line terminators in old engines. JsonSerializer must escape them.
        var hostile = "\u2028\u2029";
        var encoded = JsonSerializer.Serialize(hostile);
        Assert.DoesNotContain("\u2028", encoded);
        Assert.DoesNotContain("\u2029", encoded);
    }

    [Theory]
    [InlineData("keycloak", true)]
    [InlineData("authentik-dev", true)]
    [InlineData("a_b_c", true)]
    [InlineData("X", true)]
    [InlineData("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", true)] // 64
    [InlineData("", false)]
    [InlineData("bad/id with spaces", false)]
    [InlineData("</script>", false)]
    [InlineData("foo'bar", false)]
    [InlineData("foo.bar", false)]
    [InlineData("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", false)] // 65
    public void ProviderIdValidation_AcceptsSafeRejectsHostile(string input, bool expected)
    {
        Assert.Equal(expected, ProviderIdValidation.IsValid(input));
    }
}
