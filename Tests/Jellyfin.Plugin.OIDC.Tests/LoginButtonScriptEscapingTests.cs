using System.Collections.Generic;
using System.Text.Json;
using Jellyfin.Plugin.OIDC.Api;
using Jellyfin.Plugin.OIDC.Configuration;
using Jellyfin.Plugin.OIDC.Services;
using Microsoft.AspNetCore.Mvc;
using Moq;
using Xunit;

namespace Jellyfin.Plugin.OIDC.Tests;

/// <summary>
/// Defence-in-depth verification that the login-button JavaScript uses JsonSerializer.Serialize
/// for every admin-controlled value (DisplayName, ButtonColor) interpolated into the script body,
/// so that hostile characters cannot break out of the JS string context.
/// </summary>
public class LoginButtonScriptEscapingTests
{
    private static LoginButtonController MakeController(string displayName, string buttonColor)
    {
        var provider = new OidcProviderConfig
        {
            ProviderId = "testprovider",
            DisplayName = displayName,
            ButtonColor = buttonColor,
            Enabled = true
        };

        var config = new PluginConfiguration
        {
            Providers = new List<OidcProviderConfig> { provider }
        };

        var configProviderMock = new Mock<IPluginConfigProvider>();
        configProviderMock.Setup(x => x.GetConfiguration()).Returns(config);

        return new LoginButtonController(configProviderMock.Object);
    }

    private static string GetScript(LoginButtonController controller)
    {
        var result = controller.GetLoginButtonsScript();
        var contentResult = Assert.IsType<ContentResult>(result);
        return contentResult.Content ?? string.Empty;
    }

    [Fact]
    public void DisplayName_SingleQuote_DoesNotAppearRaw()
    {
        var controller = MakeController("O'Reilly IdP", "#4285F4");
        var script = GetScript(controller);

        // JsonSerializer escapes ' as ' by default; raw single-quote must not appear in JS assignment
        Assert.DoesNotContain("O'Reilly", script);
        Assert.Contains("Sign in with", script);
    }

    [Fact]
    public void DisplayName_Backslash_DoesNotAppearRaw()
    {
        var controller = MakeController(@"back\slash", "#4285F4");
        var script = GetScript(controller);

        // JsonSerializer encodes \ as \\; the unescaped form must not appear as a literal JS backslash
        Assert.DoesNotContain("back\\slash\"", script);
        Assert.Contains("Sign in with", script);
    }

    [Fact]
    public void DisplayName_Newline_DoesNotAppearRaw()
    {
        var controller = MakeController("line1\nline2", "#4285F4");
        var script = GetScript(controller);

        // Raw newline inside a JS string literal would be a syntax error
        Assert.DoesNotContain("line1\nline2", script);
        Assert.Contains("Sign in with", script);
    }

    [Fact]
    public void DisplayName_CarriageReturn_DoesNotAppearRaw()
    {
        var controller = MakeController("cr\rend", "#4285F4");
        var script = GetScript(controller);

        Assert.DoesNotContain("cr\rend", script);
        Assert.Contains("Sign in with", script);
    }

    [Fact]
    public void DisplayName_ScriptCloseTag_IsJsonEscaped()
    {
        var controller = MakeController("</script><script>alert(1)</script>", "#4285F4");
        var script = GetScript(controller);

        Assert.DoesNotContain("</script>", script, System.StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void DisplayName_UnicodeParagraphSeparator_IsJsonEscaped()
    {
        // U+2029 PARAGRAPH SEPARATOR terminates JS string literals in old engines.
        // JsonSerializer must escape it. Build the char programmatically to avoid source encoding issues.
        var paragraphSep = ((char)0x2029).ToString();
        var hostile = "before" + paragraphSep + "after";
        var controller = MakeController(hostile, "#4285F4");
        var script = GetScript(controller);

        Assert.DoesNotContain(paragraphSep, script);
    }

    [Fact]
    public void DisplayName_UnicodeLineSeparator_IsJsonEscaped()
    {
        // U+2028 LINE SEPARATOR terminates JS string literals in old engines.
        // JsonSerializer must escape it. Build the char programmatically to avoid source encoding issues.
        var lineSep = ((char)0x2028).ToString();
        var hostile = "before" + lineSep + "after";
        var controller = MakeController(hostile, "#4285F4");
        var script = GetScript(controller);

        Assert.DoesNotContain(lineSep, script);
    }

    [Fact]
    public void ButtonColor_SingleQuote_IsJsonEscaped()
    {
        var controller = MakeController("IdP", "'; alert(1); var x='");
        var script = GetScript(controller);

        Assert.DoesNotContain("'; alert(1)", script);
    }

    [Fact]
    public void ButtonColor_Backslash_IsJsonEscaped()
    {
        var controller = MakeController("IdP", @"#aa\bb");
        var script = GetScript(controller);

        // Raw backslash+quote must not appear
        Assert.DoesNotContain("#aa\\bb\"", script);
    }

    [Fact]
    public void ButtonColor_ScriptCloseTag_IsJsonEscaped()
    {
        var controller = MakeController("IdP", "#fff</script><script>alert(1)");
        var script = GetScript(controller);

        Assert.DoesNotContain("</script>", script, System.StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ButtonColor_Newline_DoesNotAppearRaw()
    {
        var controller = MakeController("IdP", "#fff\n; bad()");
        var script = GetScript(controller);

        Assert.DoesNotContain("#fff\n; bad()", script);
    }

    [Fact]
    public void BenignInputs_ProduceValidJavaScript()
    {
        // Verify that ordinary inputs still produce syntactically correct JS
        var controller = MakeController("My Identity Provider", "#4285F4");
        var script = GetScript(controller);

        // The output must be a well-formed IIFE
        Assert.Contains("(function() {", script);
        Assert.Contains("})();", script);

        // The label should appear as a JSON string literal: "Sign in with My Identity Provider"
        var expectedJson = JsonSerializer.Serialize("Sign in with My Identity Provider");
        Assert.Contains(expectedJson, script);

        // The CSS should contain the color value
        Assert.Contains("#4285F4", script);
    }

    [Fact]
    public void NoProviders_ReturnsEmptyScript()
    {
        var config = new PluginConfiguration { Providers = new List<OidcProviderConfig>() };
        var mock = new Mock<IPluginConfigProvider>();
        mock.Setup(x => x.GetConfiguration()).Returns(config);
        var controller = new LoginButtonController(mock.Object);

        var result = controller.GetLoginButtonsScript();
        var contentResult = Assert.IsType<ContentResult>(result);
        Assert.Equal("", contentResult.Content);
    }

    [Fact]
    public void DisabledProvider_IsExcludedFromScript()
    {
        var config = new PluginConfiguration
        {
            Providers = new List<OidcProviderConfig>
            {
                new() { ProviderId = "enabledprov",  DisplayName = "EnabledLabel",  ButtonColor = "#111", Enabled = true  },
                new() { ProviderId = "disabledprov", DisplayName = "DisabledLabel", ButtonColor = "#222", Enabled = false }
            }
        };
        var mock = new Mock<IPluginConfigProvider>();
        mock.Setup(x => x.GetConfiguration()).Returns(config);
        var controller = new LoginButtonController(mock.Object);

        var script = GetScript(controller);

        Assert.Contains("enabledprov", script);
        Assert.DoesNotContain("disabledprov", script);
    }

    [Fact]
    public void TextContent_UsesJsonLiteral_NotSingleQuotedInterpolation()
    {
        // Assert the generated .textContent assignment is a double-quoted JSON literal,
        // not the old single-quoted interpolated form.
        var controller = MakeController("Test Provider", "#4285F4");
        var script = GetScript(controller);

        // New form uses JSON: .textContent = "Sign in with Test Provider";
        // (JsonSerializer wraps in double quotes)
        Assert.Contains(".textContent = \"Sign in with Test Provider\"", script);

        // Old insecure form must not be present
        Assert.DoesNotContain(".textContent = 'Sign in with", script);
    }

    [Fact]
    public void CssText_UsesJsonLiteral_NotSingleQuotedInterpolation()
    {
        var controller = MakeController("Test Provider", "#4285F4");
        var script = GetScript(controller);

        // New form uses JSON double-quoted string; old form used single-quoted interpolation
        Assert.DoesNotContain(".style.cssText = 'display:block", script);
        // Color must appear inside the JSON CSS string
        Assert.Contains("#4285F4", script);
    }
}
