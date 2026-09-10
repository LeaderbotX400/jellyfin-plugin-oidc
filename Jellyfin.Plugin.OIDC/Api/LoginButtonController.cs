using System.Globalization;
using System.Linq;
using System.Text;
using System.Text.Json;
using Jellyfin.Plugin.OIDC.Services;
using Microsoft.AspNetCore.Mvc;

namespace Jellyfin.Plugin.OIDC.Api;

[ApiController]
[Route("sso/OIDC")]
public class LoginButtonController : ControllerBase
{
    private readonly IPluginConfigProvider _configProvider;

    public LoginButtonController(IPluginConfigProvider configProvider)
    {
        _configProvider = configProvider;
    }

    [HttpGet("LoginButtons")]
    public ActionResult GetLoginButtonsScript()
    {
        var config = _configProvider.GetConfiguration();
        var providers = config.Providers.Where(p => p.Enabled).ToList();
        if (providers.Count == 0)
        {
            return Content("", "application/javascript");
        }

        var sb = new StringBuilder();
        sb.AppendLine("(function() {");
        sb.AppendLine("  function addButtons() {");
        sb.AppendLine("    var form = document.querySelector('.manualLoginForm, #loginPage form, [data-role=\"page\"] form');");
        sb.AppendLine("    if (!form || document.getElementById('oidc-sso-buttons')) return;");
        sb.AppendLine("    var container = document.createElement('div');");
        sb.AppendLine("    container.id = 'oidc-sso-buttons';");
        sb.AppendLine("    container.style.cssText = 'margin:1em 0;text-align:center;';");

        foreach (var p in providers)
        {
            // JsonSerializer.Serialize produces a fully-escaped double-quoted JS string literal.
            // It escapes ', \, \r, \n, U+2028, U+2029, and </script> — all vectors that the old
            // single-quote + Replace("'", "\\'") approach missed.
            // ProviderId is regex-constrained [A-Za-z0-9_-]{1,64} at config-save time and is safe raw.
            var jsonLabel = JsonSerializer.Serialize("Sign in with " + p.DisplayName);
            // ButtonColor is admin-configured but unvalidated, so it must never be embedded in a
            // larger CSS string (a value like "red;}body{..." would inject arbitrary CSS via
            // cssText). Assigning style.background directly confines it to a single property
            // value — CSSOM cannot escape a property assignment into other properties/selectors.
            var jsonCss = JsonSerializer.Serialize(
                "display:block;margin:0.5em auto;padding:0.7em 1.5em;color:#fff;text-decoration:none;border-radius:4px;font-size:1em;max-width:300px;");
            var jsonColor = JsonSerializer.Serialize(p.ButtonColor);
            sb.AppendLine(CultureInfo.InvariantCulture, $"    var btn_{p.ProviderId} = document.createElement('a');");
            sb.AppendLine(CultureInfo.InvariantCulture, $"    btn_{p.ProviderId}.href = '/sso/OIDC/Start/{p.ProviderId}';");
            sb.AppendLine(CultureInfo.InvariantCulture, $"    btn_{p.ProviderId}.textContent = {jsonLabel};");
            sb.AppendLine(CultureInfo.InvariantCulture, $"    btn_{p.ProviderId}.style.cssText = {jsonCss};");
            sb.AppendLine(CultureInfo.InvariantCulture, $"    btn_{p.ProviderId}.style.background = {jsonColor};");
            sb.AppendLine(CultureInfo.InvariantCulture, $"    container.appendChild(btn_{p.ProviderId});");
        }

        // Discoverability for the Quick Connect bridge. Native clients (Android, Swiftfin,
        // Android TV) cannot show these buttons at all, so this is the path a user follows on a
        // second device to sign a television in. Root-relative, matching the provider buttons
        // above: this script runs inside /web/index.html, so a path-relative href would resolve
        // against /web/ and 404.
        // No interpolation here, but assigned from a JSON literal like every other cssText in
        // this script so the "cssText is never a single-quoted interpolation" invariant that
        // LoginButtonScriptEscapingTests enforces stays trivially checkable.
        var jsonQcCss = JsonSerializer.Serialize(
            "display:block;margin:0.4em auto;text-align:center;font-size:0.9em;color:#00a4dc;");
        sb.AppendLine("    var qc = document.createElement('a');");
        sb.AppendLine("    qc.href = '/sso/OIDC/QuickConnect';");
        sb.AppendLine("    qc.textContent = 'Sign in a TV or mobile app';");
        sb.AppendLine(CultureInfo.InvariantCulture, $"    qc.style.cssText = {jsonQcCss};");
        sb.AppendLine("    container.appendChild(qc);");

        sb.AppendLine("    var sep = document.createElement('div');");
        sb.AppendLine("    sep.style.cssText = 'margin:1em 0;text-align:center;color:#888;';");
        sb.AppendLine("    sep.textContent = '— or sign in with password —';");
        sb.AppendLine("    container.appendChild(sep);");
        sb.AppendLine("    form.parentNode.insertBefore(container, form);");
        sb.AppendLine("  }");
        sb.AppendLine("  var observer = new MutationObserver(addButtons);");
        sb.AppendLine("  observer.observe(document.body, { childList: true, subtree: true });");
        sb.AppendLine("  addButtons();");
        sb.AppendLine("})();");

        return Content(sb.ToString(), "application/javascript");
    }

    [HttpGet("BrandingSnippet")]
    public ActionResult GetBrandingSnippet()
    {
        var snippet = "<script src=\"/sso/OIDC/LoginButtons\"></script>";
        return Ok(new { Html = snippet, Instructions = "Add this to Jellyfin Dashboard > General > Custom CSS/HTML, or paste the <script> tag into the Login Disclaimer field under Branding." });
    }
}
