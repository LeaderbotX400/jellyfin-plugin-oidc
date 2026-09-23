using System.Text.Json;
using Microsoft.AspNetCore.Http;

namespace Jellyfin.Plugin.OIDC.Api;

/// <summary>
/// The HTML pages the plugin generates at the end of an SSO round trip, shared by the OIDC and
/// SAML controllers. They used to be two copies of the same page, and a fix to one (the
/// crypto.randomUUID fallback) never reached the other.
/// </summary>
internal static class SsoPages
{
    /// <summary>
    /// The server's path prefix — Jellyfin's configured base URL (e.g. "/jellyfin"), or "" when
    /// none is set — with no trailing slash. Jellyfin mounts the whole app under
    /// <c>app.Map(BaseUrl)</c>, which surfaces the prefix as <c>Request.PathBase</c>.
    ///
    /// Every URL the plugin generates must start with this. Root-relative "/sso/..." paths skip
    /// the base URL, so on a server with one they 404, and the OIDC redirect_uri and SAML ACS
    /// URL they produce do not match what the IdP was told.
    /// </summary>
    public static string ServerBase(HttpRequest request) =>
        request.PathBase.HasValue ? request.PathBase.Value!.TrimEnd('/') : string.Empty;

    /// <summary>
    /// Headers for any page carrying a one-shot session token.
    ///
    /// The page must run a small inline bootstrap that hands the token back to /Auth and writes
    /// Jellyfin's localStorage credentials, so script-src needs 'unsafe-inline' — Jellyfin's plugin
    /// model offers no way to ship a hash-pinned script file. Everything else is pinned off, and the
    /// value side is hardened instead: every interpolation is JSON-encoded. no-store keeps the
    /// token out of the browser and any intermediary cache; frame-ancestors/X-Frame-Options stop
    /// the page being framed.
    /// </summary>
    public static void SetSecurityHeaders(HttpResponse response)
    {
        response.Headers["Content-Security-Policy"] =
            "default-src 'none'; script-src 'unsafe-inline'; connect-src 'self'; style-src 'unsafe-inline'; frame-ancestors 'none'";
        response.Headers["X-Content-Type-Options"] = "nosniff";
        response.Headers["Referrer-Policy"] = "no-referrer";
        response.Headers["X-Frame-Options"] = "DENY";
        response.Headers["Cache-Control"] = "no-store";
        response.Headers["Pragma"] = "no-cache";
    }

    /// <summary>
    /// The page that completes a web sign-in: exchanges the session token at
    /// <paramref name="authUrl"/> for a Jellyfin session, stores it where Jellyfin Web looks for it,
    /// and navigates to <paramref name="homeUrl"/>.
    /// </summary>
    public static string BuildCompletionHtml(string sessionToken, string authUrl, string homeUrl, string heading)
    {
        // Every value that crosses into the <script> body is JSON-encoded. JsonSerializer
        // produces a valid JS string literal (it escapes <, >, &, ', U+2028/9), so no value can
        // break out of the literal or the script element.
        var encodedToken = JsonSerializer.Serialize(sessionToken);
        var encodedAuthUrl = JsonSerializer.Serialize(authUrl);
        var encodedHomeUrl = JsonSerializer.Serialize(homeUrl);
        // The real plugin version, so Jellyfin's session table shows it. Falls back to "0.0.0"
        // outside the Jellyfin host (e.g. unit tests).
        var encodedVersion = JsonSerializer.Serialize(OidcPlugin.Instance?.Version?.ToString() ?? "0.0.0");
        var encodedHeading = System.Net.WebUtility.HtmlEncode(heading);

        return $$"""
        <!DOCTYPE html>
        <html>
        <head><title>Authenticating...</title></head>
        <body>
        <h3>{{encodedHeading}}</h3>
        <p id="status">Please wait...</p>
        <script>
        (function() {
            const token = {{encodedToken}};

            // crypto.randomUUID() is secure-context only. A Jellyfin served over plain HTTP at a
            // non-localhost address — a LAN install on http://10.0.0.5:8096, say — has no secure
            // context, randomUUID is undefined, and calling it stranded the login on this page.
            // crypto.getRandomValues has no such restriction.
            function newDeviceId() {
                if (crypto && typeof crypto.randomUUID === 'function') {
                    return crypto.randomUUID();
                }
                if (crypto && typeof crypto.getRandomValues === 'function') {
                    const b = new Uint8Array(16);
                    crypto.getRandomValues(b);
                    b[6] = (b[6] & 0x0f) | 0x40;  // version 4
                    b[8] = (b[8] & 0x3f) | 0x80;  // variant 10x
                    const h = Array.from(b, x => x.toString(16).padStart(2, '0')).join('');
                    return h.slice(0, 8) + '-' + h.slice(8, 12) + '-' + h.slice(12, 16) + '-' +
                           h.slice(16, 20) + '-' + h.slice(20);
                }
                // Last resort: this is a device label for the session list, not a secret.
                return 'oidc-' + Date.now().toString(16) + '-' + Math.random().toString(16).slice(2, 10);
            }

            const deviceId = localStorage.getItem('_deviceId2') || newDeviceId();
            localStorage.setItem('_deviceId2', deviceId);

            fetch({{encodedAuthUrl}}, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    Token: token,
                    DeviceId: deviceId,
                    DeviceName: navigator.userAgent.substring(0, 50),
                    App: 'Jellyfin Web',
                    AppVersion: {{encodedVersion}}
                })
            })
            .then(function(r) {
                if (r.status === 409 || r.status === 403) {
                    return r.json().catch(function() { return {}; }).then(function(body) {
                        throw new Error(body && body.message ? body.message : 'Sign-in refused');
                    });
                }
                if (!r.ok) throw new Error('Auth failed: ' + r.status);
                return r.json();
            })
            .then(function(auth) {
                var credentials = {
                    Servers: [{
                        ManualAddress: window.location.origin,
                        AccessToken: auth.AccessToken,
                        UserId: auth.User.Id,
                        IsLocalUser: true
                    }]
                };
                localStorage.setItem('jellyfin_credentials', JSON.stringify(credentials));

                var user = {
                    Id: auth.User.Id,
                    ServerId: auth.ServerId,
                    AccessToken: auth.AccessToken
                };
                localStorage.setItem('_jellyfin_user_' + auth.ServerId, JSON.stringify(user));

                document.getElementById('status').textContent = 'Success! Redirecting...';
                window.location.href = {{encodedHomeUrl}};
            })
            .catch(function(err) {
                document.getElementById('status').textContent = 'Error: ' + err.message;
            });
        })();
        </script>
        </body>
        </html>
        """;
    }
}
