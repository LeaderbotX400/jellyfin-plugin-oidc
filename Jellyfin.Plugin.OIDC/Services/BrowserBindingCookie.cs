using System;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Http;

namespace Jellyfin.Plugin.OIDC.Services;

/// <summary>
/// Binds an SSO round trip to the browser that started it, which is what defeats login-CSRF (an
/// attacker completing THEIR login in a victim's browser). /Start issues a random token as a
/// cookie and keeps only its SHA-256 hash server-side; the finishing step must present the cookie.
///
/// Cookie configuration:
///   * On HTTPS the <c>__Host-</c> prefix is used — browsers enforce Secure + Path=/ + no Domain,
///     so a sibling subdomain cannot plant the cookie.
///   * On plain HTTP (dev only) the prefix would be rejected by the browser because Secure must be
///     set, so it is dropped. The whole login is already unprotected over HTTP.
///   * SameSite=Lax: sent on the OIDC callback (a top-level GET from the IdP) and on same-origin
///     fetches, which is where SAML verifies it — the SAML ACS is a cross-site POST, which Lax
///     cookies do not ride.
/// </summary>
public static class BrowserBindingCookie
{
    private const string CookieSuffix = "oidc-csrf";

    /// <summary>Lifetime mirrors the server-side state expiry.</summary>
    private static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(10);

    /// <summary>
    /// Issues a fresh binding cookie named for <paramref name="key"/> and returns the hash to store
    /// in server-side state. <paramref name="key"/> must be cookie-name safe (provider ids are
    /// validated to [A-Za-z0-9_-]).
    /// </summary>
    public static byte[] Issue(HttpRequest request, HttpResponse response, string key)
    {
        var token = StateManager.GenerateCsprngToken();
        response.Cookies.Append(CookieName(request, key), token, Options(request, Lifetime));
        return StateManager.HashToken(token);
    }

    /// <summary>
    /// Verifies the cookie against <paramref name="expectedHash"/> in fixed time, and always clears
    /// it so a stale token cannot be replayed. A null expected hash never verifies.
    /// </summary>
    public static bool VerifyAndClear(HttpRequest request, HttpResponse response, string key, byte[]? expectedHash)
    {
        var name = CookieName(request, key);
        var present = request.Cookies.TryGetValue(name, out var raw);
        response.Cookies.Delete(name, Options(request, maxAge: null));

        if (expectedHash is null || !present || string.IsNullOrEmpty(raw))
        {
            return false;
        }

        return CryptographicOperations.FixedTimeEquals(StateManager.HashToken(raw), expectedHash);
    }

    private static string CookieName(HttpRequest request, string key) =>
        $"{(request.IsHttps ? "__Host-" : string.Empty)}{CookieSuffix}-{key}";

    private static CookieOptions Options(HttpRequest request, TimeSpan? maxAge) => new()
    {
        HttpOnly = true,
        Secure = request.IsHttps,
        SameSite = SameSiteMode.Lax,
        Path = "/",
        MaxAge = maxAge
    };
}
