using System;
using System.Buffers;
using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.OIDC.Services;

/// <summary>
/// Splices the SSO login-button script into Jellyfin's web UI, so admins do not have to paste a
/// &lt;script&gt; tag into the Branding settings by hand.
///
/// Jellyfin has no supported hook for adding markup to the login page, so this rewrites the
/// <c>/web/index.html</c> response on the way out. That is inherently tied to the shape of a page
/// we do not own, so every step fails open: anything unexpected — a non-200, a non-HTML body, no
/// recognisable insertion point — returns the upstream bytes untouched. A broken injection must
/// degrade to "no button", never to "no web UI".
///
/// Mechanism adapted from ZL154/JellyfinSecurity's IndexHtmlInjectionMiddleware (MIT).
/// </summary>
public sealed class LoginButtonInjectionMiddleware
{
    private const string ScriptPath = "../sso/OIDC/LoginButtons";

    private readonly RequestDelegate _next;
    private readonly IPluginConfigProvider _configProvider;
    private readonly ILogger<LoginButtonInjectionMiddleware> _logger;

    /// <summary>
    /// Cache of the last patched page, keyed by a hash of the upstream bytes. Jellyfin serves the
    /// same index.html for every request, so without this every page load would repeat a UTF-8
    /// decode, a string search and a re-encode. Keyed by content hash rather than by path so a
    /// Jellyfin upgrade invalidates it automatically.
    /// </summary>
    private static (string Hash, byte[] Patched)? _cache;
    private static readonly object CacheLock = new();

    /// <summary>
    /// Cache-buster for the script URL. Assembly version alone is not enough: a config change
    /// (a renamed provider, a new button colour) changes the script's content at the same
    /// version, and browsers and CDNs happily serve the stale copy. Re-randomised per process.
    /// </summary>
    private static readonly string CacheToken =
        Convert.ToHexString(RandomNumberGenerator.GetBytes(4)).ToLowerInvariant();

    public LoginButtonInjectionMiddleware(
        RequestDelegate next,
        IPluginConfigProvider configProvider,
        ILogger<LoginButtonInjectionMiddleware> logger)
    {
        _next = next;
        _configProvider = configProvider;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        if (!ShouldPatch(context))
        {
            await _next(context).ConfigureAwait(false);
            return;
        }

        // Ask the inner pipeline for an uncompressed, unconditional response. Without this the
        // body we buffer is either gzip/brotli bytes or an empty 304, and the patch silently
        // does nothing — the failure mode JellyfinSecurity hit twice in its own changelog.
        context.Request.Headers.Remove("Accept-Encoding");
        context.Request.Headers.Remove("If-None-Match");
        context.Request.Headers.Remove("If-Modified-Since");

        var originalBody = context.Response.Body;
        using var buffer = new MemoryStream();
        context.Response.Body = buffer;

        try
        {
            await _next(context).ConfigureAwait(false);
        }
        finally
        {
            context.Response.Body = originalBody;
        }

        var upstream = buffer.ToArray();

        if (context.Response.StatusCode != StatusCodes.Status200OK
            || !IsHtml(context.Response.ContentType)
            || upstream.Length == 0)
        {
            await originalBody.WriteAsync(upstream).ConfigureAwait(false);
            return;
        }

        var patched = GetOrBuildPatched(upstream);

        // Length changed, and the upstream validators describe the unpatched body.
        context.Response.ContentLength = patched.Length;
        context.Response.Headers.Remove("ETag");
        context.Response.Headers.Remove("Content-MD5");

        await originalBody.WriteAsync(patched).ConfigureAwait(false);
    }

    private bool ShouldPatch(HttpContext context)
    {
        if (!HttpMethods.IsGet(context.Request.Method))
        {
            return false;
        }

        var path = context.Request.Path.Value;
        if (string.IsNullOrEmpty(path) || !IsIndexPath(path))
        {
            return false;
        }

        try
        {
            var config = _configProvider.GetConfiguration();
            if (!config.AutoInjectLoginButtons)
            {
                return false;
            }

            // Nothing to inject if no provider would render a button; leave the page alone.
            foreach (var p in config.Providers)
            {
                if (p.Enabled) return true;
            }

            foreach (var s in config.SamlProviders)
            {
                if (s.Enabled) return true;
            }

            return false;
        }
        catch (Exception ex)
        {
            // Config unreadable during startup or a reload — never take the web UI down for it.
            _logger.LogDebug(ex, "Login button injection skipped: configuration unavailable");
            return false;
        }
    }

    /// <summary>
    /// Matches the paths that serve the web UI shell, with or without a base-URL prefix.
    /// Deliberately does not try to read Jellyfin's configured base URL: the script is referenced
    /// relatively ("../sso/OIDC/LoginButtons"), which resolves correctly under any prefix.
    /// </summary>
    internal static bool IsIndexPath(string path)
    {
        var trimmed = path.TrimEnd('/');

        return trimmed.EndsWith("/web", StringComparison.OrdinalIgnoreCase)
            || trimmed.EndsWith("/web/index.html", StringComparison.OrdinalIgnoreCase)
            || trimmed.Equals("/web", StringComparison.OrdinalIgnoreCase)
            || trimmed.Equals("/web/index.html", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsHtml(string? contentType) =>
        contentType is not null
        && contentType.Contains("text/html", StringComparison.OrdinalIgnoreCase);

    private byte[] GetOrBuildPatched(byte[] upstream)
    {
        var hash = Convert.ToHexString(SHA256.HashData(upstream));

        lock (CacheLock)
        {
            if (_cache is { } cached && string.Equals(cached.Hash, hash, StringComparison.Ordinal))
            {
                return cached.Patched;
            }
        }

        var html = Encoding.UTF8.GetString(upstream);
        var patchedHtml = Inject(html);

        if (patchedHtml is null)
        {
            _logger.LogWarning(
                "Login button injection found no insertion point in the web UI shell; " +
                "serving it unmodified. Paste the tag from /sso/OIDC/BrandingSnippet into " +
                "Dashboard > Branding instead.");
            return upstream;
        }

        var patched = Encoding.UTF8.GetBytes(patchedHtml);

        lock (CacheLock)
        {
            _cache = (hash, patched);
        }

        _logger.LogDebug("Login button script injected into the web UI shell ({Bytes} bytes)", patched.Length);
        return patched;
    }

    /// <summary>
    /// Inserts the script tag after &lt;head&gt;, falling back to before &lt;/body&gt; and then
    /// after &lt;body&gt;. Returns null when the document matches none of those, which is the
    /// signal to serve the page untouched.
    /// </summary>
    internal static string? Inject(string html)
    {
        if (html.Contains("id=\"oidc-sso-injected\"", StringComparison.Ordinal))
        {
            return html; // already patched (a proxy replaying our own output)
        }

        var tag = string.Create(
            CultureInfo.InvariantCulture,
            $"<script id=\"oidc-sso-injected\" src=\"{ScriptPath}?v={CacheToken}\" defer></script>");

        var head = html.IndexOf("<head>", StringComparison.OrdinalIgnoreCase);
        if (head >= 0)
        {
            return html.Insert(head + "<head>".Length, tag);
        }

        var bodyClose = html.LastIndexOf("</body>", StringComparison.OrdinalIgnoreCase);
        if (bodyClose >= 0)
        {
            return html.Insert(bodyClose, tag);
        }

        var bodyOpen = html.IndexOf("<body", StringComparison.OrdinalIgnoreCase);
        if (bodyOpen >= 0)
        {
            var close = html.IndexOf('>', bodyOpen);
            if (close >= 0)
            {
                return html.Insert(close + 1, tag);
            }
        }

        return null;
    }

    /// <summary>Drops the cached page so the next request rebuilds it. Called after a config save.</summary>
    public static void InvalidateCache()
    {
        lock (CacheLock)
        {
            _cache = null;
        }
    }
}

/// <summary>
/// Registers <see cref="LoginButtonInjectionMiddleware"/> in Jellyfin's ASP.NET Core pipeline.
/// An <see cref="IStartupFilter"/> is the only way a plugin can insert middleware — Jellyfin
/// exposes no other hook for it.
/// </summary>
public sealed class LoginButtonStartupFilter : IStartupFilter
{
    public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next)
    {
        return builder =>
        {
            builder.UseMiddleware<LoginButtonInjectionMiddleware>();
            next(builder);
        };
    }
}
