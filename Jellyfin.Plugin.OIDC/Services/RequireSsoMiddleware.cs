using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Text.Json;
using System.Threading.Tasks;
using Jellyfin.Data;
using MediaBrowser.Controller.Library;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.OIDC.Services;

/// <summary>
/// Refuses Jellyfin's native password-authentication endpoints when the deployment has decided
/// that SSO is the only way in.
///
/// This has to live in the HTTP pipeline. <see cref="Auth.OidcAuthProvider"/> can only refuse for
/// users already pinned to it; it cannot stop Jellyfin's default password provider from serving
/// everyone else, which is what a server-wide policy needs.
///
/// The endpoint list is the load-bearing part and the easiest thing to get wrong. Jellyfin 12
/// exposes three session-creating routes, not one:
///
///   POST Users/AuthenticateByName            — password. Blocked.
///   POST Users/{userId}/Authenticate         — password, marked obsolete but still routed. Blocked.
///   POST Users/AuthenticateWithQuickConnect  — NOT blocked. Quick Connect never takes a password;
///                                              a code is approved from an already-authenticated
///                                              session, so when password login is blocked the only
///                                              way to reach it is via SSO and it already inherits
///                                              the requirement. Blocking it would lock out native
///                                              clients, which cannot render a web login button.
///
/// Re-derive this list against the server source on every Jellyfin major. Matching is on parsed
/// path segments, never a string prefix — a prefix test is how the equivalent feature elsewhere
/// shipped bypasses (a path like /Users/AuthenticateByNameFoo, or a waiver keyed on a name prefix).
/// </summary>
public sealed class RequireSsoMiddleware
{
    private readonly RequestDelegate _next;
    private readonly IPluginConfigProvider _configProvider;
    private readonly IUserManager _userManager;
    private readonly ILogger<RequireSsoMiddleware> _logger;

    public RequireSsoMiddleware(
        RequestDelegate next,
        IPluginConfigProvider configProvider,
        IUserManager userManager,
        ILogger<RequireSsoMiddleware> logger)
    {
        _next = next;
        _configProvider = configProvider;
        _userManager = userManager;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        if (!IsPasswordAuthEndpoint(context.Request.Method, context.Request.Path.Value))
        {
            await _next(context).ConfigureAwait(false);
            return;
        }

        Configuration.PluginConfiguration config;
        try
        {
            config = _configProvider.GetConfiguration();
        }
        catch (Exception ex)
        {
            // Fail OPEN on a config read failure. This gate is a policy, not a security boundary
            // of last resort, and locking every admin out of a server because a config file was
            // briefly unreadable is a worse outcome than one unblocked password login.
            _logger.LogWarning(ex, "Require-SSO check skipped: configuration unavailable");
            await _next(context).ConfigureAwait(false);
            return;
        }

        if (!config.RequireSsoForAll)
        {
            await _next(context).ConfigureAwait(false);
            return;
        }

        if (await IsExemptAsync(context, config).ConfigureAwait(false))
        {
            await _next(context).ConfigureAwait(false);
            return;
        }

        var remoteIp = ClientIpResolver.Resolve(
            context,
            config.TrustForwardedHeaders,
            ClientIpResolver.ParseCidrs(config.TrustedProxyCidrs, _logger),
            _logger);

        _logger.LogWarning(
            "Password login refused by Require-SSO policy: {Method} {Path} from {RemoteIp}",
            context.Request.Method,
            LogRedaction.Sanitize(context.Request.Path.Value, 128),
            remoteIp);

        context.Response.StatusCode = StatusCodes.Status403Forbidden;
        context.Response.ContentType = "application/json";
        await context.Response.WriteAsync(
            "{\"error\":\"sso_required\",\"message\":\"This server requires single sign-on. " +
            "Use the SSO button on the login page.\"}").ConfigureAwait(false);
    }

    /// <summary>
    /// Matches the two password-authentication routes by exact, case-insensitive path segments.
    /// Anything else — including Quick Connect — returns false. See the class remarks for why the
    /// list is what it is.
    /// </summary>
    internal static bool IsPasswordAuthEndpoint(string method, string? path)
    {
        if (!HttpMethods.IsPost(method) || string.IsNullOrEmpty(path))
        {
            return false;
        }

        var segments = path.Split('/', StringSplitOptions.RemoveEmptyEntries);

        // Tolerate a base-URL prefix by matching the tail rather than the whole path.
        // Users/AuthenticateByName
        if (segments.Length >= 2
            && segments[^2].Equals("Users", StringComparison.OrdinalIgnoreCase)
            && segments[^1].Equals("AuthenticateByName", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        // Users/{userId}/Authenticate  (obsolete, still routed)
        if (segments.Length >= 3
            && segments[^3].Equals("Users", StringComparison.OrdinalIgnoreCase)
            && segments[^1].Equals("Authenticate", StringComparison.OrdinalIgnoreCase)
            && Guid.TryParse(segments[^2], out _))
        {
            return true;
        }

        return false;
    }

    private async Task<bool> IsExemptAsync(HttpContext context, Configuration.PluginConfiguration config)
    {
        if (config.SsoExemptCidrs.Count > 0 && IsExemptByAddress(context, config))
        {
            return true;
        }

        if (config.SsoExemptAdmins && await IsAdministratorRequestAsync(context).ConfigureAwait(false))
        {
            return true;
        }

        return false;
    }

    /// <summary>
    /// True when the caller's address falls inside one of the exempt CIDRs. Uses
    /// <see cref="ClientIpResolver"/> so the X-Forwarded-For handling — and its requirement that
    /// the immediate peer be a configured trusted proxy — is identical to the rest of the plugin.
    /// A spoofable header must never be able to buy an exemption.
    /// </summary>
    private bool IsExemptByAddress(HttpContext context, Configuration.PluginConfiguration config)
    {
        var remoteIp = ClientIpResolver.Resolve(
            context,
            config.TrustForwardedHeaders,
            ClientIpResolver.ParseCidrs(config.TrustedProxyCidrs, _logger),
            _logger);

        if (remoteIp is null)
        {
            return false;
        }

        return ClientIpResolver.IsInAny(remoteIp, ClientIpResolver.ParseCidrs(config.SsoExemptCidrs, _logger));
    }

    /// <summary>
    /// True when the request is a password login for a user who really is a Jellyfin administrator.
    ///
    /// The username is read out of the request body and resolved through
    /// <see cref="IUserManager.GetUserByName"/> — an actual lookup, not a name-prefix or
    /// substring test. The equivalent feature in another plugin shipped a bypass by waiving on a
    /// string match, so anyone who could pick a username could waive themselves past the gate.
    ///
    /// The body is buffered and rewound so the real endpoint still gets to read it.
    /// </summary>
    private async Task<bool> IsAdministratorRequestAsync(HttpContext context)
    {
        try
        {
            context.Request.EnableBuffering();
            context.Request.Body.Position = 0;

            using var document = await JsonDocument
                .ParseAsync(context.Request.Body, cancellationToken: context.RequestAborted)
                .ConfigureAwait(false);

            context.Request.Body.Position = 0;

            if (document.RootElement.ValueKind != JsonValueKind.Object
                || !document.RootElement.TryGetProperty("Username", out var usernameElement)
                || usernameElement.ValueKind != JsonValueKind.String)
            {
                return false;
            }

            var username = usernameElement.GetString();
            if (string.IsNullOrEmpty(username))
            {
                return false;
            }

            var user = _userManager.GetUserByName(username);
            return user is not null && user.HasPermission(
                Jellyfin.Database.Implementations.Enums.PermissionKind.IsAdministrator);
        }
        catch (Exception ex) when (ex is JsonException or IOException or InvalidOperationException or NotSupportedException)
        {
            // An unreadable body cannot prove an exemption, so it does not get one.
            _logger.LogDebug(ex, "Require-SSO admin exemption check could not read the request body");
            try { context.Request.Body.Position = 0; } catch (Exception) { /* best effort */ }
            return false;
        }
    }
}

/// <summary>Registers <see cref="RequireSsoMiddleware"/> in Jellyfin's ASP.NET Core pipeline.</summary>
public sealed class RequireSsoStartupFilter : IStartupFilter
{
    public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next)
    {
        return builder =>
        {
            builder.UseMiddleware<RequireSsoMiddleware>();
            next(builder);
        };
    }
}
