using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Jellyfin.Database.Implementations.Entities;
using Jellyfin.Plugin.OIDC.Configuration;
using MediaBrowser.Controller;
using MediaBrowser.Controller.Library;
using MediaBrowser.Controller.Providers;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.OIDC.Services;

/// <summary>
/// Syncs a Jellyfin user's profile image from the OIDC <c>picture</c> claim.
///
/// SECURITY: the picture URL is supplied by the identity provider, and on IdPs where end users
/// can edit their own profile (Keycloak, Authentik) it is effectively attacker-controlled input
/// that makes the SERVER issue an outbound request. It therefore gets a full SSRF treatment:
/// HTTPS-only, an origin allowlist, a resolved-address blocklist, connection pinning to the
/// validated address, no redirects, a hard byte cap enforced while reading, a content-type
/// allowlist, and magic-byte verification of what actually arrived.
///
/// Avatar sync is best-effort by design: every failure path logs and returns. An IdP with a
/// broken avatar host must never be able to stop people logging in.
/// </summary>
public sealed class ProfileImageService
{
    /// <summary>Hard cap on the avatar we will accept, enforced while reading, not from headers.</summary>
    internal const int MaxProfileImageBytes = 5 * 1024 * 1024;

    /// <summary>
    /// Avatar fetches are on the login path, so the budget is tight. A stalling host must cost a
    /// few seconds, not the 100s .NET would allow by default.
    /// </summary>
    private static readonly TimeSpan FetchTimeout = TimeSpan.FromSeconds(5);

    /// <summary>
    /// Content types we will store. <c>image/svg+xml</c> is deliberately absent: SVG is an active
    /// document that can carry script, and Jellyfin serves profile images back to browsers.
    /// </summary>
    private static readonly HashSet<string> AllowedMediaTypes = new(StringComparer.OrdinalIgnoreCase)
    {
        "image/jpeg", "image/png", "image/gif", "image/webp"
    };

    private readonly Func<IPAddress, HttpClient> _pinnedClientFactory;
    private readonly Func<string, CancellationToken, Task<IPAddress[]>>? _dnsResolver;
    private readonly IUserManager _userManager;
    private readonly IServerApplicationPaths _appPaths;
    private readonly IProviderManager _providerManager;
    private readonly OidcUserStore _userStore;
    private readonly IPluginConfigProvider _configProvider;
    private readonly ILogger<ProfileImageService> _logger;

    public ProfileImageService(
        Func<IPAddress, HttpClient> pinnedClientFactory,
        IUserManager userManager,
        IServerApplicationPaths appPaths,
        IProviderManager providerManager,
        OidcUserStore userStore,
        IPluginConfigProvider configProvider,
        ILogger<ProfileImageService> logger,
        Func<string, CancellationToken, Task<IPAddress[]>>? dnsResolver = null)
    {
        _pinnedClientFactory = pinnedClientFactory;
        _userManager = userManager;
        _appPaths = appPaths;
        _providerManager = providerManager;
        _userStore = userStore;
        _configProvider = configProvider;
        _logger = logger;
        _dnsResolver = dnsResolver;
    }

    /// <summary>
    /// Builds an <see cref="HttpClient"/> that will only ever connect to <paramref name="address"/>,
    /// regardless of what DNS says at connect time. This is what makes the pre-flight address check
    /// meaningful: without pinning, an attacker-controlled resolver can answer "public" for our
    /// validation lookup and "169.254.169.254" microseconds later for the socket. TLS still validates
    /// against the original hostname, because the request URI is unchanged — only the dial target is.
    /// </summary>
    public static HttpClient CreatePinnedClient(IPAddress address)
    {
        ArgumentNullException.ThrowIfNull(address);

        var handler = new SocketsHttpHandler
        {
            // A redirect target is a fresh URL that has been through none of our checks.
            AllowAutoRedirect = false,
            ConnectCallback = async (context, cancellationToken) =>
            {
                var socket = new System.Net.Sockets.Socket(
                    System.Net.Sockets.SocketType.Stream, System.Net.Sockets.ProtocolType.Tcp)
                {
                    NoDelay = true
                };

                try
                {
                    await socket.ConnectAsync(new IPEndPoint(address, context.DnsEndPoint.Port), cancellationToken)
                        .ConfigureAwait(false);
                    return new System.Net.Sockets.NetworkStream(socket, ownsSocket: true);
                }
                catch
                {
                    socket.Dispose();
                    throw;
                }
            }
        };

        return new HttpClient(handler, disposeHandler: true) { Timeout = FetchTimeout };
    }

    /// <summary>
    /// Downloads <paramref name="pictureUrl"/> and sets it as <paramref name="userId"/>'s Jellyfin
    /// profile image. Never throws — a failed avatar sync is logged and skipped so it cannot break
    /// the login it is attached to.
    /// </summary>
    public async Task ApplyAsync(Guid userId, string? pictureUrl, string providerId, CancellationToken cancellationToken)
    {
        try
        {
            await ApplyCoreAsync(userId, pictureUrl, providerId, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            // Deliberately broad: this runs inside a login and has no failure mode worth
            // propagating. The user gets their session; they just keep their old avatar.
            _logger.LogWarning(
                ex,
                "Profile image sync failed for user {UserId} (provider={Provider}, source={Source}); login is unaffected",
                userId,
                providerId,
                LogRedaction.RedactUrl(pictureUrl));
        }
    }

    private async Task ApplyCoreAsync(Guid userId, string? pictureUrl, string providerId, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(pictureUrl))
        {
            return;
        }

        var provider = FindProvider(providerId);
        if (provider is null || !provider.SyncProfileImage)
        {
            return;
        }

        var user = _userManager.GetUserById(userId);
        if (user is null)
        {
            _logger.LogWarning("Profile image sync skipped: user {UserId} not found", userId);
            return;
        }

        // Cheapest exit first — no network at all when the IdP is still pointing at the image we
        // already stored. Avatar URLs are usually versioned, so this is the common path on every
        // login after the first.
        var record = await _userStore.GetByUserIdAsync(userId).ConfigureAwait(false);
        if (record is not null
            && string.Equals(record.ProfileImageSourceUrl, pictureUrl, StringComparison.Ordinal)
            && ProfileImageStillOnDisk(user))
        {
            _logger.LogDebug("Profile image for user {UserId} is already current; skipping fetch", userId);
            return;
        }

        SecurityValidation.EnsureSecureUrl(pictureUrl, provider.AllowInsecureAuthority, "PictureClaim URL");

        if (!Uri.TryCreate(pictureUrl, UriKind.Absolute, out var uri))
        {
            _logger.LogWarning("Profile image sync skipped: picture claim is not an absolute URL");
            return;
        }

        // The origin check is the primary control. Which of the two ways it passed then decides
        // whether the address blocklist applies (see below).
        var onAuthorityOrigin = IsAuthorityOrigin(uri, provider);
        if (!onAuthorityOrigin && !IsAllowlistedHost(uri, provider))
        {
            _logger.LogWarning(
                "Profile image sync refused: {Source} is not the provider's authority origin and is not in PictureAllowedHosts " +
                "(provider={Provider}). Add the host to that list if the IdP legitimately serves avatars from it.",
                LogRedaction.RedactUrl(pictureUrl),
                providerId);
            return;
        }

        // The provider's own Authority is exempt from the private-address blocklist. It is
        // admin-configured, we already send it the client secret and accept its identity
        // assertions, and self-hosted Authentik/Keycloak very commonly live on the LAN — blocking
        // it would mean no avatars for most self-hosted deployments in exchange for nothing:
        // an attacker who can point the Authority hostname at internal infrastructure already
        // controls the entire authentication flow. Hosts on PictureAllowedHosts get the full
        // check, since those exist for public CDNs. Either way the connection is still pinned to
        // the resolved address.
        var pinnedAddress = await SecurityValidation
            .ResolveAndValidateAsync(uri, _dnsResolver, cancellationToken, allowPrivateAddresses: onAuthorityOrigin)
            .ConfigureAwait(false);

        using var client = _pinnedClientFactory(pinnedAddress);
        using var response = await client.GetAsync(uri, HttpCompletionOption.ResponseHeadersRead, cancellationToken)
            .ConfigureAwait(false);

        if (!response.IsSuccessStatusCode)
        {
            _logger.LogWarning(
                "Profile image sync skipped: {Source} returned HTTP {Status}",
                LogRedaction.RedactUrl(pictureUrl),
                (int)response.StatusCode);
            return;
        }

        var mediaType = response.Content.Headers.ContentType?.MediaType;
        if (mediaType is null || !AllowedMediaTypes.Contains(mediaType))
        {
            _logger.LogWarning(
                "Profile image sync skipped: {Source} returned unsupported content type '{MediaType}'",
                LogRedaction.RedactUrl(pictureUrl),
                LogRedaction.Sanitize(mediaType, 64));
            return;
        }

        // Reject an honestly-declared oversize body before reading a byte; the read loop below is
        // what actually enforces the cap, because Content-Length may be absent or a lie.
        if (response.Content.Headers.ContentLength > MaxProfileImageBytes)
        {
            _logger.LogWarning(
                "Profile image sync skipped: {Source} declared {Bytes} bytes, over the {Cap} byte cap",
                LogRedaction.RedactUrl(pictureUrl),
                response.Content.Headers.ContentLength,
                MaxProfileImageBytes);
            return;
        }

        var bytes = await ReadCappedAsync(response, cancellationToken).ConfigureAwait(false);
        if (bytes is null)
        {
            _logger.LogWarning(
                "Profile image sync skipped: {Source} exceeded the {Cap} byte cap while streaming",
                LogRedaction.RedactUrl(pictureUrl),
                MaxProfileImageBytes);
            return;
        }

        // Trust the bytes, not the header. A server that says image/png and sends HTML is either
        // broken or hostile; either way we are not writing it into the user's profile.
        var extension = SniffImageExtension(bytes);
        if (extension is null)
        {
            _logger.LogWarning(
                "Profile image sync skipped: {Source} declared '{MediaType}' but the payload is not a JPEG, PNG, GIF or WebP",
                LogRedaction.RedactUrl(pictureUrl),
                LogRedaction.Sanitize(mediaType, 64));
            return;
        }

        var hash = Convert.ToHexString(SHA256.HashData(bytes));
        if (record is not null
            && string.Equals(record.ProfileImageHash, hash, StringComparison.OrdinalIgnoreCase)
            && ProfileImageStillOnDisk(user))
        {
            // URL moved but the image did not — record the new URL so the cheap check hits next time.
            await _userStore.RecordProfileImageAsync(userId, pictureUrl, hash).ConfigureAwait(false);
            return;
        }

        var imagePath = BuildImagePath(user, extension);
        if (imagePath is null)
        {
            return;
        }

        var previousPath = user.ProfileImage?.Path;
        if (user.ProfileImage is not null)
        {
            await _userManager.ClearProfileImageAsync(user).ConfigureAwait(false);
        }

        user.ProfileImage = new ImageInfo(imagePath);

        using (var source = new MemoryStream(bytes, writable: false))
        {
            await _providerManager.SaveImage(source, mediaType, imagePath).ConfigureAwait(false);
        }

        await _userManager.UpdateUserAsync(user).ConfigureAwait(false);
        await _userStore.RecordProfileImageAsync(userId, pictureUrl, hash).ConfigureAwait(false);

        // ClearProfileImageAsync drops the database row, not the file. If the new image has a
        // different extension the old file would otherwise be orphaned in the user's directory.
        DeleteSupersededImage(previousPath, imagePath);

        _logger.LogInformation(
            "Synced profile image for user '{Username}' from {Source} ({Bytes} bytes, {MediaType})",
            user.Username,
            LogRedaction.RedactUrl(pictureUrl),
            bytes.Length,
            mediaType);
    }

    /// <summary>
    /// Reads the response body, giving up as soon as it passes the cap. Returns null when the cap
    /// was exceeded. This — not the Content-Length check — is the real size limit, because a
    /// hostile host can omit the header or understate it.
    /// </summary>
    private static async Task<byte[]?> ReadCappedAsync(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        using var buffer = new MemoryStream();
        var chunk = new byte[81920];

        while (true)
        {
            var read = await stream.ReadAsync(chunk, cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                break;
            }

            if (buffer.Length + read > MaxProfileImageBytes)
            {
                return null;
            }

            await buffer.WriteAsync(chunk.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
        }

        return buffer.ToArray();
    }

    /// <summary>
    /// Returns the file extension implied by the payload's magic bytes, or null if the payload is
    /// not one of the formats we accept. Deliberately has no "unknown → .jpg" fallback: writing an
    /// unidentified payload under an image extension is how a content-type confusion bug starts.
    /// </summary>
    internal static string? SniffImageExtension(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length >= 3 && bytes[0] == 0xFF && bytes[1] == 0xD8 && bytes[2] == 0xFF)
        {
            return ".jpg";
        }

        if (bytes.Length >= 8
            && bytes[0] == 0x89 && bytes[1] == 0x50 && bytes[2] == 0x4E && bytes[3] == 0x47
            && bytes[4] == 0x0D && bytes[5] == 0x0A && bytes[6] == 0x1A && bytes[7] == 0x0A)
        {
            return ".png";
        }

        if (bytes.Length >= 6
            && bytes[0] == 0x47 && bytes[1] == 0x49 && bytes[2] == 0x46 && bytes[3] == 0x38
            && (bytes[4] == 0x37 || bytes[4] == 0x39) && bytes[5] == 0x61)
        {
            return ".gif";
        }

        // RIFF....WEBP
        if (bytes.Length >= 12
            && bytes[0] == 0x52 && bytes[1] == 0x49 && bytes[2] == 0x46 && bytes[3] == 0x46
            && bytes[8] == 0x57 && bytes[9] == 0x45 && bytes[10] == 0x42 && bytes[11] == 0x50)
        {
            return ".webp";
        }

        return null;
    }

    /// <summary>
    /// True when the URL is on the provider's own Authority origin. Delegated to
    /// <see cref="SecurityValidation.EnsureSameHost"/> so avatars follow the same scheme+host+port
    /// rule as discovered OIDC endpoints.
    /// </summary>
    private static bool IsAuthorityOrigin(Uri uri, OidcProviderConfig provider)
    {
        try
        {
            SecurityValidation.EnsureSameHost(
                SecurityValidation.NormalizeAuthority(provider.Authority), uri.ToString(), "PictureClaim URL");
            return true;
        }
        catch (InvalidOperationException)
        {
            return false;
        }
    }

    /// <summary>True when the URL's host appears on the admin's extra-hosts allowlist.</summary>
    private static bool IsAllowlistedHost(Uri uri, OidcProviderConfig provider)
    {
        foreach (var host in provider.PictureAllowedHosts)
        {
            if (!string.IsNullOrWhiteSpace(host)
                && string.Equals(host.Trim(), uri.Host, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Builds the on-disk path for the avatar, matching Jellyfin's own UserImageController layout
    /// (<c>&lt;UserConfigurationDirectoryPath&gt;/&lt;username&gt;/profile.&lt;ext&gt;</c>) so the
    /// server's existing image serving and the admin UI's upload/delete behave identically.
    /// Returns null if the composed path escapes the user-configuration directory.
    /// </summary>
    private string? BuildImagePath(User user, string extension)
    {
        var root = _appPaths.UserConfigurationDirectoryPath;
        var candidate = Path.GetFullPath(Path.Combine(root, user.Username, "profile" + extension));
        var rootFull = Path.GetFullPath(root);

        // Jellyfin validates usernames to a safe charset, so this should be unreachable —
        // it is here because the cost of being wrong is an arbitrary file write.
        if (!candidate.StartsWith(
                rootFull.EndsWith(Path.DirectorySeparatorChar) ? rootFull : rootFull + Path.DirectorySeparatorChar,
                StringComparison.Ordinal))
        {
            _logger.LogError(
                "Refusing to write profile image for user {UserId}: composed path escapes the user configuration directory",
                user.Id);
            return null;
        }

        return candidate;
    }

    private static bool ProfileImageStillOnDisk(User user)
    {
        var path = user.ProfileImage?.Path;
        return !string.IsNullOrEmpty(path) && File.Exists(path);
    }

    private void DeleteSupersededImage(string? previousPath, string currentPath)
    {
        if (string.IsNullOrEmpty(previousPath)
            || string.Equals(previousPath, currentPath, StringComparison.Ordinal)
            || !File.Exists(previousPath))
        {
            return;
        }

        try
        {
            File.Delete(previousPath);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            _logger.LogDebug(ex, "Could not delete superseded profile image; leaving it in place");
        }
    }

    private OidcProviderConfig? FindProvider(string providerId)
    {
        foreach (var p in _configProvider.GetConfiguration().Providers)
        {
            if (string.Equals(p.ProviderId, providerId, StringComparison.OrdinalIgnoreCase))
            {
                return p;
            }
        }

        return null;
    }
}
