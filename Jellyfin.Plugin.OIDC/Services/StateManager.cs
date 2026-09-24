using System;
using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.OIDC.Services;

public sealed class OidcState
{
    public required string ProviderId { get; init; }
    public required string Nonce { get; init; }
    public required string CodeVerifier { get; init; }
    public required string RedirectUri { get; init; }
    public DateTimeOffset CreatedAt { get; init; } = DateTimeOffset.UtcNow;

    /// <summary>
    /// True when this flow was started from the Quick Connect bridge, so the callback should render
    /// the code-entry page rather than hand the browser a web session. Deliberately a bare flag and
    /// not a return URL — carrying a URL through the round trip would be an open-redirect surface.
    /// </summary>
    public bool QuickConnect { get; init; }

    /// <summary>
    /// SHA-256 hash of the per-request CSRF token issued at /Start as a cookie. The /Callback
    /// handler re-reads the cookie and verifies SHA-256(cookie) == CsrfBindingHash using a
    /// fixed-time comparison. Null only when the state was constructed by flows that don't
    /// bind a browser cookie (IdP-initiated SAML, which has no /Start).
    /// </summary>
    public byte[]? CsrfBindingHash { get; init; }
}

public sealed class AuthorizedSession
{
    public required string ProviderId { get; init; }
    public required string Username { get; init; }
    public string? DisplayName { get; init; }
    public required string[] Roles { get; init; }
    public string Sub { get; init; } = string.Empty;
    public string Sid { get; init; } = string.Empty;
    public string[] Entitlements { get; init; } = Array.Empty<string>();
    public DateTimeOffset CreatedAt { get; init; } = DateTimeOffset.UtcNow;

    /// <summary>Email claim from the id_token (for AutoLinkByVerifiedEmail policy).</summary>
    public string? Email { get; init; }

    /// <summary>Whether the id_token asserted email_verified=true.</summary>
    public bool EmailVerified { get; init; }

    /// <summary>
    /// Avatar URL from the provider's picture claim, resolved at callback time from the id_token
    /// or the userinfo endpoint. Applied by <see cref="ProfileImageService"/> after the session
    /// is created. Null when the provider has profile-image sync disabled or supplied no claim.
    /// </summary>
    public string? PictureUrl { get; init; }

    /// <summary>
    /// SHA-256 of the browser-binding cookie issued when the flow started, carried to /Auth for
    /// flows whose return leg cannot see the cookie (the SAML ACS is a cross-site POST, which a
    /// SameSite=Lax cookie does not ride). Null when no binding was issued (IdP-initiated SAML).
    /// </summary>
    public byte[]? CsrfBindingHash { get; init; }
}

public sealed class StateManager : IHostedService, IDisposable
{
    private static readonly TimeSpan StateExpiry = TimeSpan.FromMinutes(10);
    private static readonly TimeSpan SessionExpiry = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan CleanupInterval = TimeSpan.FromMinutes(2);

    /// <summary>
    /// In-flight logins one client may hold at once. The per-client limit is the real control: a
    /// global cap alone let a single anonymous client fill every slot and lock everyone out.
    /// </summary>
    internal const int MaxPendingStatesPerClient = 50;

    /// <summary>Memory backstop across all clients (many sources, or an unkeyed caller).</summary>
    internal const int MaxPendingStates = 100_000;

    private readonly ConcurrentDictionary<string, int> _pendingPerClient = new(StringComparer.Ordinal);

    private sealed record OidcStateEntry(OidcState State, string? ClientKey);

    private readonly ConcurrentDictionary<string, OidcStateEntry> _pendingStates = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, AuthorizedSession> _authorizedSessions = new(StringComparer.Ordinal);
    private readonly ILogger<StateManager> _logger;
    private CancellationTokenSource? _cts;
    private Task? _cleanupLoop;

    public StateManager(ILogger<StateManager> logger)
    {
        _logger = logger;
    }

    /// <summary>
    /// Generates a 256-bit cryptographically-secure random token, base64url-encoded.
    /// Replaces the old <c>Guid.NewGuid().ToString("N")</c> approach which only delivered
    /// 122 bits of (non-CSPRNG) entropy.
    /// </summary>
    public static string GenerateCsprngToken(int byteLength = 32)
    {
        Span<byte> buf = stackalloc byte[64];
        if (byteLength > buf.Length)
        {
            var heap = new byte[byteLength];
            RandomNumberGenerator.Fill(heap);
            return WebEncoders.Base64UrlEncode(heap);
        }

        var slice = buf[..byteLength];
        RandomNumberGenerator.Fill(slice);
        return WebEncoders.Base64UrlEncode(slice.ToArray());
    }

    /// <summary>SHA-256 hash of the supplied token, suitable for storing alongside an opaque cookie.</summary>
    public static byte[] HashToken(string token)
    {
        return SHA256.HashData(Encoding.UTF8.GetBytes(token));
    }

    /// <summary>
    /// Stores the state for a flow that is about to leave for the IdP, returning its opaque key,
    /// or null when the caller must refuse (503).
    ///
    /// /Start is anonymous and every call adds an entry that lives for 10 minutes, so it needs a
    /// bound. The bound is per client (<paramref name="clientKey"/>, from
    /// <see cref="ClientKeyFor"/>): a flood from one source exhausts only its own allowance, not
    /// everyone's. Live entries are never evicted, which would let a flood cancel real users'
    /// in-flight logins; expired ones are swept first when the global backstop is reached.
    /// </summary>
    public string? StoreState(OidcState state, string? clientKey = null)
    {
        if (_pendingStates.Count >= MaxPendingStates)
        {
            Cleanup();
            if (_pendingStates.Count >= MaxPendingStates)
            {
                _logger.LogWarning(
                    "Refusing to start an SSO login: {Count} pending sign-ins already in flight (cap {Cap})",
                    _pendingStates.Count, MaxPendingStates);
                return null;
            }
        }

        if (clientKey is not null)
        {
            var held = _pendingPerClient.AddOrUpdate(clientKey, 1, (_, n) => n + 1);
            if (held > MaxPendingStatesPerClient)
            {
                ReleaseClientSlot(clientKey);
                _logger.LogWarning(
                    "Refusing to start an SSO login: client {Client} already has {Cap} sign-ins in flight",
                    clientKey, MaxPendingStatesPerClient);
                return null;
            }
        }

        var key = GenerateCsprngToken();
        _pendingStates[key] = new OidcStateEntry(state, clientKey);
        return key;
    }

    /// <summary>
    /// The key a client's pending logins are counted under: the IPv4 address, or the /64 for IPv6
    /// (one subscriber usually holds a whole /64, so per-address keys would be trivially rotated).
    /// Null when the address is unknown.
    /// </summary>
    public static string? ClientKeyFor(System.Net.IPAddress? address)
    {
        if (address is null)
        {
            return null;
        }

        if (address.IsIPv4MappedToIPv6)
        {
            address = address.MapToIPv4();
        }

        if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
        {
            return Convert.ToHexString(address.GetAddressBytes(), 0, 8) + "::/64";
        }

        return address.ToString();
    }

    private void ReleaseClientSlot(string? clientKey)
    {
        if (clientKey is null)
        {
            return;
        }

        var remaining = _pendingPerClient.AddOrUpdate(clientKey, 0, (_, n) => Math.Max(0, n - 1));
        if (remaining == 0)
        {
            _pendingPerClient.TryRemove(new KeyValuePair<string, int>(clientKey, 0));
        }
    }

    private void RemovePending(string key, OidcStateEntry entry)
    {
        if (_pendingStates.TryRemove(new KeyValuePair<string, OidcStateEntry>(key, entry)))
        {
            ReleaseClientSlot(entry.ClientKey);
        }
    }

    public OidcState? ConsumeState(string stateKey)
    {
        if (string.IsNullOrEmpty(stateKey))
        {
            return null;
        }

        if (!_pendingStates.TryRemove(stateKey, out var entry))
        {
            return null;
        }

        ReleaseClientSlot(entry.ClientKey);
        var state = entry.State;

        if (DateTimeOffset.UtcNow - state.CreatedAt > StateExpiry)
        {
            _logger.LogWarning("OIDC state expired for provider {ProviderId}", state.ProviderId);
            return null;
        }

        return state;
    }

    public string StoreAuthorizedSession(AuthorizedSession session)
    {
        var token = GenerateCsprngToken();
        _authorizedSessions[token] = session;
        return token;
    }

    public AuthorizedSession? ConsumeAuthorizedSession(string token)
    {
        if (string.IsNullOrEmpty(token))
        {
            return null;
        }

        if (!_authorizedSessions.TryRemove(token, out var session))
        {
            return null;
        }

        if (DateTimeOffset.UtcNow - session.CreatedAt > SessionExpiry)
        {
            _logger.LogWarning("Authorized session expired for user {Username}", session.Username);
            return null;
        }

        return session;
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        _cts = new CancellationTokenSource();
        _cleanupLoop = RunCleanupLoopAsync(_cts.Token);
        return Task.CompletedTask;
    }

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        if (_cts is null)
        {
            return;
        }

        await _cts.CancelAsync().ConfigureAwait(false);

        if (_cleanupLoop is not null)
        {
            try
            {
                await _cleanupLoop.ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                // expected on cancellation
            }
        }
    }

    public void Dispose()
    {
        _cts?.Dispose();
    }

    /// <summary>Exposed internal for testing: runs one cleanup pass synchronously.</summary>
    internal void RunCleanup()
    {
        Cleanup();
    }

    private async Task RunCleanupLoopAsync(CancellationToken ct)
    {
        using var timer = new PeriodicTimer(CleanupInterval);
        while (await timer.WaitForNextTickAsync(ct).ConfigureAwait(false))
        {
            try
            {
                Cleanup();
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "StateManager cleanup failed");
            }
        }
    }

    private void Cleanup()
    {
        var now = DateTimeOffset.UtcNow;

        foreach (var (key, entry) in _pendingStates)
        {
            if (now - entry.State.CreatedAt > StateExpiry)
            {
                RemovePending(key, entry);
            }
        }

        foreach (var (key, session) in _authorizedSessions)
        {
            if (now - session.CreatedAt > SessionExpiry)
            {
                _authorizedSessions.TryRemove(key, out _);
            }
        }
    }
}
