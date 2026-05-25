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

    /// <summary>Set when initiating an account-linking flow for an already-authenticated Jellyfin user.</summary>
    public Guid? LinkingForUserId { get; init; }

    /// <summary>
    /// SHA-256 hash of the per-request CSRF token issued at /Start as a cookie. The /Callback
    /// handler re-reads the cookie and verifies SHA-256(cookie) == CsrfBindingHash using a
    /// fixed-time comparison. Null only when the state was constructed by flows that don't
    /// bind a browser cookie (e.g. SAML, where RelayState already provides anti-replay binding).
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
    public string[] Entitlements { get; init; } = Array.Empty<string>();
    public DateTimeOffset CreatedAt { get; init; } = DateTimeOffset.UtcNow;

    /// <summary>Present when this session is for account linking rather than normal login.</summary>
    public Guid? LinkUserId { get; init; }
}

public sealed class StateManager : IHostedService, IDisposable
{
    private static readonly TimeSpan StateExpiry = TimeSpan.FromMinutes(10);
    private static readonly TimeSpan SessionExpiry = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan CleanupInterval = TimeSpan.FromMinutes(2);

    private readonly ConcurrentDictionary<string, OidcState> _pendingStates = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, AuthorizedSession> _authorizedSessions = new(StringComparer.Ordinal);
    private readonly ILogger<StateManager> _logger;
    private Timer? _cleanupTimer;

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

    public string StoreState(OidcState state)
    {
        var key = GenerateCsprngToken();
        _pendingStates[key] = state;
        return key;
    }

    public OidcState? ConsumeState(string stateKey)
    {
        if (string.IsNullOrEmpty(stateKey))
        {
            return null;
        }

        if (!_pendingStates.TryRemove(stateKey, out var state))
        {
            return null;
        }

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
        _cleanupTimer = new Timer(Cleanup, null, CleanupInterval, CleanupInterval);
        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        _cleanupTimer?.Change(Timeout.Infinite, 0);
        return Task.CompletedTask;
    }

    public void Dispose()
    {
        _cleanupTimer?.Dispose();
    }

    private void Cleanup(object? state)
    {
        var now = DateTimeOffset.UtcNow;

        foreach (var (key, oidcState) in _pendingStates)
        {
            if (now - oidcState.CreatedAt > StateExpiry)
            {
                _pendingStates.TryRemove(key, out _);
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
