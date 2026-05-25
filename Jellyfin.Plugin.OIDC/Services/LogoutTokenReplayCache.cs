using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.OIDC.Services;

/// <summary>
/// In-memory replay cache for OIDC back-channel logout_token jti values.
///
/// RFC 8935 §2.6: a relying party MUST reject any logout_token whose jti has been seen before
/// within the token's validity window. Keyed by (issuer, jti) so a jti collision across
/// different IdPs doesn't cause cross-provider false positives.
/// </summary>
public sealed class LogoutTokenReplayCache : IHostedService, IDisposable
{
    private static readonly TimeSpan CleanupInterval = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan DefaultTtl = TimeSpan.FromMinutes(5);

    private readonly ConcurrentDictionary<string, DateTimeOffset> _seen = new(StringComparer.Ordinal);
    private readonly ILogger<LogoutTokenReplayCache> _logger;
    private CancellationTokenSource? _cts;
    private Task? _cleanupLoop;

    public LogoutTokenReplayCache(ILogger<LogoutTokenReplayCache> logger)
    {
        _logger = logger;
    }

    /// <summary>
    /// Records the jti as seen. Returns false if this (issuer, jti) was already present and
    /// still within its TTL — caller must treat that as a replay and reject.
    /// </summary>
    public bool TryRegister(string issuer, string jti, DateTimeOffset expiresAt)
    {
        if (string.IsNullOrEmpty(issuer) || string.IsNullOrEmpty(jti))
        {
            return false;
        }

        // Clamp absurd or past TTLs to the default window so a malicious IdP can't bloat memory
        // or bypass replay protection by setting exp far in the future / in the past.
        var now = DateTimeOffset.UtcNow;
        var ttl = expiresAt - now;
        if (ttl <= TimeSpan.Zero || ttl > TimeSpan.FromHours(1))
        {
            expiresAt = now + DefaultTtl;
        }

        var key = issuer + "|" + jti;
        return _seen.TryAdd(key, expiresAt);
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
                _logger.LogWarning(ex, "LogoutTokenReplayCache cleanup failed");
            }
        }
    }

    private void Cleanup()
    {
        var now = DateTimeOffset.UtcNow;
        var removed = 0;
        foreach (var (key, exp) in _seen)
        {
            if (exp <= now && _seen.TryRemove(new KeyValuePair<string, DateTimeOffset>(key, exp)))
            {
                removed++;
            }
        }

        if (removed > 0)
        {
            _logger.LogDebug("LogoutTokenReplayCache: pruned {Count} expired jti entries", removed);
        }
    }
}
