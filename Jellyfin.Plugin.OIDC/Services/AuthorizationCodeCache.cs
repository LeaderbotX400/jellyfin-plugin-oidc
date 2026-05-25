using System;
using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.OIDC.Services;

/// <summary>
/// Defense-in-depth one-time-use cache for OIDC authorization codes.
///
/// The IdP's token endpoint already enforces single-use codes, but we add an in-process check to
/// detect replays before any token-exchange network call is made. Codes are stored keyed by
/// (providerId, code) and expire after 10 minutes (well beyond any normal browser round-trip).
///
/// This is NOT a substitute for IdP enforcement — it is an additional layer to surface replay
/// attempts in logs and avoid unnecessary token-endpoint traffic.
/// </summary>
public sealed class AuthorizationCodeCache : IHostedService, IDisposable
{
    private static readonly TimeSpan Ttl = TimeSpan.FromMinutes(10);
    private static readonly TimeSpan CleanupInterval = TimeSpan.FromMinutes(5);

    private readonly ConcurrentDictionary<string, DateTimeOffset> _seen = new(StringComparer.Ordinal);
    private readonly ILogger<AuthorizationCodeCache> _logger;
    private CancellationTokenSource? _cts;
    private Task? _cleanupLoop;

    public AuthorizationCodeCache(ILogger<AuthorizationCodeCache> logger)
    {
        _logger = logger;
    }

    /// <summary>
    /// Records the authorization code as consumed. Returns <c>true</c> if this is the first time
    /// the code has been seen (caller may proceed). Returns <c>false</c> if the code was already
    /// consumed within the TTL window (replay detected — caller must reject).
    /// </summary>
    public bool TryConsume(string code, string providerId)
    {
        if (string.IsNullOrEmpty(code) || string.IsNullOrEmpty(providerId))
        {
            return false;
        }

        var key = providerId + "|" + code;
        var expiry = DateTimeOffset.UtcNow + Ttl;
        return _seen.TryAdd(key, expiry);
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        _cts = new CancellationTokenSource();
        _cleanupLoop = RunCleanupLoopAsync(_cts.Token);
        return Task.CompletedTask;
    }

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        if (_cts != null)
        {
            await _cts.CancelAsync().ConfigureAwait(false);
        }

        if (_cleanupLoop != null)
        {
            try
            {
                await _cleanupLoop.ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                // Expected on shutdown.
            }
        }
    }

    public void Dispose()
    {
        _cts?.Dispose();
    }

    private async Task RunCleanupLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(CleanupInterval, ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                break;
            }

            var now = DateTimeOffset.UtcNow;
            var removed = 0;
            foreach (var key in _seen.Keys)
            {
                if (_seen.TryGetValue(key, out var exp) && exp <= now)
                {
                    if (_seen.TryRemove(key, out _))
                    {
                        removed++;
                    }
                }
            }

            if (removed > 0)
            {
                _logger.LogDebug("AuthorizationCodeCache: evicted {Count} expired entries", removed);
            }
        }
    }
}
