using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.OIDC.Services;

/// <summary>
/// Caps wrong-code attempts on the Quick Connect bridge, keyed by the authenticated Jellyfin user.
///
/// Why this is needed on top of the plugin's per-IP <see cref="CallbackRateLimiter"/>: a Quick
/// Connect code is six digits and lives for ten minutes, and the authorize endpoint deliberately
/// stays usable after a wrong code so a mistype does not force the whole IdP login again. Without
/// a counter, any signed-in low-privilege user could grind the code space to hijack another
/// user's pending request — the exact hole left open in the implementation this feature is
/// modelled on, whose only throttle is a per-IP limit shared with unrelated endpoints (so it is
/// both starvable by honest NAT traffic and evadable by spreading across addresses).
///
/// Keying on user id rather than IP is what makes it meaningful here: the endpoint is already
/// behind [Authorize], so the caller always has a stable identity, and that identity is precisely
/// what an attacker cannot cheaply rotate.
///
/// In-memory only, like the other limiters in this plugin — a restart resetting the counter is a
/// far smaller problem than an attacker who can restart the host.
/// </summary>
public sealed class QuickConnectAttemptLimiter : IHostedService, IDisposable
{
    internal const int MaxFailures = 5;
    private static readonly TimeSpan Window = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan CleanupInterval = TimeSpan.FromMinutes(5);

    private readonly ConcurrentDictionary<Guid, Attempts> _records = new();
    private readonly ILogger<QuickConnectAttemptLimiter> _logger;
    private CancellationTokenSource? _cts;
    private Task? _cleanupLoop;

    public QuickConnectAttemptLimiter(ILogger<QuickConnectAttemptLimiter> logger)
    {
        _logger = logger;
    }

    /// <summary>
    /// True when the user has burned through <see cref="MaxFailures"/> wrong codes inside the
    /// window and must wait. <paramref name="retryAfter"/> is the time left.
    /// </summary>
    public bool IsBlocked(Guid userId, out TimeSpan retryAfter)
    {
        retryAfter = TimeSpan.Zero;

        if (!_records.TryGetValue(userId, out var rec))
        {
            return false;
        }

        lock (rec)
        {
            var age = DateTimeOffset.UtcNow - rec.WindowStart;
            if (age >= Window)
            {
                // Window rolled over; the record is stale rather than blocking.
                return false;
            }

            if (rec.Count < MaxFailures)
            {
                return false;
            }

            retryAfter = Window - age;
            return true;
        }
    }

    /// <summary>Records a wrong or rejected code for this user.</summary>
    public void RecordFailure(Guid userId)
    {
        var rec = _records.GetOrAdd(userId, _ => new Attempts());

        lock (rec)
        {
            if (DateTimeOffset.UtcNow - rec.WindowStart >= Window)
            {
                rec.WindowStart = DateTimeOffset.UtcNow;
                rec.Count = 0;
            }

            rec.Count++;

            if (rec.Count == MaxFailures)
            {
                _logger.LogWarning(
                    "Quick Connect attempt limit reached for user {UserId} ({Count} wrong codes); " +
                    "further attempts are refused for {Minutes} minutes",
                    userId,
                    rec.Count,
                    Window.TotalMinutes);
            }
        }
    }

    /// <summary>Clears the counter after a successful authorization.</summary>
    public void RecordSuccess(Guid userId) => _records.TryRemove(userId, out _);

    public Task StartAsync(CancellationToken cancellationToken)
    {
        _cts = new CancellationTokenSource();
        _cleanupLoop = Task.Run(() => CleanupLoopAsync(_cts.Token), CancellationToken.None);
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
                // Expected on shutdown.
            }
        }
    }

    private async Task CleanupLoopAsync(CancellationToken token)
    {
        while (!token.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(CleanupInterval, token).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return;
            }

            Prune();
        }
    }

    /// <summary>Drops records whose window has elapsed, so the map cannot grow without bound.</summary>
    internal void Prune()
    {
        var now = DateTimeOffset.UtcNow;
        var stale = new List<Guid>();

        foreach (var kvp in _records)
        {
            lock (kvp.Value)
            {
                if (now - kvp.Value.WindowStart >= Window)
                {
                    stale.Add(kvp.Key);
                }
            }
        }

        foreach (var key in stale)
        {
            _records.TryRemove(key, out _);
        }
    }

    public void Dispose()
    {
        _cts?.Dispose();
        _cts = null;
    }

    private sealed class Attempts
    {
        public DateTimeOffset WindowStart { get; set; } = DateTimeOffset.UtcNow;

        public int Count { get; set; }
    }
}
