using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.OIDC.Services;

/// <summary>
/// Per-IP rate limiter for the OIDC callback. Counts failed callback attempts in a sliding window
/// and bans the source IP for a fixed cool-down once the threshold is exceeded. In-memory only;
/// state is intentionally not persisted across plugin restarts (an attacker restarting the host
/// is a much bigger problem than a reset counter).
///
/// Defaults — 10 failures per 5 minutes triggers a 15-minute ban — are conservative enough that
/// no legitimate user hits them while still bounding state-replay and code-fuzzing attempts.
/// </summary>
public sealed class CallbackRateLimiter : IHostedService, IDisposable
{
    private static readonly TimeSpan Window = TimeSpan.FromMinutes(5);
    private static readonly int MaxFailures = 10;
    private static readonly TimeSpan BanDuration = TimeSpan.FromMinutes(15);
    private static readonly TimeSpan CleanupInterval = TimeSpan.FromMinutes(5);

    private readonly ConcurrentDictionary<string, IpRecord> _records = new(StringComparer.Ordinal);
    private readonly ILogger<CallbackRateLimiter> _logger;
    private CancellationTokenSource? _cts;
    private Task? _cleanupLoop;

    public CallbackRateLimiter(ILogger<CallbackRateLimiter> logger)
    {
        _logger = logger;
    }

    /// <summary>
    /// True if the IP is currently banned. <paramref name="retryAfter"/> is the remaining ban time.
    /// Null / loopback IPs are never throttled (covers tests + admin-from-localhost cases).
    /// </summary>
    public bool IsBanned(IPAddress? ip, out TimeSpan retryAfter)
    {
        retryAfter = TimeSpan.Zero;
        var key = NormalizeKey(ip);
        if (key == null) return false;

        if (_records.TryGetValue(key, out var rec))
        {
            lock (rec)
            {
                if (rec.BannedUntil > DateTimeOffset.UtcNow)
                {
                    retryAfter = rec.BannedUntil - DateTimeOffset.UtcNow;
                    return true;
                }
            }
        }
        return false;
    }

    /// <summary>Records a failed callback for this IP and bans if threshold exceeded.</summary>
    public void RecordFailure(IPAddress? ip)
    {
        var key = NormalizeKey(ip);
        if (key == null) return;

        var rec = _records.GetOrAdd(key, _ => new IpRecord());
        var now = DateTimeOffset.UtcNow;
        lock (rec)
        {
            rec.Failures.RemoveAll(t => now - t > Window);
            rec.Failures.Add(now);
            if (rec.Failures.Count >= MaxFailures && rec.BannedUntil <= now)
            {
                rec.BannedUntil = now + BanDuration;
                _logger.LogWarning(
                    "OIDC callback rate limit: banning IP {Ip} for {Minutes}m after {Count} failures in {WindowMin}m",
                    key, BanDuration.TotalMinutes, rec.Failures.Count, Window.TotalMinutes);
            }
        }
    }

    /// <summary>Clears state for an IP after a successful login.</summary>
    public void RecordSuccess(IPAddress? ip)
    {
        var key = NormalizeKey(ip);
        if (key == null) return;
        _records.TryRemove(key, out _);
    }

    private static string? NormalizeKey(IPAddress? ip)
    {
        if (ip == null) return null;
        if (IPAddress.IsLoopback(ip)) return null;
        // Map v4-mapped-v6 to v4 for stable keying.
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        return ip.ToString();
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        _cts = new CancellationTokenSource();
        _cleanupLoop = RunCleanupLoopAsync(_cts.Token);
        return Task.CompletedTask;
    }

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        if (_cts != null) await _cts.CancelAsync().ConfigureAwait(false);
        if (_cleanupLoop != null)
        {
            try { await _cleanupLoop.ConfigureAwait(false); }
            catch (OperationCanceledException) { }
        }
    }

    public void Dispose() => _cts?.Dispose();

    private async Task RunCleanupLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try { await Task.Delay(CleanupInterval, ct).ConfigureAwait(false); }
            catch (OperationCanceledException) { break; }

            var now = DateTimeOffset.UtcNow;
            foreach (var kv in _records)
            {
                var rec = kv.Value;
                lock (rec)
                {
                    rec.Failures.RemoveAll(t => now - t > Window);
                    if (rec.Failures.Count == 0 && rec.BannedUntil <= now)
                    {
                        _records.TryRemove(kv.Key, out _);
                    }
                }
            }
        }
    }

    private sealed class IpRecord
    {
        public List<DateTimeOffset> Failures { get; } = new();
        public DateTimeOffset BannedUntil { get; set; }
    }
}
