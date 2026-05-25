using System;
using System.Threading;
using System.Threading.Tasks;
using Jellyfin.Plugin.OIDC.Services;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Jellyfin.Plugin.OIDC.Tests;

/// <summary>
/// Unit tests for <see cref="LogoutTokenReplayCache"/> — the in-memory jti replay guard
/// required by RFC 8935 §2.6.
/// </summary>
public class LogoutTokenReplayCacheTests : IAsyncDisposable
{
    private readonly LogoutTokenReplayCache _cache =
        new(NullLogger<LogoutTokenReplayCache>.Instance);

    public async ValueTask DisposeAsync()
    {
        await _cache.StopAsync(CancellationToken.None);
        _cache.Dispose();
    }

    // ── Core first-use / replay semantics ────────────────────────────────────

    [Fact]
    public void TryRegister_FirstUse_ReturnsTrue()
    {
        var expiry = DateTimeOffset.UtcNow.AddMinutes(5);
        Assert.True(_cache.TryRegister("https://idp.example", "jti-1", expiry));
    }

    [Fact]
    public void TryRegister_SecondUse_SameIssuerAndJti_ReturnsFalse()
    {
        var expiry = DateTimeOffset.UtcNow.AddMinutes(5);
        _cache.TryRegister("https://idp.example", "jti-replay", expiry);
        var second = _cache.TryRegister("https://idp.example", "jti-replay", expiry);
        Assert.False(second);
    }

    [Fact]
    public void TryRegister_SameJti_DifferentIssuers_AreIndependent()
    {
        // A jti used by IdP-A must not block the same string from IdP-B.
        var expiry = DateTimeOffset.UtcNow.AddMinutes(5);
        var a = _cache.TryRegister("https://idp-a.example", "shared-jti", expiry);
        var b = _cache.TryRegister("https://idp-b.example", "shared-jti", expiry);
        Assert.True(a);
        Assert.True(b);
    }

    // ── Guard against malicious TTL values ───────────────────────────────────

    [Fact]
    public void TryRegister_ExpiredEntry_StillRegistersWithDefaultTtl()
    {
        // A token with exp already in the past — we clamp to DefaultTtl (5 min) instead
        // of ignoring it. The jti must be stored (return true on first call).
        var pastExpiry = DateTimeOffset.UtcNow.AddMinutes(-10);
        Assert.True(_cache.TryRegister("https://idp.example", "jti-past-exp", pastExpiry));
        // And a second call for the same (issuer, jti) must still be blocked.
        Assert.False(_cache.TryRegister("https://idp.example", "jti-past-exp", pastExpiry));
    }

    [Fact]
    public void TryRegister_AbsurdFutureTtl_ClampedToOneHour()
    {
        // An IdP trying to bloat memory by setting exp far in the future must be clamped.
        // We can't directly inspect the stored expiry, but we can verify registration
        // succeeds and replay is still blocked.
        var farFuture = DateTimeOffset.UtcNow.AddYears(100);
        Assert.True(_cache.TryRegister("https://idp.example", "jti-far-future", farFuture));
        Assert.False(_cache.TryRegister("https://idp.example", "jti-far-future", farFuture));
    }

    // ── Guard against missing / empty inputs ────────────────────────────────

    [Fact]
    public void TryRegister_EmptyIssuer_ReturnsFalse()
    {
        Assert.False(_cache.TryRegister(string.Empty, "jti-x", DateTimeOffset.UtcNow.AddMinutes(5)));
    }

    [Fact]
    public void TryRegister_EmptyJti_ReturnsFalse()
    {
        Assert.False(_cache.TryRegister("https://idp.example", string.Empty, DateTimeOffset.UtcNow.AddMinutes(5)));
    }

    // ── Lifecycle ──────────────────────────────────────────────────────────

    [Fact]
    public async Task StartAndStop_CompletesCleanly()
    {
        await _cache.StartAsync(CancellationToken.None);
        await _cache.StopAsync(CancellationToken.None);
    }

    // ── Concurrency ─────────────────────────────────────────────────────────

    [Fact]
    public async Task TryRegister_ConcurrentFirstRegistration_ExactlyOneSucceeds()
    {
        const int threads = 20;
        int successCount = 0;
        var expiry = DateTimeOffset.UtcNow.AddMinutes(5);
        var barrier = new System.Threading.Barrier(threads);

        var tasks = new Task[threads];
        for (var i = 0; i < threads; i++)
        {
            tasks[i] = Task.Run(() =>
            {
                barrier.SignalAndWait();
                if (_cache.TryRegister("https://idp.example", "concurrent-jti", expiry))
                {
                    Interlocked.Increment(ref successCount);
                }
            });
        }

        await Task.WhenAll(tasks);
        Assert.Equal(1, successCount);
    }
}
