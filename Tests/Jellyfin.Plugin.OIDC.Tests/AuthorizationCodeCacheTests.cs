using System;
using System.Threading;
using System.Threading.Tasks;
using Jellyfin.Plugin.OIDC.Services;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Jellyfin.Plugin.OIDC.Tests;

/// <summary>
/// Unit tests for <see cref="AuthorizationCodeCache"/> — the in-process one-time-use guard
/// against authorization code replays.
/// </summary>
public class AuthorizationCodeCacheTests : IAsyncDisposable
{
    private readonly AuthorizationCodeCache _cache =
        new(NullLogger<AuthorizationCodeCache>.Instance);

    public async ValueTask DisposeAsync()
    {
        await _cache.StopAsync(CancellationToken.None);
        _cache.Dispose();
    }

    // ── First-use / second-use semantics ─────────────────────────────────────

    [Fact]
    public void TryConsume_FirstUse_ReturnsTrue()
    {
        var result = _cache.TryConsume("code-abc", "provider1");
        Assert.True(result);
    }

    [Fact]
    public void TryConsume_SecondUse_ReturnsFalse()
    {
        _cache.TryConsume("code-replay", "provider1");
        var second = _cache.TryConsume("code-replay", "provider1");
        Assert.False(second);
    }

    [Fact]
    public void TryConsume_SameCode_DifferentProviders_IndependentSlots()
    {
        // The same code string arriving at two different providers must be tracked separately.
        var first = _cache.TryConsume("shared-code", "provA");
        var second = _cache.TryConsume("shared-code", "provB");
        Assert.True(first, "First provider should accept");
        Assert.True(second, "Second provider has its own slot; must also accept");
    }

    [Fact]
    public void TryConsume_EmptyCode_ReturnsFalse()
    {
        Assert.False(_cache.TryConsume(string.Empty, "provider1"));
    }

    [Fact]
    public void TryConsume_EmptyProvider_ReturnsFalse()
    {
        Assert.False(_cache.TryConsume("code-xyz", string.Empty));
    }

    [Fact]
    public void TryConsume_BothEmpty_ReturnsFalse()
    {
        Assert.False(_cache.TryConsume(string.Empty, string.Empty));
    }

    // ── Lifecycle ──────────────────────────────────────────────────────────

    [Fact]
    public async Task StartAndStop_CompletesCleanly()
    {
        await _cache.StartAsync(CancellationToken.None);
        await _cache.StopAsync(CancellationToken.None);
        // No exception = pass
    }

    [Fact]
    public async Task TryConsume_AfterStop_StillWorks()
    {
        // The cache does not invalidate existing entries on stop — codes already consumed
        // must remain consumed so a replay in a grace window is still rejected.
        _cache.TryConsume("code-before-stop", "p");
        await _cache.StopAsync(CancellationToken.None);
        var result = _cache.TryConsume("code-before-stop", "p");
        Assert.False(result, "Previously-seen code must still be rejected after stop");
    }

    // ── Concurrency ─────────────────────────────────────────────────────────

    [Fact]
    public async Task TryConsume_ConcurrentFirstUse_ExactlyOneTrueReturned()
    {
        // Ten threads racing to consume the same code. Exactly one must win.
        const int threads = 10;
        int successCount = 0;
        var barrier = new System.Threading.Barrier(threads);

        var tasks = new Task[threads];
        for (var i = 0; i < threads; i++)
        {
            tasks[i] = Task.Run(() =>
            {
                barrier.SignalAndWait();
                if (_cache.TryConsume("concurrent-code", "p"))
                {
                    Interlocked.Increment(ref successCount);
                }
            });
        }

        await Task.WhenAll(tasks);
        Assert.Equal(1, successCount);
    }
}
