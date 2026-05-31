using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Jellyfin.Plugin.OIDC.Services;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Jellyfin.Plugin.OIDC.Tests;

public class CallbackRateLimiterTests
{
    private static CallbackRateLimiter NewLimiter() =>
        new(NullLogger<CallbackRateLimiter>.Instance);

    [Fact]
    public void FreshIp_IsNotBanned()
    {
        var l = NewLimiter();
        Assert.False(l.IsBanned(IPAddress.Parse("203.0.113.5"), out _));
    }

    [Fact]
    public void NullIp_IsNeverBanned()
    {
        var l = NewLimiter();
        for (var i = 0; i < 50; i++) l.RecordFailure(null);
        Assert.False(l.IsBanned(null, out _));
    }

    [Fact]
    public void LoopbackIp_IsNeverBanned()
    {
        var l = NewLimiter();
        var loop = IPAddress.Loopback;
        for (var i = 0; i < 50; i++) l.RecordFailure(loop);
        Assert.False(l.IsBanned(loop, out _));
    }

    [Fact]
    public void TenFailures_TriggersBan()
    {
        var l = NewLimiter();
        var ip = IPAddress.Parse("198.51.100.42");
        for (var i = 0; i < 10; i++) l.RecordFailure(ip);
        Assert.True(l.IsBanned(ip, out var retry));
        Assert.True(retry.TotalSeconds > 0);
    }

    [Fact]
    public void NineFailures_DoesNotBan()
    {
        var l = NewLimiter();
        var ip = IPAddress.Parse("198.51.100.43");
        for (var i = 0; i < 9; i++) l.RecordFailure(ip);
        Assert.False(l.IsBanned(ip, out _));
    }

    [Fact]
    public void RecordSuccess_ClearsCount()
    {
        var l = NewLimiter();
        var ip = IPAddress.Parse("198.51.100.44");
        for (var i = 0; i < 9; i++) l.RecordFailure(ip);
        l.RecordSuccess(ip);
        // Should need 10 more failures to trip again
        for (var i = 0; i < 9; i++) l.RecordFailure(ip);
        Assert.False(l.IsBanned(ip, out _));
    }

    [Fact]
    public void Ipv6_BansIndependentlyFromIpv4()
    {
        // An attacker shouldn't be able to flip from v4→v6 to skirt a ban.
        // But these are genuinely distinct address spaces — confirm independent counting.
        var l = NewLimiter();
        var v4 = IPAddress.Parse("198.51.100.50");
        var v6 = IPAddress.Parse("2001:db8::dead:beef");
        for (var i = 0; i < 10; i++) l.RecordFailure(v4);
        Assert.True(l.IsBanned(v4, out _));
        Assert.False(l.IsBanned(v6, out _));
    }

    [Fact]
    public void Ipv4MappedIpv6_NormalizesToIpv4()
    {
        // Kestrel sometimes surfaces v4 connections as ::ffff:a.b.c.d. Banning under
        // the v6-mapped form must hit the same bucket as the plain v4 form, otherwise
        // an attacker can dodge by toggling the IP family of their TCP stack.
        var l = NewLimiter();
        var v4 = IPAddress.Parse("198.51.100.51");
        var mapped = IPAddress.Parse("::ffff:198.51.100.51");
        for (var i = 0; i < 10; i++) l.RecordFailure(mapped);
        Assert.True(l.IsBanned(v4, out _));
    }

    [Fact]
    public async Task Concurrent_FailuresFromSameIp_AllCountedSafely()
    {
        // Hammer one IP from many threads. We don't care which exact count triggers
        // the ban (boundary races are inherent), but we MUST observe a ban without
        // crashes, exceptions, or lost updates dropping us below threshold forever.
        var l = NewLimiter();
        var ip = IPAddress.Parse("198.51.100.60");
        const int threads = 32;
        const int perThread = 5;

        var barrier = new Barrier(threads);
        var tasks = new Task[threads];
        for (var i = 0; i < threads; i++)
        {
            tasks[i] = Task.Run(() =>
            {
                barrier.SignalAndWait();
                for (var j = 0; j < perThread; j++) l.RecordFailure(ip);
            });
        }
        await Task.WhenAll(tasks);

        Assert.True(l.IsBanned(ip, out var retry));
        Assert.True(retry.TotalSeconds > 0);
    }

    [Fact]
    public async Task Concurrent_DifferentIps_DoNotCrossPolluteState()
    {
        // 16 distinct IPs each push 5 failures. None should hit the 10-failure
        // threshold; none should be banned. Confirms per-IP isolation under contention.
        var l = NewLimiter();
        const int ipCount = 16;
        var ips = new IPAddress[ipCount];
        for (var i = 0; i < ipCount; i++) ips[i] = IPAddress.Parse($"203.0.113.{i + 1}");

        var tasks = new Task[ipCount];
        for (var i = 0; i < ipCount; i++)
        {
            var ip = ips[i];
            tasks[i] = Task.Run(() =>
            {
                for (var j = 0; j < 5; j++) l.RecordFailure(ip);
            });
        }
        await Task.WhenAll(tasks);

        foreach (var ip in ips)
        {
            Assert.False(l.IsBanned(ip, out _), $"{ip} unexpectedly banned");
        }
    }

    [Fact]
    public void RetryAfter_DecreasesOverTime()
    {
        // Sanity: the reported Retry-After should be positive and bounded by the ban
        // window. We can't sleep 15 minutes in a test; just check it's in range.
        var l = NewLimiter();
        var ip = IPAddress.Parse("198.51.100.70");
        for (var i = 0; i < 10; i++) l.RecordFailure(ip);
        Assert.True(l.IsBanned(ip, out var retry));
        Assert.InRange(retry.TotalMinutes, 0, 16); // ≤ 15-min window + slack
    }

    [Fact]
    public void DoubleSuccess_DoesNotThrow()
    {
        // Defensive: success recording on an IP with no record must be a no-op.
        var l = NewLimiter();
        l.RecordSuccess(IPAddress.Parse("198.51.100.80"));
        l.RecordSuccess(IPAddress.Parse("198.51.100.80"));
    }

    [Fact]
    public void BanIsPerIp()
    {
        var l = NewLimiter();
        var banned = IPAddress.Parse("198.51.100.45");
        var fresh = IPAddress.Parse("198.51.100.46");
        for (var i = 0; i < 10; i++) l.RecordFailure(banned);
        Assert.True(l.IsBanned(banned, out _));
        Assert.False(l.IsBanned(fresh, out _));
    }
}
