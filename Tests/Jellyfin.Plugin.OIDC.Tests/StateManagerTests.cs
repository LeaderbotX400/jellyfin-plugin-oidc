using System;
using System.Threading;
using System.Threading.Tasks;
using Jellyfin.Plugin.OIDC.Services;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Jellyfin.Plugin.OIDC.Tests;

public class StateManagerTests
{
    private static StateManager Create() => new(NullLogger<StateManager>.Instance);

    [Fact]
    public void StoreAndConsumeState_ReturnsStoredState()
    {
        var sm = Create();
        var state = new OidcState
        {
            ProviderId = "test",
            Nonce = "nonce123",
            CodeVerifier = "verifier",
            RedirectUri = "https://example.com/callback"
        };
        var key = sm.StoreState(state);
        var consumed = sm.ConsumeState(key);
        Assert.NotNull(consumed);
        Assert.Equal("test", consumed.ProviderId);
        Assert.Equal("nonce123", consumed.Nonce);
    }

    [Fact]
    public void ConsumeState_CanOnlyBeConsumedOnce()
    {
        var sm = Create();
        var state = new OidcState
        {
            ProviderId = "test",
            Nonce = "n",
            CodeVerifier = "cv",
            RedirectUri = "https://example.com"
        };
        var key = sm.StoreState(state);
        sm.ConsumeState(key);
        var second = sm.ConsumeState(key);
        Assert.Null(second);
    }

    [Fact]
    public void ConsumeState_UnknownKey_ReturnsNull()
    {
        var sm = Create();
        Assert.Null(sm.ConsumeState("nonexistent"));
    }

    [Fact]
    public void StoreAndConsumeSession_ReturnsStoredSession()
    {
        var sm = Create();
        var session = new AuthorizedSession
        {
            ProviderId = "test",
            Username = "alice",
            Sub = "sub-alice",
            Roles = ["admin"],
            Entitlements = ["jellyfin:admin"]
        };
        var token = sm.StoreAuthorizedSession(session);
        var consumed = sm.ConsumeAuthorizedSession(token);
        Assert.NotNull(consumed);
        Assert.Equal("alice", consumed.Username);
        Assert.Equal("sub-alice", consumed.Sub);
        Assert.Contains("jellyfin:admin", consumed.Entitlements);
    }

    [Fact]
    public void ConsumeSession_CanOnlyBeConsumedOnce()
    {
        var sm = Create();
        var session = new AuthorizedSession
        {
            ProviderId = "test",
            Username = "bob",
            Sub = "sub-bob",
            Roles = []
        };
        var token = sm.StoreAuthorizedSession(session);
        sm.ConsumeAuthorizedSession(token);
        Assert.Null(sm.ConsumeAuthorizedSession(token));
    }

    [Fact]
    public void GenerateCsprngToken_IsNotGuidShaped_AndIsLongEnough()
    {
        // Guid.NewGuid().ToString("N") = 32 hex chars. CSPRNG tokens (32 random bytes
        // base64url-encoded) are 43 chars and contain non-hex characters like '_' or '-'
        // or mixed case. Assert both: length > 32 and the token is NOT all lower-hex.
        for (var i = 0; i < 16; i++)
        {
            var t = StateManager.GenerateCsprngToken();
            Assert.True(t.Length >= 43, $"Token too short: {t.Length}");
            var isGuidShaped = t.Length == 32 && System.Text.RegularExpressions.Regex.IsMatch(t, "^[0-9a-f]+$");
            Assert.False(isGuidShaped, "Token looks like a Guid 'N' format — not CSPRNG-base64url");
        }
    }

    [Fact]
    public void GenerateCsprngToken_AreUnique()
    {
        var bag = new System.Collections.Generic.HashSet<string>();
        for (var i = 0; i < 1024; i++)
        {
            Assert.True(bag.Add(StateManager.GenerateCsprngToken()), "Collision in CSPRNG token generator");
        }
    }

    [Fact]
    public void HashToken_IsStableAndFixedTimeComparable()
    {
        var token = StateManager.GenerateCsprngToken();
        var a = StateManager.HashToken(token);
        var b = StateManager.HashToken(token);
        Assert.Equal(32, a.Length);
        Assert.True(System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(a, b));

        var other = StateManager.HashToken(StateManager.GenerateCsprngToken());
        Assert.False(System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(a, other));
    }

    [Fact]
    public void ConcurrentStateStorage_IsThreadSafe()
    {
        var sm = Create();
        var keys = new System.Collections.Concurrent.ConcurrentBag<string>();

        Parallel.For(0, 100, i =>
        {
            var state = new OidcState
            {
                ProviderId = "p",
                Nonce = $"n{i}",
                CodeVerifier = $"cv{i}",
                RedirectUri = "https://example.com"
            };
            keys.Add(sm.StoreState(state));
        });

        Assert.Equal(100, keys.Count);

        int consumed = 0;
        foreach (var key in keys)
        {
            if (sm.ConsumeState(key) != null)
            {
                Interlocked.Increment(ref consumed);
            }
        }

        Assert.Equal(100, consumed);
    }
}
