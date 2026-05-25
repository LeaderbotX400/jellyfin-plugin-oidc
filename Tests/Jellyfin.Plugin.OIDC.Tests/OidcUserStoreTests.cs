using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Jellyfin.Plugin.OIDC.Services;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Jellyfin.Plugin.OIDC.Tests;

/// <summary>Tests for OidcUserStore account linking and persistence.</summary>
public class OidcUserStoreTests : IDisposable
{
    private readonly string _tempDir;

    public OidcUserStoreTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "oidc_test_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tempDir);
    }

    public void Dispose()
    {
        try { Directory.Delete(_tempDir, recursive: true); } catch { }
    }

    private OidcUserStore MakeStore() =>
        new(Path.Combine(_tempDir, $"store_{Guid.NewGuid():N}.json"));

    private OidcUserStore MakeStoreWithLogger(ILogger<OidcUserStore> logger, string? path = null) =>
        new(path ?? Path.Combine(_tempDir, $"store_{Guid.NewGuid():N}.json"), logger);

    // ── Existing tests (unchanged behaviour) ───────────────────────────────

    [Fact]
    public async Task LinkAndGetLinkedUserId_RoundTrip()
    {
        var store = MakeStore();
        var userId = Guid.NewGuid();

        await store.LinkAsync(userId, "sub-123", "myidp");
        var found = await store.GetLinkedUserIdAsync("sub-123", "myidp");

        Assert.Equal(userId, found);
    }

    [Fact]
    public async Task GetLinkedUserId_NotLinked_ReturnsNull()
    {
        var store = MakeStore();
        var result = await store.GetLinkedUserIdAsync("no-such-sub", "myidp");
        Assert.Null(result);
    }

    [Fact]
    public async Task UnlinkAsync_RemovesLink()
    {
        var store = MakeStore();
        var userId = Guid.NewGuid();

        await store.LinkAsync(userId, "sub-abc", "prov1");
        await store.UnlinkAsync(userId, "prov1");
        var result = await store.GetLinkedUserIdAsync("sub-abc", "prov1");

        Assert.Null(result);
    }

    [Fact]
    public async Task UnlinkAsync_OnlyRemovesMatchingProvider()
    {
        var store = MakeStore();
        var userId = Guid.NewGuid();

        await store.LinkAsync(userId, "sub-abc", "prov1");
        await store.LinkAsync(userId, "sub-abc", "prov2");
        await store.UnlinkAsync(userId, "prov1");

        Assert.Null(await store.GetLinkedUserIdAsync("sub-abc", "prov1"));
        Assert.Equal(userId, await store.GetLinkedUserIdAsync("sub-abc", "prov2"));
    }

    [Fact]
    public async Task GetLinksForUser_ReturnsAllLinks()
    {
        var store = MakeStore();
        var userId = Guid.NewGuid();

        await store.LinkAsync(userId, "sub-1", "prov1");
        await store.LinkAsync(userId, "sub-2", "prov2");

        var links = await store.GetLinksForUserAsync(userId);

        Assert.Equal(2, links.Count);
        Assert.Contains(links, l => l.ProviderId == "prov1" && l.Sub == "sub-1");
        Assert.Contains(links, l => l.ProviderId == "prov2" && l.Sub == "sub-2");
    }

    [Fact]
    public async Task UpsertAndGetAll_RoundTrip()
    {
        var store = MakeStore();
        var record = new OidcUserRecord
        {
            UserId = Guid.NewGuid(),
            Username = "alice",
            Sub = "sub-alice",
            ProviderId = "keycloak",
            Roles = new[] { "admin" },
            Entitlements = new[] { "jellyfin:admin" }
        };

        await store.UpsertAsync(record);
        var all = await store.GetAllAsync();

        Assert.Single(all);
        Assert.Equal("alice", all[0].Username);
        Assert.Contains("admin", all[0].Roles);
    }

    [Fact]
    public async Task GetBySubAsync_ReturnsMatchingRecord()
    {
        var store = MakeStore();
        await store.UpsertAsync(new OidcUserRecord
        {
            UserId = Guid.NewGuid(),
            Username = "bob",
            Sub = "sub-bob",
            ProviderId = "github",
            Roles = Array.Empty<string>(),
            Entitlements = Array.Empty<string>()
        });

        var found = await store.GetBySubAsync("sub-bob", "github");
        Assert.NotNull(found);
        Assert.Equal("bob", found!.Username);
    }

    [Fact]
    public async Task GetBySubAsync_WrongProvider_ReturnsNull()
    {
        var store = MakeStore();
        await store.UpsertAsync(new OidcUserRecord
        {
            UserId = Guid.NewGuid(),
            Username = "carol",
            Sub = "sub-carol",
            ProviderId = "keycloak",
            Roles = Array.Empty<string>(),
            Entitlements = Array.Empty<string>()
        });

        var found = await store.GetBySubAsync("sub-carol", "google");
        Assert.Null(found);
    }

    [Fact]
    public async Task GetLinksForUser_NoLinks_ReturnsEmptyList()
    {
        var store = MakeStore();
        var links = await store.GetLinksForUserAsync(Guid.NewGuid());
        Assert.NotNull(links);
        Assert.Empty(links);
    }

    [Fact]
    public async Task UnlinkAsync_UserWithNoLinks_IsIdempotent()
    {
        // Calling Unlink for a user who has no links must not throw.
        var store = MakeStore();
        var userId = Guid.NewGuid();
        var ex = await Record.ExceptionAsync(() => store.UnlinkAsync(userId, "any-provider"));
        Assert.Null(ex);
    }

    [Fact]
    public async Task LinkAsync_MultipleLinksForSameUser_AllRetrievable()
    {
        var store = MakeStore();
        var userId = Guid.NewGuid();

        await store.LinkAsync(userId, "sub-x", "prov-x");
        await store.LinkAsync(userId, "sub-y", "prov-y");
        await store.LinkAsync(userId, "sub-z", "prov-z");

        var links = await store.GetLinksForUserAsync(userId);
        Assert.Equal(3, links.Count);
        Assert.Contains(links, l => l.ProviderId == "prov-x" && l.Sub == "sub-x");
        Assert.Contains(links, l => l.ProviderId == "prov-y" && l.Sub == "sub-y");
        Assert.Contains(links, l => l.ProviderId == "prov-z" && l.Sub == "sub-z");
    }

    // ── Atomic write tests ─────────────────────────────────────────────────

    [Fact]
    public async Task Save_IsAtomic_TempFileThenRename()
    {
        // Verify that after a successful write the temp file no longer exists
        // (it was renamed to the final path) and the final path contains valid data.
        var storePath = Path.Combine(_tempDir, $"store_{Guid.NewGuid():N}.json");
        var store = new OidcUserStore(storePath);
        var userId = Guid.NewGuid();

        await store.LinkAsync(userId, "sub-atomic", "idp");

        // The temp file must not remain after a successful persist.
        var tempPath = storePath + ".tmp";
        Assert.False(File.Exists(tempPath), "Temp file should have been renamed away after successful write");

        // The final file must contain valid JSON with our data.
        Assert.True(File.Exists(storePath), "Final store file must exist");
        var content = await File.ReadAllTextAsync(storePath);
        Assert.Contains("sub-atomic", content);
    }

    [Fact]
    public async Task Save_WritesToTempFirst_ThenAtomicallyReplaces()
    {
        // Round-trip: write, then load a fresh store from the same path to confirm data survives.
        var storePath = Path.Combine(_tempDir, $"store_{Guid.NewGuid():N}.json");

        var store1 = new OidcUserStore(storePath);
        var userId = Guid.NewGuid();
        await store1.LinkAsync(userId, "sub-persist", "idp");

        // New store instance reads from the same file — confirms the rename-based write is durable.
        var store2 = new OidcUserStore(storePath);
        var found = await store2.GetLinkedUserIdAsync("sub-persist", "idp");

        Assert.Equal(userId, found);
    }

    // ── Corruption recovery tests ──────────────────────────────────────────

    [Fact]
    public async Task Load_CorruptFile_QuarantinesAndMarksUnrecoverable()
    {
        // Security rationale: silently starting fresh after corruption re-enables the
        // username-based rebind vector (TASK-04). Instead we quarantine and require
        // explicit admin action, forcing attention to a potential data-loss event.

        var storePath = Path.Combine(_tempDir, $"store_{Guid.NewGuid():N}.json");
        await File.WriteAllTextAsync(storePath, "NOT VALID JSON !!!!");

        var store = MakeStoreWithLogger(NullLogger<OidcUserStore>.Instance, storePath);

        // Any read operation should throw OidcUserStoreUnavailableException.
        await Assert.ThrowsAsync<OidcUserStoreUnavailableException>(
            () => store.GetLinkedUserIdAsync("any-sub", "any-idp"));

        // The corrupt file should have been quarantined (renamed to .corrupt-*).
        Assert.False(File.Exists(storePath), "Original corrupt file should be renamed away");
        var quarantined = Directory.GetFiles(_tempDir, Path.GetFileName(storePath) + ".corrupt-*");
        Assert.Single(quarantined);
    }

    [Fact]
    public async Task Load_CorruptFile_AllReadMethodsThrow()
    {
        // All public read/write methods must propagate the unavailable state.
        var storePath = Path.Combine(_tempDir, $"store_{Guid.NewGuid():N}.json");
        await File.WriteAllTextAsync(storePath, "{bad json");

        var store = new OidcUserStore(storePath);

        // Trigger load.
        await Assert.ThrowsAsync<OidcUserStoreUnavailableException>(
            () => store.GetAllAsync());

        // Subsequent calls on the same instance must also throw.
        await Assert.ThrowsAsync<OidcUserStoreUnavailableException>(
            () => store.GetBySubAsync("s", "p"));
        await Assert.ThrowsAsync<OidcUserStoreUnavailableException>(
            () => store.GetLinkedUserIdAsync("s", "p"));
        await Assert.ThrowsAsync<OidcUserStoreUnavailableException>(
            () => store.LinkAsync(Guid.NewGuid(), "s", "p"));
        await Assert.ThrowsAsync<OidcUserStoreUnavailableException>(
            () => store.UnlinkAsync(Guid.NewGuid(), "p"));
        await Assert.ThrowsAsync<OidcUserStoreUnavailableException>(
            () => store.GetLinksForUserAsync(Guid.NewGuid()));
        await Assert.ThrowsAsync<OidcUserStoreUnavailableException>(
            () => store.UpsertAsync(new OidcUserRecord { UserId = Guid.NewGuid() }));
    }

    [Fact]
    public async Task AdminReset_AfterCorruption_ClearsUnrecoverable()
    {
        var storePath = Path.Combine(_tempDir, $"store_{Guid.NewGuid():N}.json");
        await File.WriteAllTextAsync(storePath, "totally not json");

        var store = new OidcUserStore(storePath);

        // Trigger load and corruption detection.
        await Assert.ThrowsAsync<OidcUserStoreUnavailableException>(
            () => store.GetLinkedUserIdAsync("x", "y"));

        // Admin reset re-enables the store.
        store.AdminReset();

        // Should not throw — and should return null (empty store).
        var result = await store.GetLinkedUserIdAsync("x", "y");
        Assert.Null(result);

        // Writes should work again.
        var userId = Guid.NewGuid();
        await store.LinkAsync(userId, "sub-reset", "idp");
        var found = await store.GetLinkedUserIdAsync("sub-reset", "idp");
        Assert.Equal(userId, found);
    }

    [Fact]
    public async Task Logging_CorruptionLoggedAtError()
    {
        // Verify a logger receives at least one Error-level entry when a corrupt file is detected.
        var storePath = Path.Combine(_tempDir, $"store_{Guid.NewGuid():N}.json");
        await File.WriteAllTextAsync(storePath, "garbage");

        var collector = new LogCollector<OidcUserStore>();
        var store = MakeStoreWithLogger(collector, storePath);

        await Assert.ThrowsAsync<OidcUserStoreUnavailableException>(
            () => store.GetAllAsync());

        Assert.True(
            collector.HasLevel(LogLevel.Error),
            "Expected at least one Error-level log entry for corruption detection");
    }

    // ── Log collector helper ───────────────────────────────────────────────

    private sealed class LogCollector<T> : ILogger<T>
    {
        private readonly List<(LogLevel Level, string Message)> _entries = new();

        public bool HasLevel(LogLevel level) => _entries.Any(e => e.Level == level);
        public IReadOnlyList<(LogLevel Level, string Message)> Entries => _entries;

        IDisposable? ILogger.BeginScope<TState>(TState state) => null;
        bool ILogger.IsEnabled(LogLevel logLevel) => true;

        void ILogger.Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            _entries.Add((logLevel, formatter(state, exception)));
        }
    }
}
