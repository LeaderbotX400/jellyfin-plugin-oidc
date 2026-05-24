using System;
using System.IO;
using System.Threading.Tasks;
using Jellyfin.Plugin.OIDC.Services;
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
}
