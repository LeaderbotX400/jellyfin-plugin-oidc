using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace Jellyfin.Plugin.OIDC.Services;

public class OidcUserRecord
{
    public Guid UserId { get; set; }
    public string Username { get; set; } = string.Empty;
    public string Sub { get; set; } = string.Empty;
    public string ProviderId { get; set; } = string.Empty;
    public string[] Roles { get; set; } = Array.Empty<string>();
    public string[] Entitlements { get; set; } = Array.Empty<string>();
    public DateTimeOffset LastSyncedAt { get; set; }
}

/// <summary>Persists per-user OIDC claim snapshots and account links for re-sync and back-channel logout.</summary>
public class OidcUserStore
{
    private sealed class StoreData
    {
        public OidcUserRecord[] Records { get; set; } = Array.Empty<OidcUserRecord>();

        /// <summary>Maps "{providerId}:{sub}" → Jellyfin UserId for manually linked accounts.</summary>
        public Dictionary<string, Guid> Links { get; set; } = new();
    }

    private static readonly JsonSerializerOptions _jsonOptions = new() { WriteIndented = false };
    private readonly SemaphoreSlim _writeLock = new(1, 1);
    private readonly ConcurrentDictionary<Guid, OidcUserRecord> _records = new();
    private readonly ConcurrentDictionary<string, Guid> _links = new(); // key = "providerId:sub"
    private bool _loaded;
    private readonly string? _overridePath;

    public OidcUserStore() { }

    /// <summary>Constructor for tests: bypasses plugin data folder lookup.</summary>
    public OidcUserStore(string storePath) => _overridePath = storePath;

    private string StorePath => _overridePath ?? GetDefaultStorePath();

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static string GetDefaultStorePath() =>
        Path.Combine(OidcPlugin.Instance?.DataFolderPath ?? Path.GetTempPath(), "oidc_users.json");

    public async Task UpsertAsync(OidcUserRecord record)
    {
        await EnsureLoadedAsync().ConfigureAwait(false);
        record.LastSyncedAt = DateTimeOffset.UtcNow;
        _records[record.UserId] = record;
        await PersistAsync().ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<OidcUserRecord>> GetAllAsync()
    {
        await EnsureLoadedAsync().ConfigureAwait(false);
        return _records.Values.ToList();
    }

    public async Task<OidcUserRecord?> GetBySubAsync(string sub, string providerId)
    {
        await EnsureLoadedAsync().ConfigureAwait(false);
        return _records.Values.FirstOrDefault(r =>
            string.Equals(r.Sub, sub, StringComparison.Ordinal) &&
            string.Equals(r.ProviderId, providerId, StringComparison.OrdinalIgnoreCase));
    }

    // ── Account linking ─────────────────────────────────────────────────────

    /// <summary>Returns the Jellyfin user ID linked to the given OIDC subject, or null if not linked.</summary>
    public async Task<Guid?> GetLinkedUserIdAsync(string sub, string providerId)
    {
        await EnsureLoadedAsync().ConfigureAwait(false);
        var key = LinkKey(providerId, sub);
        return _links.TryGetValue(key, out var userId) ? userId : null;
    }

    /// <summary>Links an existing Jellyfin user to an OIDC identity. Subsequent logins with this sub will resolve to this user.</summary>
    public async Task LinkAsync(Guid userId, string sub, string providerId)
    {
        await EnsureLoadedAsync().ConfigureAwait(false);
        _links[LinkKey(providerId, sub)] = userId;
        await PersistAsync().ConfigureAwait(false);
    }

    /// <summary>Removes all links for a specific user+provider combination.</summary>
    public async Task UnlinkAsync(Guid userId, string providerId)
    {
        await EnsureLoadedAsync().ConfigureAwait(false);
        var prefix = providerId.ToLowerInvariant() + ":";
        foreach (var (key, uid) in _links)
        {
            if (uid == userId && key.StartsWith(prefix, StringComparison.Ordinal))
            {
                _links.TryRemove(key, out _);
            }
        }

        await PersistAsync().ConfigureAwait(false);
    }

    /// <summary>Returns all OIDC identities linked to a Jellyfin user.</summary>
    public async Task<IReadOnlyList<(string ProviderId, string Sub)>> GetLinksForUserAsync(Guid userId)
    {
        await EnsureLoadedAsync().ConfigureAwait(false);
        var result = new List<(string, string)>();
        foreach (var (key, uid) in _links)
        {
            if (uid != userId) continue;
            var sep = key.IndexOf(':', StringComparison.Ordinal);
            if (sep > 0)
            {
                result.Add((key[..sep], key[(sep + 1)..]));
            }
        }

        return result;
    }

    // ── Persistence ─────────────────────────────────────────────────────────

    private async Task EnsureLoadedAsync()
    {
        if (_loaded) return;

        await _writeLock.WaitAsync().ConfigureAwait(false);
        try
        {
            if (_loaded) return;

            var path = StorePath;
            if (File.Exists(path))
            {
                var json = await File.ReadAllTextAsync(path).ConfigureAwait(false);
                try
                {
                    var data = JsonSerializer.Deserialize<StoreData>(json);
                    if (data != null)
                    {
                        foreach (var r in data.Records)
                        {
                            _records[r.UserId] = r;
                        }

                        foreach (var (k, v) in data.Links)
                        {
                            _links[k] = v;
                        }
                    }
                }
                catch
                {
                    // Attempt legacy format (plain array of records, no links)
                    try
                    {
                        var records = JsonSerializer.Deserialize<OidcUserRecord[]>(json);
                        if (records != null)
                        {
                            foreach (var r in records)
                            {
                                _records[r.UserId] = r;
                            }
                        }
                    }
                    catch
                    {
                        // Corrupt file — start fresh
                    }
                }
            }

            _loaded = true;
        }
        finally
        {
            _writeLock.Release();
        }
    }

    private async Task PersistAsync()
    {
        await _writeLock.WaitAsync().ConfigureAwait(false);
        try
        {
            var data = new StoreData
            {
                Records = _records.Values.ToArray(),
                Links = new Dictionary<string, Guid>(_links)
            };
            var json = JsonSerializer.Serialize(data, _jsonOptions);
            var path = StorePath;
            var dir = Path.GetDirectoryName(path);
            if (!string.IsNullOrEmpty(dir))
            {
                Directory.CreateDirectory(dir);
            }

            await File.WriteAllTextAsync(path, json).ConfigureAwait(false);
        }
        finally
        {
            _writeLock.Release();
        }
    }

    private static string LinkKey(string providerId, string sub) =>
        providerId.ToLowerInvariant() + ":" + sub;
}
