using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Jellyfin.Database.Implementations.Entities;
using MediaBrowser.Model.Activity;
using Microsoft.Extensions.Logging;

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

    /// <summary>
    /// Map of OIDC `sid` claim values to the Jellyfin DeviceId of the session they were issued to.
    /// Populated at login when the IdP includes a `sid` in the ID token. Used by back-channel
    /// logout to identify which specific session a logout_token refers to. NOTE: Jellyfin's
    /// public ISessionManager.RevokeUserTokens only supports revoking ALL tokens for a user,
    /// so sid-targeted logout is logged but currently still triggers a full revoke. Tracking
    /// the mapping anyway so we have parity if Jellyfin gains a per-session revoke API later.
    /// </summary>
    public Dictionary<string, string> Sids { get; set; } = new();
}

/// <summary>Persists per-user OIDC claim snapshots and account links for re-sync and back-channel logout.</summary>
public class OidcUserStore : IDisposable
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
    private bool _unrecoverable;
    private readonly string? _overridePath;
    private readonly ILogger<OidcUserStore>? _logger;
    private readonly IActivityManager? _activityManager;

    public OidcUserStore() { }

    /// <summary>Constructor for tests: bypasses plugin data folder lookup.</summary>
    public OidcUserStore(string storePath) => _overridePath = storePath;

    /// <summary>Constructor for tests with logger injection.</summary>
    public OidcUserStore(string storePath, ILogger<OidcUserStore> logger)
    {
        _overridePath = storePath;
        _logger = logger;
    }

    /// <summary>Production constructor with full DI.</summary>
    public OidcUserStore(ILogger<OidcUserStore> logger, IActivityManager activityManager)
    {
        _logger = logger;
        _activityManager = activityManager;
    }

    private string StorePath => _overridePath ?? GetDefaultStorePath();

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static string GetDefaultStorePath() =>
        Path.Combine(OidcPlugin.Instance?.DataFolderPath ?? Path.GetTempPath(), "oidc_users.json");

    /// <summary>
    /// Throws <see cref="OidcUserStoreUnavailableException"/> if the store is in an unrecoverable state.
    /// </summary>
    private void ThrowIfUnrecoverable()
    {
        if (_unrecoverable)
        {
            throw new OidcUserStoreUnavailableException();
        }
    }

    public async Task UpsertAsync(OidcUserRecord record)
    {
        await EnsureLoadedAsync().ConfigureAwait(false);
        ThrowIfUnrecoverable();
        record.LastSyncedAt = DateTimeOffset.UtcNow;
        _records[record.UserId] = record;
        await PersistAsync().ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<OidcUserRecord>> GetAllAsync()
    {
        await EnsureLoadedAsync().ConfigureAwait(false);
        ThrowIfUnrecoverable();
        return _records.Values.ToList();
    }

    /// <summary>Records the OIDC `sid` claim against an existing user record, mapped to a session DeviceId.</summary>
    public async Task RecordSidAsync(Guid userId, string sid, string deviceId)
    {
        if (string.IsNullOrEmpty(sid)) return;
        await EnsureLoadedAsync().ConfigureAwait(false);
        if (!_records.TryGetValue(userId, out var record)) return;
        record.Sids ??= new Dictionary<string, string>();
        record.Sids[sid] = deviceId ?? string.Empty;
        await PersistAsync().ConfigureAwait(false);
    }

    public async Task<OidcUserRecord?> GetBySubAsync(string sub, string providerId)
    {
        await EnsureLoadedAsync().ConfigureAwait(false);
        ThrowIfUnrecoverable();
        return _records.Values.FirstOrDefault(r =>
            string.Equals(r.Sub, sub, StringComparison.Ordinal) &&
            string.Equals(r.ProviderId, providerId, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>Finds the user record (for this provider) that has the given OIDC `sid` recorded.</summary>
    public async Task<OidcUserRecord?> GetBySidAsync(string sid, string providerId)
    {
        if (string.IsNullOrEmpty(sid)) return null;
        await EnsureLoadedAsync().ConfigureAwait(false);
        return _records.Values.FirstOrDefault(r =>
            string.Equals(r.ProviderId, providerId, StringComparison.OrdinalIgnoreCase) &&
            r.Sids != null && r.Sids.ContainsKey(sid));
    }

    // ── Account linking ─────────────────────────────────────────────────────

    /// <summary>Returns the Jellyfin user ID linked to the given OIDC subject, or null if not linked.</summary>
    public async Task<Guid?> GetLinkedUserIdAsync(string sub, string providerId)
    {
        await EnsureLoadedAsync().ConfigureAwait(false);
        ThrowIfUnrecoverable();
        var key = LinkKey(providerId, sub);
        return _links.TryGetValue(key, out var userId) ? userId : null;
    }

    /// <summary>Links an existing Jellyfin user to an OIDC identity. Subsequent logins with this sub will resolve to this user.</summary>
    public async Task LinkAsync(Guid userId, string sub, string providerId)
    {
        await EnsureLoadedAsync().ConfigureAwait(false);
        ThrowIfUnrecoverable();
        _links[LinkKey(providerId, sub)] = userId;
        await PersistAsync().ConfigureAwait(false);
    }

    /// <summary>Removes all links for a specific user+provider combination.</summary>
    public async Task UnlinkAsync(Guid userId, string providerId)
    {
        await EnsureLoadedAsync().ConfigureAwait(false);
        ThrowIfUnrecoverable();
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
        ThrowIfUnrecoverable();
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

    // ── Admin recovery ───────────────────────────────────────────────────────

    /// <summary>
    /// Resets the store after an unrecoverable corruption event.
    /// Clears all in-memory state and re-enables operations.
    /// Only invoke this after explicit administrator action via the admin endpoint.
    /// </summary>
    public void AdminReset()
    {
        _records.Clear();
        _links.Clear();
        _loaded = false;
        _unrecoverable = false;
        _logger?.LogWarning("OidcUserStore: admin reset performed — store cleared and re-enabled");
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
                string json;
                try
                {
                    json = await File.ReadAllTextAsync(path).ConfigureAwait(false);
                }
                catch (IOException ex)
                {
                    _logger?.LogWarning(ex, "OidcUserStore: failed to read store file '{Path}' — treating as empty", path);
                    _loaded = true;
                    return;
                }

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
                catch (JsonException)
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
                    catch (JsonException ex)
                    {
                        // True corruption — quarantine file and mark store unrecoverable.
                        // Security: we do NOT start fresh because silently losing all sub→user links
                        // re-enables the username-based rebind vector that TASK-04 closed, or forces
                        // all OIDC logins to fail without admin awareness. Explicit reset is required.
                        await QuarantineCorruptFileAsync(path, ex).ConfigureAwait(false);
                        _loaded = true;
                        return;
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

    private async Task QuarantineCorruptFileAsync(string path, Exception ex)
    {
        _logger?.LogError(ex, "OidcUserStore: corrupt store file detected at '{Path}' — quarantining", path);

        var timestamp = DateTimeOffset.UtcNow.ToString("yyyyMMddTHHmmssZ", System.Globalization.CultureInfo.InvariantCulture);
        var quarantinePath = path + ".corrupt-" + timestamp;

        try
        {
            File.Move(path, quarantinePath);
            _logger?.LogError(
                "OidcUserStore: corrupt file renamed to '{QuarantinePath}'. " +
                "All user store operations are suspended. " +
                "An administrator must investigate and call POST /sso/OIDC/Admin/UserStore/Reset to resume.",
                quarantinePath);
        }
        catch (IOException moveEx)
        {
            _logger?.LogError(moveEx, "OidcUserStore: failed to rename corrupt file '{Path}' to quarantine path", path);
        }

        _unrecoverable = true;

        if (_activityManager != null)
        {
            try
            {
                var entry = new ActivityLog(
                    "OIDC plugin: user store corruption — manual recovery required",
                    "OidcUserStoreCorruption",
                    Guid.Empty)
                {
                    Overview = $"Corrupt store file quarantined as '{quarantinePath}'. " +
                               "Call POST /sso/OIDC/Admin/UserStore/Reset after investigation.",
                    LogSeverity = Microsoft.Extensions.Logging.LogLevel.Error
                };
                await _activityManager.CreateAsync(entry).ConfigureAwait(false);
            }
            catch (Exception actEx)
            {
                _logger?.LogWarning(actEx, "OidcUserStore: failed to write activity log for corruption event");
            }
        }
    }

    private async Task PersistAsync()
    {
        await _writeLock.WaitAsync().ConfigureAwait(false);
        try
        {
            ThrowIfUnrecoverable();

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

            var tempPath = path + ".tmp";

            // Write with WriteThrough so OS buffers are flushed to the storage device before rename.
            await using (var fs = new FileStream(
                tempPath,
                FileMode.Create,
                FileAccess.Write,
                FileShare.None,
                bufferSize: 4096,
                FileOptions.WriteThrough | FileOptions.Asynchronous))
            {
                await using var writer = new StreamWriter(fs);
                await writer.WriteAsync(json).ConfigureAwait(false);
                await writer.FlushAsync().ConfigureAwait(false);
                await fs.FlushAsync().ConfigureAwait(false);
            }

            // Atomic rename: on POSIX this is atomic replace of the directory entry;
            // on Windows it uses MoveFileEx with MOVEFILE_REPLACE_EXISTING.
            File.Move(tempPath, path, overwrite: true);
        }
        catch (OidcUserStoreUnavailableException)
        {
            throw;
        }
        catch (IOException ex)
        {
            _logger?.LogWarning(ex, "OidcUserStore: failed to persist store to '{Path}'", StorePath);
            throw;
        }
        finally
        {
            _writeLock.Release();
        }
    }

    private static string LinkKey(string providerId, string sub) =>
        providerId.ToLowerInvariant() + ":" + sub;

    /// <inheritdoc/>
    public void Dispose()
    {
        _writeLock.Dispose();
        GC.SuppressFinalize(this);
    }
}
