using System;
using System.Collections.Concurrent;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;

namespace Jellyfin.Plugin.OIDC.Services;

/// <summary>
/// Thread-safe JWKS cache that fetches and caches JSON Web Key Sets by URI.
/// Prevents hammering the IdP on every token validation; keys rotate infrequently.
/// </summary>
public sealed class JwksCache
{
    /// <summary>
    /// Minimum gap between forced refreshes for a given JWKS URI when we hit an unknown <c>kid</c>.
    /// Exposed as a const so tests can reason about / override timing without touching the cache TTL.
    /// </summary>
    public const int MinimumRefreshIntervalSeconds = 60;

    private sealed record CacheEntry(JsonWebKeySet Keys, DateTime ExpiresAt);

    private readonly ConcurrentDictionary<string, CacheEntry> _cache = new();
    private readonly ConcurrentDictionary<string, DateTime> _lastRefresh = new();
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ILogger<JwksCache> _logger;
    private readonly SemaphoreSlim _fetchLock = new(1, 1);
    private readonly TimeSpan _refreshGate;

    public JwksCache(IHttpClientFactory httpClientFactory, ILogger<JwksCache> logger)
        : this(httpClientFactory, logger, TimeSpan.FromSeconds(MinimumRefreshIntervalSeconds))
    {
    }

    /// <summary>Test ctor allowing the refresh rate-limit to be overridden.</summary>
    internal JwksCache(IHttpClientFactory httpClientFactory, ILogger<JwksCache> logger, TimeSpan refreshGate)
    {
        _httpClientFactory = httpClientFactory;
        _logger = logger;
        _refreshGate = refreshGate;
    }

    /// <summary>
    /// Returns cached JWKS for the given URI, fetching and caching if stale or missing.
    /// Default TTL is 1 hour. Use <see cref="Invalidate"/> to force a refresh, or
    /// <see cref="RefreshAsync"/> for the rate-limited on-rotation path.
    /// </summary>
    public async Task<JsonWebKeySet> GetKeysAsync(string jwksUri, TimeSpan? ttl = null)
    {
        var effectiveTtl = ttl ?? TimeSpan.FromHours(1);

        if (_cache.TryGetValue(jwksUri, out var cached) && cached.ExpiresAt > DateTime.UtcNow)
        {
            return cached.Keys;
        }

        await _fetchLock.WaitAsync().ConfigureAwait(false);
        try
        {
            // Re-check after acquiring lock (another thread may have just fetched)
            if (_cache.TryGetValue(jwksUri, out cached) && cached.ExpiresAt > DateTime.UtcNow)
            {
                return cached.Keys;
            }

            return await FetchAndStoreAsync(jwksUri, effectiveTtl).ConfigureAwait(false);
        }
        finally
        {
            _fetchLock.Release();
        }
    }

    /// <summary>
    /// Forces a JWKS re-fetch for the given URI, but no more often than
    /// <see cref="MinimumRefreshIntervalSeconds"/> per URI. Returns the freshly fetched key set
    /// if a refresh actually happened, or the currently cached one when rate-limited.
    /// Designed for "token's kid is unknown — did the IdP rotate?" recovery.
    /// </summary>
    public async Task<JsonWebKeySet?> RefreshAsync(string jwksUri, TimeSpan? ttl = null)
    {
        var effectiveTtl = ttl ?? TimeSpan.FromHours(1);
        var now = DateTime.UtcNow;

        if (_lastRefresh.TryGetValue(jwksUri, out var last) && now - last < _refreshGate)
        {
            _logger.LogDebug(
                "JWKS refresh for {JwksUri} skipped — last refresh {Seconds:F1}s ago (gate {GateSeconds}s)",
                jwksUri, (now - last).TotalSeconds, _refreshGate.TotalSeconds);
            return _cache.TryGetValue(jwksUri, out var existing) ? existing.Keys : null;
        }

        await _fetchLock.WaitAsync().ConfigureAwait(false);
        try
        {
            // Re-check the gate inside the lock — another thread may have just refreshed.
            if (_lastRefresh.TryGetValue(jwksUri, out last) && DateTime.UtcNow - last < _refreshGate)
            {
                return _cache.TryGetValue(jwksUri, out var existing) ? existing.Keys : null;
            }

            _logger.LogInformation("JWKS refresh triggered for {JwksUri} (likely IdP key rotation)", jwksUri);
            _lastRefresh[jwksUri] = DateTime.UtcNow;
            return await FetchAndStoreAsync(jwksUri, effectiveTtl).ConfigureAwait(false);
        }
        finally
        {
            _fetchLock.Release();
        }
    }

    /// <summary>Removes the cached entry for the given URI, forcing a fresh fetch next time.</summary>
    public void Invalidate(string jwksUri) => _cache.TryRemove(jwksUri, out _);

    private async Task<JsonWebKeySet> FetchAndStoreAsync(string jwksUri, TimeSpan ttl)
    {
        _logger.LogDebug("JWKS cache miss — fetching {JwksUri}", jwksUri);
        var httpClient = _httpClientFactory.CreateClient("OidcPlugin");
        var jwksJson = await httpClient.GetStringAsync(jwksUri).ConfigureAwait(false);
        var keySet = new JsonWebKeySet(jwksJson);
        _cache[jwksUri] = new CacheEntry(keySet, DateTime.UtcNow.Add(ttl));
        return keySet;
    }
}
