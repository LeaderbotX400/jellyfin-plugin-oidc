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
    private sealed record CacheEntry(JsonWebKeySet Keys, DateTime ExpiresAt);

    private readonly ConcurrentDictionary<string, CacheEntry> _cache = new();
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ILogger<JwksCache> _logger;
    private readonly SemaphoreSlim _fetchLock = new(1, 1);

    public JwksCache(IHttpClientFactory httpClientFactory, ILogger<JwksCache> logger)
    {
        _httpClientFactory = httpClientFactory;
        _logger = logger;
    }

    /// <summary>
    /// Returns cached JWKS for the given URI, fetching and caching if stale or missing.
    /// Default TTL is 1 hour. Use <see cref="Invalidate"/> to force a refresh.
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

            _logger.LogDebug("JWKS cache miss — fetching {JwksUri}", jwksUri);
            var httpClient = _httpClientFactory.CreateClient("OidcPlugin");
            var jwksJson = await httpClient.GetStringAsync(jwksUri).ConfigureAwait(false);
            var keySet = new JsonWebKeySet(jwksJson);
            _cache[jwksUri] = new CacheEntry(keySet, DateTime.UtcNow.Add(effectiveTtl));
            return keySet;
        }
        finally
        {
            _fetchLock.Release();
        }
    }

    /// <summary>Removes the cached entry for the given URI, forcing a fresh fetch next time.</summary>
    public void Invalidate(string jwksUri) => _cache.TryRemove(jwksUri, out _);
}
