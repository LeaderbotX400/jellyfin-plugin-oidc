using System;
using System.Collections.Concurrent;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using IdentityModel.Client;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.OIDC.Services;

/// <summary>
/// Per-authority cache of OIDC discovery documents. Avoids re-fetching `.well-known/openid-configuration`
/// (and the implicit `/jwks` validation fetch that <see cref="HttpClientDiscoveryExtensions"/> performs)
/// on every authorize/callback/logout request.
/// </summary>
public sealed class OidcDiscoveryCache
{
    private sealed record CacheEntry(DiscoveryDocumentResponse Doc, DateTime ExpiresAt);

    private readonly ConcurrentDictionary<string, CacheEntry> _cache = new();
    private readonly ConcurrentDictionary<string, SemaphoreSlim> _locks = new();
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ILogger<OidcDiscoveryCache> _logger;

    public OidcDiscoveryCache(IHttpClientFactory httpClientFactory, ILogger<OidcDiscoveryCache> logger)
    {
        _httpClientFactory = httpClientFactory;
        _logger = logger;
    }

    /// <summary>
    /// Returns a cached discovery document for <paramref name="authority"/>, fetching if stale or missing.
    /// Default TTL is 1 hour. Errors are not cached — callers can retry on transient IdP outages.
    /// </summary>
    public async Task<DiscoveryDocumentResponse> GetAsync(string authority, TimeSpan? ttl = null)
    {
        var effectiveTtl = ttl ?? TimeSpan.FromHours(1);

        if (_cache.TryGetValue(authority, out var cached) && cached.ExpiresAt > DateTime.UtcNow)
        {
            return cached.Doc;
        }

        // Per-authority lock so two providers don't block each other
        var perAuthLock = _locks.GetOrAdd(authority, _ => new SemaphoreSlim(1, 1));
        await perAuthLock.WaitAsync().ConfigureAwait(false);
        try
        {
            if (_cache.TryGetValue(authority, out cached) && cached.ExpiresAt > DateTime.UtcNow)
            {
                return cached.Doc;
            }

            _logger.LogDebug("Discovery cache miss — fetching from {Authority}", authority);
            var httpClient = _httpClientFactory.CreateClient("OidcPlugin");
            var doc = await httpClient.GetDiscoveryDocumentAsync(new DiscoveryDocumentRequest
            {
                Address = authority,
                Policy = new DiscoveryPolicy
                {
                    ValidateIssuerName = true,
                    ValidateEndpoints = false
                }
            }).ConfigureAwait(false);

            if (!doc.IsError)
            {
                _cache[authority] = new CacheEntry(doc, DateTime.UtcNow.Add(effectiveTtl));
            }

            return doc;
        }
        finally
        {
            perAuthLock.Release();
        }
    }

    /// <summary>Drops the cached entry for the given authority, forcing a fresh fetch next call.</summary>
    public void Invalidate(string authority) => _cache.TryRemove(authority, out _);
}
