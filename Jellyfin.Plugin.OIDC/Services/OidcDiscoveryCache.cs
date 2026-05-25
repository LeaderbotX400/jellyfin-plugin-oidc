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
/// <remarks>
/// Concurrency is managed via a striped semaphore array (8 stripes hashed by authority) rather than one
/// <c>SemaphoreSlim</c> per authority. This eliminates the unbounded-growth and never-disposed resource
/// leak that a <c>ConcurrentDictionary&lt;string, SemaphoreSlim&gt;</c> would cause, at the cost of
/// slightly more contention between authorities that hash to the same stripe — acceptable since the
/// number of configured providers is small and the critical section is short (one HTTP fetch).
/// </remarks>
public sealed class OidcDiscoveryCache : IDisposable
{
    private const int StripeCount = 8;

    private sealed record CacheEntry(DiscoveryDocumentResponse Doc, DateTime ExpiresAt);

    private readonly ConcurrentDictionary<string, CacheEntry> _cache = new();
    private readonly SemaphoreSlim[] _stripes;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ILogger<OidcDiscoveryCache> _logger;
    private readonly bool _allowEndpointMismatch;
    private bool _disposed;

    /// <summary>Production ctor: strict endpoint validation.</summary>
    public OidcDiscoveryCache(IHttpClientFactory httpClientFactory, ILogger<OidcDiscoveryCache> logger)
        : this(httpClientFactory, logger, allowEndpointMismatch: false)
    {
    }

    /// <summary>
    /// Test-only ctor that disables IdentityModel's endpoint-vs-authority host match.
    /// NOT exposed in <c>PluginConfiguration</c>; intended for in-process mock IdPs whose
    /// endpoint hosts may not align with the authority host (e.g. WireMock random ports).
    /// Production code paths must construct with the default ctor.
    /// </summary>
    public OidcDiscoveryCache(
        IHttpClientFactory httpClientFactory,
        ILogger<OidcDiscoveryCache> logger,
        bool allowEndpointMismatch)
    {
        _httpClientFactory = httpClientFactory;
        _logger = logger;
        _allowEndpointMismatch = allowEndpointMismatch;

        _stripes = new SemaphoreSlim[StripeCount];
        for (var i = 0; i < StripeCount; i++)
        {
            _stripes[i] = new SemaphoreSlim(1, 1);
        }
    }

    /// <summary>
    /// Returns a cached discovery document for <paramref name="authority"/>, fetching if stale or missing.
    /// Default TTL is 1 hour. Errors are not cached — callers can retry on transient IdP outages.
    /// </summary>
    /// <param name="authority">The IdP authority (issuer base URL).</param>
    /// <param name="allowInsecureAuthority">When true, allows plain HTTP to a localhost authority. Default false.</param>
    /// <param name="ttl">Optional cache TTL override.</param>
    public async Task<DiscoveryDocumentResponse> GetAsync(
        string authority,
        bool allowInsecureAuthority = false,
        TimeSpan? ttl = null)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        SecurityValidation.EnsureSecureUrl(authority, allowInsecureAuthority, nameof(authority));

        var effectiveTtl = ttl ?? TimeSpan.FromHours(1);

        if (_cache.TryGetValue(authority, out var cached) && cached.ExpiresAt > DateTime.UtcNow)
        {
            return cached.Doc;
        }

        // Select the stripe for this authority (stable hash, not cryptographic)
        var stripe = _stripes[(uint)authority.GetHashCode() % StripeCount];
        await stripe.WaitAsync().ConfigureAwait(false);
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
                    ValidateEndpoints = !_allowEndpointMismatch
                }
            }).ConfigureAwait(false);

            if (!doc.IsError)
            {
                // Defence in depth: even after IdentityModel validation, double-check that the
                // endpoints we're about to use are themselves not http:// to an arbitrary host.
                SecurityValidation.EnsureSecureUrl(doc.TokenEndpoint, allowInsecureAuthority, "token_endpoint");
                SecurityValidation.EnsureSecureUrl(doc.AuthorizeEndpoint, allowInsecureAuthority, "authorization_endpoint");
                if (!string.IsNullOrEmpty(doc.JwksUri))
                {
                    SecurityValidation.EnsureSecureUrl(doc.JwksUri, allowInsecureAuthority, "jwks_uri");
                }

                _cache[authority] = new CacheEntry(doc, DateTime.UtcNow.Add(effectiveTtl));
            }

            return doc;
        }
        finally
        {
            stripe.Release();
        }
    }

    /// <summary>Drops the cached entry for the given authority, forcing a fresh fetch next call.</summary>
    public void Invalidate(string authority) => _cache.TryRemove(authority, out _);

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;

        foreach (var stripe in _stripes)
        {
            stripe.Dispose();
        }
    }
}
