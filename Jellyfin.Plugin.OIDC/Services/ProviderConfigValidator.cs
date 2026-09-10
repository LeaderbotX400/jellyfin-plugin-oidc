using System;
using System.Collections.Generic;
using Jellyfin.Plugin.OIDC.Configuration;
using Jellyfin.Plugin.OIDC.Api;

namespace Jellyfin.Plugin.OIDC.Services;

/// <summary>
/// Save-time guard for <see cref="OidcProviderConfig"/>. Centralises the "don't let admins point
/// the plugin at plain-HTTP authorities" rule so it's enforced both from the config UI and from
/// any direct API mutation.
/// </summary>
public static class ProviderConfigValidator
{
    /// <summary>
    /// JOSE algorithm names that are accepted in <see cref="OidcProviderConfig.AllowedSigningAlgorithms"/>.
    /// Case-sensitive per the JOSE spec (RFC 7518 §3).
    /// Note: "none" is deliberately absent — it is never a valid choice.
    /// </summary>
    private static readonly HashSet<string> KnownAlgorithms = new(StringComparer.Ordinal)
    {
        "RS256", "RS384", "RS512",
        "ES256", "ES384", "ES512",
        "PS256", "PS384", "PS512",
        "HS256", "HS384", "HS512"
    };

    /// <summary>Throws <see cref="InvalidOperationException"/> if the provider is unsafe to persist.</summary>
    public static void ValidateOrThrow(OidcProviderConfig provider)
    {
        if (string.IsNullOrWhiteSpace(provider.Authority))
        {
            return; // empty-shell providers (newly-added rows) are allowed to be incomplete
        }

        SecurityValidation.EnsureSecureUrl(
            provider.Authority,
            provider.AllowInsecureAuthority,
            $"Provider '{provider.ProviderId}' Authority");

        // Validate AdditionalParameters at save time — reject reserved OIDC keys so that a
        // misconfiguration is caught early rather than at the first login attempt.
        if (!string.IsNullOrWhiteSpace(provider.AdditionalParameters))
        {
            // Reuse the same parse + rejection logic from OidcController to keep them in sync.
            // ParseAdditionalParameters throws InvalidOperationException on reserved keys.
            OidcController.ParseAdditionalParameters(provider.AdditionalParameters);
        }

        // Validate AllowedSigningAlgorithms — each entry must be a known JOSE algorithm name.
        // An empty list is rejected: SigningKeyResolver refuses to validate tokens when no
        // algorithms are configured, so an empty list would block all logins silently.
        ValidateSigningAlgorithms(provider);

        ValidatePictureAllowedHosts(provider);
    }

    /// <summary>
    /// Validates <see cref="OidcProviderConfig.PictureAllowedHosts"/>. Entries must be bare
    /// hostnames — no scheme, port, path, or wildcard. This list widens what the server is
    /// willing to fetch, so a malformed entry must be a save-time error rather than something
    /// that silently never matches (an admin who typed "https://cdn.example.com/" and saw no
    /// error would reasonably assume avatars were enabled when they are not).
    /// </summary>
    private static void ValidatePictureAllowedHosts(OidcProviderConfig provider)
    {
        foreach (var entry in provider.PictureAllowedHosts)
        {
            var host = entry?.Trim();

            if (string.IsNullOrEmpty(host))
            {
                throw new InvalidOperationException(
                    $"Provider '{provider.ProviderId}' has an empty entry in PictureAllowedHosts. " +
                    "Remove the blank row, or enter a bare hostname such as lh3.googleusercontent.com.");
            }

            if (host.Contains("://", StringComparison.Ordinal)
                || host.Contains('/', StringComparison.Ordinal)
                || host.Contains(':', StringComparison.Ordinal)
                || host.Contains('*', StringComparison.Ordinal)
                || host.Contains(' ', StringComparison.Ordinal))
            {
                throw new InvalidOperationException(
                    $"Provider '{provider.ProviderId}' PictureAllowedHosts entry '{host}' is not a bare hostname. " +
                    "Enter only the host — no scheme, port, path or wildcard (e.g. lh3.googleusercontent.com).");
            }

            if (!Uri.CheckHostName(host).Equals(UriHostNameType.Dns)
                && !Uri.CheckHostName(host).Equals(UriHostNameType.IPv4))
            {
                throw new InvalidOperationException(
                    $"Provider '{provider.ProviderId}' PictureAllowedHosts entry '{host}' is not a valid hostname.");
            }
        }
    }

    /// <summary>
    /// Validates the <see cref="OidcProviderConfig.AllowedSigningAlgorithms"/> list.
    /// Throws <see cref="InvalidOperationException"/> if:
    ///   - The list is null or empty (would block all token validation).
    ///   - Any entry is null/whitespace.
    ///   - Any entry is not a recognized JOSE algorithm name (notably "none" is rejected).
    /// </summary>
    private static void ValidateSigningAlgorithms(OidcProviderConfig provider)
    {
        var algs = provider.AllowedSigningAlgorithms;

        if (algs == null || algs.Count == 0)
        {
            throw new InvalidOperationException(
                $"Provider '{provider.ProviderId}': AllowedSigningAlgorithms must not be empty — " +
                "an empty list blocks all token validation. " +
                "Allowed values: RS256, RS384, RS512, ES256, ES384, ES512, PS256, PS384, PS512, HS256, HS384, HS512.");
        }

        foreach (var alg in algs)
        {
            if (string.IsNullOrWhiteSpace(alg))
            {
                throw new InvalidOperationException(
                    $"Provider '{provider.ProviderId}': AllowedSigningAlgorithms contains a null or whitespace entry. " +
                    "Allowed values: RS256, RS384, RS512, ES256, ES384, ES512, PS256, PS384, PS512, HS256, HS384, HS512.");
            }

            if (!KnownAlgorithms.Contains(alg))
            {
                throw new InvalidOperationException(
                    $"Provider '{provider.ProviderId}': AllowedSigningAlgorithms contains unknown or disallowed algorithm '{alg}'. " +
                    "Allowed values: RS256, RS384, RS512, ES256, ES384, ES512, PS256, PS384, PS512, HS256, HS384, HS512. " +
                    "Note: 'none' is never permitted.");
            }
        }
    }
}
