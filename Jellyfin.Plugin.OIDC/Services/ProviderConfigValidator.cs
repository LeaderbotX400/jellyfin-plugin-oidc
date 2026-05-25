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
    }
}
