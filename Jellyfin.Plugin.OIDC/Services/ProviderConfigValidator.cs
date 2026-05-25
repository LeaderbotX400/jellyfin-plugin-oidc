using System;
using Jellyfin.Plugin.OIDC.Configuration;

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
    }
}
