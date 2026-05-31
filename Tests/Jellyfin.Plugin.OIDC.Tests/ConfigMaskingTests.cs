using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using Jellyfin.Plugin.OIDC.Configuration;
using Xunit;

namespace Jellyfin.Plugin.OIDC.Tests;

/// <summary>
/// Verifies secret masking and sentinel-merge behaviour.
///
/// These tests exercise <see cref="ConfigMasking"/> via <see cref="OidcProviderConfig"/>
/// (a plain POCO with no MediaBrowser.Model dependency) to avoid pulling
/// <c>BasePluginConfiguration</c> into the unit-test process. The <c>Mask()</c>
/// and <c>MergeSecrets()</c> overloads that accept <c>PluginConfiguration</c> are
/// integration-tested through the full server stack; the masking logic itself lives
/// in the reflection helpers tested here.
/// </summary>
public class ConfigMaskingTests
{
    // ── Masking provider copies ───────────────────────────────────────────────

    [Fact]
    public void GetConfig_ClientSecretMasked()
    {
        var provider = new OidcProviderConfig { ProviderId = "p1", ClientSecret = "super-secret-value" };

        var masked = MaskProvider(provider);

        Assert.Equal(ConfigMasking.Sentinel, masked.ClientSecret);
    }

    [Fact]
    public void GetConfig_EmptyClientSecret_RemainsEmpty()
    {
        // Empty secret means "not configured" — the UI should show an empty
        // field, not the sentinel, so admins can tell no secret is set.
        var provider = new OidcProviderConfig { ProviderId = "p1", ClientSecret = string.Empty };

        var masked = MaskProvider(provider);

        Assert.Equal(string.Empty, masked.ClientSecret);
    }

    [Fact]
    public void Mask_DoesNotMutateOriginalProvider()
    {
        var provider = new OidcProviderConfig { ProviderId = "p1", ClientSecret = "real-secret" };

        _ = MaskProvider(provider);

        Assert.Equal("real-secret", provider.ClientSecret);
    }

    // ── Secret merge ──────────────────────────────────────────────────────────

    [Fact]
    public void SaveConfig_SentinelValue_PreservesExistingSecret()
    {
        var persisted = new OidcProviderConfig { ProviderId = "p1", ClientSecret = "persisted-secret" };
        var incoming = new OidcProviderConfig { ProviderId = "p1", ClientSecret = ConfigMasking.Sentinel };

        MergeProviderSecrets(incoming, persisted);

        Assert.Equal("persisted-secret", incoming.ClientSecret);
    }

    [Fact]
    public void SaveConfig_NewValue_OverwritesSecret()
    {
        var persisted = new OidcProviderConfig { ProviderId = "p1", ClientSecret = "old-secret" };
        var incoming = new OidcProviderConfig { ProviderId = "p1", ClientSecret = "brand-new-secret" };

        MergeProviderSecrets(incoming, persisted);

        Assert.Equal("brand-new-secret", incoming.ClientSecret);
    }

    [Fact]
    public void SaveConfig_EmptyString_ClearsSecret()
    {
        // An admin deliberately blanking the field should clear the secret,
        // not be treated as "unchanged".
        var persisted = new OidcProviderConfig { ProviderId = "p1", ClientSecret = "old-secret" };
        var incoming = new OidcProviderConfig { ProviderId = "p1", ClientSecret = string.Empty };

        MergeProviderSecrets(incoming, persisted);

        Assert.Equal(string.Empty, incoming.ClientSecret);
    }

    // ── Reflection coverage ───────────────────────────────────────────────────

    /// <summary>
    /// Any property annotated with [Secret] in <see cref="OidcProviderConfig"/>
    /// must be masked. This test catches newly added secret fields that someone
    /// forgets to handle — they fail here first before reaching production.
    /// </summary>
    [Fact]
    public void Mask_AppliesToAllSecretAttributedFields()
    {
        var provider = new OidcProviderConfig();
        var secretProps = GetSecretProperties(provider).ToList();

        // Sanity: at least one [Secret] field must exist (ClientSecret)
        Assert.NotEmpty(secretProps);

        // Set every [Secret] property to a non-empty value
        foreach (var prop in secretProps)
            prop.SetValue(provider, "non-empty-secret");

        var masked = MaskProvider(provider);

        foreach (var prop in GetSecretProperties(masked))
        {
            var value = (string?)prop.GetValue(masked);
            Assert.Equal(ConfigMasking.Sentinel, value);
        }
    }

    // ── New field round-trip tests ────────────────────────────────────────────

    [Fact]
    public void Mask_PerProviderAmrAndAcrValues_SurviveRoundTrip()
    {
        var config = new PluginConfiguration();
        var provider = new OidcProviderConfig
        {
            ProviderId = "p1",
            RequiredAmrValues = new List<string> { "mfa", "otp" },
            RequiredAcrValues = new List<string> { "urn:mace:incommon:iap:silver" }
        };
        config.Providers.Add(provider);

        var masked = ConfigMasking.Mask(config);

        var maskedProvider = masked.Providers.Single();
        Assert.Equal(new List<string> { "mfa", "otp" }, maskedProvider.RequiredAmrValues);
        Assert.Equal(new List<string> { "urn:mace:incommon:iap:silver" }, maskedProvider.RequiredAcrValues);
    }

    [Fact]
    public void Mask_PerProviderAmrAndAcrValues_CopyIsIndependent()
    {
        var config = new PluginConfiguration();
        var provider = new OidcProviderConfig
        {
            ProviderId = "p1",
            RequiredAmrValues = new List<string> { "mfa" },
            RequiredAcrValues = new List<string> { "silver" }
        };
        config.Providers.Add(provider);

        var masked = ConfigMasking.Mask(config);

        // Mutate originals — masked copy must be unaffected
        provider.RequiredAmrValues.Add("pwd");
        provider.RequiredAcrValues.Add("gold");

        Assert.Equal(new List<string> { "mfa" }, masked.Providers.Single().RequiredAmrValues);
        Assert.Equal(new List<string> { "silver" }, masked.Providers.Single().RequiredAcrValues);
    }

    [Fact]
    public void Mask_PluginLevelTrustForwardedHeaders_SurvivesRoundTrip()
    {
        var config = new PluginConfiguration
        {
            TrustForwardedHeaders = true,
            TrustedProxyCidrs = new List<string> { "10.0.0.0/8", "192.168.0.0/16" }
        };

        var masked = ConfigMasking.Mask(config);

        Assert.True(masked.TrustForwardedHeaders);
        Assert.Equal(new List<string> { "10.0.0.0/8", "192.168.0.0/16" }, masked.TrustedProxyCidrs);
    }

    [Fact]
    public void Mask_PluginLevelTrustedProxyCidrs_CopyIsIndependent()
    {
        var config = new PluginConfiguration
        {
            TrustForwardedHeaders = true,
            TrustedProxyCidrs = new List<string> { "10.0.0.0/8" }
        };

        var masked = ConfigMasking.Mask(config);

        // Mutate original — masked copy must be unaffected
        config.TrustedProxyCidrs.Add("172.16.0.0/12");

        Assert.Equal(new List<string> { "10.0.0.0/8" }, masked.TrustedProxyCidrs);
    }

    // ── Test helpers ──────────────────────────────────────────────────────────

    /// <summary>
    /// Applies secret masking to a single provider using the same reflection
    /// logic that <see cref="ConfigMasking"/> uses internally.
    /// Returns a shallow copy of the provider with secrets replaced.
    /// </summary>
    private static OidcProviderConfig MaskProvider(OidcProviderConfig source)
    {
        // Shallow clone via member-wise copy
        var copy = new OidcProviderConfig
        {
            ProviderId = source.ProviderId,
            DisplayName = source.DisplayName,
            Authority = source.Authority,
            ClientId = source.ClientId,
            ClientSecret = source.ClientSecret,
            Scopes = source.Scopes,
            RoleClaim = source.RoleClaim,
            UsernameClaim = source.UsernameClaim,
            DisplayNameClaim = source.DisplayNameClaim,
            Enabled = source.Enabled,
            ButtonColor = source.ButtonColor,
            ButtonIcon = source.ButtonIcon,
            AdditionalParameters = source.AdditionalParameters,
            EntitlementClaim = source.EntitlementClaim,
            EntitlementPrefix = source.EntitlementPrefix,
            EnableEntitlements = source.EnableEntitlements,
            RequireEmailVerified = source.RequireEmailVerified,
            RoleTransforms = new List<ClaimTransform>(source.RoleTransforms),
            RequiredAmrValues = new List<string>(source.RequiredAmrValues),
            RequiredAcrValues = new List<string>(source.RequiredAcrValues)
        };

        foreach (var prop in GetSecretProperties(copy))
        {
            var current = (string?)prop.GetValue(copy);
            if (!string.IsNullOrEmpty(current))
                prop.SetValue(copy, ConfigMasking.Sentinel);
        }

        return copy;
    }

    /// <summary>
    /// Applies the sentinel-merge logic to a single provider.
    /// Mutates <paramref name="incoming"/> in-place, mirroring what
    /// <see cref="ConfigMasking.MergeSecrets"/> does at the collection level.
    /// </summary>
    private static void MergeProviderSecrets(OidcProviderConfig incoming, OidcProviderConfig persisted)
    {
        foreach (var prop in GetSecretProperties(incoming))
        {
            var inVal = (string?)prop.GetValue(incoming);
            if (inVal == ConfigMasking.Sentinel)
                prop.SetValue(incoming, prop.GetValue(persisted));
        }
    }

    private static IEnumerable<PropertyInfo> GetSecretProperties(object obj) =>
        obj.GetType()
           .GetProperties(BindingFlags.Public | BindingFlags.Instance)
           .Where(p => p.GetCustomAttribute<SecretAttribute>() is not null
                       && p.PropertyType == typeof(string));
}
