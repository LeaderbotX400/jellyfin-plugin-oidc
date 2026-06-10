using System;
using System.Collections.Generic;
using System.Linq;
using Jellyfin.Plugin.OIDC.Api;
using Jellyfin.Plugin.OIDC.Configuration;
using Jellyfin.Plugin.OIDC.Services;
using Xunit;

namespace Jellyfin.Plugin.OIDC.Tests;

public class ConfigValidationTests
{
    [Fact]
    public void Validate_AcceptsCleanConfig()
    {
        var cfg = new PluginConfiguration();
        cfg.Providers.Add(new OidcProviderConfig { ProviderId = "keycloak", DisplayName = "KC" });
        cfg.SamlProviders.Add(new SamlProviderConfig { Id = "okta-saml", DisplayName = "Okta" });

        var errors = ConfigController.ValidateConfiguration(cfg);
        Assert.Empty(errors);
    }

    [Theory]
    [InlineData("bad/id with spaces")]
    [InlineData("has.dots")]
    [InlineData("has'quote")]
    [InlineData("</script>")]
    [InlineData("")]
    public void Validate_RejectsHostileProviderId(string badId)
    {
        var cfg = new PluginConfiguration();
        cfg.Providers.Add(new OidcProviderConfig { ProviderId = badId, DisplayName = "X" });

        var errors = ConfigController.ValidateConfiguration(cfg);
        Assert.NotEmpty(errors);
        Assert.Contains(errors, e => e.Contains("ProviderId"));
    }

    [Fact]
    public void Validate_RejectsHostileSamlId()
    {
        var cfg = new PluginConfiguration();
        cfg.SamlProviders.Add(new SamlProviderConfig { Id = "bad id", DisplayName = "X" });

        var errors = ConfigController.ValidateConfiguration(cfg);
        Assert.NotEmpty(errors);
    }

    // ── AllowedSigningAlgorithms validation via ProviderConfigValidator ────────────────────────

    /// <summary>
    /// The default AllowedSigningAlgorithms (RS256/ES256/PS256 family) must pass validation
    /// for an enabled provider with a non-empty Authority (HTTPS).
    /// </summary>
    [Fact]
    public void ValidateOrThrow_DefaultAlgorithms_NoException()
    {
        var provider = new OidcProviderConfig
        {
            ProviderId = "p1",
            Authority = "https://idp.example.com",
            // AllowedSigningAlgorithms defaults to RS*/ES*/PS* — all valid
        };

        // Should not throw
        ProviderConfigValidator.ValidateOrThrow(provider);
    }

    /// <summary>
    /// Each of the 12 known JOSE algorithm names must be accepted individually.
    /// </summary>
    [Theory]
    [InlineData("RS256")]
    [InlineData("RS384")]
    [InlineData("RS512")]
    [InlineData("ES256")]
    [InlineData("ES384")]
    [InlineData("ES512")]
    [InlineData("PS256")]
    [InlineData("PS384")]
    [InlineData("PS512")]
    [InlineData("HS256")]
    [InlineData("HS384")]
    [InlineData("HS512")]
    public void ValidateOrThrow_AllValidAlgorithms_Accepted(string alg)
    {
        var provider = new OidcProviderConfig
        {
            ProviderId = "p1",
            Authority = "https://idp.example.com",
            AllowedSigningAlgorithms = new List<string> { alg }
        };

        // Should not throw
        ProviderConfigValidator.ValidateOrThrow(provider);
    }

    /// <summary>
    /// "none" and other disallowed / unknown values must be rejected.
    /// </summary>
    [Theory]
    [InlineData("none")]
    [InlineData("rs256")]   // wrong case — JOSE names are case-sensitive
    [InlineData("RS-256")]  // wrong format
    [InlineData("garbage")]
    [InlineData("")]        // empty string entry
    [InlineData("   ")]     // whitespace-only entry
    public void ValidateOrThrow_InvalidAlgorithm_Throws(string badAlg)
    {
        var provider = new OidcProviderConfig
        {
            ProviderId = "myidp",
            Authority = "https://idp.example.com",
            AllowedSigningAlgorithms = new List<string> { badAlg }
        };

        var ex = Assert.Throws<InvalidOperationException>(() =>
            ProviderConfigValidator.ValidateOrThrow(provider));

        // Error message must name the provider and explain the problem.
        Assert.Contains("myidp", ex.Message);
    }

    /// <summary>
    /// An empty AllowedSigningAlgorithms list must be rejected for an enabled provider with
    /// a non-empty Authority because SigningKeyResolver throws when the list is empty.
    /// </summary>
    [Fact]
    public void ValidateOrThrow_EmptyAlgorithmList_Throws()
    {
        var provider = new OidcProviderConfig
        {
            ProviderId = "p1",
            Authority = "https://idp.example.com",
            AllowedSigningAlgorithms = new List<string>()
        };

        var ex = Assert.Throws<InvalidOperationException>(() =>
            ProviderConfigValidator.ValidateOrThrow(provider));

        Assert.Contains("p1", ex.Message);
        Assert.Contains("empty", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// An empty-shell provider (no Authority set) must bypass algorithm validation entirely —
    /// newly-added rows are allowed to be incomplete.
    /// </summary>
    [Fact]
    public void ValidateOrThrow_EmptyAuthority_SkipsAlgorithmValidation()
    {
        var provider = new OidcProviderConfig
        {
            ProviderId = "p1",
            Authority = "",
            AllowedSigningAlgorithms = new List<string>() // would fail if validated
        };

        // Should not throw — empty authority = empty-shell row, skip all validation
        ProviderConfigValidator.ValidateOrThrow(provider);
    }
}
