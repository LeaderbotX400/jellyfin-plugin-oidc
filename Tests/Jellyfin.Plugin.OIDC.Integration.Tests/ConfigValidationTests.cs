using System.Collections.Generic;
using System.Linq;
using Jellyfin.Plugin.OIDC.Api;
using Jellyfin.Plugin.OIDC.Configuration;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Xunit;

namespace Jellyfin.Plugin.OIDC.Integration.Tests;

/// <summary>
/// Tests for the transform→admin-role warning logic that ConfigController.ValidateConfig produces,
/// as well as SAML EntityId warnings and the interpolation fix for the FromValue placeholder.
/// </summary>
public class ConfigValidationTests
{
    /// <summary>Mimics the warning-detection logic from ConfigController.ValidateConfig.</summary>
    private static List<string> DetectWarnings(PluginConfiguration config)
    {
        var warnings = new List<string>();
        if (config.Providers == null || config.RoleMappings == null) return warnings;

        var adminRoleNames = config.RoleMappings
            .Where(m => !m.IsExplicitDeny && m.IsAdmin)
            .Select(m => m.RoleName)
            .ToHashSet(System.StringComparer.OrdinalIgnoreCase);

        foreach (var provider in config.Providers)
        {
            foreach (var transform in provider.RoleTransforms ?? new List<ClaimTransform>())
            {
                if (!string.IsNullOrWhiteSpace(transform.ToValue) &&
                    adminRoleNames.Contains(transform.ToValue))
                {
                    warnings.Add(
                        $"Provider '{provider.ProviderId}': transform from='{transform.FromValue}' " +
                        $"to='{transform.ToValue}' targets admin role '{transform.ToValue}'.");
                }
            }
        }

        return warnings;
    }

    /// <summary>
    /// Creates a <see cref="ConfigController"/> wired with NullLogger and no-op fakes.
    /// Sufficient for calling ValidateConfig which only uses the logger.
    /// </summary>
    private static ConfigController BuildController()
    {
        var configProviderMock = new Mock<Services.IPluginConfigProvider>();
        configProviderMock.Setup(c => c.GetConfiguration()).Returns(new PluginConfiguration());

        var rbacService = new Services.RbacService(
            FakeJellyfinFactory.CreateUserManager(new FakeUserStore()).Object,
            FakeJellyfinFactory.CreateLibraryManager().Object,
            FakeJellyfinFactory.CreateActivityManager().Object,
            configProviderMock.Object,
            NullLogger<Services.RbacService>.Instance);

        return new ConfigController(
            rbacService,
            new FakeHttpClientFactory(),
            configProviderMock.Object,
            new Services.OidcUserStore(System.IO.Path.Combine(System.IO.Path.GetTempPath(), $"oidc-ctrl-test-{System.Guid.NewGuid():N}.json")),
            NullLogger<ConfigController>.Instance);
    }

    /// <summary>Calls <see cref="ConfigController.ValidateConfig"/> and returns the warnings list.</summary>
    private static List<string> GetControllerWarnings(PluginConfiguration config)
    {
        var ctrl = BuildController();
        var result = ctrl.ValidateConfig(config);
        var ok = Assert.IsType<OkObjectResult>(result);
        // anonymous type — use reflection to get Warnings
        var warnings = (IEnumerable<string>)ok.Value!.GetType().GetProperty("Warnings")!.GetValue(ok.Value)!;
        return warnings.ToList();
    }

    [Fact]
    public void ValidateConfig_TransformToAdminRole_ReturnsWarning()
    {
        var config = new PluginConfiguration
        {
            RoleMappings = new List<RoleMapping>
            {
                new() { RoleName = "administrator", IsAdmin = true },
                new() { RoleName = "user", IsAdmin = false, EnableMediaPlayback = true }
            },
            Providers = new List<OidcProviderConfig>
            {
                new()
                {
                    ProviderId = "myidp",
                    RoleTransforms = new List<ClaimTransform>
                    {
                        // This maps "cn=admins,dc=org" → "administrator" (an admin role) — warn!
                        new() { FromValue = "cn=admins,dc=org", ToValue = "administrator" }
                    }
                }
            }
        };

        var warnings = DetectWarnings(config);

        Assert.NotEmpty(warnings);
        Assert.Contains(warnings, w => w.Contains("administrator") && w.Contains("cn=admins,dc=org"));
    }

    [Fact]
    public void ValidateConfig_TransformToNonAdminRole_NoWarning()
    {
        var config = new PluginConfiguration
        {
            RoleMappings = new List<RoleMapping>
            {
                new() { RoleName = "administrator", IsAdmin = true },
                new() { RoleName = "viewer", IsAdmin = false }
            },
            Providers = new List<OidcProviderConfig>
            {
                new()
                {
                    ProviderId = "myidp",
                    RoleTransforms = new List<ClaimTransform>
                    {
                        // Maps to "viewer" — non-admin, no warning
                        new() { FromValue = "legacy-viewer", ToValue = "viewer" }
                    }
                }
            }
        };

        var warnings = DetectWarnings(config);
        Assert.Empty(warnings);
    }

    [Fact]
    public void ValidateConfig_TransformDropsRole_NoWarning()
    {
        var config = new PluginConfiguration
        {
            RoleMappings = new List<RoleMapping>
            {
                new() { RoleName = "administrator", IsAdmin = true }
            },
            Providers = new List<OidcProviderConfig>
            {
                new()
                {
                    ProviderId = "myidp",
                    RoleTransforms = new List<ClaimTransform>
                    {
                        // Empty ToValue = drop — not a promotion, no warning
                        new() { FromValue = "bad-actor", ToValue = "" }
                    }
                }
            }
        };

        var warnings = DetectWarnings(config);
        Assert.Empty(warnings);
    }

    [Fact]
    public void ValidateConfig_DenyMappingWithAdminName_NoWarning()
    {
        // A deny mapping named "administrator" should NOT generate a warning —
        // deny mappings strip permissions, not grant them.
        var config = new PluginConfiguration
        {
            RoleMappings = new List<RoleMapping>
            {
                // IsAdmin=true but IsExplicitDeny=true — this denies admin, not grants it
                new() { RoleName = "administrator", IsAdmin = true, IsExplicitDeny = true }
            },
            Providers = new List<OidcProviderConfig>
            {
                new()
                {
                    ProviderId = "myidp",
                    RoleTransforms = new List<ClaimTransform>
                    {
                        new() { FromValue = "x", ToValue = "administrator" }
                    }
                }
            }
        };

        var warnings = DetectWarnings(config);
        // deny mappings are excluded from adminRoleNames, so no warning should fire
        Assert.Empty(warnings);
    }

    [Fact]
    public void ValidateConfig_NoTransforms_NoWarnings()
    {
        var config = new PluginConfiguration
        {
            RoleMappings = new List<RoleMapping>
            {
                new() { RoleName = "administrator", IsAdmin = true }
            },
            Providers = new List<OidcProviderConfig>
            {
                new() { ProviderId = "myidp", RoleTransforms = new List<ClaimTransform>() }
            }
        };

        var warnings = DetectWarnings(config);
        Assert.Empty(warnings);
    }

    // ── SAML EntityId / IdpEntityId warnings ──────────────────────────────────────────────────

    [Fact]
    public void ValidateConfig_EnabledSamlProvider_MissingEntityId_ProducesWarning()
    {
        var config = new PluginConfiguration
        {
            SamlProviders = new List<SamlProviderConfig>
            {
                new()
                {
                    Id = "okta-saml",
                    EntityId = "",          // empty — audience validation will be skipped
                    IdpEntityId = "https://idp.example.com",
                    Enabled = true
                }
            }
        };

        var warnings = GetControllerWarnings(config);

        Assert.Contains(warnings, w =>
            w.Contains("okta-saml") &&
            w.Contains("SP EntityID") &&
            w.Contains("audience validation will be SKIPPED"));
    }

    [Fact]
    public void ValidateConfig_EnabledSamlProvider_MissingIdpEntityId_ProducesWarning()
    {
        var config = new PluginConfiguration
        {
            SamlProviders = new List<SamlProviderConfig>
            {
                new()
                {
                    Id = "okta-saml",
                    EntityId = "https://jellyfin.example.com",
                    IdpEntityId = "",       // empty — issuer validation will be skipped
                    Enabled = true
                }
            }
        };

        var warnings = GetControllerWarnings(config);

        Assert.Contains(warnings, w =>
            w.Contains("okta-saml") &&
            w.Contains("IdP EntityID") &&
            w.Contains("issuer validation will be SKIPPED"));
    }

    [Fact]
    public void ValidateConfig_EnabledSamlProvider_BothEntityIdsEmpty_ProducesTwoWarnings()
    {
        var config = new PluginConfiguration
        {
            SamlProviders = new List<SamlProviderConfig>
            {
                new()
                {
                    Id = "saml-p1",
                    EntityId = "",
                    IdpEntityId = "",
                    Enabled = true
                }
            }
        };

        var warnings = GetControllerWarnings(config);

        Assert.Equal(2, warnings.Count(w => w.Contains("saml-p1")));
    }

    [Fact]
    public void ValidateConfig_DisabledSamlProvider_MissingEntityIds_NoWarning()
    {
        // Disabled providers are not in active use — don't spam warnings about them.
        var config = new PluginConfiguration
        {
            SamlProviders = new List<SamlProviderConfig>
            {
                new()
                {
                    Id = "saml-off",
                    EntityId = "",
                    IdpEntityId = "",
                    Enabled = false
                }
            }
        };

        var warnings = GetControllerWarnings(config);

        Assert.DoesNotContain(warnings, w => w.Contains("saml-off"));
    }

    [Fact]
    public void ValidateConfig_EnabledSamlProvider_BothEntityIdsPopulated_NoWarning()
    {
        var config = new PluginConfiguration
        {
            SamlProviders = new List<SamlProviderConfig>
            {
                new()
                {
                    Id = "saml-full",
                    EntityId = "https://jellyfin.example.com",
                    IdpEntityId = "https://idp.example.com",
                    Enabled = true
                }
            }
        };

        var warnings = GetControllerWarnings(config);

        Assert.DoesNotContain(warnings, w => w.Contains("saml-full"));
    }

    // ── Interpolation regression: FromValue must appear literally in admin-transform warning ──

    [Fact]
    public void ValidateConfig_AdminTransformWarning_ContainsActualFromValue()
    {
        // Regression: the third string segment of the warning message previously lacked the `$`
        // prefix so '{transform.FromValue}' was emitted literally instead of the actual value.
        var config = new PluginConfiguration
        {
            RoleMappings = new List<RoleMapping>
            {
                new() { RoleName = "admins", IsAdmin = true }
            },
            Providers = new List<OidcProviderConfig>
            {
                new()
                {
                    ProviderId = "myidp",
                    RoleTransforms = new List<ClaimTransform>
                    {
                        new() { FromValue = "cn=admins,dc=example,dc=com", ToValue = "admins" }
                    }
                }
            }
        };

        var warnings = GetControllerWarnings(config);

        // The actual FromValue must appear in the message — not the literal '{transform.FromValue}'.
        Assert.Contains(warnings, w => w.Contains("cn=admins,dc=example,dc=com"));
        Assert.DoesNotContain(warnings, w => w.Contains("{transform.FromValue}"));
    }
}
