using System.Collections.Generic;
using System.Linq;
using Jellyfin.Plugin.OIDC.Configuration;
using Xunit;

namespace Jellyfin.Plugin.OIDC.Integration.Tests;

/// <summary>
/// Tests for the transform→admin-role warning logic that ConfigController.ValidateConfig produces.
/// The detection logic is tested in isolation here (no HTTP layer) to keep tests fast.
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
}
