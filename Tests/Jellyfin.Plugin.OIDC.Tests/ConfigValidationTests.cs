using System.Linq;
using Jellyfin.Plugin.OIDC.Api;
using Jellyfin.Plugin.OIDC.Configuration;
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
}
