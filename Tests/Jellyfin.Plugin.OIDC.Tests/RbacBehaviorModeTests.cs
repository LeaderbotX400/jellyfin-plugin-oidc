using System.Collections.Generic;
using Jellyfin.Plugin.OIDC.Configuration;
using Jellyfin.Plugin.OIDC.Services;
using Xunit;

namespace Jellyfin.Plugin.OIDC.Tests;

/// <summary>
/// Verifies that <see cref="RbacBehaviorMode.RespectExistingWhenUnspecified"/> produces nullable
/// (untouched) fields in the role-only path, and that the new <c>rating:unlimited</c> sentinel flows
/// into <see cref="PermissionPreview.ClearMaxParentalRating"/>.
/// </summary>
public class RbacBehaviorModeTests
{
    private static PermissionPreview Compute(
        string[] roles,
        string[] entitlements,
        ResolverConfig cfg,
        string providerId = "test")
    {
        return PermissionResolver.Resolve(roles, entitlements, providerId, cfg);
    }

    private static ResolverConfig MakeConfig(
        RbacBehaviorMode mode,
        List<RoleMapping>? mappings = null,
        bool enableEntitlements = true)
    {
        return new ResolverConfig
        {
            RbacBehavior = mode,
            RoleMappings = mappings ?? new List<RoleMapping>(),
            Providers = new List<OidcProviderConfig>
            {
                new() { ProviderId = "test", EnableEntitlements = enableEntitlements, EntitlementPrefix = "jellyfin:" },
            },
        };
    }

    [Fact]
    public void Authoritative_RoleOnly_AllFieldsAreConcrete()
    {
        var cfg = MakeConfig(
            RbacBehaviorMode.EntitlementsAuthoritative,
            new() { new() { RoleName = "viewer", EnableMediaPlayback = true } });

        var p = Compute(["viewer"], [], cfg);

        Assert.NotNull(p.IsAdmin);
        Assert.True(p.EnableMediaPlayback);
        Assert.False(p.EnableContentDeletion);
        Assert.NotNull(p.EnableAllLibraries);
        Assert.NotNull(p.Libraries);
    }

    [Fact]
    public void RespectExisting_RoleOnly_UnopinedFieldsAreNull()
    {
        var cfg = MakeConfig(
            RbacBehaviorMode.RespectExistingWhenUnspecified,
            new() { new() { RoleName = "viewer", EnableMediaPlayback = true, EnableContentDeletion = false } });

        var p = Compute(["viewer"], [], cfg);

        Assert.True(p.EnableMediaPlayback);
        Assert.Null(p.EnableContentDeletion);
        Assert.Null(p.IsAdmin);
        Assert.Null(p.EnableAllLibraries);
        Assert.Null(p.Libraries);
    }

    [Fact]
    public void RespectExisting_DenyStillForcesFalse()
    {
        var cfg = MakeConfig(
            RbacBehaviorMode.RespectExistingWhenUnspecified,
            new()
            {
                new() { RoleName = "viewer", EnableContentDeletion = true },
                new() { RoleName = "no-delete", EnableContentDeletion = true, IsExplicitDeny = true },
            });

        var p = Compute(["viewer", "no-delete"], [], cfg);

        Assert.False(p.EnableContentDeletion);
    }

    [Fact]
    public void RespectExisting_WithEntitlements_BehavesAuthoritatively()
    {
        var cfg = MakeConfig(
            RbacBehaviorMode.RespectExistingWhenUnspecified,
            new() { new() { RoleName = "viewer", EnableMediaPlayback = true } });

        var p = Compute(["viewer"], ["jellyfin:admin"], cfg);

        Assert.True(p.IsAdmin);
        Assert.False(p.EnableContentDeletion);
        Assert.NotNull(p.EnableAllLibraries);
    }

    [Fact]
    public void RatingUnlimited_FlowsToClearFlag()
    {
        var cfg = MakeConfig(
            RbacBehaviorMode.EntitlementsAuthoritative,
            new() { new() { RoleName = "user", EnableMediaPlayback = true } });

        var p = Compute(["user"], ["jellyfin:rating:unlimited"], cfg);

        Assert.True(p.ClearMaxParentalRating);
        Assert.Null(p.MaxParentalRating);
    }

    [Fact]
    public void RespectExisting_LibraryGrant_BecomesConcrete()
    {
        var cfg = MakeConfig(
            RbacBehaviorMode.RespectExistingWhenUnspecified,
            new() { new() { RoleName = "viewer", EnableAllLibraries = true } });

        var p = Compute(["viewer"], [], cfg);

        Assert.True(p.EnableAllLibraries);
        Assert.NotNull(p.Libraries);
    }

    [Fact]
    public void RespectExisting_NoMatches_NoOpinions()
    {
        var cfg = MakeConfig(
            RbacBehaviorMode.RespectExistingWhenUnspecified,
            new() { new() { RoleName = "admin", IsAdmin = true } });

        var p = Compute(["other-role"], [], cfg);

        Assert.Null(p.IsAdmin);
        Assert.Null(p.EnableMediaPlayback);
        Assert.Null(p.EnableAllLibraries);
        Assert.Null(p.Libraries);
        Assert.Empty(p.MatchedGrantMappings);
    }

    [Fact]
    public void MergeMappings_NoRating_KeepsMaxParentalRatingNull()
    {
        // Regression: previously DefaultIfEmpty().Max() produced 0, locking users to rating=0.
        var cfg = MakeConfig(
            RbacBehaviorMode.EntitlementsAuthoritative,
            new() { new() { RoleName = "user", EnableMediaPlayback = true } });

        var p = Compute(["user"], [], cfg);

        Assert.Null(p.MaxParentalRating);
        Assert.False(p.ClearMaxParentalRating);
    }
}
