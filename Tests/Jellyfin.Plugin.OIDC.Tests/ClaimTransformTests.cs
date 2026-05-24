using System.Collections.Generic;
using Jellyfin.Plugin.OIDC.Configuration;
using Jellyfin.Plugin.OIDC.Services;
using Xunit;

namespace Jellyfin.Plugin.OIDC.Tests;

public class ClaimTransformTests
{
    [Fact]
    public void ApplyTransforms_NullTransforms_ReturnsSameValues()
    {
        var values = new[] { "admin", "viewer" };
        var result = ClaimParser.ApplyTransforms(values, null);
        Assert.Equal(values, result);
    }

    [Fact]
    public void ApplyTransforms_EmptyTransforms_ReturnsSameValues()
    {
        var values = new[] { "admin", "viewer" };
        var result = ClaimParser.ApplyTransforms(values, new List<ClaimTransform>());
        Assert.Equal(values, result);
    }

    [Fact]
    public void ApplyTransforms_MatchingRule_ReplacesValue()
    {
        var transforms = new List<ClaimTransform>
        {
            new() { FromValue = "cn=admins,dc=org", ToValue = "admin" }
        };
        var result = ClaimParser.ApplyTransforms(new[] { "cn=admins,dc=org", "viewer" }, transforms);
        Assert.Equal(new[] { "admin", "viewer" }, result);
    }

    [Fact]
    public void ApplyTransforms_EmptyToValue_DropsValue()
    {
        var transforms = new List<ClaimTransform>
        {
            new() { FromValue = "legacy-role", ToValue = "" }
        };
        var result = ClaimParser.ApplyTransforms(new[] { "admin", "legacy-role", "viewer" }, transforms);
        Assert.Equal(new[] { "admin", "viewer" }, result);
    }

    [Fact]
    public void ApplyTransforms_CaseInsensitiveMatch()
    {
        var transforms = new List<ClaimTransform>
        {
            new() { FromValue = "ADMIN", ToValue = "administrator" }
        };
        var result = ClaimParser.ApplyTransforms(new[] { "admin" }, transforms);
        Assert.Equal(new[] { "administrator" }, result);
    }

    [Fact]
    public void ApplyTransforms_UnmatchedValues_PassThrough()
    {
        var transforms = new List<ClaimTransform>
        {
            new() { FromValue = "old-role", ToValue = "new-role" }
        };
        var result = ClaimParser.ApplyTransforms(new[] { "admin", "viewer" }, transforms);
        Assert.Equal(new[] { "admin", "viewer" }, result);
    }

    [Fact]
    public void ApplyTransforms_FirstMatchWins()
    {
        var transforms = new List<ClaimTransform>
        {
            new() { FromValue = "admin", ToValue = "superadmin" },
            new() { FromValue = "admin", ToValue = "megaadmin" }
        };
        var result = ClaimParser.ApplyTransforms(new[] { "admin" }, transforms);
        Assert.Equal(new[] { "superadmin" }, result);
    }
}
