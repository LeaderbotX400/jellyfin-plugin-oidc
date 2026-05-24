using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text.Json;
using Jellyfin.Plugin.OIDC.Services;
using Xunit;

namespace Jellyfin.Plugin.OIDC.Tests;

public class ClaimParserTests
{
    private static JwtSecurityToken BuildToken(IEnumerable<Claim> claims)
    {
        return new JwtSecurityToken(claims: claims);
    }

    [Fact]
    public void ExtractClaim_ReturnsValueForKnownClaim()
    {
        var token = BuildToken([new Claim("preferred_username", "alice")]);
        Assert.Equal("alice", ClaimParser.ExtractClaim(token, "preferred_username"));
    }

    [Fact]
    public void ExtractClaim_ReturnsEmptyForMissingClaim()
    {
        var token = BuildToken([]);
        Assert.Equal(string.Empty, ClaimParser.ExtractClaim(token, "missing"));
    }

    [Fact]
    public void ExtractRoles_FlatClaim_ReturnsAllValues()
    {
        var token = BuildToken([
            new Claim("roles", "admin"),
            new Claim("roles", "editor")
        ]);
        var roles = ClaimParser.ExtractRoles(token, "roles");
        Assert.Contains("admin", roles);
        Assert.Contains("editor", roles);
    }

    [Fact]
    public void ExtractRoles_FlatClaim_JsonArray_IsParsed()
    {
        var json = JsonSerializer.Serialize(new[] { "admin", "viewer" });
        var token = BuildToken([new Claim("roles", json)]);
        var roles = ClaimParser.ExtractRoles(token, "roles");
        Assert.Contains("admin", roles);
        Assert.Contains("viewer", roles);
    }

    [Fact]
    public void ExtractRoles_NestedClaim_RealmAccessRoles()
    {
        // Simulate Keycloak-style realm_access.roles
        var realmAccess = JsonSerializer.Serialize(new { roles = new[] { "uma_authorization", "media_user" } });
        var token = BuildToken([new Claim("realm_access", realmAccess)]);
        var roles = ClaimParser.ExtractRoles(token, "realm_access.roles");
        Assert.Contains("uma_authorization", roles);
        Assert.Contains("media_user", roles);
    }

    [Fact]
    public void ExtractRoles_EmptyPath_ReturnsEmpty()
    {
        var token = BuildToken([]);
        var roles = ClaimParser.ExtractRoles(token, string.Empty);
        Assert.Empty(roles);
    }

    [Fact]
    public void ExtractRoles_MissingClaim_ReturnsEmpty()
    {
        var token = BuildToken([]);
        var roles = ClaimParser.ExtractRoles(token, "groups");
        Assert.Empty(roles);
    }
}
