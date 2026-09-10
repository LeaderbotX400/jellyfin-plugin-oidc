using System;
using Jellyfin.Plugin.OIDC.Services;
using Xunit;

namespace Jellyfin.Plugin.OIDC.Tests;

/// <summary>
/// Route matching for the Require-SSO gate. This is the load-bearing half of the feature: the
/// comparable feature in JellyfinSecurity shipped bypasses by matching paths with a string prefix
/// and by waiving on a username prefix, so most of these are attempts to sneak past the matcher.
/// </summary>
public sealed class RequireSsoRouteTests
{
    [Theory]
    [InlineData("/Users/AuthenticateByName")]
    [InlineData("/users/authenticatebyname")]          // Jellyfin routes are case-insensitive
    [InlineData("/USERS/AUTHENTICATEBYNAME")]
    [InlineData("/jellyfin/Users/AuthenticateByName")] // behind a base URL
    [InlineData("/a/b/c/Users/AuthenticateByName")]
    public void BlocksAuthenticateByName(string path)
        => Assert.True(RequireSsoMiddleware.IsPasswordAuthEndpoint("POST", path), path);

    [Theory]
    [InlineData("/Users/6f1a1e6c-1f0a-4b2f-9a3e-2b8c1d4e5f60/Authenticate")]
    [InlineData("/users/6F1A1E6C1F0A4B2F9A3E2B8C1D4E5F60/authenticate")]
    [InlineData("/jellyfin/Users/6f1a1e6c-1f0a-4b2f-9a3e-2b8c1d4e5f60/Authenticate")]
    public void BlocksTheObsoletePerUserRoute(string path)
        => Assert.True(RequireSsoMiddleware.IsPasswordAuthEndpoint("POST", path), path);

    /// <summary>
    /// Quick Connect takes no password — a code is approved from an already-authenticated session,
    /// which under this policy can only have come from SSO. Blocking it would lock out native
    /// clients, which cannot render a web login button.
    /// </summary>
    [Fact]
    public void DoesNotBlockQuickConnect()
        => Assert.False(RequireSsoMiddleware.IsPasswordAuthEndpoint("POST", "/Users/AuthenticateWithQuickConnect"));

    /// <summary>
    /// The bypass class that a StartsWith/Contains matcher would let through. Each of these is a
    /// different route that merely looks like the blocked one.
    /// </summary>
    [Theory]
    [InlineData("/Users/AuthenticateByNameFoo")]
    [InlineData("/Users/AuthenticateByName/Extra")]
    [InlineData("/UsersX/AuthenticateByName")]
    [InlineData("/Users/AuthenticateByNameWithQuickConnect")]
    [InlineData("/Evil/Users/AuthenticateByName/Bypass")]
    [InlineData("/Users/notaguid/Authenticate")]
    [InlineData("/Users/Authenticate")]
    public void DoesNotBlockLookalikeRoutes(string path)
        => Assert.False(RequireSsoMiddleware.IsPasswordAuthEndpoint("POST", path), path);

    [Theory]
    [InlineData("/Users")]
    [InlineData("/Users/Public")]
    [InlineData("/System/Info/Public")]
    [InlineData("/web/index.html")]
    [InlineData("/sso/OIDC/Start/authentik")]
    [InlineData("")]
    [InlineData("/")]
    public void IgnoresUnrelatedPaths(string path)
        => Assert.False(RequireSsoMiddleware.IsPasswordAuthEndpoint("POST", path), path);

    /// <summary>Only POST creates a session; a GET of the same path is not the auth call.</summary>
    [Theory]
    [InlineData("GET")]
    [InlineData("PUT")]
    [InlineData("DELETE")]
    [InlineData("HEAD")]
    [InlineData("OPTIONS")]
    public void OnlyBlocksPost(string method)
        => Assert.False(RequireSsoMiddleware.IsPasswordAuthEndpoint(method, "/Users/AuthenticateByName"), method);

    [Fact]
    public void HandlesNullPath()
        => Assert.False(RequireSsoMiddleware.IsPasswordAuthEndpoint("POST", null));

    /// <summary>
    /// Trailing and doubled slashes must not change the decision — empty segments are discarded
    /// before matching, so "//Users//AuthenticateByName//" is the same route.
    /// </summary>
    [Theory]
    [InlineData("/Users/AuthenticateByName/")]
    [InlineData("//Users//AuthenticateByName")]
    [InlineData("//Users//AuthenticateByName//")]
    public void NormalisesSlashes(string path)
        => Assert.True(RequireSsoMiddleware.IsPasswordAuthEndpoint("POST", path), path);
}
