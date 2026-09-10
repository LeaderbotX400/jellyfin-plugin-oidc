using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Xunit;

namespace Jellyfin.Plugin.OIDC.Integration.Tests;

/// <summary>
/// End-to-end avatar sync: real OIDC flow (Start → Callback → Authenticate) against the WireMock
/// IdP, with the avatar served from the IdP's own origin. Complements the unit tests in
/// Jellyfin.Plugin.OIDC.Tests, which cover the refusal paths in isolation.
/// </summary>
public class ProfileImageFlowTests : IClassFixture<MockIdpFixture>
{
    private readonly MockIdpFixture _idp;

    public ProfileImageFlowTests(MockIdpFixture idp) => _idp = idp;

    [Fact]
    public async Task PictureClaimInIdToken_SetsProfileImage()
    {
        var fixture = new TestFixture(_idp);
        fixture.AddProvider();
        var avatarUrl = _idp.StubAvatarEndpoint("/avatar-idtoken.png");

        await RunFlowWithPicture(fixture, "alice", "sub-alice", avatarUrl);

        var user = fixture.UserStore.Inner.ById.Values.Single(u => u.Username == "alice");
        Assert.NotNull(user.ProfileImage);
        Assert.Equal(
            Path.Combine(fixture.UserConfigurationDirectory, "alice", "profile.png"),
            user.ProfileImage!.Path);
        Assert.True(File.Exists(user.ProfileImage.Path));

        var record = await fixture.OidcUserStore.GetByUserIdAsync(user.Id);
        Assert.Equal(avatarUrl, record!.ProfileImageSourceUrl);
    }

    /// <summary>
    /// Authentik — the IdP this repo ships an example for — exposes <c>picture</c> only from
    /// userinfo, never in the ID token. Without this fallback the feature is dead for it.
    /// </summary>
    [Fact]
    public async Task PictureOnlyInUserInfo_StillSetsProfileImage()
    {
        var fixture = new TestFixture(_idp);
        fixture.AddProvider();
        var avatarUrl = _idp.StubAvatarEndpoint("/avatar-userinfo.png");
        _idp.StubUserInfo(new { sub = "sub-bob", picture = avatarUrl });

        // No picture claim in the ID token at all.
        await RunFlowWithPicture(fixture, "bob", "sub-bob", picture: null);

        var user = fixture.UserStore.Inner.ById.Values.Single(u => u.Username == "bob");
        Assert.NotNull(user.ProfileImage);
        Assert.True(File.Exists(user.ProfileImage!.Path));
    }

    [Fact]
    public async Task SyncDisabled_LeavesProfileImageUnset()
    {
        var fixture = new TestFixture(_idp);
        var provider = fixture.AddProvider();
        provider.SyncProfileImage = false;
        var avatarUrl = _idp.StubAvatarEndpoint("/avatar-disabled.png");

        await RunFlowWithPicture(fixture, "carol", "sub-carol", avatarUrl);

        var user = fixture.UserStore.Inner.ById.Values.Single(u => u.Username == "carol");
        Assert.Null(user.ProfileImage);
    }

    /// <summary>
    /// A broken avatar host must cost the user their avatar, not their session — the whole point
    /// of the fail-open design in ProfileImageService.
    /// </summary>
    [Fact]
    public async Task UnreachableAvatarHost_DoesNotBreakLogin()
    {
        var fixture = new TestFixture(_idp);
        fixture.AddProvider();

        await RunFlowWithPicture(fixture, "dave", "sub-dave", _idp.Authority.TrimEnd('/') + "/no-such-avatar.png");

        var user = fixture.UserStore.Inner.ById.Values.Single(u => u.Username == "dave");
        Assert.Null(user.ProfileImage);   // no avatar…
        Assert.NotNull(user);             // …but the account was still provisioned and signed in
    }

    private static async Task RunFlowWithPicture(TestFixture fixture, string username, string sub, string? picture)
    {
        var startResult = await fixture.Controller.Start("testidp");
        var redirect = (Microsoft.AspNetCore.Mvc.RedirectResult)startResult;
        var query = System.Web.HttpUtility.ParseQueryString(new System.Uri(redirect.Url).Query);
        var state = query["state"]!;
        var nonce = query["nonce"]!;
        TestFixture.PropagateCookies(fixture.Controller);

        _ = fixture.Idp.EnqueueTokenResponse(sub: sub, username: username, nonce: nonce, picture: picture);

        var callbackResult = await fixture.Controller.Callback(
            "testidp", code: $"code-{System.Guid.NewGuid():N}", state: state);
        var token = TestFixture.ExtractSessionTokenFromHtml(((Microsoft.AspNetCore.Mvc.ContentResult)callbackResult).Content!);

        await fixture.Controller.Authenticate("testidp", new Jellyfin.Plugin.OIDC.Api.AuthenticateRequest
        {
            Token = token,
            DeviceId = "test-dev"
        });
    }
}
