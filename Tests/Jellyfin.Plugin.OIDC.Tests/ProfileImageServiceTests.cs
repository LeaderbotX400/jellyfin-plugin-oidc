using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading;
using System.Threading.Tasks;
using Jellyfin.Database.Implementations.Entities;
using Jellyfin.Plugin.OIDC.Configuration;
using Jellyfin.Plugin.OIDC.Services;
using MediaBrowser.Controller;
using MediaBrowser.Controller.Library;
using MediaBrowser.Controller.Providers;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Xunit;

namespace Jellyfin.Plugin.OIDC.Tests;

/// <summary>
/// Covers <see cref="ProfileImageService"/>. The bulk of these are refusal cases: the picture
/// claim is IdP-supplied and, on IdPs where users edit their own profile, user-controlled, so
/// the interesting behaviour is everything the service declines to fetch or store.
/// </summary>
public sealed class ProfileImageServiceTests : IDisposable
{
    private const string Authority = "https://idp.example.com";
    private const string AvatarUrl = "https://idp.example.com/avatar/alice.png";

    private static readonly byte[] PngBytes =
    {
        0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52
    };

    private static readonly byte[] JpegBytes = { 0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46 };

    private readonly string _tempRoot;
    private readonly OidcUserStore _store;
    private readonly TestConfigProvider _config;
    private readonly Mock<IUserManager> _userManagerMock;
    private readonly Mock<IProviderManager> _providerManagerMock;
    private readonly User _user;

    private StubHandler _handler = new();
    private int _clientsCreated;
    private Func<string, CancellationToken, Task<IPAddress[]>> _resolver =
        (_, _) => Task.FromResult(new[] { IPAddress.Parse("203.0.113.10") });

    public ProfileImageServiceTests()
    {
        _tempRoot = Path.Combine(Path.GetTempPath(), $"oidc-avatar-tests-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempRoot);

        _store = new OidcUserStore(Path.Combine(_tempRoot, "oidc_users.json"));
        _config = new TestConfigProvider();
        _config.Configuration.Providers.Add(new OidcProviderConfig
        {
            ProviderId = "testidp",
            Authority = Authority,
            SyncProfileImage = true
        });

        _user = new User("alice", "OidcAuthProvider", "FakeResetProvider");

        _userManagerMock = new Mock<IUserManager>();
        _userManagerMock.Setup(m => m.GetUserById(It.IsAny<Guid>()))
            .Returns<Guid>(id => id == _user.Id ? _user : null);
        _userManagerMock.Setup(m => m.UpdateUserAsync(It.IsAny<User>())).Returns(Task.CompletedTask);
        _userManagerMock.Setup(m => m.ClearProfileImageAsync(It.IsAny<User>()))
            .Returns<User>(u => { u.ProfileImage = null; return Task.CompletedTask; });

        _providerManagerMock = new Mock<IProviderManager>();
        _providerManagerMock.Setup(m => m.SaveImage(It.IsAny<Stream>(), It.IsAny<string>(), It.IsAny<string>()))
            .Returns<Stream, string, string>(async (source, _, path) =>
            {
                Directory.CreateDirectory(Path.GetDirectoryName(path)!);
                await using var target = File.Create(path);
                await source.CopyToAsync(target);
            });
    }

    public void Dispose()
    {
        _store.Dispose();
        _handler.Dispose();
        try { Directory.Delete(_tempRoot, recursive: true); } catch (IOException) { /* best effort */ }
    }

    private ProfileImageService CreateService() => new(
        _ => { _clientsCreated++; return new HttpClient(_handler); },
        _userManagerMock.Object,
        BuildPaths(),
        _providerManagerMock.Object,
        _store,
        _config,
        NullLogger<ProfileImageService>.Instance,
        dnsResolver: (host, ct) => _resolver(host, ct));

    private IServerApplicationPaths BuildPaths()
    {
        var mock = new Mock<IServerApplicationPaths>();
        mock.SetupGet(m => m.UserConfigurationDirectoryPath).Returns(_tempRoot);
        return mock.Object;
    }

    private OidcProviderConfig Provider => _config.Configuration.Providers[0];

    private Task ApplyAsync(string? url = AvatarUrl) =>
        CreateService().ApplyAsync(_user.Id, url, "testidp", CancellationToken.None);

    private void RespondWith(byte[] body, string mediaType = "image/png", HttpStatusCode status = HttpStatusCode.OK)
    {
        _handler.Dispose();
        _handler = new StubHandler { Body = body, MediaType = mediaType, Status = status };
    }

    // ── Cases where we must never touch the network ─────────────────────────

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public async Task NoPictureClaim_DoesNothing(string? url)
    {
        RespondWith(PngBytes);
        await ApplyAsync(url);

        Assert.Equal(0, _clientsCreated);
        Assert.Null(_user.ProfileImage);
    }

    [Fact]
    public async Task SyncDisabled_DoesNothing()
    {
        Provider.SyncProfileImage = false;
        RespondWith(PngBytes);

        await ApplyAsync();

        Assert.Equal(0, _clientsCreated);
        Assert.Null(_user.ProfileImage);
    }

    [Fact]
    public async Task UnknownProvider_DoesNothing()
    {
        RespondWith(PngBytes);
        await CreateService().ApplyAsync(_user.Id, AvatarUrl, "no-such-provider", CancellationToken.None);

        Assert.Equal(0, _clientsCreated);
    }

    [Fact]
    public async Task SecondLoginWithUnchangedUrl_MakesNoRequest()
    {
        RespondWith(PngBytes);
        await SeedUserRecordAsync();

        await ApplyAsync();
        Assert.Equal(1, _clientsCreated);
        Assert.NotNull(_user.ProfileImage);

        await ApplyAsync();
        Assert.Equal(1, _clientsCreated); // no second fetch
    }

    [Fact]
    public async Task UrlUnchangedButFileDeleted_RefetchesImage()
    {
        RespondWith(PngBytes);
        await SeedUserRecordAsync();

        await ApplyAsync();
        File.Delete(_user.ProfileImage!.Path);

        await ApplyAsync();
        Assert.Equal(2, _clientsCreated);
        Assert.True(File.Exists(_user.ProfileImage!.Path));
    }

    // ── SSRF refusals ───────────────────────────────────────────────────────

    [Fact]
    public async Task PlainHttpUrl_IsRefused()
    {
        RespondWith(PngBytes);
        await ApplyAsync("http://idp.example.com/avatar.png");

        Assert.Equal(0, _clientsCreated);
        Assert.Null(_user.ProfileImage);
    }

    [Fact]
    public async Task HostOutsideAuthorityAndAllowlist_IsRefused()
    {
        RespondWith(PngBytes);
        await ApplyAsync("https://cdn.evil.example/avatar.png");

        Assert.Equal(0, _clientsCreated);
        Assert.Null(_user.ProfileImage);
    }

    [Fact]
    public async Task HostOnAllowlist_IsAccepted()
    {
        Provider.PictureAllowedHosts.Add("lh3.googleusercontent.com");
        RespondWith(PngBytes);
        await SeedUserRecordAsync();

        await ApplyAsync("https://lh3.googleusercontent.com/a/abc123");

        Assert.Equal(1, _clientsCreated);
        Assert.NotNull(_user.ProfileImage);
    }

    [Theory]
    [InlineData("127.0.0.1")]        // loopback
    [InlineData("10.0.0.1")]         // RFC1918
    [InlineData("172.16.5.4")]       // RFC1918
    [InlineData("192.168.1.10")]     // RFC1918
    [InlineData("100.64.0.1")]       // carrier NAT
    [InlineData("::1")]              // IPv6 loopback
    [InlineData("fd00::1")]          // IPv6 unique local
    public async Task UrlResolvingToPrivateAddress_IsRefused(string address)
    {
        _resolver = (_, _) => Task.FromResult(new[] { IPAddress.Parse(address) });
        RespondWith(PngBytes);

        await ApplyAsync();

        Assert.Equal(0, _clientsCreated);
        Assert.Null(_user.ProfileImage);
    }

    /// <summary>
    /// The cloud instance-metadata endpoint is the payoff target for an SSRF like this one:
    /// a hostile picture claim pointing at it would otherwise have the server fetch, and store
    /// as a user's avatar, whatever credentials the metadata service returns.
    /// </summary>
    [Fact]
    public async Task UrlResolvingToCloudMetadataEndpoint_IsRefused()
    {
        _resolver = (_, _) => Task.FromResult(new[] { IPAddress.Parse("169.254.169.254") });
        RespondWith(PngBytes);

        await ApplyAsync();

        Assert.Equal(0, _clientsCreated);
        Assert.Null(_user.ProfileImage);
    }

    /// <summary>
    /// A host answering with one public and one private address is a DNS-rebinding setup, not a
    /// dual-homed service. Any blocked address in the answer must reject the whole fetch.
    /// </summary>
    [Fact]
    public async Task UrlResolvingToMixedPublicAndPrivateAddresses_IsRefused()
    {
        _resolver = (_, _) => Task.FromResult(new[]
        {
            IPAddress.Parse("203.0.113.10"), IPAddress.Parse("169.254.169.254")
        });
        RespondWith(PngBytes);

        await ApplyAsync();

        Assert.Equal(0, _clientsCreated);
        Assert.Null(_user.ProfileImage);
    }

    [Fact]
    public async Task DnsFailure_IsHandledAndDoesNotThrow()
    {
        _resolver = (_, _) => throw new System.Net.Sockets.SocketException(11001);
        RespondWith(PngBytes);

        await ApplyAsync();

        Assert.Null(_user.ProfileImage);
    }

    // ── Response validation ─────────────────────────────────────────────────

    [Fact]
    public async Task NonSuccessStatus_IsSkipped()
    {
        RespondWith(PngBytes, status: HttpStatusCode.NotFound);
        await ApplyAsync();

        Assert.Null(_user.ProfileImage);
    }

    [Theory]
    [InlineData("text/html")]
    [InlineData("application/json")]
    [InlineData("image/svg+xml")]   // active content — must never be stored as an avatar
    public async Task DisallowedContentType_IsSkipped(string mediaType)
    {
        RespondWith(PngBytes, mediaType);
        await ApplyAsync();

        Assert.Null(_user.ProfileImage);
    }

    /// <summary>
    /// Trust the bytes, not the header: a server claiming image/png while sending HTML is either
    /// broken or hostile, and either way must not have its payload written under a .png name.
    /// </summary>
    [Fact]
    public async Task ContentTypeLiesAboutPayload_IsSkipped()
    {
        RespondWith(System.Text.Encoding.UTF8.GetBytes("<!DOCTYPE html><html><body>nope</body></html>"), "image/png");
        await ApplyAsync();

        Assert.Null(_user.ProfileImage);
    }

    [Fact]
    public async Task OversizeBodyWithHonestContentLength_IsSkipped()
    {
        RespondWith(BuildOversizePng());
        await ApplyAsync();

        Assert.Null(_user.ProfileImage);
    }

    /// <summary>
    /// The real cap. A host that omits Content-Length cannot be caught by a header check, so the
    /// read loop has to give up on its own — otherwise an endless response streams straight into
    /// the image writer.
    /// </summary>
    [Fact]
    public async Task OversizeBodyWithNoContentLength_IsAbortedAtTheCap()
    {
        _handler.Dispose();
        _handler = new StubHandler
        {
            Body = BuildOversizePng(),
            MediaType = "image/png",
            SuppressContentLength = true
        };

        await ApplyAsync();

        Assert.Null(_user.ProfileImage);
    }

    /// <summary>
    /// Defence in depth for redirects. The transport-level guard is
    /// <c>AllowAutoRedirect = false</c> in <see cref="ProfileImageService.CreatePinnedClient"/>
    /// (asserted separately in <see cref="PinnedClientTests"/>) — this covers the service's own
    /// half: a 3xx is not a success status, so nothing is fetched or stored even if some future
    /// handler were to hand one back. A redirect target has been through none of our checks.
    /// </summary>
    [Fact]
    public async Task RedirectResponse_IsTreatedAsFailure()
    {
        _handler.Dispose();
        _handler = new StubHandler
        {
            Status = HttpStatusCode.Found,
            RedirectLocation = new Uri("https://idp.example.com/elsewhere.png"),
            Body = Array.Empty<byte>(),
            MediaType = "image/png"
        };

        await ApplyAsync();

        Assert.Equal(1, _handler.RequestCount); // one request, not two
        Assert.Null(_user.ProfileImage);
    }

    [Fact]
    public async Task FetchThrowing_DoesNotPropagate()
    {
        _handler.Dispose();
        _handler = new StubHandler { ThrowOnSend = true };

        await ApplyAsync(); // must not throw

        Assert.Null(_user.ProfileImage);
    }

    // ── Happy paths ─────────────────────────────────────────────────────────

    [Fact]
    public async Task ValidPng_IsStoredAndRecorded()
    {
        RespondWith(PngBytes);
        await SeedUserRecordAsync();

        await ApplyAsync();

        Assert.NotNull(_user.ProfileImage);
        Assert.Equal(Path.Combine(_tempRoot, "alice", "profile.png"), _user.ProfileImage!.Path);
        Assert.True(File.Exists(_user.ProfileImage.Path));
        Assert.Equal(PngBytes, await File.ReadAllBytesAsync(_user.ProfileImage.Path));

        var record = await _store.GetByUserIdAsync(_user.Id);
        Assert.Equal(AvatarUrl, record!.ProfileImageSourceUrl);
        Assert.NotEmpty(record.ProfileImageHash);
    }

    /// <summary>Extension comes from the sniffed bytes, so a JPEG stays a .jpg.</summary>
    [Fact]
    public async Task ExtensionFollowsTheActualFormat()
    {
        RespondWith(JpegBytes, "image/jpeg");
        await SeedUserRecordAsync();

        await ApplyAsync("https://idp.example.com/avatar/alice.jpg");

        Assert.Equal(Path.Combine(_tempRoot, "alice", "profile.jpg"), _user.ProfileImage!.Path);
    }

    /// <summary>
    /// ClearProfileImageAsync only drops the database row. When the format changes the old file
    /// would otherwise be orphaned next to the new one.
    /// </summary>
    [Fact]
    public async Task ChangingFormat_RemovesTheSupersededFile()
    {
        RespondWith(PngBytes);
        await SeedUserRecordAsync();
        await ApplyAsync();
        var pngPath = _user.ProfileImage!.Path;

        RespondWith(JpegBytes, "image/jpeg");
        await ApplyAsync("https://idp.example.com/avatar/alice-v2.jpg");

        Assert.EndsWith("profile.jpg", _user.ProfileImage!.Path, StringComparison.Ordinal);
        Assert.True(File.Exists(_user.ProfileImage.Path));
        Assert.False(File.Exists(pngPath));
    }

    /// <summary>A moved URL serving identical bytes should re-record the URL but not rewrite the file.</summary>
    [Fact]
    public async Task UnchangedBytesAtNewUrl_SkipsTheWrite()
    {
        RespondWith(PngBytes);
        await SeedUserRecordAsync();
        await ApplyAsync();

        _providerManagerMock.Invocations.Clear();
        await ApplyAsync("https://idp.example.com/avatar/alice.png?v=2");

        _providerManagerMock.Verify(
            m => m.SaveImage(It.IsAny<Stream>(), It.IsAny<string>(), It.IsAny<string>()), Times.Never);

        var record = await _store.GetByUserIdAsync(_user.Id);
        Assert.Equal("https://idp.example.com/avatar/alice.png?v=2", record!.ProfileImageSourceUrl);
    }

    [Fact]
    public async Task MissingUser_IsSkipped()
    {
        RespondWith(PngBytes);
        await CreateService().ApplyAsync(Guid.NewGuid(), AvatarUrl, "testidp", CancellationToken.None);

        Assert.Null(_user.ProfileImage);
    }

    // ── Magic-byte sniffing ─────────────────────────────────────────────────

    [Fact]
    public void SniffImageExtension_RecognisesSupportedFormats()
    {
        Assert.Equal(".png", ProfileImageService.SniffImageExtension(PngBytes));
        Assert.Equal(".jpg", ProfileImageService.SniffImageExtension(JpegBytes));
        Assert.Equal(".gif", ProfileImageService.SniffImageExtension("GIF89a"u8.ToArray()));
        Assert.Equal(".webp", ProfileImageService.SniffImageExtension("RIFF\0\0\0\0WEBP"u8.ToArray()));
    }

    [Fact]
    public void SniffImageExtension_ReturnsNullForAnythingElse()
    {
        Assert.Null(ProfileImageService.SniffImageExtension("<!DOCTYPE html>"u8.ToArray()));
        Assert.Null(ProfileImageService.SniffImageExtension("<svg xmlns="u8.ToArray()));
        Assert.Null(ProfileImageService.SniffImageExtension(Array.Empty<byte>()));
        Assert.Null(ProfileImageService.SniffImageExtension(new byte[] { 0xFF, 0xD8 })); // truncated JPEG
    }

    // ── Helpers ─────────────────────────────────────────────────────────────

    /// <summary>
    /// RecordProfileImageAsync only updates an existing record, mirroring RecordSidAsync. In the
    /// real flow SyncUserAsync has already created one by the time avatars are applied.
    /// </summary>
    private Task SeedUserRecordAsync() => _store.UpsertAsync(new OidcUserRecord
    {
        UserId = _user.Id,
        Username = _user.Username,
        Sub = "sub-alice",
        ProviderId = "testidp"
    });

    private static byte[] BuildOversizePng()
    {
        var bytes = new byte[ProfileImageService.MaxProfileImageBytes + 1024];
        PngBytes.CopyTo(bytes, 0);
        return bytes;
    }

    private sealed class TestConfigProvider : IPluginConfigProvider
    {
        public PluginConfiguration Configuration { get; set; } = new();
        public PluginConfiguration GetConfiguration() => Configuration;
        public void SaveConfiguration(PluginConfiguration config) => Configuration = config;
    }

    private sealed class StubHandler : HttpMessageHandler
    {
        public byte[] Body { get; init; } = Array.Empty<byte>();
        public string MediaType { get; init; } = "image/png";
        public HttpStatusCode Status { get; init; } = HttpStatusCode.OK;
        public Uri? RedirectLocation { get; init; }
        public bool SuppressContentLength { get; init; }
        public bool ThrowOnSend { get; init; }
        public int RequestCount { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            RequestCount++;

            if (ThrowOnSend)
            {
                throw new HttpRequestException("simulated transport failure");
            }

            var response = new HttpResponseMessage(Status);

            if (RedirectLocation is not null)
            {
                response.Headers.Location = RedirectLocation;
            }

            // A stream content with unknown length is how a real server omits Content-Length.
            response.Content = SuppressContentLength
                ? new StreamContent(new MemoryStream(Body))
                : new ByteArrayContent(Body);
            response.Content.Headers.ContentType = new MediaTypeHeaderValue(MediaType);
            if (SuppressContentLength)
            {
                response.Content.Headers.ContentLength = null;
            }

            return Task.FromResult(response);
        }
    }
}

/// <summary>
/// Covers the real client factory used in production. The tests above substitute a stub client,
/// so without this the transport-level guards — the short timeout and disabled redirects — would
/// go unasserted entirely.
/// </summary>
public sealed class PinnedClientTests
{
    [Fact]
    public void PinnedClient_HasAShortTimeout()
    {
        using var client = ProfileImageService.CreatePinnedClient(IPAddress.Parse("203.0.113.10"));

        // Well under HttpClient's 100s default: an avatar fetch sits on the login path, so a
        // stalling host must not be able to hold the request open.
        Assert.True(client.Timeout <= TimeSpan.FromSeconds(10), $"timeout was {client.Timeout}");
    }

    [Fact]
    public void PinnedClient_DoesNotFollowRedirects()
    {
        using var client = ProfileImageService.CreatePinnedClient(IPAddress.Parse("203.0.113.10"));

        // The handler is private to the client, so reach it the way the runtime stores it.
        var handlerField = typeof(HttpMessageInvoker)
            .GetField("_handler", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic);
        var handler = Assert.IsType<SocketsHttpHandler>(handlerField!.GetValue(client), exactMatch: false);

        Assert.False(handler.AllowAutoRedirect);
        Assert.NotNull(handler.ConnectCallback); // connection is pinned, not re-resolved
    }
}

/// <summary>Direct coverage of the address blocklist that <see cref="ProfileImageService"/> depends on.</summary>
public sealed class SecurityValidationAddressTests
{
    [Theory]
    [InlineData("127.0.0.1")]
    [InlineData("127.10.20.30")]
    [InlineData("0.0.0.0")]
    [InlineData("10.1.2.3")]
    [InlineData("100.64.1.1")]
    [InlineData("169.254.169.254")]
    [InlineData("172.16.0.1")]
    [InlineData("172.31.255.254")]
    [InlineData("192.168.0.1")]
    [InlineData("192.0.0.1")]
    [InlineData("198.18.0.1")]
    [InlineData("224.0.0.1")]
    [InlineData("255.255.255.255")]
    [InlineData("::1")]
    [InlineData("fe80::1")]
    [InlineData("fd12:3456::1")]
    [InlineData("ff02::1")]
    [InlineData("::ffff:169.254.169.254")]  // IPv4-mapped form of the metadata endpoint
    [InlineData("::ffff:10.0.0.1")]
    public void BlockedRanges(string address)
        => Assert.True(SecurityValidation.IsBlockedAddress(IPAddress.Parse(address)), address);

    [Theory]
    [InlineData("8.8.8.8")]
    [InlineData("203.0.113.10")]
    [InlineData("172.32.0.1")]      // just outside 172.16/12
    [InlineData("172.15.255.255")]  // just outside 172.16/12
    [InlineData("100.63.255.255")]  // just outside 100.64/10
    [InlineData("100.128.0.1")]     // just outside 100.64/10
    [InlineData("169.253.0.1")]     // just outside link-local
    [InlineData("2606:4700:4700::1111")]
    public void AllowedRanges(string address)
        => Assert.False(SecurityValidation.IsBlockedAddress(IPAddress.Parse(address)), address);

    [Fact]
    public async Task ResolveAndValidateAsync_ReturnsTheAddressToPinTo()
    {
        var expected = IPAddress.Parse("203.0.113.10");
        var actual = await SecurityValidation.ResolveAndValidateAsync(
            new Uri("https://cdn.example.com/a.png"), (_, _) => Task.FromResult(new[] { expected }));

        Assert.Equal(expected, actual);
    }

    [Fact]
    public async Task ResolveAndValidateAsync_ThrowsWhenNoAddressesReturned()
    {
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            SecurityValidation.ResolveAndValidateAsync(
                new Uri("https://cdn.example.com/a.png"), (_, _) => Task.FromResult(Array.Empty<IPAddress>())));
    }

    [Fact]
    public async Task ResolveAndValidateAsync_ThrowsWhenAnyAddressIsBlocked()
    {
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            SecurityValidation.ResolveAndValidateAsync(
                new Uri("https://cdn.example.com/a.png"),
                (_, _) => Task.FromResult(new[]
                {
                    IPAddress.Parse("203.0.113.10"), IPAddress.Parse("127.0.0.1")
                })));
    }
}

/// <summary>Save-time validation of the avatar host allowlist.</summary>
public sealed class PictureAllowedHostsValidationTests
{
    private static OidcProviderConfig ProviderWith(params string[] hosts)
    {
        var p = new OidcProviderConfig
        {
            ProviderId = "p1",
            Authority = "https://idp.example.com"
        };
        p.PictureAllowedHosts.AddRange(hosts);
        return p;
    }

    [Theory]
    [InlineData("lh3.googleusercontent.com")]
    [InlineData("graph.microsoft.com")]
    [InlineData("cdn.example.co.uk")]
    [InlineData("203.0.113.10")]
    public void ValidHostnames_AreAccepted(string host)
        => ProviderConfigValidator.ValidateOrThrow(ProviderWith(host));

    [Theory]
    [InlineData("https://cdn.example.com")]  // scheme
    [InlineData("cdn.example.com/avatars")]  // path
    [InlineData("cdn.example.com:8443")]     // port
    [InlineData("*.example.com")]            // wildcard
    [InlineData("cdn example com")]          // spaces
    [InlineData("")]                         // blank row
    [InlineData("   ")]
    public void MalformedEntries_AreRejectedAtSaveTime(string host)
        => Assert.Throws<InvalidOperationException>(() =>
            ProviderConfigValidator.ValidateOrThrow(ProviderWith(host)));

    [Fact]
    public void EmptyList_IsFine()
        => ProviderConfigValidator.ValidateOrThrow(ProviderWith());
}
