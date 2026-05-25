using Jellyfin.Plugin.OIDC.Services;
using Xunit;

namespace Jellyfin.Plugin.OIDC.Tests;

public class EntitlementParserTests
{
    [Fact]
    public void Parse_AdminEntitlement_SetsIsAdmin()
    {
        var set = EntitlementParser.Parse(["jellyfin:admin"], "jellyfin:");
        Assert.True(set.IsAdmin);
        Assert.True(set.HasAny);
    }

    [Fact]
    public void Parse_SyncPlayHost_SetsBothFlags()
    {
        var set = EntitlementParser.Parse(["jellyfin:syncplay:host"], "jellyfin:");
        Assert.True(set.EnableSyncplay);
        Assert.True(set.EnableSyncplayGroupCreation);
    }

    [Fact]
    public void Parse_SyncPlayJoin_SetsJoinOnly()
    {
        var set = EntitlementParser.Parse(["jellyfin:syncplay"], "jellyfin:");
        Assert.True(set.EnableSyncplay);
        Assert.False(set.EnableSyncplayGroupCreation);
    }

    [Fact]
    public void Parse_LibraryAll_SetsEnableAllLibraries()
    {
        var set = EntitlementParser.Parse(["jellyfin:library:all"], "jellyfin:");
        Assert.True(set.EnableAllLibraries);
        Assert.Empty(set.LibraryNames);
    }

    [Fact]
    public void Parse_SpecificLibrary_AddsToLibraryNames()
    {
        var set = EntitlementParser.Parse(["jellyfin:library:Movies", "jellyfin:library:TV Shows"], "jellyfin:");
        Assert.Contains("Movies", set.LibraryNames);
        Assert.Contains("TV Shows", set.LibraryNames);
        Assert.False(set.EnableAllLibraries);
    }

    [Fact]
    public void Parse_ParentalRating_SetsMaxRating()
    {
        var set = EntitlementParser.Parse(["jellyfin:rating:13"], "jellyfin:");
        Assert.Equal(13, set.MaxParentalRating);
    }

    [Fact]
    public void Parse_MultipleRatings_TakesMostPermissive()
    {
        var set = EntitlementParser.Parse(["jellyfin:rating:13", "jellyfin:rating:17"], "jellyfin:");
        Assert.Equal(17, set.MaxParentalRating);
    }

    [Fact]
    public void Parse_LiveTvManage_SetsBothLiveTvFlags()
    {
        var set = EntitlementParser.Parse(["jellyfin:livetv:manage"], "jellyfin:");
        Assert.True(set.EnableLiveTv);
        Assert.True(set.EnableLiveTvManagement);
    }

    [Fact]
    public void Parse_UnknownPrefix_IsIgnored()
    {
        var set = EntitlementParser.Parse(["other:admin", "different:library:Movies"], "jellyfin:");
        Assert.False(set.HasAny);
        Assert.False(set.IsAdmin);
    }

    [Fact]
    public void Parse_EmptyArray_ReturnsEmptySet()
    {
        var set = EntitlementParser.Parse([], "jellyfin:");
        Assert.False(set.HasAny);
    }

    [Fact]
    public void Parse_CustomPrefix_Works()
    {
        var set = EntitlementParser.Parse(["myapp:admin"], "myapp:");
        Assert.True(set.IsAdmin);
        Assert.True(set.HasAny);
    }

    [Theory]
    [InlineData("jellyfin:rating:unlimited")]
    [InlineData("jellyfin:rating:none")]
    [InlineData("jellyfin:rating:max")]
    public void Parse_RatingUnlimited_SetsClearFlag(string token)
    {
        var set = EntitlementParser.Parse([token], "jellyfin:");
        Assert.True(set.ClearMaxParentalRating);
        Assert.Null(set.MaxParentalRating);
        Assert.True(set.HasAny);
    }

    [Fact]
    public void Parse_RatingUnlimited_OverridesNumericRating()
    {
        var set = EntitlementParser.Parse(["jellyfin:rating:13", "jellyfin:rating:unlimited"], "jellyfin:");
        Assert.True(set.ClearMaxParentalRating);
        // numeric still recorded so MaxParentalRating reflects what was claimed; downstream prefers Clear
        Assert.Equal(13, set.MaxParentalRating);
    }

    [Fact]
    public void Parse_AllPermissions_AreParsed()
    {
        var entitlements = new[]
        {
            "jellyfin:admin",
            "jellyfin:playback",
            "jellyfin:remote",
            "jellyfin:transcoding",
            "jellyfin:livetv",
            "jellyfin:content:delete",
            "jellyfin:collection:manage",
            "jellyfin:subtitle:manage",
            "jellyfin:download",
        };
        var set = EntitlementParser.Parse(entitlements, "jellyfin:");
        Assert.True(set.IsAdmin);
        Assert.True(set.EnableMediaPlayback);
        Assert.True(set.EnableRemoteAccess);
        Assert.True(set.EnableTranscoding);
        Assert.True(set.EnableLiveTv);
        Assert.True(set.EnableContentDeletion);
        Assert.True(set.EnableCollectionManagement);
        Assert.True(set.EnableSubtitleManagement);
        Assert.True(set.EnableDownload);
    }

    [Fact]
    public void Parse_BitrateNumeric_HighestWins()
    {
        var set = EntitlementParser.Parse(["jellyfin:bitrate:5000", "jellyfin:bitrate:10000"], "jellyfin:");
        Assert.Equal(10000, set.RemoteClientBitrateLimit);
        Assert.False(set.ClearRemoteClientBitrateLimit);
    }

    [Fact]
    public void Parse_BitrateUnlimited_SetsClearFlag()
    {
        var set = EntitlementParser.Parse(["jellyfin:bitrate:unlimited"], "jellyfin:");
        Assert.True(set.ClearRemoteClientBitrateLimit);
    }

    [Fact]
    public void Parse_SessionsUnlimited_MapsToZero()
    {
        // Jellyfin convention: MaxActiveSessions=0 means unlimited.
        var set = EntitlementParser.Parse(["jellyfin:sessions:unlimited"], "jellyfin:");
        Assert.Equal(0, set.MaxActiveSessions);
    }

    [Fact]
    public void Parse_SessionsNumeric_HighestWinsUnlessUnlimited()
    {
        var set = EntitlementParser.Parse(
            ["jellyfin:sessions:3", "jellyfin:sessions:5", "jellyfin:sessions:unlimited"],
            "jellyfin:");
        Assert.Equal(0, set.MaxActiveSessions);  // unlimited trumps numeric
    }

    [Fact]
    public void Parse_LoginAttempts_NumericAndUnlimited()
    {
        var set = EntitlementParser.Parse(["jellyfin:login-attempts:10"], "jellyfin:");
        Assert.Equal(10, set.LoginAttemptsBeforeLockout);
        Assert.False(set.ClearLoginAttemptsBeforeLockout);

        var set2 = EntitlementParser.Parse(["jellyfin:login-attempts:unlimited"], "jellyfin:");
        Assert.True(set2.ClearLoginAttemptsBeforeLockout);
    }

    [Fact]
    public void Parse_RatingSub_IndependentFromRating()
    {
        var set = EntitlementParser.Parse(["jellyfin:rating:13", "jellyfin:rating:sub:7"], "jellyfin:");
        Assert.Equal(13, set.MaxParentalRating);
        Assert.Equal(7, set.MaxParentalRatingSub);
    }

    [Fact]
    public void Parse_ExpandedVocabulary_AreParsed()
    {
        var entitlements = new[]
        {
            "jellyfin:disabled",
            "jellyfin:hidden",
            "jellyfin:transcoding:sync",
            "jellyfin:transcoding:force-remote",
            "jellyfin:remux",
            "jellyfin:conversion",
            "jellyfin:lyric:manage",
            "jellyfin:channels:all",
            "jellyfin:devices:all",
            "jellyfin:devices:shared-control",
            "jellyfin:remote-control",
            "jellyfin:public-sharing",
        };
        var set = EntitlementParser.Parse(entitlements, "jellyfin:");
        Assert.True(set.IsDisabled);
        Assert.True(set.IsHidden);
        Assert.True(set.EnableSyncTranscoding);
        Assert.True(set.ForceRemoteSourceTranscoding);
        Assert.True(set.EnablePlaybackRemuxing);
        Assert.True(set.EnableMediaConversion);
        Assert.True(set.EnableLyricManagement);
        Assert.True(set.EnableAllChannels);
        Assert.True(set.EnableAllDevices);
        Assert.True(set.EnableSharedDeviceControl);
        Assert.True(set.EnableRemoteControlOfOtherUsers);
        Assert.True(set.EnablePublicSharing);
    }
}
