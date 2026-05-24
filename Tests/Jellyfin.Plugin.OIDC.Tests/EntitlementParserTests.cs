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
}
