using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Jellyfin.Database.Implementations.Entities;
using Jellyfin.Database.Implementations.Enums;
using Jellyfin.Plugin.OIDC.Services;
using MediaBrowser.Controller.Authentication;
using MediaBrowser.Controller.Library;
using MediaBrowser.Controller.Session;
using MediaBrowser.Model.Activity;
using MediaBrowser.Model.Entities;
using Moq;

namespace Jellyfin.Plugin.OIDC.Integration.Tests;

/// <summary>
/// In-memory store of users keyed by id + username. Single source of truth for the fake user manager.
/// </summary>
public sealed class FakeUserStore
{
    public ConcurrentDictionary<Guid, User> ById { get; } = new();
    public ConcurrentDictionary<string, Guid> ByName { get; } = new(StringComparer.OrdinalIgnoreCase);

    public User CreateUser(string name)
    {
        var user = new User(name, "FakeAuthProvider", "FakeResetProvider");
        ById[user.Id] = user;
        ByName[name] = user.Id;
        return user;
    }
}

/// <summary>Builds Moq-backed Jellyfin service doubles wired to a shared in-memory user store.</summary>
public static class FakeJellyfinFactory
{
    public static Mock<IUserManager> CreateUserManager(FakeUserStore store)
    {
        var mock = new Mock<IUserManager>();

        mock.Setup(m => m.GetUserById(It.IsAny<Guid>()))
            .Returns<Guid>(id => store.ById.TryGetValue(id, out var u) ? u : null);

        mock.Setup(m => m.GetUserByName(It.IsAny<string>()))
            .Returns<string>(name => store.ByName.TryGetValue(name, out var id) ? store.ById[id] : null);

        mock.Setup(m => m.CreateUserAsync(It.IsAny<string>()))
            .Returns<string>(name => Task.FromResult(store.CreateUser(name)));

        mock.Setup(m => m.UpdateUserAsync(It.IsAny<User>()))
            .Returns<User>(u => { store.ById[u.Id] = u; return Task.CompletedTask; });

        mock.Setup(m => m.ChangePassword(It.IsAny<User>(), It.IsAny<string>()))
            .Returns(Task.CompletedTask);

        // Users property — needed by last-admin lockout check in RbacService
        mock.Setup(m => m.Users)
            .Returns(() => store.ById.Values.AsQueryable());

        return mock;
    }

    public static Mock<ISessionManager> CreateSessionManager()
    {
        var mock = new Mock<ISessionManager>();
        mock.Setup(m => m.AuthenticateDirect(It.IsAny<AuthenticationRequest>()))
            .Returns<AuthenticationRequest>(req => Task.FromResult(new AuthenticationResult
            {
                AccessToken = "fake-access-token-" + req.UserId.ToString("N").Substring(0, 8),
                ServerId = "test-server",
                User = new MediaBrowser.Model.Dto.UserDto
                {
                    Id = req.UserId,
                    Name = "test-user"
                }
            }));
        return mock;
    }

    public static Mock<ILibraryManager> CreateLibraryManager()
    {
        var mock = new Mock<ILibraryManager>();
        mock.Setup(m => m.GetVirtualFolders())
            .Returns(new List<VirtualFolderInfo>());
        return mock;
    }

    public static Mock<IActivityManager> CreateActivityManager()
    {
        var mock = new Mock<IActivityManager>();
        mock.Setup(m => m.CreateAsync(It.IsAny<Jellyfin.Database.Implementations.Entities.ActivityLog>()))
            .Returns(Task.CompletedTask);
        return mock;
    }
}

/// <summary>Real <see cref="IHttpClientFactory"/> that hands out fresh <see cref="HttpClient"/> instances. Used so the OIDC flow can actually call the WireMock IdP over HTTP.</summary>
public sealed class FakeHttpClientFactory : IHttpClientFactory
{
    public HttpClient CreateClient(string name) => new(new HttpClientHandler());
}

/// <summary>Mutable <see cref="IPluginConfigProvider"/> so tests can swap configuration mid-run.</summary>
public sealed class TestPluginConfigProvider : IPluginConfigProvider
{
    public Configuration.PluginConfiguration Configuration { get; set; } = new();
    public Configuration.PluginConfiguration GetConfiguration() => Configuration;
}
