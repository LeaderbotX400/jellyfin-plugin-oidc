using System;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Jellyfin.Data;
using Jellyfin.Database.Implementations.Enums;
using MediaBrowser.Controller.Library;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.OIDC.Services;

public class UserSyncService
{
    private readonly IUserManager _userManager;
    private readonly RbacService _rbacService;
    private readonly OidcUserStore _userStore;
    private readonly IPluginConfigProvider _configProvider;
    private readonly ILogger<UserSyncService> _logger;

    public UserSyncService(
        IUserManager userManager,
        RbacService rbacService,
        OidcUserStore userStore,
        IPluginConfigProvider configProvider,
        ILogger<UserSyncService> logger)
    {
        _userManager = userManager;
        _rbacService = rbacService;
        _userStore = userStore;
        _configProvider = configProvider;
        _logger = logger;
    }

    public async Task<Guid> SyncUserAsync(
        string username,
        string? displayName,
        string sub,
        string[] roles,
        string[] entitlements,
        string providerId)
    {
        // C.2 — check account links before username lookup
        var linkedUserId = await _userStore.GetLinkedUserIdAsync(sub, providerId).ConfigureAwait(false);
        var user = linkedUserId.HasValue
            ? _userManager.GetUserById(linkedUserId.Value)
            : _userManager.GetUserByName(username);

        if (user == null)
        {
            if (_configProvider.GetConfiguration().AutoCreateUsers != true)
            {
                throw new InvalidOperationException(
                    $"User '{username}' does not exist and auto-creation is disabled");
            }

            user = await _userManager.CreateUserAsync(username).ConfigureAwait(false);
            user.AuthenticationProviderId = typeof(Auth.OidcAuthProvider).FullName!;

            var randomPassword = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
            await _userManager.ChangePassword(user, randomPassword).ConfigureAwait(false);

            _logger.LogInformation("Created new OIDC user: {Username}", username);
        }
        else
        {
            // Enforce SSO as the only auth path so RBAC cannot be bypassed via local password
            user.AuthenticationProviderId = typeof(Auth.OidcAuthProvider).FullName!;
        }

        user.SetPermission(PermissionKind.IsDisabled, false);
        await _userManager.UpdateUserAsync(user).ConfigureAwait(false);

        await _userStore.UpsertAsync(new OidcUserRecord
        {
            UserId = user.Id,
            Username = username,
            Sub = sub,
            ProviderId = providerId,
            Roles = roles,
            Entitlements = entitlements
        }).ConfigureAwait(false);

        await _rbacService.ApplyRoleMappingsAsync(user.Id, roles, entitlements, providerId).ConfigureAwait(false);

        return user.Id;
    }
}
