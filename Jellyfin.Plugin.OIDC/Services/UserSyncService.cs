using System;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Jellyfin.Data;
using Jellyfin.Database.Implementations.Enums;
using MediaBrowser.Controller.Library;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.OIDC.Services;

/// <summary>
/// Thrown when an incoming OIDC identity has no existing <c>sub</c>→user link, but the
/// supplied username collides with an existing local Jellyfin user and policy forbids
/// auto-binding. The user must ask an admin to link the account manually, or change
/// their IdP username. This is a security boundary — see task-04 (account takeover via
/// preferred_username collision).
/// </summary>
public sealed class OidcUsernameCollisionException : InvalidOperationException
{
    public OidcUsernameCollisionException(string username)
        : base($"Local user '{username}' already exists. An administrator must link this OIDC identity to the existing account, or change your IdP username.")
    {
        Username = username;
    }

    public string Username { get; }
}

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

    public Task<Guid> SyncUserAsync(
        string username,
        string? displayName,
        string sub,
        string[] roles,
        string[] entitlements,
        string providerId)
        => SyncUserAsync(username, displayName, sub, roles, entitlements, providerId, email: null, emailVerified: false);

    public async Task<Guid> SyncUserAsync(
        string username,
        string? displayName,
        string sub,
        string[] roles,
        string[] entitlements,
        string providerId,
        string? email,
        bool emailVerified)
    {
        var config = _configProvider.GetConfiguration();

        // 1) sub-link is the only auto-bind path.
        var linkedUserId = await _userStore.GetLinkedUserIdAsync(sub, providerId).ConfigureAwait(false);

        Jellyfin.Database.Implementations.Entities.User? user = null;
        bool weCreatedThisUser = false;

        if (linkedUserId.HasValue)
        {
            user = _userManager.GetUserById(linkedUserId.Value);
            if (user == null)
            {
                // Stale link — the underlying user was deleted. Refuse rather than silently rebind.
                throw new InvalidOperationException(
                    $"OIDC link for sub '{sub}' references a Jellyfin user that no longer exists. Please re-link from the admin UI.");
            }
        }
        else
        {
            // No link. Look up by name only to detect collisions; we will NOT auto-bind to a local user
            // unless the opt-in AutoLinkByVerifiedEmail policy allows it.
            var existing = _userManager.GetUserByName(username);

            if (existing == null)
            {
                if (config.AutoCreateUsers != true)
                {
                    throw new InvalidOperationException(
                        $"User '{username}' does not exist and auto-creation is disabled");
                }

                user = await _userManager.CreateUserAsync(username).ConfigureAwait(false);
                user.AuthenticationProviderId = typeof(Auth.OidcAuthProvider).FullName!;

                // Defense in depth: scramble the local password so the user can't be auth'd
                // via the default password provider if AuthenticationProviderId ever gets
                // cleared. The setter signature has varied across Jellyfin point releases
                // (sometimes ChangePassword, sometimes ChangePasswordAsync, sometimes both),
                // so we resolve via reflection and skip silently when nothing matches —
                // AuthenticationProviderId above is the load-bearing protection.
                var randomPassword = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
                await TryScrambleLocalPasswordAsync(user, randomPassword).ConfigureAwait(false);

                weCreatedThisUser = true;
                _logger.LogInformation("Created new OIDC user: {Username}", username);

                // CRITICAL: persist the sub→user link immediately so subsequent logins resolve
                // through the link path and never fall back to name lookup.
                await _userStore.LinkAsync(user.Id, sub, providerId).ConfigureAwait(false);
            }
            else
            {
                // Name collision. Auto-link only if explicitly allowed AND verified-email matches.
                var provider = FindProvider(providerId);
                var autoLinkByEmail = provider?.AutoLinkByVerifiedEmail == true;

                if (!autoLinkByEmail)
                {
                    _logger.LogWarning(
                        "Refusing OIDC auto-bind: local user '{Username}' already exists (provider={Provider}, sub={SubRedacted})",
                        username, providerId, LogRedaction.RedactSub(sub));
                    throw new OidcUsernameCollisionException(username);
                }

                if (!emailVerified)
                {
                    _logger.LogWarning(
                        "Refusing OIDC auto-link by email: email_verified is not true (provider={Provider}, sub={SubRedacted})",
                        providerId, LogRedaction.RedactSub(sub));
                    throw new OidcUsernameCollisionException(username);
                }

                if (string.IsNullOrEmpty(email) ||
                    !string.Equals(email, existing.Username, StringComparison.OrdinalIgnoreCase))
                {
                    _logger.LogWarning(
                        "Refusing OIDC auto-link by email: token email domain '{EmailDomain}' does not match existing username",
                        LogRedaction.RedactEmail(email));
                    throw new OidcUsernameCollisionException(username);
                }

                // The existing user must never have been converted to another provider.
                var currentProvider = existing.AuthenticationProviderId;
                var defaultProvider = "Jellyfin.Server.Implementations.Users.DefaultAuthenticationProvider";
                var isUnset = string.IsNullOrEmpty(currentProvider)
                              || string.Equals(currentProvider, defaultProvider, StringComparison.Ordinal);
                if (!isUnset)
                {
                    _logger.LogWarning(
                        "Refusing OIDC auto-link by email: existing user already bound to provider '{Provider}'",
                        currentProvider);
                    throw new OidcUsernameCollisionException(username);
                }

                user = existing;
                await _userStore.LinkAsync(user.Id, sub, providerId).ConfigureAwait(false);
                _logger.LogInformation(
                    "Auto-linked OIDC sub={SubRedacted} to existing user '{Username}' via verified email match",
                    LogRedaction.RedactSub(sub), username);

                if (provider?.EnforceSsoOnLink == true)
                {
                    user.AuthenticationProviderId = typeof(Auth.OidcAuthProvider).FullName!;
                }
                // else: leave AuthenticationProviderId alone — local password still works.
            }
        }

        // NOTE: We deliberately do NOT touch IsDisabled here. A disabled user must stay disabled.
        // NOTE: We deliberately do NOT overwrite AuthenticationProviderId for users we didn't create
        //       (handled above only on the create / EnforceSsoOnLink paths).

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

        _ = weCreatedThisUser; // currently informational; kept for future audit hooks
        return user.Id;
    }

    private async Task TryScrambleLocalPasswordAsync(Jellyfin.Database.Implementations.Entities.User user, string newPassword)
    {
        var type = _userManager.GetType();
        foreach (var name in new[] { "ChangePasswordAsync", "ChangePassword" })
        {
            var method = type.GetMethod(name, new[] { user.GetType(), typeof(string) });
            if (method == null) continue;
            try
            {
                var result = method.Invoke(_userManager, new object[] { user, newPassword });
                if (result is Task task)
                {
                    await task.ConfigureAwait(false);
                }
                return;
            }
            catch (System.Reflection.TargetInvocationException ex)
            {
                _logger.LogDebug(ex.InnerException ?? ex, "Local-password scramble via {Method} threw; relying on AuthenticationProviderId for isolation", name);
                return;
            }
        }

        _logger.LogDebug("No compatible ChangePassword method on IUserManager; relying on AuthenticationProviderId for isolation");
    }

    private Configuration.OidcProviderConfig? FindProvider(string providerId)
    {
        var cfg = _configProvider.GetConfiguration();
        foreach (var p in cfg.Providers)
        {
            if (string.Equals(p.ProviderId, providerId, StringComparison.OrdinalIgnoreCase))
            {
                return p;
            }
        }

        return null;
    }
}
