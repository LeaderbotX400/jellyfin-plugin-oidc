using System;
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

/// <summary>
/// Thrown when the SSO identity resolves to a Jellyfin account that is disabled. Jellyfin itself
/// only refuses disabled accounts on the password path, so the plugin must refuse here.
/// </summary>
public sealed class OidcUserDisabledException : InvalidOperationException
{
    public OidcUserDisabledException(string username)
        : base($"The account '{username}' is disabled.")
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
            // No sub-link yet. Resolution order, most-explicit-first:
            //
            //   Path 1: Admin-pre-authorized user. The admin set the Authentication Provider of
            //           the user with this exact username to "OIDC-Auth" in Jellyfin's standard
            //           user UI, and that user has never been bound to any SSO identity. See
            //           FindAdminPreAuthorizedUserAsync for why both conditions are required.
            //
            //   Path 2: AutoLinkByVerifiedEmail policy (opt-in per provider).
            //
            //   Path 3: AutoCreateUsers — create a fresh local user matching the OIDC identity.
            //
            //   Otherwise: refuse with a clear collision error.
            var ourProviderId = typeof(Auth.OidcAuthProvider).FullName!;
            var preAuthorized = await FindAdminPreAuthorizedUserAsync(ourProviderId, username, providerId).ConfigureAwait(false);
            if (preAuthorized != null)
            {
                user = preAuthorized;
                await _userStore.LinkAsync(user.Id, sub, providerId).ConfigureAwait(false);
                _logger.LogInformation(
                    "Linked OIDC sub={SubRedacted} to user '{Username}' via admin-set AuthenticationProviderId",
                    LogRedaction.RedactSub(sub), user.Username);
            }
            else if (_userManager.GetUserByName(username) is not { } existing)
            {
                if (config.AutoCreateUsers != true)
                {
                    throw new InvalidOperationException(
                        $"User '{username}' does not exist and auto-creation is disabled");
                }

                user = await _userManager.CreateUserAsync(username).ConfigureAwait(false);
                user.AuthenticationProviderId = typeof(Auth.OidcAuthProvider).FullName!;

                // DO NOT touch the local password. Deployments commonly back local password
                // auth with an external store (LDAP, etc.) and treat it as the backup auth
                // method when OIDC is unavailable. AuthenticationProviderId above is the
                // load-bearing protection: Jellyfin routes auth to the provider whose
                // FullName matches that string, so the default password provider is bypassed
                // for OIDC-managed users.

                weCreatedThisUser = true;
                _logger.LogInformation("Created new OIDC user: {Username}", username);

                // CRITICAL: persist the sub→user link immediately so subsequent logins resolve
                // through the link path and never fall back to name lookup.
                await _userStore.LinkAsync(user.Id, sub, providerId).ConfigureAwait(false);
            }
            else
            {
                // Name collision and not admin-pre-authorized. AutoLinkByVerifiedEmail or refuse.
                var provider = FindProvider(providerId);
                user = await AutoLinkByVerifiedEmailAsync(
                    existing, provider, sub, username, providerId, email ?? string.Empty, emailVerified).ConfigureAwait(false);
            }
        }

        // NOTE: We deliberately do NOT clear IsDisabled here. A disabled user must stay disabled
        //       (and is refused below).
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

        if (weCreatedThisUser)
        {
            await _rbacService.LogActivityAsync(
                $"OIDC user provisioned: {username}",
                "OidcUserProvisioned",
                user.Id,
                $"provider={providerId}",
                Microsoft.Extensions.Logging.LogLevel.Information).ConfigureAwait(false);
        }

        // Jellyfin enforces IsDisabled only on its own password path (UserManager.AuthenticateUser).
        // SessionManager.AuthenticateDirect — which every SSO login ends in — and the per-request
        // authorization handler never look at it, so without this check a disabled account keeps
        // signing in through SSO. Checked after RBAC so an entitlement that disables the user
        // takes effect on the login that carries it.
        var current = _userManager.GetUserById(user.Id) ?? user;
        if (current.HasPermission(PermissionKind.IsDisabled))
        {
            throw new OidcUserDisabledException(current.Username);
        }

        return user.Id;
    }

    private async Task<Jellyfin.Database.Implementations.Entities.User> AutoLinkByVerifiedEmailAsync(
        Jellyfin.Database.Implementations.Entities.User existing,
        Configuration.OidcProviderConfig? provider,
        string sub,
        string username,
        string providerId,
        string email,
        bool emailVerified)
    {
        var autoLinkByEmail = provider?.AutoLinkByVerifiedEmail == true;

        if (!autoLinkByEmail)
        {
            _logger.LogWarning(
                "Refusing OIDC auto-bind: local user '{Username}' already exists (provider={Provider}, sub={SubRedacted}). " +
                "To migrate this user, set their Authentication Provider to 'OIDC-Auth' in the Jellyfin admin UI, " +
                "or enable AutoLinkByVerifiedEmail on the provider.",
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

        if (string.IsNullOrEmpty(email)
            || !string.Equals(email, existing.Username, StringComparison.OrdinalIgnoreCase))
        {
            _logger.LogWarning(
                "Refusing OIDC auto-link by email: token email '{EmailRedacted}' does not match existing username",
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

        await _userStore.LinkAsync(existing.Id, sub, providerId).ConfigureAwait(false);
        _logger.LogInformation(
            "Auto-linked OIDC sub={SubRedacted} to existing user '{Username}' via verified email match",
            LogRedaction.RedactSub(sub), username);

        if (provider?.EnforceSsoOnLink == true)
        {
            existing.AuthenticationProviderId = typeof(Auth.OidcAuthProvider).FullName!;
        }
        // else: leave AuthenticationProviderId alone — local password still works.

        return existing;
    }

    /// <summary>
    /// Finds the user (if any) that an admin has pre-authorized for this SSO login: the local user
    /// whose username matches the incoming one, whose Authentication Provider an admin set to
    /// "OIDC-Auth", and who has never been bound to any SSO identity.
    ///
    /// Every condition is load-bearing. The pin alone is not an identity: the plugin pins every
    /// user it creates, so "pinned and not linked on THIS provider" matched every existing SSO user
    /// the moment a second provider (or a SAML provider) existed — and handed their account to
    /// whichever new identity logged in first. Requiring zero links and zero stored records means
    /// only an account that has never had an SSO owner can be claimed, and requiring the username
    /// means it can only be claimed by the identity the admin named. Jellyfin usernames are unique,
    /// so there is at most one candidate.
    /// </summary>
    private async Task<Jellyfin.Database.Implementations.Entities.User?> FindAdminPreAuthorizedUserAsync(
        string ourProviderId, string oidcUsername, string providerId)
    {
        var candidate = _userManager.GetUserByName(oidcUsername);
        if (candidate is null
            || !string.Equals(candidate.AuthenticationProviderId, ourProviderId, StringComparison.Ordinal))
        {
            return null;
        }

        var links = await _userStore.GetLinksForUserAsync(candidate.Id).ConfigureAwait(false);
        var record = await _userStore.GetByUserIdAsync(candidate.Id).ConfigureAwait(false);
        if (links.Count > 0 || record is not null)
        {
            // Already owned by some SSO identity. Never rebind; the caller falls through to the
            // collision path, which refuses.
            _logger.LogWarning(
                "Not treating '{Username}' as pre-authorized for provider {Provider}: that user is already bound to an SSO identity",
                candidate.Username, providerId);
            return null;
        }

        return candidate;
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
