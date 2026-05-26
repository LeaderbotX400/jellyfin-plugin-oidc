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
            //   Path 1: Admin-pre-authorized user. The admin set someone's Authentication
            //           Provider to "OIDC RBAC" in Jellyfin's standard user UI. We find that
            //           user by the AuthProviderId pin — NOT by username — because Jellyfin
            //           usernames are display labels, not identities, and there's no reason
            //           the OIDC preferred_username should match a chosen Jellyfin username.
            //           If exactly one user is pre-marked and unbound, we bind it. If multiple
            //           are pre-marked, we tiebreak by username match (best-effort) and refuse
            //           if still ambiguous.
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

                // Fall through to UpdateUserAsync + Upsert + RBAC apply.
                await _userManager.UpdateUserAsync(user).ConfigureAwait(false);
                await UpsertAndApplyAsync(user, sub, providerId, roles, entitlements).ConfigureAwait(false);
                return user.Id;
            }

            // Fall back to username-based lookup for the remaining paths (create / collision).
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
                "To migrate this user, set their Authentication Provider to 'OIDC RBAC' in the Jellyfin admin UI, " +
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
    /// Finds the user (if any) that an admin has pre-authorized for OIDC login by setting their
    /// Authentication Provider to "OIDC RBAC" in Jellyfin's standard user UI. Identification is
    /// by the AuthProviderId pin alone — Jellyfin usernames are not identities, so we do not
    /// require the OIDC preferred_username to match.
    ///
    /// Resolution:
    ///   - 0 candidates: returns null (caller continues with create/collision logic).
    ///   - 1 candidate: returns that user.
    ///   - N candidates (admin pinned multiple users for OIDC, all still unbound):
    ///       prefer a username match against the incoming OIDC username; on tie or no match,
    ///       refuse with a clear error so the admin can disambiguate.
    /// </summary>
    private async Task<Jellyfin.Database.Implementations.Entities.User?> FindAdminPreAuthorizedUserAsync(
        string ourProviderId, string oidcUsername, string providerId)
    {
        var candidates = new List<Jellyfin.Database.Implementations.Entities.User>();
        foreach (var u in JellyfinCompat.EnumerateUsers(_userManager))
        {
            if (!string.Equals(u.AuthenticationProviderId, ourProviderId, StringComparison.Ordinal)) continue;
            // Already linked to some sub on this provider? Then this candidate "belongs" to that
            // other sub; skip. (Different provider — we'd happily link them on a 2nd provider.)
            var existingLinks = await _userStore.GetLinksForUserAsync(u.Id).ConfigureAwait(false);
            var alreadyLinkedOnThisProvider = false;
            foreach (var l in existingLinks)
            {
                if (string.Equals(l.ProviderId, providerId, StringComparison.OrdinalIgnoreCase))
                {
                    alreadyLinkedOnThisProvider = true;
                    break;
                }
            }
            if (alreadyLinkedOnThisProvider) continue;
            candidates.Add(u);
        }

        if (candidates.Count == 0) return null;
        if (candidates.Count == 1) return candidates[0];

        var byName = candidates.Find(u =>
            string.Equals(u.Username, oidcUsername, StringComparison.OrdinalIgnoreCase));
        if (byName != null) return byName;

        _logger.LogWarning(
            "Multiple admin-pre-authorized OIDC users found and none match OIDC username '{Username}'. " +
            "Refuse to guess; admin should leave only one user pre-marked for OIDC, OR rename one of the candidates to match the OIDC username.",
            oidcUsername);
        throw new OidcUsernameCollisionException(oidcUsername);
    }

    private async Task UpsertAndApplyAsync(
        Jellyfin.Database.Implementations.Entities.User user,
        string sub, string providerId, string[] roles, string[] entitlements)
    {
        await _userStore.UpsertAsync(new OidcUserRecord
        {
            UserId = user.Id,
            Username = user.Username,
            Sub = sub,
            ProviderId = providerId,
            Roles = roles,
            Entitlements = entitlements
        }).ConfigureAwait(false);

        await _rbacService.ApplyRoleMappingsAsync(user.Id, roles, entitlements, providerId).ConfigureAwait(false);
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
