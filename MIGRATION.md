# Migration Notes

## v1.0.0 — Jellyfin 12

### What changed

Plugin 1.0.x targets **Jellyfin 12.0 and newer only**. Jellyfin 12 retargeted the server to
.NET 10, so the plugin is now built for `net10.0` against `Jellyfin.Controller` 12.0.0 and
declares `targetAbi 12.0.0.0`. It will not load on Jellyfin 10.10 or 10.11.

**If you run Jellyfin 10.10/10.11:** stay on plugin **0.3.3**, the last release for that line. The published manifest still
carries that entry, and Jellyfin's installer picks the newest version whose `targetAbi` your
server satisfies — so a 10.x server will simply keep being offered 0.3.3 and will not be
upgraded to 1.0.x by accident.

Your existing plugin configuration carries over untouched and no config migration runs. The
OIDC/SAML login flows, RBAC, entitlements and back-channel logout are unchanged by the retarget
itself.

This release does add four features, two of which change behaviour on upgrade without you
configuring anything — read the next two sections before upgrading:

- **Profile pictures** sync from the `picture` claim, **on by default**.
- **Login buttons** are injected into the web UI automatically, **on by default**.
- **Require SSO** (disable password login) — off by default, opt-in.
- **Quick Connect bridge** for signing in native apps — no setting; it follows Jellyfin's own
  Quick Connect switch.

It also fixes a bug that stopped SSO login working entirely on servers reached over plain HTTP
at a non-localhost address — a common LAN setup — where the login hung on
"Completing authentication...". And account **Link/Unlink** were silently broken: they always
answered "Could not determine current user", because the plugin read the wrong identity claim.

### Profile pictures from the `picture` claim

The Jellyfin avatar is now synced from the OIDC `picture` claim, and this is **on by
default** for every provider. On the first login after upgrading, a user whose IdP
publishes a `picture` claim will have their Jellyfin avatar replaced by the IdP's.

**If your users manage their own Jellyfin avatars, turn this off before upgrading**
— uncheck *Sync profile picture* on each provider (`SyncProfileImage: false`).

Two things may need configuration:

- **Avatar Allowed Hosts.** The server will only fetch avatars from the provider's
  Authority origin unless you list additional hosts. Google (`lh3.googleusercontent.com`)
  and Entra ID (`graph.microsoft.com`) serve avatars off a separate host and will be
  refused — with a Warning in the log naming the host — until you add them. Self-hosted
  Authentik and Keycloak serve avatars from their own origin and need nothing.
- **Scopes.** The `picture` claim usually requires the `profile` scope, which is in the
  default scope list already.

A failed or refused avatar fetch never affects the login itself.

### Login buttons are now injected automatically

The SSO buttons are added to the login page by the plugin itself, so the `<script>` tag
you previously pasted into **Dashboard > General > Branding** is no longer needed. Leaving
it in place is harmless — the injected script is idempotent and will not add a second set of
buttons — but you can remove it. To go back to doing it by hand, turn off
*Auto-inject login buttons* in the plugin's General settings.

### Server API changes absorbed by this release

For anyone maintaining a fork, these are the Jellyfin 12 breaking changes that actually touched
this plugin:

- `IAuthenticationProvider.HasPassword(User)` was removed from the interface. The implementation
  in `Auth/OidcAuthProvider.cs` was deleted.
- `IUserManager.Users` / `UsersIds` properties became `GetUsers()` / `GetUsersIds()` methods.
  Production code was already routed through `Services/JellyfinCompat.EnumerateUsers`, which
  tries the property and then the method, so no production change was needed — only the test
  fakes.
- `IUserManager.ChangePassword`, `ResetPassword` and `RenameUser` now take a `Guid` instead of a
  `User`. This plugin never called them; only the test fakes needed updating.

Everything else the plugin uses — `ISessionManager.AuthenticateDirect`, `IPluginServiceRegistrator`,
`IHasWebPages`, `BasePlugin<>`, the `User` entity, `PermissionKind`, and the `Jellyfin.Data`
permission extensions — is unchanged. Jellyfin 12's large EF Core/database rewrite does not affect
this plugin, which never touches `DbContext` and keeps its own state in `oidc_users.json`.

### Before upgrading the server to Jellyfin 12

Two items from Jellyfin's own 12.0 release guidance that matter here:

1. **Remove non-built-in plugins before migrating, and reinstall afterwards.** Remove OIDC-Auth
   before the server upgrade, then install 1.0.x once the server is on 12.0. Plugin
   configuration lives outside the plugin directory and survives this.
2. **Fix usernames that differ only by case first.** Jellyfin 12 stores usernames in a
   normalized, uniquely-indexed column, and a pair like `Alice` / `alice` will block the server
   migration. This plugin auto-provisions users from the IdP `preferred_username` claim, so
   auto-created accounts are squarely in scope — audit Dashboard → Users before upgrading.


## v0.1.3 — Deny-mapping default-permission fix

### What changed

`EnableMediaPlayback`, `EnableRemoteAccess`, and `EnableTranscoding` on `RoleMapping` are now
`bool?` (nullable boolean) instead of `bool`.

**Before (v0.1.2 and earlier):** These fields defaulted to `true` on every new `RoleMapping`,
including deny mappings. An admin who created a deny mapping to strip, say, administrator
privileges would also inadvertently strip playback, remote access, and transcoding from every
matched user — because those fields were silently `true` on the deny mapping.

**After (v0.1.3):** The semantics are:

| Context | Field value | Meaning |
|---------|-------------|---------|
| Allow mapping | `null` | Default true — behaves as before (backward compatible) |
| Allow mapping | `true` | Explicitly granted |
| Allow mapping | `false` | Not granted by this mapping |
| Deny mapping | `null` | **No-op — this deny rule does not touch this permission** |
| Deny mapping | `true` | Explicitly stripped after grants are applied |
| Deny mapping | `false` | No-op (same as null for deny path) |

### Automatic migration on first load

On first startup after upgrading to v0.1.3, the plugin inspects every deny mapping in the
saved configuration. For each deny mapping that has `EnableMediaPlayback`, `EnableRemoteAccess`,
or `EnableTranscoding` set to `true` **and** has not already been migrated (checked via the
new `MigratedDenyDefaults` sentinel field), the plugin:

1. Clears those three fields to `null`.
2. Sets `MigratedDenyDefaults = true` on that mapping to prevent the migration from running
   again on subsequent loads.
3. Logs a **warning** identifying the affected deny mapping by role name.

### Action required after upgrade

After upgrading, check the Jellyfin server log for warnings like:

```
WARN  Jellyfin.Plugin.OIDC.OidcPlugin OIDC-Auth migration (v0.1.3): deny mapping 'my-deny-role'
      had legacy default-true values for EnableMediaPlayback / EnableRemoteAccess / EnableTranscoding.
      These have been cleared to null (no-op for deny). Please review your deny mappings in the
      admin UI and explicitly enable the permissions you want this deny rule to strip.
```

If you see this warning, open the plugin admin UI → Role Mappings, find the affected deny
mapping, and check the permissions you actually want that deny rule to strip. Save the
configuration. After saving, the `MigratedDenyDefaults` sentinel ensures the migration will
not clear your explicit choices again.

### Admin UI changes

- Deny mappings now show a hint explaining that only checked permissions are stripped.
- The three formerly-default-true checkboxes (Playback, Remote Access, Transcoding) now render
  as **unchecked** for deny mappings where they have not been explicitly set — matching the new
  semantics.
- Toggling "Explicit Deny" on an existing mapping still clears all permission checkboxes
  (existing behaviour), preventing accidental strip-all on conversion.
- New role mappings use `null` for the three fields, rendering correctly as checked for allow
  mappings and unchecked for deny mappings.

### No action needed for allow mappings

Allow mappings are unaffected. `null` on an allow mapping is treated as `true` (default
playback/remote/transcoding granted), preserving all existing allow behaviour.

---

# Migrating Existing Jellyfin Users to OIDC

If you already have Jellyfin users with watch history, favorites, playlists, etc., you can move them onto OIDC-Auth without losing data — as long as the OIDC username matches the existing Jellyfin username.

## How it works

When a user completes SSO for the first time, the plugin (`UserSyncService.SyncUserAsync`) calls `_userManager.GetUserByName(username)` using the value of the configured **Username Claim** (default: `preferred_username`).

- **Existing user found**: that user is reused. All their existing watch state, favorites, playlists, and per-user preferences are preserved.
- **No match**: a new user is created (when `AutoCreateUsers` is enabled).

The match is by **exact username**. Case sensitivity follows whatever `IUserManager.GetUserByName` does in your Jellyfin version (currently case-insensitive in 10.11.x).

## What gets preserved

- Watch history (resume positions, played status)
- Favorites
- Playlists
- Subtitle, audio language, and other per-user playback preferences
- Created watchlists / collections owned by the user

## What gets overwritten on every SSO login

The matched role mapping is re-applied each time the user logs in via SSO, so these fields are replaced by the role mapping values:

- `IsAdministrator`
- `EnableMediaPlayback`, `EnableRemoteAccess`, audio/video transcoding flags
- `EnableLiveTvAccess`, `EnableLiveTvManagement`
- `EnableContentDeletion`, `EnableCollectionManagement`, `EnableSubtitleManagement`
- `EnableAllFolders` and the list of enabled folders (library access)
- `MaxParentalRatingScore` (only when a role provides one)

Plan your role mappings to match the access you want users to have **before** they log in — otherwise their first SSO login can silently strip permissions or library access.

## Migration steps

1. **Identify the username mismatch (if any)**

   For each existing Jellyfin user, check what `preferred_username` (or whichever claim you configured) the IdP will emit for them. Authentik exposes this on the user's profile; Keycloak shows it under the user attributes.

2. **Align the names**

   If the OIDC username differs from the Jellyfin username, pick one to change:
   - **Rename the Jellyfin user** — Dashboard → Users → click the user → change Username → Save.
   - **Or change the IdP attribute** — set the user's `preferred_username` in the IdP to match the existing Jellyfin name. (Keycloak: under user attributes; Authentik: under the user's profile.)

3. **Create role mappings that grant the same access the user has today**

   Open Plugins → OIDC-Auth → Role Mappings. For each role/group used in your IdP, define a mapping that grants the same libraries and permissions the user has now. Use the **Test Connection** button on the provider card to confirm discovery succeeds before the first login.

4. **Add the user to the right IdP group(s)**

   Make sure each user is in the IdP group whose name matches a Role Mapping's `RoleName`. With Authentik this is Directory → Groups; with Keycloak it's Groups under the realm.

5. **Log in via SSO**

   The first SSO login finds the existing user by name, leaves their data alone, and applies the role mapping.

## Caveats

### Password login still works after migration

The plugin does **not** change the user's `AuthenticationProviderId` when an existing user logs in via SSO. The user can still sign in with their old Jellyfin password. If you want to lock that down, manually disable the user's password (Dashboard → Users → user → Password tab → set an empty / random password) or delete it via the API after migration.

### Duplicate accounts on username mismatch

If a user logs in via SSO before you've aligned usernames, the plugin will create a **second** Jellyfin user with the OIDC username, and the old account's data will not be visible to the new one. To recover, delete the new (empty) account and re-align the names before retrying.

### Display name claim is ignored on existing users

The configured **Display Name Claim** is read but never applied to existing users (or new ones — see `UserSyncService.cs:49-54`). The Jellyfin username is what's shown. If you need a different display name, set it manually in Jellyfin.

### Disabled users are re-enabled on SSO login

The plugin sets `IsDisabled = false` on every successful SSO login. If you've disabled a user in Jellyfin to lock them out, that won't survive an SSO login — remove them from the IdP group instead.
