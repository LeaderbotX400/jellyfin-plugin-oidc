# RBAC Reference — Permissions & Entitlements

This is the canonical list of every permission the plugin can set on a Jellyfin
user, both from **role mappings** (admin UI) and **entitlement claims** (IdP).

There are two ways to grant permissions:

1. **Role mappings** — admin-defined in the plugin's **Role Mappings** tab. They
   match IdP role/group claim values to a set of Jellyfin permissions.
2. **Entitlement claims** — fine-grained tokens the IdP emits in a configurable
   claim (default: `entitlements`) with a configurable prefix
   (default: `jellyfin:`). Authentik calls these *entitlements*; other IdPs can
   emit equivalent values in any string-array claim.

Both paths feed the same resolver. When both are present, **entitlements are
authoritative** — see [Resolution semantics](#resolution-semantics).

---

## Role-mapping fields

Every field below is configurable per mapping in the admin UI. A mapping is
either a **grant** (default) or an **explicit deny** (toggle on the card).
Match rules:

- **Role Name** — must equal the IdP role/group claim value (case-insensitive,
  NFKC-normalized). Required.
- **Provider Scope** — provider ID this mapping applies to. Empty = all providers.
- **Priority** — higher first when ordering matched mappings. Merge semantics still
  apply: a high-priority mapping does not block lower-priority grants.
- **Explicit Deny** — when on, this mapping *strips* whatever permissions it has
  checked, after all grants and entitlements are applied. Unchecked permissions
  on a deny mapping are **no-ops** (deny only acts on what you explicitly opt in
  to strip).

### Permissions

| UI label                         | Jellyfin `PermissionKind`                                                | Merge rule (grants)                  | Deny semantics                                 |
|----------------------------------|---------------------------------------------------------------------------|--------------------------------------|------------------------------------------------|
| Administrator                    | `IsAdministrator`                                                         | any-true wins                        | strips when checked                            |
| Hide from login screen           | `IsHidden`                                                                | any-true wins                        | strips when checked                            |
| Access all libraries             | `EnableAllFolders`                                                        | any-true wins                        | strips when checked (falls back to library list)|
| Libraries (multi-select)         | `EnabledFolders` preference                                               | union of all matched mappings        | n/a                                            |
| Watch Live TV                    | `EnableLiveTvAccess`                                                      | any-true wins                        | strips when checked                            |
| Manage Live TV                   | `EnableLiveTvManagement`                                                  | any-true wins                        | strips when checked                            |
| Play media                       | `EnableMediaPlayback`                                                     | tri-state¹                           | strips only when explicit true                 |
| Remote access                    | `EnableRemoteAccess`                                                      | tri-state¹                           | strips only when explicit true                 |
| Allow transcoding                | `EnableAudioPlaybackTranscoding` + `EnableVideoPlaybackTranscoding`       | tri-state¹                           | strips only when explicit true                 |
| Allow video remuxing             | `EnablePlaybackRemuxing`                                                  | any-true wins                        | strips when checked                            |
| Delete media                     | `EnableContentDeletion`                                                   | any-true wins                        | strips when checked                            |
| Manage collections               | `EnableCollectionManagement`                                              | any-true wins                        | strips when checked                            |
| Manage subtitles                 | `EnableSubtitleManagement`                                                | any-true wins                        | strips when checked                            |
| Download media                   | `EnableContentDownloading`                                                | any-true wins                        | strips when checked                            |
| Join SyncPlay                    | `SyncPlayAccess.JoinGroups`²                                              | any-true wins                        | strips when checked                            |
| Host SyncPlay                    | `SyncPlayAccess.CreateAndJoinGroups`²                                     | any-true wins (implies Join)         | strips when checked                            |
| Remote-control other users       | `EnableRemoteControlOfOtherUsers`                                         | any-true wins                        | strips when checked                            |
| Remote-control shared devices    | `EnableSharedDeviceControl`                                               | any-true wins                        | strips when checked                            |
| Max parental rating              | `MaxParentalRatingScore`                                                  | highest value wins                   | n/a (use entitlement `rating:unlimited` to clear) |
| Max simultaneous sessions        | `MaxActiveSessions`                                                       | 0 (unlimited) wins, else highest cap | n/a                                            |

¹ **Tri-state fields** (`EnableMediaPlayback`, `EnableRemoteAccess`,
`EnableTranscoding`) are `bool?` on the mapping:
- **Grant + null** → "no opinion, default true" (backward compat — these were
  always-true historically).
- **Grant + true** → grant.
- **Grant + false** → revoke (in `EntitlementsAuthoritative` mode) or no-op
  (in `RespectExistingWhenUnspecified` mode).
- **Deny + null** → no-op (this rule does not touch the permission).
- **Deny + true** → strip.

² SyncPlay is a single tri-state column on the user
(`None` / `JoinGroups` / `CreateAndJoinGroups`). The plugin writes it only
when at least one SyncPlay grant matched.

---

## Entitlement tokens

Entitlements are string values in the configured claim, each prefixed with the
configured prefix (default `jellyfin:`). Anything without the prefix is ignored.
Tokens are case-insensitive; values after the second colon are case-preserved
(matters for library names).

### Per-provider config

| Field               | Default          | Notes                                                                 |
|---------------------|------------------|-----------------------------------------------------------------------|
| `EnableEntitlements`| `true`           | When false, entitlements from this provider are ignored entirely.     |
| `EntitlementClaim`  | `entitlements`   | Claim path in the ID token (supports dotted paths like `app.perms`).  |
| `EntitlementPrefix` | `jellyfin:`      | ASCII-only. Non-ASCII prefixes are not supported (byte-index parsing).|

### Boolean tokens

Tokens marked **entitlement-only** have no equivalent field on `RoleMapping` —
they can only be granted via an IdP claim, not from the admin UI.

| Token                          | Sets                                                          | Notes              |
|--------------------------------|---------------------------------------------------------------|--------------------|
| `jellyfin:admin`               | `IsAdministrator`                                             |                    |
| `jellyfin:disabled`            | `IsDisabled` (user cannot log in)                             | entitlement-only   |
| `jellyfin:hidden`              | `IsHidden`                                                    |                    |
| `jellyfin:playback`            | `EnableMediaPlayback`                                         |                    |
| `jellyfin:remote`              | `EnableRemoteAccess`                                          |                    |
| `jellyfin:transcoding`         | Audio + video playback transcoding                            |                    |
| `jellyfin:transcoding:sync`    | `EnableSyncTranscoding`                                       | entitlement-only   |
| `jellyfin:transcoding:force-remote` | `ForceRemoteSourceTranscoding`                           | entitlement-only   |
| `jellyfin:remux`               | `EnablePlaybackRemuxing`                                      |                    |
| `jellyfin:conversion`          | `EnableMediaConversion`                                       | entitlement-only   |
| `jellyfin:livetv`              | `EnableLiveTvAccess`                                          |                    |
| `jellyfin:livetv:manage`       | `EnableLiveTvAccess` **and** `EnableLiveTvManagement`         |                    |
| `jellyfin:content:delete`      | `EnableContentDeletion`                                       |                    |
| `jellyfin:collection:manage`   | `EnableCollectionManagement`                                  |                    |
| `jellyfin:subtitle:manage`     | `EnableSubtitleManagement`                                    |                    |
| `jellyfin:lyric:manage`        | `EnableLyricManagement`                                       | entitlement-only   |
| `jellyfin:download`            | `EnableContentDownloading`                                    |                    |
| `jellyfin:syncplay`            | `SyncPlayAccess.JoinGroups`                                   |                    |
| `jellyfin:syncplay:host`       | `SyncPlayAccess.CreateAndJoinGroups`                          |                    |
| `jellyfin:library:all`         | `EnableAllFolders`                                            |                    |
| `jellyfin:channels:all`        | `EnableAllChannels`                                           | entitlement-only   |
| `jellyfin:devices:all`         | `EnableAllDevices`                                            | entitlement-only   |
| `jellyfin:devices:shared-control` | `EnableSharedDeviceControl`                                |                    |
| `jellyfin:remote-control`      | `EnableRemoteControlOfOtherUsers`                             |                    |
| `jellyfin:public-sharing`      | `EnablePublicSharing`                                         | entitlement-only   |

### Library tokens

| Token                       | Effect                                                                      |
|-----------------------------|-----------------------------------------------------------------------------|
| `jellyfin:library:all`      | All libraries (`EnableAllFolders = true`).                                  |
| `jellyfin:library:<NAME>`   | Add the named library to `EnabledFolders` (matched case-insensitively against virtual-folder display names). Names are case-preserved from the token. |

When `library:all` is present, individual `library:<NAME>` tokens are ignored
(all-libs takes precedence).

### Numeric / quota tokens

All numeric tokens support `unlimited` / `none` / `max` (where it makes sense) as
sentinels. When multiple values are emitted, the **most permissive** wins.

| Token                                  | Sets                                | Source           | Sentinel behavior                                             |
|----------------------------------------|-------------------------------------|------------------|---------------------------------------------------------------|
| `jellyfin:rating:<N>`                  | `MaxParentalRatingScore`            | mapping + ent.   | `rating:unlimited` clears the cap (highest priority).         |
| `jellyfin:rating:sub:<N>`              | `MaxParentalRatingSubScore`         | entitlement-only | `rating:sub:unlimited` clears the sub-cap.                    |
| `jellyfin:bitrate:<kbps>`              | `RemoteClientBitrateLimit`          | entitlement-only | `bitrate:unlimited` clears the cap; otherwise highest wins.   |
| `jellyfin:sessions:<N>`                | `MaxActiveSessions`                 | mapping + ent.   | `sessions:unlimited` → 0 (Jellyfin convention for unlimited). |
| `jellyfin:login-attempts:<N>`          | `LoginAttemptsBeforeLockout`        | entitlement-only | `login-attempts:unlimited` clears the cap.                    |

#### "No opinion" handling for numeric fields

In **`EntitlementsAuthoritative`** mode, when *nothing* (mapping or entitlement)
opines on a numeric field, behavior is **asymmetric**:

- **`MaxParentalRatingScore`** is **cleared to null** (user becomes
  unrestricted). This is deliberate — the assumption is the IdP/admin owns
  parental ratings, so the absence of a cap means "no cap", not "preserve
  whatever was there".
- **`MaxActiveSessions`, `RemoteClientBitrateLimit`,
  `LoginAttemptsBeforeLockout`, `MaxParentalRatingSubScore`** are **left
  untouched** (existing user value preserved).

In **`RespectExistingWhenUnspecified`** mode (and only when no entitlements
were emitted), all numeric fields are left untouched when no opinion exists.

---

## Resolution semantics

The resolver runs once per login. Order:

1. **Match mappings.** Roles are NFKC-normalized before comparison (prevents
   homoglyph bypass like Turkish dotless `admın`). All grant + deny mappings
   that match the user's roles are collected.
2. **Default Role fallback.** If no grant mapping matched and a Default Role is
   configured, the mapping with that role name is added as the single grant.
3. **Merge grants.** For each field: any-true wins (booleans), highest-value
   wins (`MaxParentalRating`), 0-trumps-numeric (`MaxActiveSessions`), union
   (libraries).
4. **Parse entitlements.** Only when the matched provider has
   `EnableEntitlements = true`.
5. **Resolve per-field:**
   - Deny opinion `true` → off, always wins.
   - Entitlement `true` → on.
   - Grant `true` → on.
   - Otherwise → off (or `null` "no opinion" in `RespectExistingWhenUnspecified`
     mode when no entitlement was emitted at all).

### RBAC behavior modes

Configured in the **General** tab as **RBAC Behavior**:

- **`EntitlementsAuthoritative`** *(default)* — the plugin owns every covered
  permission. Anything not granted by mappings or entitlements is explicitly
  written off on every login. Predictable; recommended for new installs.
- **`RespectExistingWhenUnspecified`** — when entitlements are present, the
  default mode applies. When the user logged in with only role mappings (no
  entitlements), only fields a matched mapping explicitly opined on are written;
  all other Jellyfin permissions are left untouched. Useful when permissions
  are partially managed outside the plugin.

### Last-admin lockout guard

The plugin refuses to demote the last remaining Jellyfin administrator via
RBAC. Set **Allow Last-Admin Demotion** to `true` in the General tab only as a
deliberate escape hatch (e.g. you are demoting yourself and have another way
back in), then reset to `false`.

---

## Worked examples

### Admin via role mapping

IdP claim: `"groups": ["jellyfin-admins"]`

Role mapping:
- Role Name: `jellyfin-admins`
- Administrator: ✓
- All Libraries: ✓

Result: full admin, every library, all default-true permissions.

### Read-only kids account via entitlements

IdP entitlements:
```json
"entitlements": [
  "jellyfin:playback",
  "jellyfin:library:Kids Movies",
  "jellyfin:library:Cartoons",
  "jellyfin:rating:7",
  "jellyfin:sessions:2"
]
```

Result: can play media in two named libraries, parental cap 7, max 2 concurrent
sessions, all other permissions off.

### Deny mapping to revoke transcoding for a group

Two mappings, both matching `jellyfin-users`:
- Grant (priority 0): playback ✓, remote ✓, transcoding ✓
- Deny  (priority 0): transcoding ✓

Result: playback and remote on; transcoding stripped (deny wins).

### Mixed grant + entitlement

User has role `jellyfin-users` (grants playback) and emits
`jellyfin:transcoding`. Result: both playback and transcoding on. Other
permissions are governed by the resolver mode — in `EntitlementsAuthoritative`
they are explicitly off; in `RespectExistingWhenUnspecified` they are off too
because at least one entitlement was present (entitlements are authoritative
whenever any are emitted).
