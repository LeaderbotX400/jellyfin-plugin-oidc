# Jellyfin OIDC-Auth Plugin

A Jellyfin plugin providing **OpenID Connect authentication** with **role-based library access control**.

Authenticate users via any OIDC-compatible identity provider (Authentik, Keycloak, Azure AD, Okta, etc.) and automatically assign Jellyfin permissions and library access based on IdP group/role claims.

## Features

- **OIDC Authentication** with PKCE (Authorization Code flow)
- **Multi-provider support** - configure multiple IdPs simultaneously with branded login buttons
- **Role-based access control** - map IdP roles/groups to Jellyfin permissions and specific libraries
- **Auto-provisioning** - create Jellyfin users on first SSO login
- **Flexible claim parsing** - extract roles from nested JWT claims (e.g. `realm_access.roles`, `groups`)
- **Merge semantics** - users with multiple roles get the union of all permissions (most permissive wins)
- **Default role fallback** - assign a baseline role to users with no matching IdP roles
- **Admin UI** - full configuration from the Jellyfin dashboard (Providers, Role Mappings, General settings)
- **Auto-injected login buttons** - no manual branding HTML required
- **Profile pictures** - sync the Jellyfin avatar from the OIDC `picture` claim, behind a full SSRF guard
- **Optional SSO-only mode** - refuse Jellyfin's password login, with admin and LAN escape hatches

## Compatibility

| Jellyfin server | Plugin version | Target framework |
|-----------------|----------------|------------------|
| 12.0 and newer  | 0.2.x          | net10.0          |
| 10.10 / 10.11   | 0.1.11.x       | net9.0           |

Jellyfin 12 retargeted the server to .NET 10 and changed `IUserManager`, so a
single build cannot serve both server lines. The 0.2.x artifact declares
`targetAbi 12.0.0.0`, which stops Jellyfin's installer from offering it to a 10.x
server; 10.x installs keep receiving 0.1.11.x from the same manifest.

**Upgrading a server to Jellyfin 12:** per Jellyfin's own 12.0 release guidance,
remove non-built-in plugins before migrating and reinstall them afterwards. Also
check for Jellyfin usernames that differ only by case *before* upgrading — 12.0
stores usernames in a normalized, uniquely-indexed column and such a pair will
block the migration. This plugin creates and matches users by username, so
auto-provisioned accounts are in scope for that check.

## Installation

### Quick install — add this repository to Jellyfin

```
https://raw.githubusercontent.com/LeaderbotX400/jellyfin-plugin-oidc/manifest/manifest.json
```

### From the Jellyfin Plugin Catalog

1. Go to **Admin Dashboard > Plugins > Repositories**
2. Click **Add repository** and paste the URL above (Repository Name: `OIDC-Auth`)
3. Go to **Catalog > Authentication**
4. Install **OIDC-Auth**
5. Restart Jellyfin

### Manual Installation

```bash
# Build via Docker (no .NET SDK needed)
make docker-build

# Copy to Jellyfin plugin directory
sudo cp dist/*.dll dist/meta.json /var/lib/jellyfin/plugins/OIDC-RBAC/

# Restart Jellyfin
sudo systemctl restart jellyfin
```

## Quick Start

### 1. Configure a Provider

Go to **Admin Dashboard > Plugins > OIDC-Auth > Providers tab**

| Field              | Example (Authentik)                                        |
|--------------------|------------------------------------------------------------|
| Provider ID        | `authentik`                                                |
| Display Name       | `Authentik`                                                |
| Authority URL      | `https://auth.example.com/application/o/jellyfin/`        |
| Client ID          | *(from your IdP)*                                          |
| Client Secret      | *(from your IdP)*                                          |
| Scopes             | `openid profile email`                                     |
| Role Claim Path    | `groups`                                                   |
| Username Claim     | `preferred_username`                                       |

### 2. Create Role Mappings

Go to **Role Mappings tab** and create mappings:

**Example - Admin role:**
- Role Name: `jellyfin-admins`
- Administrator: checked
- All Libraries: checked

**Example - Standard user:**
- Role Name: `jellyfin-users`
- Libraries: select specific libraries
- Playback, Remote Access, Transcoding: checked

**Example - Kids:**
- Role Name: `jellyfin-kids`
- Libraries: Kids only
- Max Parental Rating: 7

### 3. The Login Button

Nothing to do — the plugin splices its login-button script into the Jellyfin web UI itself, and a
button appears on the login page for every enabled provider, styled with that provider's colour.

If you would rather do it by hand — because another plugin also rewrites the web UI, or you want
the button somewhere specific — turn off **Auto-inject login buttons** in the plugin's General
settings and paste the tag from `GET /sso/OIDC/BrandingSnippet` into
**Admin Dashboard > General > Branding > Login disclaimer**:

```html
<script src="/sso/OIDC/LoginButtons"></script>
```

Injection is best-effort by design: if Jellyfin's web shell ever changes shape enough that the
plugin cannot find an insertion point, it serves the page untouched and logs a warning telling you
to use the manual snippet. It never breaks the web UI.

## Requiring SSO

By default the plugin adds SSO alongside Jellyfin's password login. To make SSO the only
way in, enable **Require SSO (disable password login)** in the plugin's General settings.

**Turn this on only after you have confirmed an SSO login works**, and leave at least one
escape hatch enabled. There is no way to undo it from the login page.

| Endpoint | Under Require SSO |
|----------|-------------------|
| `POST /Users/AuthenticateByName` | refused, `403 sso_required` |
| `POST /Users/{userId}/Authenticate` (obsolete, still routed) | refused |
| `POST /Users/AuthenticateWithQuickConnect` | **allowed** |

Quick Connect stays open on purpose. It never takes a password — a code is approved from an
already-authenticated session, which under this policy can only have come from SSO, so it
already inherits the requirement. Blocking it would lock out Android, iOS/Swiftfin and
Android TV, which cannot render a web login button and have no other way in.

Existing sessions are unaffected: the gate is on session *creation*, so nobody is signed out
when you enable it.

### Escape hatches

- **Administrators may still use a password** (on by default) — break-glass for an IdP
  outage. The submitted username is looked up through `IUserManager` and checked for the
  administrator permission; it is *not* a name match, and it is not a password bypass —
  a wrong password still fails.
- **CIDRs allowed to use a password** — e.g. `192.168.0.0/16` so the household can sign in
  when the IdP is unreachable. Evaluated through the same trusted-proxy rules as the rest
  of the plugin, so a spoofed `X-Forwarded-For` cannot buy an exemption unless the
  immediate peer is already a configured trusted proxy.

If the plugin config is ever unreadable, the gate fails **open**. Locking every account out
of a server over a transient config read is worse than one unblocked password login.

### If you lock yourself out

Stop Jellyfin, edit `config/plugins/configurations/OIDC-Auth.xml`, set
`<RequireSsoForAll>false</RequireSsoForAll>`, and start it again.

## Migrating Existing Users

Already have Jellyfin users you want to move to SSO without losing watch history? See [MIGRATION.md](MIGRATION.md) — username-match is automatic, but there are a few caveats around permissions overwrite and password fallback.

## How It Works

```
Browser                    Jellyfin Plugin              Identity Provider
   |                            |                            |
   |--- Click SSO button ------>|                            |
   |                            |--- OIDC authorize -------->|
   |<---------------------------|    (with PKCE)             |
   |                            |                            |
   |--- Login at IdP -----------|--------------------------->|
   |<---------------------------|------- callback + code ----|
   |                            |                            |
   |                            |--- exchange code --------->|
   |                            |<------ ID token + roles ---|
   |                            |                            |
   |                            |--- sync user + RBAC        |
   |                            |--- issue Jellyfin session  |
   |<--- authenticated ---------|                            |
```

1. User clicks the SSO login button on the Jellyfin login page
2. Plugin redirects to the IdP's authorization endpoint (with PKCE)
3. User authenticates at the IdP
4. IdP redirects back with an authorization code
5. Plugin exchanges the code for tokens, extracts roles from the configured claim path
6. Plugin creates/updates the Jellyfin user and applies role-based permissions
7. Plugin issues a Jellyfin session token and redirects to the dashboard

## RBAC Details

> Full reference of every role-mapping field, every `jellyfin:*` entitlement
> token, merge rules, and worked examples: **[docs/rbac-permissions.md](docs/rbac-permissions.md)**.

### Role Merging

When a user matches multiple role mappings, permissions are **merged (union)**:
- Boolean permissions: `true` if **any** matched role has it enabled
- Libraries: union of all matched roles' library sets
- `EnableAllLibraries`: `true` if any role enables it
- `MaxParentalRating`: highest value across all matched roles

### Priority

Each role mapping has a priority field. Higher priority roles take precedence in ordering, though merge semantics still apply.

### Default Role

If no role mappings match a user's IdP roles, the **Default Role** (configured in the General tab) is used as a fallback.

### Supported Claim Paths

The **Role Claim Path** supports:

| Path                   | Token Structure                                  | Provider     |
|------------------------|--------------------------------------------------|--------------|
| `groups`               | `{"groups": ["admin", "users"]}`                 | Authentik    |
| `realm_access.roles`   | `{"realm_access": {"roles": ["admin"]}}`         | Keycloak     |
| `roles`                | `{"roles": ["admin"]}`                           | Custom/Azure |

The plugin checks both the ID token and access token for role claims.

## Profile Pictures

The Jellyfin avatar is synced from the OIDC `picture` claim on login. This is **on by
default**; turn it off per provider with the *Sync profile picture* checkbox.

- The claim name is configurable (**Picture Claim**, default `picture`). If the ID token
  does not carry it, the plugin falls back to the provider's `userinfo` endpoint —
  Authentik, for one, only exposes `picture` there.
- The image is re-downloaded only when the claim URL changes, so repeat logins cost no
  network request. If the URL changes but the bytes are identical, the file is not rewritten.
- Sync **overwrites** an avatar set in Jellyfin. If users should manage their own, turn it off.
- A failed fetch never fails the login. The user keeps their previous avatar and the reason
  is logged at Warning.

### Which hosts the server will fetch from

The picture claim is a URL supplied by the IdP that **your server** then requests, and on
IdPs where users edit their own profile (Keycloak, Authentik) it is effectively user-supplied.
It is therefore treated as untrusted input:

| Guard | Behaviour |
|-------|-----------|
| Scheme | HTTPS only (plain HTTP to localhost needs *Allow insecure authority*) |
| Origin | The provider's Authority origin, plus any host in **Avatar Allowed Hosts** |
| Address | Rejected if the host resolves to any loopback, private, link-local, CGNAT or ULA address — this is what blocks `169.254.169.254` and friends |
| DNS rebinding | The connection is pinned to the address that was validated, so it cannot be re-resolved to an internal one |
| Redirects | Not followed — a redirect target has been through none of the above |
| Size | 5 MiB, enforced while reading rather than trusting `Content-Length` |
| Type | `image/jpeg`, `image/png`, `image/gif`, `image/webp`, and the payload's magic bytes must agree. `image/svg+xml` is refused outright — SVG can carry script |

**Avatar Allowed Hosts** is only needed when the IdP serves avatars off a different host
than its issuer. Common cases:

| IdP | Add to Avatar Allowed Hosts |
|-----|------------------------------|
| Authentik, Keycloak (self-hosted avatars) | *nothing — same origin as the Authority* |
| Google | `lh3.googleusercontent.com` |
| Microsoft Entra ID | `graph.microsoft.com` |
| Gravatar-backed IdPs | `www.gravatar.com` |

Entries are bare hostnames — no scheme, port, path or wildcard. A malformed entry is
rejected when you save, rather than silently never matching.

Images are written to `<user configuration directory>/<username>/profile.<ext>`, the same
location Jellyfin's own avatar upload uses.

## Identity Provider Guides

### Authentik

See [examples/authentik/SETUP.md](examples/authentik/SETUP.md) for a complete step-by-step guide including:
- Docker Compose stack (Jellyfin + Authentik)
- Group creation and OIDC provider configuration
- Custom property mapping for filtered role claims
- Troubleshooting

### Keycloak

1. Create a new Client in your realm (Client type: OpenID Connect, Client authentication: On)
2. Set Valid Redirect URIs: `https://jellyfin.example.com/sso/OIDC/Callback/keycloak`
3. Roles are in `realm_access.roles` by default
4. Plugin config: Authority = `https://keycloak.example.com/realms/myrealm`, Role Claim Path = `realm_access.roles`

## API Endpoints

| Method | Endpoint                          | Description                        |
|--------|-----------------------------------|------------------------------------|
| GET    | `/sso/OIDC/Start/{providerId}`    | Initiate OIDC flow                 |
| GET    | `/sso/OIDC/Callback/{providerId}` | OIDC callback (handles code exchange) |
| POST   | `/sso/OIDC/Auth/{providerId}`     | Complete authentication            |
| GET    | `/sso/OIDC/Providers`             | List enabled providers             |
| GET    | `/sso/OIDC/LoginButtons`          | JS snippet for login buttons       |
| GET    | `/sso/OIDC/BrandingSnippet`       | HTML snippet for branding config   |
| GET    | `/sso/OIDC/Config/Libraries`      | List available libraries (admin)   |
| GET    | `/sso/OIDC/Config/Status`         | Plugin status (admin)              |

## Building

### Requirements

- .NET 10.0 SDK **or** Docker

### Build

```bash
# With .NET SDK
make build

# With Docker only
make docker-build
```

### Package (installable zip)

```bash
make package
# Output: dist/oidc-rbac.zip
```

### Release

```bash
git tag v1.0.0
git push origin v1.0.0
# GitHub Actions builds, creates a release, and updates manifest.json
```

## Project Structure

```
Jellyfin.Plugin.OIDC/
  OidcPlugin.cs                  # Plugin entry point
  Configuration/
    PluginConfiguration.cs       # Provider + role mapping config DTOs
    configPage.html              # Admin UI (embedded resource)
  Api/
    OidcController.cs            # OIDC authorization code flow
    ConfigController.cs          # Admin config API
    LoginButtonController.cs     # Auto-injected login buttons
  Auth/
    OidcAuthProvider.cs          # Blocks password login for SSO users
  Services/
    StateManager.cs              # Thread-safe OIDC state with TTL
    ClaimParser.cs               # JWT claim extraction (nested paths)
    RbacService.cs               # Role-to-permission mapping engine
    UserSyncService.cs           # User provisioning and sync
    ServiceRegistrator.cs        # DI registration
```

## License

GPLv3 (required by linking against Jellyfin's GPLv3 libraries)
