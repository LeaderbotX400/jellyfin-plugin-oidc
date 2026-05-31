# Security Policy

## Reporting a vulnerability

Email **robots@s10y.ca** with details. Please do not file public issues for
security problems — open an issue only after a fix has shipped.

What to include if you can:

- A description of the vulnerability and its impact.
- Steps to reproduce, including plugin version, Jellyfin version, and IdP.
- Any proof-of-concept request/response captures (redact secrets first).

You should expect an acknowledgement within 5 business days. There is no
bug bounty.

## Supported versions

Only the latest released version is supported. Fixes are shipped as a new
release; older versions do not receive backports.

## Threat model

This plugin sits in the authentication path for Jellyfin and grants
permissions based on identity-provider (IdP) claims. The IdP is part of
the trusted computing base — if it is compromised, the plugin cannot
defend the server.

### What this plugin defends against

- **Token forgery.** ID tokens are validated against the IdP's JWKS using
  only the algorithms in `AllowedSigningAlgorithms` (asymmetric by
  default). Unsigned tokens (`alg: none`) and unexpected algorithms are
  rejected.
- **Authorization-code replay.** Codes are tracked in an in-process
  one-time-use cache (`AuthorizationCodeCache`) before any token-endpoint
  call, on top of the IdP's own replay protection.
- **CSRF on the callback.** Each `/Start` issues a per-request CSRF
  binding cookie whose hash is stored in server-side state. The callback
  rejects if the cookie is missing or does not match the stored hash.
- **Nonce replay.** A 32-byte CSPRNG nonce is required in the ID token
  and matched against the state-stored value.
- **Authorization-state forgery.** State entries are server-side only;
  the client receives an opaque key.
- **Brute-force / state-fuzzing.** Per-IP rate limit on the OIDC
  callback (`CallbackRateLimiter`) bans IPs after 10 failures in 5
  minutes for 15 minutes.
- **Account takeover via username collision.** OIDC logins whose
  preferred username matches an existing local user are rejected unless
  the admin has set the user's authentication provider, or
  `AutoLinkByVerifiedEmail` is enabled and the IdP asserts a verified
  email matching the local Jellyfin username.
- **Optional IdP-MFA enforcement.** Per-provider `RequiredAmrValues`
  and `RequiredAcrValues` reject logins whose ID token does not assert
  the configured authentication-method or assurance-level claims (RFC
  8176 / OIDC core).
- **MITM on plain-HTTP IdPs.** Non-HTTPS authorities are refused unless
  the dev-only `AllowInsecureAuthority` is set AND the host is
  localhost.
- **Silent role-mapping drift.** Role transforms that drop or rename
  IdP claims are surfaced in Jellyfin's activity log so admins can see
  why a user's effective roles differ from their IdP groups.
- **Last-admin demotion via RBAC.** A guarded escape hatch
  (`AllowLastAdminDemotion`, default off) blocks RBAC writes that
  would leave the server with zero administrators.

### What this plugin does NOT defend against

- A compromised IdP issuing valid tokens for arbitrary identities.
- Jellyfin core vulnerabilities, including authentication-bypass bugs
  in other plugins.
- Server-side log access by other Jellyfin administrators. Verbose
  claim logging is opt-in and warns about this.
- Network-level attacks against the Jellyfin server itself. Run behind
  a reverse proxy with TLS termination and standard hardening.
- Phishing the user out-of-band. Use a phishing-resistant authenticator
  in your IdP (passkey, hardware key) and enforce it via
  `RequiredAmrValues`.

## Hardening checklist

- Set `RequireEmailVerified = true` on every provider whose IdP issues
  the `email_verified` claim.
- Set `RequiredAmrValues` (e.g. `["mfa"]`) or `RequiredAcrValues` to
  require IdP-side MFA.
- Leave `AllowInsecureAuthority` and `AllowLastAdminDemotion` off in
  production.
- Use `EntitlementsAuthoritative` RBAC mode unless you have a specific
  reason to preserve manually-set permissions.
- Disable `VerboseClaimLogging` outside of debugging sessions.
- Verify the published `.sha256` checksum of release artifacts before
  installing.
