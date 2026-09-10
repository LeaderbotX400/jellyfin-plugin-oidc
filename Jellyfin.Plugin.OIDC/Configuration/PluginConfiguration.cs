using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using MediaBrowser.Model.Plugins;

namespace Jellyfin.Plugin.OIDC.Configuration;

/// <summary>
/// Marks a string property as a secret. The masking helper replaces non-empty
/// values with <see cref="ConfigMasking.Sentinel"/> when serializing to the
/// admin UI, and merges back the sentinel on save.
/// </summary>
[AttributeUsage(AttributeTargets.Property)]
public sealed class SecretAttribute : Attribute { }

/// <summary>Sentinel value and masking/merge helpers for secret fields.</summary>
public static class ConfigMasking
{
    /// <summary>Placeholder sent to the UI in place of an actual secret.</summary>
    public const string Sentinel = "__UNCHANGED__";

    /// <summary>
    /// Returns a deep copy of <paramref name="config"/> with all
    /// <see cref="SecretAttribute"/>-annotated string properties replaced by
    /// <see cref="Sentinel"/> (only when the value is non-empty).
    ///
    /// The clone is produced by a JSON round-trip rather than a hand-written
    /// member-by-member copy. The hand-written version silently dropped every
    /// property nobody remembered to add to it — EmailClaim, AutoLinkByVerifiedEmail,
    /// EnforceSsoOnLink, AllowInsecureAuthority and AllowedSigningAlgorithms were all
    /// being returned to the admin UI as type defaults rather than their saved values.
    /// A round-trip cannot drift as the config grows.
    /// </summary>
    public static PluginConfiguration Mask(PluginConfiguration config)
    {
        var json = JsonSerializer.Serialize(config, CloneOptions);
        var masked = JsonSerializer.Deserialize<PluginConfiguration>(json, CloneOptions)
                     ?? throw new InvalidOperationException("Failed to clone plugin configuration for masking");

        MaskSecretProperties(masked);
        foreach (var provider in masked.Providers)
        {
            MaskSecretProperties(provider);
        }

        foreach (var saml in masked.SamlProviders)
        {
            MaskSecretProperties(saml);
        }

        return masked;
    }

    private static readonly JsonSerializerOptions CloneOptions = new()
    {
        // Match the property casing the plugin's own API surface uses so the round-trip
        // is lossless regardless of how the config was originally deserialized.
        PropertyNameCaseInsensitive = true
    };


    /// <summary>
    /// Merges incoming (possibly sentinel-containing) values from
    /// <paramref name="incoming"/> into <paramref name="persisted"/>.
    /// For each <see cref="SecretAttribute"/> property: if the incoming
    /// value equals <see cref="Sentinel"/>, the persisted value is kept;
    /// an empty string explicitly clears the secret; any other value overwrites.
    /// </summary>
    public static void MergeSecrets(PluginConfiguration incoming, PluginConfiguration persisted)
    {
        for (var i = 0; i < incoming.Providers.Count; i++)
        {
            // Match by index — the UI preserves provider order
            var inProv = incoming.Providers[i];
            var persistedProv = i < persisted.Providers.Count
                ? persisted.Providers.FirstOrDefault(p =>
                    string.Equals(p.ProviderId, inProv.ProviderId, StringComparison.Ordinal))
                  ?? (i < persisted.Providers.Count ? persisted.Providers[i] : null)
                : null;

            if (persistedProv is null) continue;
            MergeSecretProperties(inProv, persistedProv);
        }
    }

    // ── Reflection helpers ────────────────────────────────────────────────────

    private static readonly BindingFlags PropFlags =
        BindingFlags.Public | BindingFlags.Instance;

    private static void MaskSecretProperties(object obj)
    {
        foreach (var prop in obj.GetType().GetProperties(PropFlags))
        {
            if (prop.GetCustomAttribute<SecretAttribute>() is null) continue;
            if (prop.PropertyType != typeof(string)) continue;
            var current = (string?)prop.GetValue(obj);
            if (!string.IsNullOrEmpty(current))
                prop.SetValue(obj, Sentinel);
        }
    }

    private static void MergeSecretProperties(object incoming, object persisted)
    {
        foreach (var prop in incoming.GetType().GetProperties(PropFlags))
        {
            if (prop.GetCustomAttribute<SecretAttribute>() is null) continue;
            if (prop.PropertyType != typeof(string)) continue;
            var inVal = (string?)prop.GetValue(incoming);
            if (inVal == Sentinel)
            {
                // Keep the persisted secret
                prop.SetValue(incoming, prop.GetValue(persisted));
            }
            // Empty string or any other value: use as-is (clear or overwrite)
        }
    }
}

/// <summary>
/// Validation helpers for provider identifiers. Provider IDs are interpolated into URLs,
/// HTML <c>data-</c> attributes, and JS string literals in the callback HTML. A strict
/// charset (A-Z, a-z, 0-9, underscore, hyphen, 1-64 chars) keeps every downstream context safe
/// even without further escaping.
/// </summary>
public static class ProviderIdValidation
{
    public const string CharsetDescription = "letters, digits, underscore, or hyphen; 1-64 chars";

    private static readonly Regex Pattern = new(
        "^[A-Za-z0-9_-]{1,64}$",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    public static bool IsValid(string? providerId) =>
        !string.IsNullOrEmpty(providerId) && Pattern.IsMatch(providerId);
}

public class PluginConfiguration : BasePluginConfiguration
{
    public List<OidcProviderConfig> Providers { get; set; } = new();

    public List<RoleMapping> RoleMappings { get; set; } = new();

    public List<SamlProviderConfig> SamlProviders { get; set; } = new();

    public string DefaultProvider { get; set; } = string.Empty;

    public bool AutoCreateUsers { get; set; } = true;

    public string DefaultRoleName { get; set; } = string.Empty;

    /// <summary>
    /// Controls how RBAC writes apply to user records. Serialized as the enum's string name so the
    /// web UI can send/receive "EntitlementsAuthoritative" / "RespectExistingWhenUnspecified".
    /// </summary>
    [JsonConverter(typeof(JsonStringEnumConverter))]
    public RbacBehaviorMode RbacBehavior { get; set; } = RbacBehaviorMode.EntitlementsAuthoritative;

    /// <summary>
    /// When false (default), the plugin refuses to demote the last remaining Jellyfin administrator
    /// via RBAC. Set to true only as a deliberate escape hatch (e.g. you are demoting yourself and
    /// have another way in). Reset to false after use.
    /// </summary>
    public bool AllowLastAdminDemotion { get; set; }

    /// <summary>
    /// When true, Jellyfin's native password-authentication endpoints are refused, making SSO the
    /// only way in. Quick Connect is deliberately NOT blocked (see RequireSsoMiddleware).
    /// Default false -- this locks people out if the IdP is misconfigured, so it must be a
    /// deliberate choice made after SSO is known to work.
    /// </summary>
    public bool RequireSsoForAll { get; set; }

    /// <summary>
    /// When true, a password login for a user who really is a Jellyfin administrator is still
    /// allowed while <see cref="RequireSsoForAll"/> is on. This is the break-glass path for an IdP
    /// outage. The check is a real IUserManager lookup of the submitted username, not a name match.
    /// </summary>
    public bool SsoExemptAdmins { get; set; } = true;

    /// <summary>
    /// CIDRs whose clients may still use password login while <see cref="RequireSsoForAll"/> is on --
    /// typically the LAN, so a household can sign in when the IdP is unreachable. Evaluated through
    /// ClientIpResolver, so a spoofed X-Forwarded-For cannot buy an exemption unless the immediate
    /// peer is already a configured trusted proxy.
    /// </summary>
    public List<string> SsoExemptCidrs { get; set; } = new();

    /// <summary>
    /// When true (default), the SSO login-button script is spliced into the Jellyfin web UI
    /// automatically, so no manual Branding/Custom-CSS step is needed. Turn it off if you would
    /// rather paste the tag from /sso/OIDC/BrandingSnippet yourself, or if the injection ever
    /// conflicts with another plugin that rewrites the same page.
    /// </summary>
    public bool AutoInjectLoginButtons { get; set; } = true;

    /// <summary>
    /// DANGER — enables full PII logging to the server log (role lists, sub values, email addresses).
    /// Only enable temporarily for debugging. All other admins who can read server logs will be able
    /// to see arbitrary group memberships and user identifiers. Default false.
    /// </summary>
    public bool VerboseClaimLogging { get; set; }

    /// <summary>
    /// Sentinel for the one-time v0.1.3 deny-mapping migration (see <see cref="Services.ConfigMigration"/>).
    /// False on installs that pre-date v0.1.3. Set true after the migration runs once; never re-evaluated.
    /// Kept at the plugin level rather than per-mapping so the admin UI doesn't need to round-trip it
    /// on every save — round-tripping a per-mapping sentinel made every save re-run the migration and
    /// wipe deliberately-set deny flags.
    /// </summary>
    public bool MigratedDenyDefaultsV013 { get; set; }

    /// <summary>
    /// When true, the callback rate limiter and audit log will honor <c>X-Forwarded-For</c>
    /// and <c>X-Real-IP</c> headers — but ONLY when the immediate TCP peer is itself in
    /// <see cref="TrustedProxyCidrs"/>. Required if Jellyfin sits behind a reverse proxy,
    /// otherwise every request looks like it comes from the proxy and a single failed-login
    /// burst bans the proxy IP, locking out all users. Default false.
    /// </summary>
    public bool TrustForwardedHeaders { get; set; }

    /// <summary>
    /// CIDR ranges (e.g. <c>10.0.0.0/8</c>, <c>192.168.0.0/16</c>, <c>::1/128</c>) for the
    /// reverse proxies whose forwarded headers we trust. Empty disables forwarded-header
    /// resolution even when <see cref="TrustForwardedHeaders"/> is true (fail-closed default).
    /// Invalid entries are ignored with a logged warning.
    /// </summary>
    public List<string> TrustedProxyCidrs { get; set; } = new();
}

/// <summary>
/// Controls how the plugin reconciles computed permissions with the user's existing Jellyfin record.
/// </summary>
public enum RbacBehaviorMode
{
    /// <summary>
    /// Plugin owns every covered permission. Anything not granted by entitlements or role mappings
    /// is explicitly set off (or cleared) on every login. Backwards-compatible default.
    /// </summary>
    EntitlementsAuthoritative = 0,

    /// <summary>
    /// When entitlements are present they remain authoritative (matching the default mode).
    /// When only role mappings matched, only fields explicitly opined on by a matched grant or deny
    /// mapping are written — all other permissions on the user are left as Jellyfin has them.
    /// </summary>
    RespectExistingWhenUnspecified = 1,
}

public class OidcProviderConfig
{
    public string ProviderId { get; set; } = string.Empty;

    public string DisplayName { get; set; } = string.Empty;

    public string Authority { get; set; } = string.Empty;

    public string ClientId { get; set; } = string.Empty;

    [Secret]
    public string ClientSecret { get; set; } = string.Empty;

    public string Scopes { get; set; } = "openid profile email";

    public string RoleClaim { get; set; } = "realm_access.roles";

    public string UsernameClaim { get; set; } = "preferred_username";

    public string DisplayNameClaim { get; set; } = "name";

    public bool Enabled { get; set; } = true;

    public string ButtonColor { get; set; } = "#4285F4";

    public string ButtonIcon { get; set; } = string.Empty;

    public string AdditionalParameters { get; set; } = string.Empty;

    public string EntitlementClaim { get; set; } = "entitlements";

    public string EntitlementPrefix { get; set; } = "jellyfin:";

    public bool EnableEntitlements { get; set; } = true;

    /// <summary>Reject authentication if the id_token does not contain email_verified=true.</summary>
    public bool RequireEmailVerified { get; set; }

    /// <summary>
    /// When true, and the id_token contains no roles, roles are read from the access token
    /// after full signature and issuer validation (audience validation is skipped because
    /// access-token <c>aud</c> is the resource server, not the client).
    /// Default false — reading the access token without validation is a security risk for
    /// most IdP configurations, so this must be explicitly opted in to.
    /// </summary>
    public bool RolesFromAccessToken { get; set; }

    /// <summary>Transforms applied to extracted roles before matching against RoleMappings.</summary>
    public List<ClaimTransform> RoleTransforms { get; set; } = new();

    /// <summary>
    /// When true, an OIDC login whose username matches an existing local Jellyfin user may
    /// auto-link to that user — but ONLY if the id_token's <c>email_verified</c> claim is
    /// <c>true</c> and the <c>email</c> claim matches the existing user's Jellyfin Username
    /// (case-insensitive). The existing user must not already be bound to another auth provider.
    /// Default false. With this off, name collisions are rejected and an admin must link manually.
    /// </summary>
    public bool AutoLinkByVerifiedEmail { get; set; }

    /// <summary>
    /// When true, on a successful auto-link via <see cref="AutoLinkByVerifiedEmail"/>, the linked
    /// Jellyfin user is converted to OIDC-only authentication (local password disabled).
    /// Default false — auto-link preserves the original AuthenticationProviderId.
    /// </summary>
    public bool EnforceSsoOnLink { get; set; }

    /// <summary>OIDC claim name carrying the user's email address. Used by AutoLinkByVerifiedEmail.</summary>
    public string EmailClaim { get; set; } = "email";

    /// <summary>OIDC claim name carrying the URL of the user's avatar. Used by <see cref="SyncProfileImage"/>.</summary>
    public string PictureClaim { get; set; } = "picture";

    /// <summary>
    /// When true (default), the Jellyfin profile image is synced from the <see cref="PictureClaim"/>
    /// URL on login, overwriting any avatar set in Jellyfin. The image is only re-downloaded when the
    /// claim URL changes. A failure never fails the login — it is logged and skipped.
    /// </summary>
    public bool SyncProfileImage { get; set; } = true;

    /// <summary>
    /// Extra hostnames the avatar fetcher may contact, beyond the provider's own <see cref="Authority"/>
    /// origin (which is always allowed). Needed for IdPs that serve avatars off a separate CDN —
    /// e.g. <c>lh3.googleusercontent.com</c> for Google, <c>graph.microsoft.com</c> for Entra ID.
    ///
    /// This is a security control, not a convenience: the picture claim is an IdP-supplied URL that the
    /// SERVER fetches, and on IdPs where end users can edit their own profile (Keycloak, Authentik) it is
    /// effectively user-controlled. Anything not on this list or the Authority origin is refused. Entries
    /// are bare hostnames — no scheme, port, path, or wildcard.
    /// </summary>
    public List<string> PictureAllowedHosts { get; set; } = new();

    /// <summary>
    /// Algorithms (JWS "alg" header values) accepted when validating ID tokens / logout tokens from this provider.
    /// Defaults to asymmetric algorithms only. Including any HS* algorithm is DANGEROUS: it allows
    /// any holder of the client_secret to mint forged tokens, even when the IdP normally signs with RSA/EC.
    /// </summary>
    public List<string> AllowedSigningAlgorithms { get; set; } = new()
    {
        "RS256", "RS384", "RS512",
        "ES256", "ES384", "ES512",
        "PS256", "PS384", "PS512"
    };

    /// <summary>
    /// DANGER — dev/test only. When true, allows non-HTTPS Authority/JWKS/Token/Authorize endpoints,
    /// but ONLY when the host is localhost / 127.0.0.1. Production deployments MUST leave this false:
    /// MITM on plain HTTP can swap JWKS and forge arbitrary tokens.
    /// </summary>
    public bool AllowInsecureAuthority { get; set; }

    /// <summary>
    /// Optional. If non-empty, the id_token's <c>amr</c> claim must contain at least one of these
    /// values or the login is rejected. Use to require the IdP to have performed MFA
    /// (e.g. <c>["mfa"]</c>, <c>["otp", "hwk"]</c>). Empty = no enforcement.
    /// See RFC 8176 for standard AMR values.
    /// </summary>
    public List<string> RequiredAmrValues { get; set; } = new();

    /// <summary>
    /// Optional. If non-empty, the id_token's <c>acr</c> claim must equal one of these values
    /// (case-sensitive, per spec) or the login is rejected. Empty = no enforcement.
    /// </summary>
    public List<string> RequiredAcrValues { get; set; } = new();
}

/// <summary>Maps a raw claim value to a normalized value before role matching.</summary>
public class ClaimTransform
{
    /// <summary>Exact role value to match (case-insensitive).</summary>
    public string FromValue { get; set; } = string.Empty;

    /// <summary>Replacement value. Empty string drops the role entirely (deny-list).</summary>
    public string ToValue { get; set; } = string.Empty;
}

public class RoleMapping
{
    public string RoleName { get; set; } = string.Empty;

    /// <summary>Provider this mapping applies to. Empty means it applies to all providers.</summary>
    public string ProviderId { get; set; } = string.Empty;

    /// <summary>
    /// When true, this mapping strips the specified permissions after all grants are applied.
    /// Deny takes precedence over grants and entitlements.
    /// </summary>
    public bool IsExplicitDeny { get; set; }

    public bool IsAdmin { get; set; }

    public bool EnableAllLibraries { get; set; }

    public List<string> LibraryIds { get; set; } = new();

    public List<string> LibraryNames { get; set; } = new();

    public bool EnableLiveTv { get; set; }

    public bool EnableLiveTvManagement { get; set; }

    /// <summary>
    /// Nullable so deny mappings can express "don't touch this permission" via null.
    /// For allow mappings: null is treated as true (preserve prior default).
    /// For deny mappings: only explicit true strips the permission; null is a no-op.
    /// </summary>
    public bool? EnableMediaPlayback { get; set; }

    /// <inheritdoc cref="EnableMediaPlayback"/>
    public bool? EnableRemoteAccess { get; set; }

    /// <inheritdoc cref="EnableMediaPlayback"/>
    public bool? EnableTranscoding { get; set; }

    public bool EnableContentDeletion { get; set; }

    public bool EnableCollectionManagement { get; set; }

    public bool EnableSubtitleManagement { get; set; }

    public bool EnableDownload { get; set; }

    /// <summary>Allow joining existing SyncPlay groups.</summary>
    public bool EnableSyncplay { get; set; }

    /// <summary>Allow creating SyncPlay groups (implies EnableSyncplay).</summary>
    public bool EnableSyncplayGroupCreation { get; set; }

    /// <summary>Hide the user from the login screen's user-picker list.</summary>
    public bool IsHidden { get; set; }

    /// <summary>Allow video playback that requires conversion without re-encoding (remuxing).</summary>
    public bool EnablePlaybackRemuxing { get; set; }

    /// <summary>Allow remote control of other users' sessions.</summary>
    public bool EnableRemoteControlOfOtherUsers { get; set; }

    /// <summary>Allow remote control of shared devices (e.g. DLNA endpoints, public displays).</summary>
    public bool EnableSharedDeviceControl { get; set; }

    /// <summary>
    /// Maximum number of simultaneous sessions. Null = no opinion from this mapping;
    /// 0 = unlimited (Jellyfin convention); positive N = cap at N. When merging multiple matched
    /// grants, 0 (unlimited) wins; otherwise the largest cap wins (most permissive).
    /// </summary>
    public int? MaxActiveSessions { get; set; }

    public int? MaxParentalRating { get; set; }

    public int Priority { get; set; }

    /// <summary>
    /// Set to true by the v0.1.3 migration once legacy default-true deny flags have been
    /// cleared. Prevents the migration guard from repeatedly clearing values that the
    /// admin has deliberately set to true in the new UI.
    /// </summary>
    public bool MigratedDenyDefaults { get; set; }
}

/// <summary>Configuration for a SAML 2.0 identity provider.</summary>
public class SamlProviderConfig
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");

    public string DisplayName { get; set; } = string.Empty;

    /// <summary>
    /// Service Provider EntityID — typically your Jellyfin base URL. Sent as the
    /// AuthnRequest Issuer and compared against the AudienceRestriction in responses.
    /// </summary>
    public string EntityId { get; set; } = string.Empty;

    /// <summary>
    /// Expected IdP EntityID. Compared (when non-empty) against the Issuer element in
    /// SAML Responses and assertions. Leave empty during initial setup to skip the check;
    /// production deployments should populate this.
    /// </summary>
    public string IdpEntityId { get; set; } = string.Empty;

    /// <summary>IdP Single Sign-On URL (HTTP-Redirect binding).</summary>
    public string SsoUrl { get; set; } = string.Empty;

    /// <summary>IdP signing certificate (PEM or raw base64 DER). Used to verify response signatures.</summary>
    public string IdpCertificate { get; set; } = string.Empty;

    /// <summary>SAML attribute name containing the username. Use "NameID" for the NameID element.</summary>
    public string UsernameClaim { get; set; } = "NameID";

    /// <summary>SAML attribute name containing the role list.</summary>
    public string RoleClaim { get; set; } = "groups";

    public bool Enabled { get; set; } = true;

    public string ButtonColor { get; set; } = "#4285F4";

    /// <summary>
    /// Allow IdP-initiated SSO (no in-flight AuthnRequest, missing InResponseTo). Off by default;
    /// when off, only SP-initiated flows whose InResponseTo matches a stored RequestID are accepted.
    /// IdP-initiated flows lack CSRF protection so leave this off unless an integration specifically
    /// requires it (e.g. dashboard tile launches from the IdP).
    /// </summary>
    public bool AllowIdpInitiated { get; set; }
}
