using System;
using System.Collections.Generic;
using MediaBrowser.Model.Plugins;

namespace Jellyfin.Plugin.OIDC.Configuration;

public class PluginConfiguration : BasePluginConfiguration
{
    public List<OidcProviderConfig> Providers { get; set; } = new();

    public List<RoleMapping> RoleMappings { get; set; } = new();

    public List<SamlProviderConfig> SamlProviders { get; set; } = new();

    public string DefaultProvider { get; set; } = string.Empty;

    public bool AutoCreateUsers { get; set; } = true;

    public string DefaultRoleName { get; set; } = string.Empty;
}

public class OidcProviderConfig
{
    public string ProviderId { get; set; } = string.Empty;

    public string DisplayName { get; set; } = string.Empty;

    public string Authority { get; set; } = string.Empty;

    public string ClientId { get; set; } = string.Empty;

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

    /// <summary>Transforms applied to extracted roles before matching against RoleMappings.</summary>
    public List<ClaimTransform> RoleTransforms { get; set; } = new();
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

    /// <summary>Service Provider EntityID — typically your Jellyfin base URL.</summary>
    public string EntityId { get; set; } = string.Empty;

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
}
