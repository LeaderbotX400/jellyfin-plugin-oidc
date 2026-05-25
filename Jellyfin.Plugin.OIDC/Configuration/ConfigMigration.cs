using System.Collections.Generic;
using System.Linq;

namespace Jellyfin.Plugin.OIDC.Configuration;

/// <summary>
/// One-time migrations applied when plugin configuration is loaded or saved.
/// </summary>
public static class ConfigMigration
{
    /// <summary>
    /// v0.1.3: Before nullable-bool semantics were introduced, <c>EnableMediaPlayback</c>,
    /// <c>EnableRemoteAccess</c>, and <c>EnableTranscoding</c> defaulted to <c>true</c> on
    /// every new <see cref="RoleMapping"/> — including deny mappings.  This caused deny
    /// mappings to silently strip playback, remote access, and transcoding even when the
    /// admin never intended it.
    ///
    /// Since we cannot distinguish "admin explicitly set true" from "constructor default true"
    /// in already-persisted XML, the safe recovery is: for any deny mapping where those fields
    /// are still <c>true</c> and the migration sentinel (<see cref="RoleMapping.MigratedDenyDefaults"/>)
    /// has not been set, clear them to <c>null</c> (no-op) and return the affected role names
    /// so the caller can log an appropriate warning.
    ///
    /// After the NEW admin UI saves a deny mapping, it serialises explicit <c>true</c> only
    /// for permissions the admin deliberately checked.  The sentinel prevents the migration from
    /// wiping those deliberate choices on the next load.
    /// </summary>
    /// <param name="roleMappings">The list to migrate in-place.</param>
    /// <returns>Names of deny mappings that were migrated (empty if none needed migration).</returns>
    public static IReadOnlyList<string> MigrateDenyMappings(IList<RoleMapping> roleMappings)
    {
        var migrated = new List<string>();

        foreach (var m in roleMappings.Where(m => m.IsExplicitDeny))
        {
            bool changed = false;

            if (m.EnableMediaPlayback == true && !m.MigratedDenyDefaults)
            {
                m.EnableMediaPlayback = null;
                changed = true;
            }

            if (m.EnableRemoteAccess == true && !m.MigratedDenyDefaults)
            {
                m.EnableRemoteAccess = null;
                changed = true;
            }

            if (m.EnableTranscoding == true && !m.MigratedDenyDefaults)
            {
                m.EnableTranscoding = null;
                changed = true;
            }

            if (changed)
            {
                m.MigratedDenyDefaults = true;
                migrated.Add(m.RoleName);
            }
        }

        return migrated;
    }
}
