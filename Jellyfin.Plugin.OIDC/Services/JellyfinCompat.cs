using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using Jellyfin.Database.Implementations.Entities;
using MediaBrowser.Controller.Library;

namespace Jellyfin.Plugin.OIDC.Services;

/// <summary>
/// Reflection-based accessors for IUserManager members whose signatures have drifted across
/// Jellyfin 10.x point releases. Plugin DLLs are loaded against the runtime Jellyfin's actual
/// assemblies, so a strict-signature mismatch (e.g. property return type changed from
/// IEnumerable&lt;User&gt; to IReadOnlyList&lt;User&gt;) throws MissingMethodException at JIT
/// time — even when the call is semantically valid. Use these helpers instead of touching
/// the drift-prone members directly.
/// </summary>
internal static class JellyfinCompat
{
    /// <summary>
    /// Enumerates all Jellyfin users via whichever shape the runtime exposes. Tries property
    /// <c>Users</c> first, then method <c>GetUsers()</c>; both are known to have existed in
    /// different point releases. Falls back to an empty enumeration with no throw so callers
    /// can degrade gracefully (the caller's logic should still be safe in that case — empty
    /// "no candidates found" rather than a crash).
    /// </summary>
    public static IEnumerable<User> EnumerateUsers(IUserManager userManager)
    {
        var type = userManager.GetType();

        // Property: IUserManager.Users { get; }
        var prop = type.GetProperty("Users");
        if (prop != null && prop.CanRead)
        {
            object? value;
            try { value = prop.GetValue(userManager); }
            catch (Exception) { value = null; }
            if (value is IEnumerable<User> generic) return generic;
            if (value is IEnumerable nonGeneric)
            {
                return nonGeneric.Cast<object>().OfType<User>();
            }
        }

        // Method: IEnumerable<User> GetUsers()
        var method = type.GetMethod("GetUsers", Type.EmptyTypes);
        if (method != null)
        {
            object? value;
            try { value = method.Invoke(userManager, Array.Empty<object>()); }
            catch (Exception) { value = null; }
            if (value is IEnumerable<User> generic) return generic;
            if (value is IEnumerable nonGeneric)
            {
                return nonGeneric.Cast<object>().OfType<User>();
            }
        }

        return Array.Empty<User>();
    }
}
