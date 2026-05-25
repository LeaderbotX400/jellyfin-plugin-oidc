using System;

namespace Jellyfin.Plugin.OIDC.Services;

/// <summary>
/// Thrown when the OIDC user store is in an unrecoverable state due to file corruption.
/// An administrator must explicitly reset the store via the admin endpoint before operations resume.
/// </summary>
public class OidcUserStoreUnavailableException : InvalidOperationException
{
    public OidcUserStoreUnavailableException()
        : base("OIDC user store is unavailable due to file corruption. " +
               "An administrator must reset the store via POST /sso/OIDC/Admin/UserStore/Reset.")
    {
    }

    public OidcUserStoreUnavailableException(string message)
        : base(message)
    {
    }
}
