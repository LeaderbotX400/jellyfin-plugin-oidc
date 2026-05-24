using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;

namespace Jellyfin.Plugin.OIDC.Services;

/// <summary>
/// Picks the right set of validation keys for an ID token, based on the alg in the token header.
///
/// - For HMAC algorithms (HS256/384/512) — symmetric, the client_secret is the signing key
///   (OIDC Core 1.0 §10.1 / RFC 7518 §3.2). JWKS is irrelevant; some IdPs serve an empty JWKS.
/// - For asymmetric algorithms (RS256, ES256, PS256, etc.) — fetch the IdP's public keys from JWKS.
/// </summary>
public static class SigningKeyResolver
{
    public static async Task<SecurityKey[]> ResolveAsync(
        string rawJwt,
        string clientSecret,
        string? jwksUri,
        JwksCache jwksCache)
    {
        var alg = new JwtSecurityToken(rawJwt).Header.Alg ?? string.Empty;

        if (alg.StartsWith("HS", StringComparison.Ordinal))
        {
            if (string.IsNullOrEmpty(clientSecret))
            {
                throw new InvalidOperationException(
                    "ID token uses HMAC signing but the provider has no client_secret configured");
            }

            return new SecurityKey[]
            {
                new SymmetricSecurityKey(Encoding.UTF8.GetBytes(clientSecret))
            };
        }

        if (string.IsNullOrEmpty(jwksUri))
        {
            throw new InvalidOperationException(
                $"ID token uses {alg} signing but the discovery document has no JWKS URI");
        }

        var keys = await jwksCache.GetKeysAsync(jwksUri).ConfigureAwait(false);
        return keys.GetSigningKeys().ToArray();
    }
}
