using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Text.Json;
using Jellyfin.Plugin.OIDC.Configuration;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.OIDC.Services;

public static class ClaimParser
{
    /// <summary>
    /// Extracts roles from a JWT using a dot-separated claim path.
    /// Supports nested JSON objects (e.g. "realm_access.roles") and flat claim arrays.
    /// </summary>
    public static string[] ExtractRoles(JwtSecurityToken token, string roleClaim)
    {
        if (string.IsNullOrWhiteSpace(roleClaim))
        {
            return Array.Empty<string>();
        }

        var parts = roleClaim.Split('.');

        // Try flat claim first (single segment like "roles" or "groups")
        if (parts.Length == 1)
        {
            return ExtractFromFlatClaim(token, roleClaim);
        }

        // Nested path: walk the JSON payload
        return ExtractFromNestedClaim(token, parts);
    }

    public static string ExtractClaim(JwtSecurityToken token, string claimType)
    {
        return token.Claims.FirstOrDefault(c => c.Type == claimType)?.Value ?? string.Empty;
    }

    private static string[] ExtractFromFlatClaim(JwtSecurityToken token, string claimType)
    {
        var claims = token.Claims.Where(c => c.Type == claimType).Select(c => c.Value).ToArray();
        if (claims.Length == 0)
        {
            return Array.Empty<string>();
        }

        // Single claim whose value is a JSON array string (some IdPs encode arrays this way)
        if (claims.Length == 1 && claims[0].TrimStart().StartsWith('['))
        {
            return ParseJsonStringArray(claims[0]);
        }

        return claims;
    }

    private static string[] ExtractFromNestedClaim(JwtSecurityToken token, string[] pathParts)
    {
        // The root claim is the first segment
        var rootClaim = token.Claims.FirstOrDefault(c => c.Type == pathParts[0])?.Value;
        if (string.IsNullOrEmpty(rootClaim))
        {
            // Try to reconstruct from the raw payload
            try
            {
                using var doc = JsonDocument.Parse(
                    Base64UrlDecode(token.RawPayload));
                return WalkJsonPath(doc.RootElement, pathParts);
            }
            catch (Exception e) when (e is JsonException or FormatException or ArgumentException)
            {
                return Array.Empty<string>();
            }
        }

        // If root claim is JSON, parse and walk
        try
        {
            using var doc = JsonDocument.Parse(rootClaim);
            var remaining = pathParts.Skip(1).ToArray();
            return WalkJsonPath(doc.RootElement, remaining);
        }
        catch (JsonException)
        {
            return Array.Empty<string>();
        }
    }

    private static string[] WalkJsonPath(JsonElement element, string[] path)
    {
        var current = element;

        foreach (var segment in path)
        {
            if (current.ValueKind != JsonValueKind.Object ||
                !current.TryGetProperty(segment, out var next))
            {
                return Array.Empty<string>();
            }

            current = next;
        }

        if (current.ValueKind == JsonValueKind.Array)
        {
            return current.EnumerateArray()
                .Where(e => e.ValueKind == JsonValueKind.String)
                .Select(e => e.GetString()!)
                .ToArray();
        }

        if (current.ValueKind == JsonValueKind.String)
        {
            return new[] { current.GetString()! };
        }

        return Array.Empty<string>();
    }

    private static string[] ParseJsonStringArray(string json)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            if (doc.RootElement.ValueKind == JsonValueKind.Array)
            {
                return doc.RootElement.EnumerateArray()
                    .Where(e => e.ValueKind == JsonValueKind.String)
                    .Select(e => e.GetString()!)
                    .ToArray();
            }
        }
        catch (JsonException)
        {
            // Not valid JSON
        }

        return Array.Empty<string>();
    }

    /// <summary>
    /// Applies claim transform rules to a set of role values.
    /// Rules are applied in order; first match wins. Empty ToValue drops the value.
    /// Values with no matching rule pass through unchanged.
    /// </summary>
    /// <param name="values">The raw role values extracted from the token.</param>
    /// <param name="transforms">The transform rules from provider config.</param>
    /// <param name="providerId">Provider identifier used in log messages (not a claim value).</param>
    /// <param name="logger">Optional logger. When supplied, logs each transform application at Info
    /// and each role drop at Warning. Claim values from the token are NOT logged here (TASK-18);
    /// only transform rule properties (FromValue, ToValue) are emitted.</param>
    public static string[] ApplyTransforms(
        string[] values,
        IReadOnlyList<ClaimTransform>? transforms,
        string? providerId = null,
        ILogger? logger = null)
    {
        if (transforms == null || transforms.Count == 0)
        {
            return values;
        }

        var result = new List<string>(values.Length);
        foreach (var value in values)
        {
            var matched = false;
            foreach (var transform in transforms)
            {
                if (string.Equals(value, transform.FromValue, StringComparison.OrdinalIgnoreCase))
                {
                    matched = true;
                    if (!string.IsNullOrWhiteSpace(transform.ToValue))
                    {
                        result.Add(transform.ToValue);
                        logger?.LogInformation(
                            "Transform applied: provider={Provider} from={From} to={To} (role={Role})",
                            providerId ?? "(unknown)", transform.FromValue, transform.ToValue, value);
                    }
                    else
                    {
                        // Empty/whitespace ToValue is an intentional role-drop (deny-list).
                        logger?.LogWarning(
                            "Transform dropped role={Role} via empty To (provider={Provider} from={From})",
                            value, providerId ?? "(unknown)", transform.FromValue);
                    }

                    break;
                }
            }

            if (!matched)
            {
                result.Add(value);
            }
        }

        return result.ToArray();
    }

    private static string Base64UrlDecode(string input)
    {
        var padded = input.Replace('-', '+').Replace('_', '/');
        switch (padded.Length % 4)
        {
            case 2: padded += "=="; break;
            case 3: padded += "="; break;
        }

        var bytes = Convert.FromBase64String(padded);
        return System.Text.Encoding.UTF8.GetString(bytes);
    }
}
