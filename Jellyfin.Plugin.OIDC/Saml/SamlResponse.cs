using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;
using Jellyfin.Plugin.OIDC.Configuration;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.OIDC.Saml;

public sealed class ParsedSamlAssertion
{
    public string NameId { get; init; } = string.Empty;
    public string[] Roles { get; init; } = Array.Empty<string>();
    public IReadOnlyDictionary<string, string[]> Attributes { get; init; } =
        new Dictionary<string, string[]>();
}

/// <summary>
/// Parses and validates SAML 2.0 Response messages (HTTP-POST binding).
/// Security: XXE blocked, signature verified against IdP certificate, time conditions enforced.
/// </summary>
public static class SamlResponse
{
    private const string AssertionNs = "urn:oasis:names:tc:SAML:2.0:assertion";
    private const string ProtocolNs = "urn:oasis:names:tc:SAML:2.0:protocol";

    /// <summary>
    /// Parses and validates a base64-encoded SAML Response.
    /// Throws <see cref="InvalidOperationException"/> on validation failure.
    /// </summary>
    public static ParsedSamlAssertion Parse(
        string samlResponseBase64,
        SamlProviderConfig provider,
        ILogger logger)
    {
        string xml;
        try
        {
            xml = Encoding.UTF8.GetString(Convert.FromBase64String(samlResponseBase64));
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException("SAMLResponse is not valid base64", ex);
        }

        var doc = LoadXmlSecure(xml);
        VerifySignature(doc, provider.IdpCertificate, logger);

        var nsMgr = new XmlNamespaceManager(doc.NameTable);
        nsMgr.AddNamespace("saml", AssertionNs);
        nsMgr.AddNamespace("samlp", ProtocolNs);

        // Verify top-level status
        var statusCode = doc.SelectSingleNode(
            "//samlp:Response/samlp:Status/samlp:StatusCode", nsMgr)?
            .Attributes?["Value"]?.Value;
        if (!string.Equals(statusCode, "urn:oasis:names:tc:SAML:2.0:status:Success", StringComparison.Ordinal))
        {
            throw new InvalidOperationException($"IdP returned non-success status: {statusCode}");
        }

        ValidateConditions(doc, nsMgr);

        // Extract NameID
        var nameId = doc.SelectSingleNode(
            "//saml:Assertion/saml:Subject/saml:NameID", nsMgr)?.InnerText?.Trim() ?? string.Empty;

        // Extract attributes
        var attributes = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase);
        var attrNodes = doc.SelectNodes(
            "//saml:Assertion/saml:AttributeStatement/saml:Attribute", nsMgr);

        if (attrNodes != null)
        {
            foreach (XmlNode attrNode in attrNodes)
            {
                var attrName = attrNode.Attributes?["Name"]?.Value;
                if (string.IsNullOrEmpty(attrName)) continue;

                var values = new List<string>();
                foreach (XmlNode child in attrNode.ChildNodes)
                {
                    var val = child.InnerText?.Trim();
                    if (!string.IsNullOrEmpty(val))
                    {
                        values.Add(val);
                    }
                }

                attributes[attrName] = values.ToArray();
            }
        }

        var roles = attributes.TryGetValue(provider.RoleClaim, out var roleValues)
            ? roleValues
            : Array.Empty<string>();

        return new ParsedSamlAssertion
        {
            NameId = nameId,
            Roles = roles,
            Attributes = attributes
        };
    }

    private static XmlDocument LoadXmlSecure(string xml)
    {
        var doc = new XmlDocument { PreserveWhitespace = true };
        var settings = new XmlReaderSettings
        {
            DtdProcessing = DtdProcessing.Prohibit,
            XmlResolver = null
        };
        try
        {
            using var reader = XmlReader.Create(new System.IO.StringReader(xml), settings);
            doc.Load(reader);
        }
        catch (XmlException ex)
        {
            throw new InvalidOperationException("SAMLResponse contains invalid or prohibited XML", ex);
        }

        return doc;
    }

    private static void VerifySignature(XmlDocument doc, string certificatePem, ILogger logger)
    {
        if (string.IsNullOrWhiteSpace(certificatePem))
        {
            // No cert configured — warn but allow (useful during initial setup)
            logger.LogWarning("SAML: No IdP certificate configured — signature verification skipped. Configure IdpCertificate for production use.");
            return;
        }

        var sigElements = doc.GetElementsByTagName("Signature", SignedXml.XmlDsigNamespaceUrl);
        if (sigElements.Count == 0)
        {
            throw new InvalidOperationException("SAML response contains no Signature element");
        }

        X509Certificate2 cert;
        try
        {
            cert = LoadCertificate(certificatePem);
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException("Failed to load IdP certificate", ex);
        }

        foreach (XmlElement sigElement in sigElements)
        {
            var signedXml = new SignedXml(doc);
            signedXml.LoadXml(sigElement);
            if (!signedXml.CheckSignature(cert, verifySignatureOnly: true))
            {
                throw new InvalidOperationException("SAML response signature is invalid");
            }
        }
    }

    private static X509Certificate2 LoadCertificate(string pem)
    {
        var cleaned = pem
            .Replace("-----BEGIN CERTIFICATE-----", string.Empty, StringComparison.Ordinal)
            .Replace("-----END CERTIFICATE-----", string.Empty, StringComparison.Ordinal)
            .Replace("\n", string.Empty, StringComparison.Ordinal)
            .Replace("\r", string.Empty, StringComparison.Ordinal)
            .Trim();
        return X509CertificateLoader.LoadCertificate(Convert.FromBase64String(cleaned));
    }

    private static void ValidateConditions(XmlDocument doc, XmlNamespaceManager nsMgr)
    {
        var conditions = doc.SelectSingleNode("//saml:Assertion/saml:Conditions", nsMgr);
        if (conditions == null) return;

        var now = DateTime.UtcNow;

        var notBefore = conditions.Attributes?["NotBefore"]?.Value;
        if (notBefore != null &&
            DateTime.TryParse(notBefore, null, System.Globalization.DateTimeStyles.RoundtripKind, out var nb) &&
            now < nb.AddSeconds(-30))
        {
            throw new InvalidOperationException($"SAML assertion is not valid yet (NotBefore: {notBefore})");
        }

        var notOnOrAfter = conditions.Attributes?["NotOnOrAfter"]?.Value;
        if (notOnOrAfter != null &&
            DateTime.TryParse(notOnOrAfter, null, System.Globalization.DateTimeStyles.RoundtripKind, out var noa) &&
            now >= noa.AddSeconds(30))
        {
            throw new InvalidOperationException($"SAML assertion has expired (NotOnOrAfter: {notOnOrAfter})");
        }
    }
}
