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
/// Security: XXE blocked, signature verified against IdP certificate, time conditions enforced,
/// XSW mitigated by anchoring extraction to the signed element, algorithm allowlist enforced.
/// </summary>
public static class SamlResponse
{
    private const string AssertionNs = "urn:oasis:names:tc:SAML:2.0:assertion";
    private const string ProtocolNs = "urn:oasis:names:tc:SAML:2.0:protocol";

    // Allowlists: explicitly reject SHA-1 and other weak algorithms.
    private static readonly HashSet<string> AllowedSignatureMethods = new(StringComparer.Ordinal)
    {
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384",
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512",
        "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256",
        "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384",
        "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512",
    };

    private static readonly HashSet<string> AllowedDigestMethods = new(StringComparer.Ordinal)
    {
        "http://www.w3.org/2001/04/xmlenc#sha256",
        "http://www.w3.org/2001/04/xmldsig-more#sha384",
        "http://www.w3.org/2001/04/xmlenc#sha512",
    };

    private static readonly HashSet<string> AllowedTransforms = new(StringComparer.Ordinal)
    {
        "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
        "http://www.w3.org/2001/10/xml-exc-c14n#",
        "http://www.w3.org/2001/10/xml-exc-c14n#WithComments",
    };

    /// <summary>
    /// Parses and validates a base64-encoded SAML Response.
    /// Throws <see cref="InvalidOperationException"/> on validation failure.
    /// </summary>
    public static ParsedSamlAssertion Parse(
        string samlResponseBase64,
        SamlProviderConfig provider,
        ILogger logger)
    {
        if (provider is null)
        {
            throw new ArgumentNullException(nameof(provider));
        }

        // Fail closed: an empty IdP cert means we cannot verify the assertion's authenticity.
        // Allowing this would let any attacker POST a forged unsigned assertion and authenticate
        // as anyone. Reject up front rather than emitting a "warning and continue".
        if (string.IsNullOrWhiteSpace(provider.IdpCertificate))
        {
            throw new InvalidOperationException(
                "SAML provider is misconfigured: IdpCertificate is required to verify response signatures.");
        }

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

        var nsMgr = new XmlNamespaceManager(doc.NameTable);
        nsMgr.AddNamespace("saml", AssertionNs);
        nsMgr.AddNamespace("samlp", ProtocolNs);

        // Reject EncryptedAssertion (not supported and would otherwise be silently ignored).
        if (doc.GetElementsByTagName("EncryptedAssertion", AssertionNs).Count > 0)
        {
            throw new InvalidOperationException(
                "SAML response contains EncryptedAssertion which is not supported by this plugin.");
        }

        // Reject multiple assertions (XSW vector).
        var assertionNodes = doc.GetElementsByTagName("Assertion", AssertionNs);
        if (assertionNodes.Count == 0)
        {
            throw new InvalidOperationException("SAML response contains no Assertion element");
        }
        if (assertionNodes.Count > 1)
        {
            throw new InvalidOperationException(
                "SAML response contains multiple Assertion elements (possible signature-wrapping attack).");
        }

        // Verify signature and anchor extraction to the signed element.
        var signedRoot = VerifySignature(doc, provider.IdpCertificate, logger);

        // Resolve the assertion to use for downstream extraction. The signed element must be
        // either the Response itself (in which case the single assertion within it is trusted),
        // or the Assertion element directly.
        XmlElement signedAssertion;
        if (string.Equals(signedRoot.LocalName, "Response", StringComparison.Ordinal) &&
            string.Equals(signedRoot.NamespaceURI, ProtocolNs, StringComparison.Ordinal))
        {
            // Signed root is the Response; its lone child Assertion is what we'll consume.
            signedAssertion = (XmlElement)assertionNodes[0]!;
            // Anchor: ensure the assertion is a direct descendant of the signed Response.
            if (!IsDescendantOf(signedAssertion, signedRoot))
            {
                throw new InvalidOperationException(
                    "SAML response: assertion is not contained within the signed Response element.");
            }
        }
        else if (string.Equals(signedRoot.LocalName, "Assertion", StringComparison.Ordinal) &&
                 string.Equals(signedRoot.NamespaceURI, AssertionNs, StringComparison.Ordinal))
        {
            signedAssertion = signedRoot;
            // The doc's single assertion must be the very same node that was signed.
            if (!ReferenceEquals(assertionNodes[0], signedRoot))
            {
                throw new InvalidOperationException(
                    "SAML response: signed Assertion does not match the document's Assertion element.");
            }
        }
        else
        {
            throw new InvalidOperationException(
                $"SAML response: signed element <{signedRoot.LocalName}> is neither a Response nor an Assertion.");
        }

        // Status: anchored to the document root (Response), not descendant-axis.
        var statusCode = doc.SelectSingleNode(
            "/samlp:Response/samlp:Status/samlp:StatusCode", nsMgr)?
            .Attributes?["Value"]?.Value;
        if (!string.Equals(statusCode, "urn:oasis:names:tc:SAML:2.0:status:Success", StringComparison.Ordinal))
        {
            throw new InvalidOperationException($"IdP returned non-success status: {statusCode}");
        }

        ValidateConditions(signedAssertion, nsMgr);

        // Anchored extraction from the signed assertion only.
        var nameId = signedAssertion.SelectSingleNode(
            "./saml:Subject/saml:NameID", nsMgr)?.InnerText?.Trim() ?? string.Empty;

        var attributes = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase);
        var attrNodes = signedAssertion.SelectNodes(
            "./saml:AttributeStatement/saml:Attribute", nsMgr);

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

    /// <summary>
    /// Verifies the response signature against the configured IdP certificate.
    /// Returns the element that was actually signed (Response or Assertion) so callers can
    /// anchor downstream extraction to that exact element and avoid XSW.
    /// </summary>
    private static XmlElement VerifySignature(XmlDocument doc, string certificatePem, ILogger logger)
    {
        // Caller is responsible for the empty-cert fail-closed check.
        var sigElements = doc.GetElementsByTagName("Signature", SignedXml.XmlDsigNamespaceUrl);
        if (sigElements.Count == 0)
        {
            throw new InvalidOperationException("SAML response contains no Signature element");
        }
        if (sigElements.Count > 1)
        {
            throw new InvalidOperationException(
                "SAML response contains multiple Signature elements (possible signature-wrapping attack).");
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

        var sigElement = (XmlElement)sigElements[0]!;
        var signedXml = new SignedXml(doc);
        signedXml.LoadXml(sigElement);

        // Algorithm allowlist — enforced BEFORE crypto verification so an attacker can't even
        // attempt to exploit weak primitives.
        var sigMethod = signedXml.SignedInfo?.SignatureMethod ?? string.Empty;
        if (!AllowedSignatureMethods.Contains(sigMethod))
        {
            throw new InvalidOperationException(
                $"SAML response uses disallowed signature algorithm: {sigMethod}");
        }

        if (signedXml.SignedInfo!.References.Count != 1)
        {
            throw new InvalidOperationException(
                $"SAML response must have exactly one signed Reference; found {signedXml.SignedInfo.References.Count}.");
        }

        var reference = (Reference)signedXml.SignedInfo.References[0]!;
        if (!AllowedDigestMethods.Contains(reference.DigestMethod ?? string.Empty))
        {
            throw new InvalidOperationException(
                $"SAML response uses disallowed digest algorithm: {reference.DigestMethod}");
        }

        foreach (Transform tx in reference.TransformChain)
        {
            if (!AllowedTransforms.Contains(tx.Algorithm ?? string.Empty))
            {
                throw new InvalidOperationException(
                    $"SAML response uses disallowed transform: {tx.Algorithm}");
            }
        }

        if (!signedXml.CheckSignature(cert, verifySignatureOnly: true))
        {
            throw new InvalidOperationException("SAML response signature is invalid");
        }

        // Resolve the URI to the actual signed element. An empty URI means "the whole document"
        // (the document root). A "#id" URI must resolve to an element with that ID.
        var uri = reference.Uri ?? string.Empty;
        XmlElement signedRoot;
        if (uri.Length == 0)
        {
            signedRoot = doc.DocumentElement ??
                throw new InvalidOperationException("SAML response has no document element.");
        }
        else if (uri.StartsWith("#", StringComparison.Ordinal))
        {
            var id = uri.Substring(1);
            signedRoot = FindElementById(doc, id) ??
                throw new InvalidOperationException(
                    $"SAML response signature references unknown element ID: {id}");
        }
        else
        {
            throw new InvalidOperationException(
                $"SAML response signature uses unsupported external reference URI: {uri}");
        }

        return signedRoot;
    }

    /// <summary>Locate an element by its convention-named "ID" attribute.</summary>
    /// <remarks>
    /// SAML uses an "ID" attribute by convention rather than via DTD/schema declaration, so
    /// <see cref="XmlDocument.GetElementById"/> won't find it without a schema. We walk the tree
    /// instead — small documents, negligible cost.
    /// </remarks>
    private static XmlElement? FindElementById(XmlDocument doc, string id)
    {
        if (doc.DocumentElement == null) return null;
        return FindByIdRecursive(doc.DocumentElement, id);
    }

    private static XmlElement? FindByIdRecursive(XmlElement element, string id)
    {
        if (string.Equals(element.GetAttribute("ID"), id, StringComparison.Ordinal))
        {
            return element;
        }
        foreach (XmlNode child in element.ChildNodes)
        {
            if (child is XmlElement childEl)
            {
                var found = FindByIdRecursive(childEl, id);
                if (found != null) return found;
            }
        }
        return null;
    }

    private static bool IsDescendantOf(XmlNode node, XmlNode ancestor)
    {
        for (var p = node.ParentNode; p != null; p = p.ParentNode)
        {
            if (ReferenceEquals(p, ancestor)) return true;
        }
        return false;
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

    private static void ValidateConditions(XmlElement assertion, XmlNamespaceManager nsMgr)
    {
        var conditions = assertion.SelectSingleNode("./saml:Conditions", nsMgr);
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
