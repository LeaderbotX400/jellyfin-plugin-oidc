using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
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

    /// <summary>Issuer of the accepted assertion (after validation against configured IdP EntityID).</summary>
    public string Issuer { get; init; } = string.Empty;

    /// <summary>Assertion ID — surfaced for replay-cache integration by the caller.</summary>
    public string AssertionId { get; init; } = string.Empty;

    /// <summary>NotOnOrAfter from the assertion Conditions (UTC). Always populated — missing rejects.</summary>
    public DateTimeOffset NotOnOrAfter { get; init; }
}

/// <summary>
/// Per-request parameters that the ACS endpoint must supply so the response can be validated
/// against this specific in-flight authentication exchange.
/// </summary>
public sealed class SamlResponseValidationContext
{
    /// <summary>The ACS URL that the IdP POST'd to (used for Destination + Recipient checks).</summary>
    public required string AcsUrl { get; init; }

    /// <summary>
    /// The AuthnRequest ID we issued when initiating SP-initiated SSO, retrieved from the RelayState
    /// round-trip. <c>null</c> for IdP-initiated flows (only accepted when
    /// <see cref="SamlProviderConfig.AllowIdpInitiated"/> is true).
    /// </summary>
    public string? ExpectedInResponseTo { get; init; }
}

/// <summary>
/// Parses and validates SAML 2.0 Response messages (HTTP-POST binding).
/// Security: XXE blocked + size/entity caps, signature verified against IdP certificate, time
/// conditions enforced, XSW mitigated by anchoring extraction to the signed element, algorithm
/// allowlist enforced, Issuer/Audience/Destination/Recipient/InResponseTo/SubjectConfirmation
/// validated against the request context.
/// </summary>
public static class SamlResponse
{
    private const string AssertionNs = "urn:oasis:names:tc:SAML:2.0:assertion";
    private const string ProtocolNs = "urn:oasis:names:tc:SAML:2.0:protocol";
    private const string BearerMethod = "urn:oasis:names:tc:SAML:2.0:cm:bearer";
    private const int MaxClockSkewSeconds = 30;

    // XML parser caps — keep aligned with SamlController's payload cap. A 256 KB base64-decoded
    // payload is ~190 KB of XML; 1 MiB of characters covers comfortably-decompressed payloads
    // without admitting megabyte-scale entity bombs.
    private const int MaxXmlCharacters = 1_048_576;

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
        SamlResponseValidationContext context,
        ILogger logger)
    {
        ArgumentNullException.ThrowIfNull(provider);
        ArgumentNullException.ThrowIfNull(context);

        // Fail closed: an empty IdP cert means we cannot verify the assertion's authenticity.
        // Allowing this would let any attacker POST a forged unsigned assertion and authenticate
        // as anyone. Reject up front rather than emitting a "warning and continue".
        if (string.IsNullOrWhiteSpace(provider.IdpCertificate))
        {
            throw new InvalidOperationException(
                "SAML provider is misconfigured: IdpCertificate is required to verify response signatures.");
        }

        if (string.IsNullOrWhiteSpace(context.AcsUrl))
        {
            throw new InvalidOperationException("SAML validation context is missing the ACS URL.");
        }

        byte[] xmlBytes;
        try
        {
            xmlBytes = Convert.FromBase64String(samlResponseBase64);
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException("SAMLResponse is not valid base64", ex);
        }

        var doc = LoadXmlSecure(xmlBytes);

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

        // ── Response-level checks (anchored to document root, not descendant axis) ───────────
        var responseEl = doc.SelectSingleNode("/samlp:Response", nsMgr) as XmlElement
            ?? throw new InvalidOperationException("SAML response: missing Response element.");

        var statusCode = responseEl.SelectSingleNode("./samlp:Status/samlp:StatusCode", nsMgr)?
            .Attributes?["Value"]?.Value;
        if (!string.Equals(statusCode, "urn:oasis:names:tc:SAML:2.0:status:Success", StringComparison.Ordinal))
        {
            throw new InvalidOperationException($"IdP returned non-success status: {statusCode}");
        }

        // Destination — when present, must equal the ACS URL the IdP POST'd to. SAML core makes
        // it mandatory for signed responses (which is the only kind we accept), but historically
        // some IdPs omit it; reject the omission rather than silently accepting a response that
        // could have been replayed against a different endpoint.
        var destination = responseEl.GetAttribute("Destination");
        if (string.IsNullOrEmpty(destination))
        {
            throw new InvalidOperationException("SAML response is missing required Destination attribute.");
        }
        if (!UrlEquals(destination, context.AcsUrl))
        {
            throw new InvalidOperationException(
                $"SAML response Destination '{destination}' does not match ACS URL '{context.AcsUrl}'.");
        }

        // Response-level Issuer (when present) must match. The assertion-level Issuer below is the
        // authoritative one; a mismatch on the outer wrapper is still a misconfiguration / attack.
        var responseIssuer = responseEl.SelectSingleNode("./saml:Issuer", nsMgr)?.InnerText?.Trim();
        if (!string.IsNullOrEmpty(responseIssuer) && !string.IsNullOrEmpty(provider.IdpEntityId) &&
            !string.Equals(responseIssuer, provider.IdpEntityId, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                $"SAML response Issuer '{responseIssuer}' does not match configured IdpEntityId.");
        }

        // InResponseTo on the Response: validates against our stashed request ID. Missing means
        // IdP-initiated, which requires explicit opt-in.
        var responseInResponseTo = responseEl.GetAttribute("InResponseTo");
        ValidateInResponseTo(responseInResponseTo, context.ExpectedInResponseTo, provider.AllowIdpInitiated,
            "Response/@InResponseTo");

        // ── Assertion-level checks ───────────────────────────────────────────────────────────
        var assertionId = signedAssertion.GetAttribute("ID");
        if (string.IsNullOrEmpty(assertionId))
        {
            throw new InvalidOperationException("SAML assertion is missing required ID attribute.");
        }

        var assertionIssuer = signedAssertion.SelectSingleNode("./saml:Issuer", nsMgr)?.InnerText?.Trim() ?? string.Empty;
        if (string.IsNullOrEmpty(assertionIssuer))
        {
            throw new InvalidOperationException("SAML assertion is missing required Issuer element.");
        }
        if (!string.IsNullOrEmpty(provider.IdpEntityId) &&
            !string.Equals(assertionIssuer, provider.IdpEntityId, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                $"SAML assertion Issuer '{assertionIssuer}' does not match configured IdpEntityId '{provider.IdpEntityId}'.");
        }

        // Subject + SubjectConfirmation (bearer): tie this assertion to *this* SP, *this* ACS,
        // and *this* request, and apply the SubjectConfirmationData time bounds.
        var subjectConfirmation = signedAssertion.SelectSingleNode(
            "./saml:Subject/saml:SubjectConfirmation", nsMgr) as XmlElement
            ?? throw new InvalidOperationException("SAML assertion is missing required SubjectConfirmation.");

        var method = subjectConfirmation.GetAttribute("Method");
        if (!string.Equals(method, BearerMethod, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                $"SAML SubjectConfirmation Method '{method}' is not the required bearer method.");
        }

        var subjectConfirmationData = subjectConfirmation.SelectSingleNode(
            "./saml:SubjectConfirmationData", nsMgr) as XmlElement
            ?? throw new InvalidOperationException(
                "SAML assertion is missing required SubjectConfirmationData (bearer).");

        var recipient = subjectConfirmationData.GetAttribute("Recipient");
        if (string.IsNullOrEmpty(recipient))
        {
            throw new InvalidOperationException("SAML SubjectConfirmationData is missing required Recipient.");
        }
        if (!UrlEquals(recipient, context.AcsUrl))
        {
            throw new InvalidOperationException(
                $"SAML SubjectConfirmationData Recipient '{recipient}' does not match ACS URL '{context.AcsUrl}'.");
        }

        var scdInResponseTo = subjectConfirmationData.GetAttribute("InResponseTo");
        ValidateInResponseTo(scdInResponseTo, context.ExpectedInResponseTo, provider.AllowIdpInitiated,
            "SubjectConfirmationData/@InResponseTo");

        var scdNotOnOrAfterStr = subjectConfirmationData.GetAttribute("NotOnOrAfter");
        if (string.IsNullOrEmpty(scdNotOnOrAfterStr))
        {
            throw new InvalidOperationException(
                "SAML SubjectConfirmationData is missing required NotOnOrAfter.");
        }
        var scdNotOnOrAfter = ParseSamlInstant(scdNotOnOrAfterStr, "SubjectConfirmationData/@NotOnOrAfter");
        if (DateTimeOffset.UtcNow >= scdNotOnOrAfter + TimeSpan.FromSeconds(MaxClockSkewSeconds))
        {
            throw new InvalidOperationException(
                $"SAML SubjectConfirmationData has expired (NotOnOrAfter: {scdNotOnOrAfterStr}).");
        }

        // NotBefore on SubjectConfirmationData is optional; honor it when present.
        var scdNotBeforeStr = subjectConfirmationData.GetAttribute("NotBefore");
        if (!string.IsNullOrEmpty(scdNotBeforeStr))
        {
            var scdNotBefore = ParseSamlInstant(scdNotBeforeStr, "SubjectConfirmationData/@NotBefore");
            if (DateTimeOffset.UtcNow < scdNotBefore - TimeSpan.FromSeconds(MaxClockSkewSeconds))
            {
                throw new InvalidOperationException(
                    $"SAML SubjectConfirmationData is not yet valid (NotBefore: {scdNotBeforeStr}).");
            }
        }

        // Conditions: NotBefore/NotOnOrAfter + AudienceRestriction. NotOnOrAfter is required.
        var assertionNotOnOrAfter = ValidateConditions(signedAssertion, nsMgr, provider.EntityId);

        // ── Extract claims (anchored to the signed assertion only) ──────────────────────────
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
            Attributes = attributes,
            Issuer = assertionIssuer,
            AssertionId = assertionId,
            NotOnOrAfter = assertionNotOnOrAfter
        };
    }

    private static XmlDocument LoadXmlSecure(byte[] xmlBytes)
    {
        // PreserveWhitespace is required so SignedXml.CheckSignature canonicalizes the same bytes
        // the IdP signed. The locked-down XmlReader still applies: DtdProcessing.Prohibit kills
        // XXE, MaxCharactersInDocument and MaxCharactersFromEntities cap the parse cost.
        var doc = new XmlDocument { PreserveWhitespace = true };
        var settings = new XmlReaderSettings
        {
            DtdProcessing = DtdProcessing.Prohibit,
            XmlResolver = null,
            MaxCharactersInDocument = MaxXmlCharacters,
            MaxCharactersFromEntities = 0,
            CloseInput = true,
        };
        try
        {
            using var stream = new MemoryStream(xmlBytes, writable: false);
            using var reader = XmlReader.Create(stream, settings);
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
        else if (uri.StartsWith('#'))
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

    /// <summary>
    /// Validates time conditions + AudienceRestriction on the signed assertion. Returns the parsed
    /// NotOnOrAfter as a UTC <see cref="DateTimeOffset"/> so the caller can feed the replay cache.
    /// </summary>
    private static DateTimeOffset ValidateConditions(
        XmlElement assertion, XmlNamespaceManager nsMgr, string spEntityId)
    {
        var conditions = assertion.SelectSingleNode("./saml:Conditions", nsMgr) as XmlElement
            ?? throw new InvalidOperationException("SAML assertion is missing required Conditions element.");

        // NotOnOrAfter is required — without it the assertion never expires, which is unsafe.
        var notOnOrAfterStr = conditions.GetAttribute("NotOnOrAfter");
        if (string.IsNullOrEmpty(notOnOrAfterStr))
        {
            throw new InvalidOperationException("SAML assertion Conditions is missing required NotOnOrAfter.");
        }
        var notOnOrAfter = ParseSamlInstant(notOnOrAfterStr, "Conditions/@NotOnOrAfter");

        var now = DateTimeOffset.UtcNow;
        if (now >= notOnOrAfter + TimeSpan.FromSeconds(MaxClockSkewSeconds))
        {
            throw new InvalidOperationException(
                $"SAML assertion has expired (NotOnOrAfter: {notOnOrAfterStr}).");
        }

        var notBeforeStr = conditions.GetAttribute("NotBefore");
        if (!string.IsNullOrEmpty(notBeforeStr))
        {
            var notBefore = ParseSamlInstant(notBeforeStr, "Conditions/@NotBefore");
            if (now < notBefore - TimeSpan.FromSeconds(MaxClockSkewSeconds))
            {
                throw new InvalidOperationException(
                    $"SAML assertion is not valid yet (NotBefore: {notBeforeStr}).");
            }
        }

        // AudienceRestriction: at least one Audience must match the configured SP EntityID.
        // (Skipped when no SP EntityID is configured — initial-setup convenience; flagged in docs.)
        if (!string.IsNullOrEmpty(spEntityId))
        {
            var audienceNodes = conditions.SelectNodes(
                "./saml:AudienceRestriction/saml:Audience", nsMgr);
            if (audienceNodes == null || audienceNodes.Count == 0)
            {
                throw new InvalidOperationException(
                    "SAML assertion Conditions is missing required AudienceRestriction/Audience.");
            }

            var matched = false;
            foreach (XmlNode aud in audienceNodes)
            {
                var value = aud.InnerText?.Trim();
                if (string.Equals(value, spEntityId, StringComparison.Ordinal))
                {
                    matched = true;
                    break;
                }
            }

            if (!matched)
            {
                throw new InvalidOperationException(
                    $"SAML assertion AudienceRestriction does not include configured SP EntityID '{spEntityId}'.");
            }
        }

        return notOnOrAfter;
    }

    private static void ValidateInResponseTo(
        string actual, string? expected, bool allowIdpInitiated, string fieldDescription)
    {
        if (string.IsNullOrEmpty(actual))
        {
            // No InResponseTo at all — this is an IdP-initiated assertion. Reject unless the
            // operator has explicitly opted in via the provider config.
            if (expected != null)
            {
                throw new InvalidOperationException(
                    $"SAML response is missing {fieldDescription} but a SP-initiated request was in flight.");
            }
            if (!allowIdpInitiated)
            {
                throw new InvalidOperationException(
                    $"SAML response has no {fieldDescription}: IdP-initiated SSO is disabled for this provider.");
            }
            return;
        }

        // InResponseTo is present: must match our stashed request ID.
        if (expected == null)
        {
            throw new InvalidOperationException(
                $"SAML response carries {fieldDescription}='{actual}' but no SP-initiated request is in flight.");
        }
        if (!string.Equals(actual, expected, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                $"SAML response {fieldDescription} '{actual}' does not match expected request ID '{expected}'.");
        }
    }

    /// <summary>
    /// Parse a SAML "dateTime" instant, treating any input — Z-suffixed, offset, or naive — as UTC.
    /// SAML core requires UTC, but real-world IdPs occasionally emit naive timestamps; treating
    /// those as UTC (rather than local) keeps validation deterministic across deployments.
    /// </summary>
    private static DateTimeOffset ParseSamlInstant(string value, string fieldName)
    {
        if (!DateTimeOffset.TryParse(
                value,
                CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                out var parsed))
        {
            throw new InvalidOperationException(
                $"SAML {fieldName} is not a valid dateTime: '{value}'.");
        }
        return parsed;
    }

    private static bool UrlEquals(string a, string b)
    {
        // SAML Recipient/Destination matching is "string equality" per spec but real-world
        // deployments suffer from trailing-slash and case-of-host mismatches that break loginat
        // without weakening security. We compare with Uri normalization (lowercase scheme/host,
        // identical path/query) so https://host/Acs == https://HOST/Acs == https://host:443/Acs.
        // Trailing slashes are NOT normalized away — they're meaningful in the spec, and a
        // misconfigured IdP that includes one against an ACS that doesn't (or vice versa) is
        // a real misconfiguration that should be surfaced loudly.
        if (string.Equals(a, b, StringComparison.Ordinal)) return true;
        if (!Uri.TryCreate(a, UriKind.Absolute, out var ua) ||
            !Uri.TryCreate(b, UriKind.Absolute, out var ub))
        {
            return false;
        }
        return string.Equals(ua.Scheme, ub.Scheme, StringComparison.OrdinalIgnoreCase) &&
               string.Equals(ua.Host, ub.Host, StringComparison.OrdinalIgnoreCase) &&
               ua.Port == ub.Port &&
               string.Equals(ua.AbsolutePath, ub.AbsolutePath, StringComparison.Ordinal) &&
               string.Equals(ua.Query, ub.Query, StringComparison.Ordinal);
    }
}
