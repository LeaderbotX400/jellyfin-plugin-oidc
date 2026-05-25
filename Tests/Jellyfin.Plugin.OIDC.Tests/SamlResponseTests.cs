using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;
using Jellyfin.Plugin.OIDC.Configuration;
using Jellyfin.Plugin.OIDC.Saml;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Jellyfin.Plugin.OIDC.Tests;

public class SamlResponseTests
{
    // Shared self-signed certificate used to sign the test SAML responses.
    private static readonly (X509Certificate2 Cert, RSA Key, string PemB64) Signer = CreateSigner();

    private const string AcsUrl = "https://jellyfin.test/sso/SAML/ACS/saml-test";
    private const string IdpEntityId = "https://idp.example.com";
    private const string SpEntityId = "https://jellyfin.test";
    private const string RequestId = "_req-abc";
    private const string AssertionId = "_assert1";

    private static SamlResponseValidationContext SpContext(string? expectedRequestId = RequestId) => new()
    {
        AcsUrl = AcsUrl,
        ExpectedInResponseTo = expectedRequestId
    };

    private static SamlProviderConfig MakeProvider(bool allowIdpInitiated = false) => new()
    {
        Id = "saml-test",
        IdpCertificate = Signer.PemB64,
        IdpEntityId = IdpEntityId,
        EntityId = SpEntityId,
        UsernameClaim = "NameID",
        RoleClaim = "groups",
        AllowIdpInitiated = allowIdpInitiated
    };

    private static string ToBase64(string xml) =>
        Convert.ToBase64String(Encoding.UTF8.GetBytes(xml));

    private static (X509Certificate2, RSA, string) CreateSigner()
    {
        var rsa = RSA.Create(2048);
        var req = new CertificateRequest(
            "CN=test-idp.example.com",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        var pemB64 = Convert.ToBase64String(cert.Export(X509ContentType.Cert));
        return (cert, rsa, pemB64);
    }

    /// <summary>
    /// Builder for SAML test responses. Defaults match a valid SP-initiated bearer assertion
    /// against the canonical Acs/Entity/RequestId constants. Mutate fields to construct
    /// negative-test variants without rewriting the entire XML each time.
    /// </summary>
    private sealed class ResponseBuilder
    {
        public string Destination { get; set; } = AcsUrl;
        public string? ResponseInResponseTo { get; set; } = RequestId;
        public string ResponseIssuer { get; set; } = IdpEntityId;
        public string AssertionIssuer { get; set; } = IdpEntityId;
        public string SubjectConfirmationMethod { get; set; } = "urn:oasis:names:tc:SAML:2.0:cm:bearer";
        public string? Recipient { get; set; } = AcsUrl;
        public string? ScdInResponseTo { get; set; } = RequestId;
        public string? ScdNotOnOrAfter { get; set; } = "2099-12-31T23:59:59Z";
        public string? Audience { get; set; } = SpEntityId;
        public string? ConditionsNotOnOrAfter { get; set; } = "2099-12-31T23:59:59Z";
        public string? ConditionsNotBefore { get; set; } = "2020-01-01T00:00:00Z";
        public string NameId { get; set; } = "alice";
        public string AssertionIdValue { get; set; } = AssertionId;
        public string StatusCode { get; set; } = "urn:oasis:names:tc:SAML:2.0:status:Success";
        public string SigAlg { get; set; } = SignedXml.XmlDsigRSASHA256Url;
        public string DigestAlg { get; set; } = "http://www.w3.org/2001/04/xmlenc#sha256";
        public string? ExtraInsideResponse { get; set; }

        public string BuildXml()
        {
            var sb = new StringBuilder();
            sb.Append("<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_resp1\" Version=\"2.0\" IssueInstant=\"2025-01-01T00:00:00Z\"");
            sb.Append(" Destination=\"").Append(Destination).Append('"');
            if (ResponseInResponseTo != null) sb.Append(" InResponseTo=\"").Append(ResponseInResponseTo).Append('"');
            sb.Append('>');
            sb.Append("<saml:Issuer>").Append(ResponseIssuer).Append("</saml:Issuer>");
            sb.Append("<samlp:Status><samlp:StatusCode Value=\"").Append(StatusCode).Append("\"/></samlp:Status>");

            sb.Append("<saml:Assertion ID=\"").Append(AssertionIdValue).Append("\" Version=\"2.0\" IssueInstant=\"2025-01-01T00:00:00Z\">");
            sb.Append("<saml:Issuer>").Append(AssertionIssuer).Append("</saml:Issuer>");

            sb.Append("<saml:Subject>");
            sb.Append("<saml:NameID Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified\">").Append(NameId).Append("</saml:NameID>");
            sb.Append("<saml:SubjectConfirmation Method=\"").Append(SubjectConfirmationMethod).Append("\">");
            sb.Append("<saml:SubjectConfirmationData");
            if (Recipient != null) sb.Append(" Recipient=\"").Append(Recipient).Append('"');
            if (ScdInResponseTo != null) sb.Append(" InResponseTo=\"").Append(ScdInResponseTo).Append('"');
            if (ScdNotOnOrAfter != null) sb.Append(" NotOnOrAfter=\"").Append(ScdNotOnOrAfter).Append('"');
            sb.Append("/>");
            sb.Append("</saml:SubjectConfirmation>");
            sb.Append("</saml:Subject>");

            sb.Append("<saml:Conditions");
            if (ConditionsNotBefore != null) sb.Append(" NotBefore=\"").Append(ConditionsNotBefore).Append('"');
            if (ConditionsNotOnOrAfter != null) sb.Append(" NotOnOrAfter=\"").Append(ConditionsNotOnOrAfter).Append('"');
            sb.Append('>');
            if (Audience != null)
            {
                sb.Append("<saml:AudienceRestriction><saml:Audience>").Append(Audience).Append("</saml:Audience></saml:AudienceRestriction>");
            }
            sb.Append("</saml:Conditions>");

            sb.Append("<saml:AttributeStatement>");
            sb.Append("<saml:Attribute Name=\"groups\"><saml:AttributeValue>admin</saml:AttributeValue><saml:AttributeValue>viewers</saml:AttributeValue></saml:Attribute>");
            sb.Append("<saml:Attribute Name=\"email\"><saml:AttributeValue>alice@example.com</saml:AttributeValue></saml:Attribute>");
            sb.Append("</saml:AttributeStatement>");
            sb.Append("</saml:Assertion>");
            if (ExtraInsideResponse != null) sb.Append(ExtraInsideResponse);
            sb.Append("</samlp:Response>");
            return sb.ToString();
        }

        public string BuildSigned()
        {
            var doc = new XmlDocument { PreserveWhitespace = true };
            doc.LoadXml(BuildXml());
            SignElement(doc, AssertionIdValue, SigAlg, DigestAlg);
            return doc.OuterXml;
        }
    }

    private static string ValidResponse() => new ResponseBuilder().BuildSigned();

    private static void SignElement(XmlDocument doc, string id, string sigAlg, string digestAlg)
    {
        var target = FindById(doc.DocumentElement!, id)
            ?? throw new InvalidOperationException($"No element with ID={id}");
        var signedXml = new SignedXml(doc) { SigningKey = Signer.Key };
        signedXml.SignedInfo!.SignatureMethod = sigAlg;
        signedXml.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;

        var reference = new Reference("#" + id) { DigestMethod = digestAlg };
        reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
        reference.AddTransform(new XmlDsigExcC14NTransform());
        signedXml.AddReference(reference);

        signedXml.ComputeSignature();
        var sigElement = signedXml.GetXml();
        target.InsertBefore(doc.ImportNode(sigElement, true), target.FirstChild);
    }

    private static XmlElement? FindById(XmlElement el, string id)
    {
        if (string.Equals(el.GetAttribute("ID"), id, StringComparison.Ordinal)) return el;
        foreach (XmlNode child in el.ChildNodes)
        {
            if (child is XmlElement ce)
            {
                var f = FindById(ce, id);
                if (f != null) return f;
            }
        }
        return null;
    }

    // ── Happy path ───────────────────────────────────────────────────────────────────────

    [Fact]
    public void Parse_ValidSignedResponse_Succeeds()
    {
        var assertion = SamlResponse.Parse(ToBase64(ValidResponse()), MakeProvider(), SpContext(), NullLogger.Instance);
        Assert.Equal("alice", assertion.NameId);
        Assert.Equal(IdpEntityId, assertion.Issuer);
        Assert.Equal(AssertionId, assertion.AssertionId);
        Assert.Contains("admin", assertion.Roles);
        Assert.Equal("alice@example.com", assertion.Attributes["email"][0]);
        Assert.True(assertion.NotOnOrAfter > DateTimeOffset.UtcNow);
    }

    // ── Empty / misconfigured ────────────────────────────────────────────────────────────

    [Fact]
    public void Parse_EmptyCertificate_Rejects()
    {
        var provider = MakeProvider();
        provider.IdpCertificate = string.Empty;
        var ex = Assert.Throws<InvalidOperationException>(() =>
            SamlResponse.Parse(ToBase64(ValidResponse()), provider, SpContext(), NullLogger.Instance));
        Assert.Contains("IdpCertificate", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Parse_WhitespaceCertificate_Rejects()
    {
        var provider = MakeProvider();
        provider.IdpCertificate = "   \n\t  ";
        Assert.Throws<InvalidOperationException>(() =>
            SamlResponse.Parse(ToBase64(ValidResponse()), provider, SpContext(), NullLogger.Instance));
    }

    [Fact]
    public void Parse_MissingAcsUrl_Throws()
    {
        var ctx = new SamlResponseValidationContext { AcsUrl = string.Empty, ExpectedInResponseTo = RequestId };
        Assert.Throws<InvalidOperationException>(() =>
            SamlResponse.Parse(ToBase64(ValidResponse()), MakeProvider(), ctx, NullLogger.Instance));
    }

    // ── Identity / destination ───────────────────────────────────────────────────────────

    [Fact]
    public void Parse_IssuerMismatch_Rejects()
    {
        var xml = new ResponseBuilder { AssertionIssuer = "https://evil.example.com" }.BuildSigned();
        var ex = Assert.Throws<InvalidOperationException>(() =>
            SamlResponse.Parse(ToBase64(xml), MakeProvider(), SpContext(), NullLogger.Instance));
        Assert.Contains("Issuer", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Parse_ResponseIssuerMismatch_Rejects()
    {
        var xml = new ResponseBuilder { ResponseIssuer = "https://evil.example.com" }.BuildSigned();
        Assert.Throws<InvalidOperationException>(() =>
            SamlResponse.Parse(ToBase64(xml), MakeProvider(), SpContext(), NullLogger.Instance));
    }

    [Fact]
    public void Parse_DestinationMismatch_Rejects()
    {
        var xml = new ResponseBuilder { Destination = "https://other.test/acs" }.BuildSigned();
        var ex = Assert.Throws<InvalidOperationException>(() =>
            SamlResponse.Parse(ToBase64(xml), MakeProvider(), SpContext(), NullLogger.Instance));
        Assert.Contains("Destination", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Parse_MissingDestination_Rejects()
    {
        // Strip Destination by building XML then editing it (the builder doesn't expose omission)
        var xml = new ResponseBuilder().BuildXml().Replace($" Destination=\"{AcsUrl}\"", string.Empty, StringComparison.Ordinal);
        var doc = new XmlDocument { PreserveWhitespace = true };
        doc.LoadXml(xml);
        SignElement(doc, AssertionId, SignedXml.XmlDsigRSASHA256Url, "http://www.w3.org/2001/04/xmlenc#sha256");
        Assert.Throws<InvalidOperationException>(() =>
            SamlResponse.Parse(ToBase64(doc.OuterXml), MakeProvider(), SpContext(), NullLogger.Instance));
    }

    [Fact]
    public void Parse_AudienceMismatch_Rejects()
    {
        var xml = new ResponseBuilder { Audience = "https://other.test" }.BuildSigned();
        var ex = Assert.Throws<InvalidOperationException>(() =>
            SamlResponse.Parse(ToBase64(xml), MakeProvider(), SpContext(), NullLogger.Instance));
        Assert.Contains("Audience", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Parse_MissingAudience_Rejects()
    {
        var xml = new ResponseBuilder { Audience = null }.BuildSigned();
        Assert.Throws<InvalidOperationException>(() =>
            SamlResponse.Parse(ToBase64(xml), MakeProvider(), SpContext(), NullLogger.Instance));
    }

    [Fact]
    public void Parse_RecipientMismatch_Rejects()
    {
        var xml = new ResponseBuilder { Recipient = "https://other.test/acs" }.BuildSigned();
        var ex = Assert.Throws<InvalidOperationException>(() =>
            SamlResponse.Parse(ToBase64(xml), MakeProvider(), SpContext(), NullLogger.Instance));
        Assert.Contains("Recipient", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    // ── SubjectConfirmation method ──────────────────────────────────────────────────────

    [Fact]
    public void Parse_NonBearerSubjectConfirmation_Rejects()
    {
        var xml = new ResponseBuilder
        {
            SubjectConfirmationMethod = "urn:oasis:names:tc:SAML:2.0:cm:holder-of-key"
        }.BuildSigned();
        var ex = Assert.Throws<InvalidOperationException>(() =>
            SamlResponse.Parse(ToBase64(xml), MakeProvider(), SpContext(), NullLogger.Instance));
        Assert.Contains("bearer", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    // ── InResponseTo / IdP-initiated ────────────────────────────────────────────────────

    [Fact]
    public void Parse_MissingInResponseTo_RejectsWhenSpInitiated()
    {
        var xml = new ResponseBuilder { ResponseInResponseTo = null, ScdInResponseTo = null }.BuildSigned();
        var ex = Assert.Throws<InvalidOperationException>(() =>
            SamlResponse.Parse(ToBase64(xml), MakeProvider(), SpContext(), NullLogger.Instance));
        Assert.Contains("InResponseTo", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Parse_InResponseToMismatch_Rejects()
    {
        var xml = new ResponseBuilder { ResponseInResponseTo = "_attacker", ScdInResponseTo = "_attacker" }.BuildSigned();
        var ex = Assert.Throws<InvalidOperationException>(() =>
            SamlResponse.Parse(ToBase64(xml), MakeProvider(), SpContext(), NullLogger.Instance));
        Assert.Contains("InResponseTo", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Parse_ScdInResponseToMismatch_Rejects()
    {
        // Response/@InResponseTo matches, but SubjectConfirmationData/@InResponseTo doesn't.
        // Both must agree with the stored request ID.
        var xml = new ResponseBuilder { ScdInResponseTo = "_attacker" }.BuildSigned();
        Assert.Throws<InvalidOperationException>(() =>
            SamlResponse.Parse(ToBase64(xml), MakeProvider(), SpContext(), NullLogger.Instance));
    }

    [Fact]
    public void Parse_IdpInitiated_AllowedWhenConfigured()
    {
        var xml = new ResponseBuilder { ResponseInResponseTo = null, ScdInResponseTo = null }.BuildSigned();
        var ctx = new SamlResponseValidationContext { AcsUrl = AcsUrl, ExpectedInResponseTo = null };
        var assertion = SamlResponse.Parse(
            ToBase64(xml), MakeProvider(allowIdpInitiated: true), ctx, NullLogger.Instance);
        Assert.Equal("alice", assertion.NameId);
    }

    [Fact]
    public void Parse_IdpInitiated_RejectedByDefault()
    {
        var xml = new ResponseBuilder { ResponseInResponseTo = null, ScdInResponseTo = null }.BuildSigned();
        var ctx = new SamlResponseValidationContext { AcsUrl = AcsUrl, ExpectedInResponseTo = null };
        Assert.Throws<InvalidOperationException>(() =>
            SamlResponse.Parse(ToBase64(xml), MakeProvider(), ctx, NullLogger.Instance));
    }

    [Fact]
    public void Parse_InResponseToPresentButNoExpectedRequest_Rejects()
    {
        // The IdP carries an InResponseTo but we have no in-flight request. Reject — possible
        // replay of an old assertion across a state-cache restart.
        var xml = new ResponseBuilder().BuildSigned();
        var ctx = new SamlResponseValidationContext { AcsUrl = AcsUrl, ExpectedInResponseTo = null };
        Assert.Throws<InvalidOperationException>(() =>
            SamlResponse.Parse(ToBase64(xml), MakeProvider(allowIdpInitiated: true), ctx, NullLogger.Instance));
    }

    // ── Conditions / NotOnOrAfter ───────────────────────────────────────────────────────

    [Fact]
    public void Parse_MissingNotOnOrAfter_Rejects()
    {
        var xml = new ResponseBuilder { ConditionsNotOnOrAfter = null }.BuildSigned();
        var ex = Assert.Throws<InvalidOperationException>(() =>
            SamlResponse.Parse(ToBase64(xml), MakeProvider(), SpContext(), NullLogger.Instance));
        Assert.Contains("NotOnOrAfter", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Parse_ExpiredConditions_Rejects()
    {
        var xml = new ResponseBuilder { ConditionsNotOnOrAfter = "2000-01-01T00:00:00Z" }.BuildSigned();
        Assert.Throws<InvalidOperationException>(() =>
            SamlResponse.Parse(ToBase64(xml), MakeProvider(), SpContext(), NullLogger.Instance));
    }

    [Fact]
    public void Parse_NotYetValidConditions_Rejects()
    {
        var xml = new ResponseBuilder { ConditionsNotBefore = "2099-01-01T00:00:00Z" }.BuildSigned();
        Assert.Throws<InvalidOperationException>(() =>
            SamlResponse.Parse(ToBase64(xml), MakeProvider(), SpContext(), NullLogger.Instance));
    }

    [Fact]
    public void Parse_ScdMissingNotOnOrAfter_Rejects()
    {
        var xml = new ResponseBuilder { ScdNotOnOrAfter = null }.BuildSigned();
        Assert.Throws<InvalidOperationException>(() =>
            SamlResponse.Parse(ToBase64(xml), MakeProvider(), SpContext(), NullLogger.Instance));
    }

    [Fact]
    public void Parse_ScdExpired_Rejects()
    {
        var xml = new ResponseBuilder { ScdNotOnOrAfter = "2000-01-01T00:00:00Z" }.BuildSigned();
        Assert.Throws<InvalidOperationException>(() =>
            SamlResponse.Parse(ToBase64(xml), MakeProvider(), SpContext(), NullLogger.Instance));
    }

    [Fact]
    public void Parse_NaiveDateTimeTreatedAsUtc()
    {
        // Timestamp without timezone in the *future* — must be interpreted as UTC, not local.
        // A naive timestamp interpreted as local time would be off by hours and could either
        // expire prematurely or extend validity across the wrong window.
        var farFuture = DateTime.UtcNow.AddHours(2).ToString("yyyy-MM-ddTHH:mm:ss", System.Globalization.CultureInfo.InvariantCulture);
        var xml = new ResponseBuilder
        {
            ConditionsNotOnOrAfter = farFuture,
            ScdNotOnOrAfter = farFuture,
            ConditionsNotBefore = "2020-01-01T00:00:00"
        }.BuildSigned();
        var assertion = SamlResponse.Parse(ToBase64(xml), MakeProvider(), SpContext(), NullLogger.Instance);
        Assert.Equal("alice", assertion.NameId);
        // The parsed NotOnOrAfter must be UTC, within ~2 hours of now.
        Assert.True(assertion.NotOnOrAfter > DateTimeOffset.UtcNow);
        Assert.True(assertion.NotOnOrAfter < DateTimeOffset.UtcNow.AddHours(3));
    }

    // ── XSW / wrapping ───────────────────────────────────────────────────────────────────

    [Fact]
    public void Parse_XSW_TwoAssertions_Rejects()
    {
        var attackerAssertion =
            "<saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_attacker\" Version=\"2.0\" IssueInstant=\"2025-01-01T00:00:00Z\">" +
            "<saml:Issuer>https://idp.example.com</saml:Issuer>" +
            "<saml:Subject><saml:NameID>eve</saml:NameID></saml:Subject>" +
            "</saml:Assertion>";
        var xml = new ResponseBuilder { ExtraInsideResponse = attackerAssertion }.BuildSigned();
        var ex = Assert.Throws<InvalidOperationException>(() =>
            SamlResponse.Parse(ToBase64(xml), MakeProvider(), SpContext(), NullLogger.Instance));
        Assert.Contains("multiple Assertion", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Parse_Sha1Signature_Rejects()
    {
        var xml = new ResponseBuilder
        {
            SigAlg = SignedXml.XmlDsigRSASHA1Url,
            DigestAlg = SignedXml.XmlDsigSHA1Url
        }.BuildSigned();
        var ex = Assert.Throws<InvalidOperationException>(() =>
            SamlResponse.Parse(ToBase64(xml), MakeProvider(), SpContext(), NullLogger.Instance));
        Assert.Contains("disallowed", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Parse_EncryptedAssertion_Rejects()
    {
        var encrypted =
            "<saml:EncryptedAssertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">" +
            "<xenc:EncryptedData xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\" Type=\"http://www.w3.org/2001/04/xmlenc#Element\">" +
            "<xenc:CipherData><xenc:CipherValue>ZmFrZQ==</xenc:CipherValue></xenc:CipherData>" +
            "</xenc:EncryptedData></saml:EncryptedAssertion>";
        var xml = new ResponseBuilder { ExtraInsideResponse = encrypted }.BuildSigned();
        var ex = Assert.Throws<InvalidOperationException>(() =>
            SamlResponse.Parse(ToBase64(xml), MakeProvider(), SpContext(), NullLogger.Instance));
        Assert.Contains("EncryptedAssertion", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Parse_NoSignature_Rejects()
    {
        var xml = new ResponseBuilder().BuildXml(); // unsigned
        var ex = Assert.Throws<InvalidOperationException>(() =>
            SamlResponse.Parse(ToBase64(xml), MakeProvider(), SpContext(), NullLogger.Instance));
        Assert.Contains("Signature", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Parse_TamperedAssertion_Rejects()
    {
        var doc = new XmlDocument { PreserveWhitespace = true };
        doc.LoadXml(new ResponseBuilder().BuildXml());
        SignElement(doc, AssertionId, SignedXml.XmlDsigRSASHA256Url, "http://www.w3.org/2001/04/xmlenc#sha256");
        var nameId = doc.GetElementsByTagName("NameID", "urn:oasis:names:tc:SAML:2.0:assertion")[0]!;
        nameId.InnerText = "eve";

        Assert.Throws<InvalidOperationException>(() =>
            SamlResponse.Parse(ToBase64(doc.OuterXml), MakeProvider(), SpContext(), NullLogger.Instance));
    }

    [Fact]
    public void Parse_FailureStatus_Throws()
    {
        var xml = new ResponseBuilder
        {
            StatusCode = "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed"
        }.BuildSigned();
        Assert.Throws<InvalidOperationException>(() =>
            SamlResponse.Parse(ToBase64(xml), MakeProvider(), SpContext(), NullLogger.Instance));
    }

    [Fact]
    public void Parse_InvalidBase64_Throws()
    {
        Assert.Throws<InvalidOperationException>(() =>
            SamlResponse.Parse("not-valid-base64!!!", MakeProvider(), SpContext(), NullLogger.Instance));
    }

    [Fact]
    public void Parse_XxeBlocked_Throws()
    {
        var xxe = "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\"><samlp:Status><samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/></samlp:Status></samlp:Response>";
        Assert.Throws<InvalidOperationException>(() =>
            SamlResponse.Parse(ToBase64(xxe), MakeProvider(), SpContext(), NullLogger.Instance));
    }
}
