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

    private const string AssertionXml = """
        <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_assert1" Version="2.0" IssueInstant="2025-01-01T00:00:00Z">
            <saml:Issuer>https://idp.example.com</saml:Issuer>
            <saml:Subject>
                <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">alice</saml:NameID>
            </saml:Subject>
            <saml:Conditions NotBefore="2020-01-01T00:00:00Z" NotOnOrAfter="2099-12-31T23:59:59Z" />
            <saml:AttributeStatement>
                <saml:Attribute Name="groups">
                    <saml:AttributeValue>admin</saml:AttributeValue>
                    <saml:AttributeValue>viewers</saml:AttributeValue>
                </saml:Attribute>
                <saml:Attribute Name="email">
                    <saml:AttributeValue>alice@example.com</saml:AttributeValue>
                </saml:Attribute>
            </saml:AttributeStatement>
        </saml:Assertion>
        """;

    private const string ResponseTemplate = """
        <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_resp1" Version="2.0" IssueInstant="2025-01-01T00:00:00Z">
            <samlp:Status>
                <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
            </samlp:Status>
            {ASSERTION}
        </samlp:Response>
        """;

    private static SamlProviderConfig MakeProvider() => new()
    {
        IdpCertificate = Signer.PemB64,
        UsernameClaim = "NameID",
        RoleClaim = "groups"
    };

    private static string ToBase64(string xml) =>
        Convert.ToBase64String(Encoding.UTF8.GetBytes(xml));

    /// <summary>Build a Response wrapping the canonical assertion, then sign the assertion in place.</summary>
    private static string BuildSignedResponse(string assertionXml = AssertionXml, string idToSign = "_assert1",
        string sigAlg = SignedXml.XmlDsigRSASHA256Url, string digestAlg = "http://www.w3.org/2001/04/xmlenc#sha256")
    {
        var xml = ResponseTemplate.Replace("{ASSERTION}", assertionXml, StringComparison.Ordinal);
        var doc = new XmlDocument { PreserveWhitespace = true };
        doc.LoadXml(xml);
        SignElementInPlace(doc, idToSign, sigAlg, digestAlg);
        return doc.OuterXml;
    }

    /// <summary>Locate element by convention "ID" attribute and embed an enveloped signature.</summary>
    private static void SignElementInPlace(XmlDocument doc, string id, string sigAlg, string digestAlg)
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

        // Insert signature as first child of the target (SAML convention: directly after Issuer,
        // but anywhere inside the signed element is fine for this test since the enveloped-sig
        // transform strips it before digest).
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

    [Fact]
    public void Parse_ValidSignedSingleAssertion_Succeeds()
    {
        var xml = BuildSignedResponse();
        var assertion = SamlResponse.Parse(ToBase64(xml), MakeProvider(), NullLogger.Instance);
        Assert.Equal("alice", assertion.NameId);
        Assert.Contains("admin", assertion.Roles);
        Assert.Contains("viewers", assertion.Roles);
        Assert.True(assertion.Attributes.ContainsKey("email"));
        Assert.Equal("alice@example.com", assertion.Attributes["email"][0]);
    }

    [Fact]
    public void Parse_EmptyCertificate_Rejects()
    {
        // Fail closed: an empty IdpCertificate must throw, NOT skip signature verification.
        var provider = new SamlProviderConfig
        {
            IdpCertificate = string.Empty,
            UsernameClaim = "NameID",
            RoleClaim = "groups"
        };
        var xml = BuildSignedResponse();
        var ex = Assert.Throws<InvalidOperationException>(() =>
            SamlResponse.Parse(ToBase64(xml), provider, NullLogger.Instance));
        Assert.Contains("IdpCertificate", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Parse_WhitespaceCertificate_Rejects()
    {
        var provider = new SamlProviderConfig
        {
            IdpCertificate = "   \n\t  ",
            UsernameClaim = "NameID",
            RoleClaim = "groups"
        };
        var xml = BuildSignedResponse();
        Assert.Throws<InvalidOperationException>(() =>
            SamlResponse.Parse(ToBase64(xml), provider, NullLogger.Instance));
    }

    [Fact]
    public void Parse_XSW_TwoAssertions_Rejects()
    {
        // Classic XML Signature Wrapping: sign one assertion, then add a second unsigned
        // attacker-controlled assertion. The plugin must reject documents with more than one
        // <Assertion>.
        var attackerAssertion = AssertionXml
            .Replace("ID=\"_assert1\"", "ID=\"_attacker\"", StringComparison.Ordinal)
            .Replace(">alice<", ">eve<", StringComparison.Ordinal);
        var xml = ResponseTemplate.Replace(
            "{ASSERTION}",
            AssertionXml + "\n" + attackerAssertion,
            StringComparison.Ordinal);
        var doc = new XmlDocument { PreserveWhitespace = true };
        doc.LoadXml(xml);
        SignElementInPlace(doc, "_assert1", SignedXml.XmlDsigRSASHA256Url, "http://www.w3.org/2001/04/xmlenc#sha256");
        var signed = doc.OuterXml;

        var ex = Assert.Throws<InvalidOperationException>(() =>
            SamlResponse.Parse(ToBase64(signed), MakeProvider(), NullLogger.Instance));
        Assert.Contains("multiple Assertion", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Parse_Sha1Signature_Rejects()
    {
        var xml = BuildSignedResponse(
            sigAlg: SignedXml.XmlDsigRSASHA1Url,
            digestAlg: SignedXml.XmlDsigSHA1Url);
        var ex = Assert.Throws<InvalidOperationException>(() =>
            SamlResponse.Parse(ToBase64(xml), MakeProvider(), NullLogger.Instance));
        Assert.Contains("disallowed", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Parse_EncryptedAssertion_Rejects()
    {
        // Build a response with an <EncryptedAssertion> in place of (or alongside) a normal one.
        // The plugin must refuse rather than silently ignoring it.
        var encrypted = """
            <saml:EncryptedAssertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
                <xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" Type="http://www.w3.org/2001/04/xmlenc#Element">
                    <xenc:CipherData><xenc:CipherValue>ZmFrZQ==</xenc:CipherValue></xenc:CipherData>
                </xenc:EncryptedData>
            </saml:EncryptedAssertion>
            """;
        var xml = ResponseTemplate.Replace("{ASSERTION}", AssertionXml + encrypted, StringComparison.Ordinal);
        var doc = new XmlDocument { PreserveWhitespace = true };
        doc.LoadXml(xml);
        SignElementInPlace(doc, "_assert1", SignedXml.XmlDsigRSASHA256Url, "http://www.w3.org/2001/04/xmlenc#sha256");

        var ex = Assert.Throws<InvalidOperationException>(() =>
            SamlResponse.Parse(ToBase64(doc.OuterXml), MakeProvider(), NullLogger.Instance));
        Assert.Contains("EncryptedAssertion", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Parse_NoSignature_Rejects()
    {
        // No signature element at all; cert is configured → must reject.
        var xml = ResponseTemplate.Replace("{ASSERTION}", AssertionXml, StringComparison.Ordinal);
        var ex = Assert.Throws<InvalidOperationException>(() =>
            SamlResponse.Parse(ToBase64(xml), MakeProvider(), NullLogger.Instance));
        Assert.Contains("Signature", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Parse_TamperedAssertion_Rejects()
    {
        // Sign, then mutate the assertion → CheckSignature should fail.
        var doc = new XmlDocument { PreserveWhitespace = true };
        doc.LoadXml(ResponseTemplate.Replace("{ASSERTION}", AssertionXml, StringComparison.Ordinal));
        SignElementInPlace(doc, "_assert1", SignedXml.XmlDsigRSASHA256Url, "http://www.w3.org/2001/04/xmlenc#sha256");

        // Tamper: change NameID inner text.
        var nameId = doc.GetElementsByTagName("NameID", "urn:oasis:names:tc:SAML:2.0:assertion")[0]!;
        nameId.InnerText = "eve";

        Assert.Throws<InvalidOperationException>(() =>
            SamlResponse.Parse(ToBase64(doc.OuterXml), MakeProvider(), NullLogger.Instance));
    }

    [Fact]
    public void Parse_ExpiredAssertion_Throws()
    {
        var expired = AssertionXml.Replace(
            "NotOnOrAfter=\"2099-12-31T23:59:59Z\"",
            "NotOnOrAfter=\"2000-01-01T00:00:00Z\"",
            StringComparison.Ordinal);
        var xml = BuildSignedResponse(expired);
        Assert.Throws<InvalidOperationException>(() =>
            SamlResponse.Parse(ToBase64(xml), MakeProvider(), NullLogger.Instance));
    }

    [Fact]
    public void Parse_NotYetValidAssertion_Throws()
    {
        var future = AssertionXml.Replace(
            "NotBefore=\"2020-01-01T00:00:00Z\"",
            "NotBefore=\"2099-01-01T00:00:00Z\"",
            StringComparison.Ordinal);
        var xml = BuildSignedResponse(future);
        Assert.Throws<InvalidOperationException>(() =>
            SamlResponse.Parse(ToBase64(xml), MakeProvider(), NullLogger.Instance));
    }

    [Fact]
    public void Parse_FailureStatus_Throws()
    {
        // Status check must come AFTER signature verify; use a signed response with a non-success status.
        var doc = new XmlDocument { PreserveWhitespace = true };
        doc.LoadXml(ResponseTemplate.Replace("{ASSERTION}", AssertionXml, StringComparison.Ordinal));
        var statusCode = doc.GetElementsByTagName("StatusCode", "urn:oasis:names:tc:SAML:2.0:protocol")[0]!;
        statusCode.Attributes!["Value"]!.Value = "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed";
        SignElementInPlace(doc, "_assert1", SignedXml.XmlDsigRSASHA256Url, "http://www.w3.org/2001/04/xmlenc#sha256");

        Assert.Throws<InvalidOperationException>(() =>
            SamlResponse.Parse(ToBase64(doc.OuterXml), MakeProvider(), NullLogger.Instance));
    }

    [Fact]
    public void Parse_InvalidBase64_Throws()
    {
        Assert.Throws<InvalidOperationException>(() =>
            SamlResponse.Parse("not-valid-base64!!!", MakeProvider(), NullLogger.Instance));
    }

    [Fact]
    public void Parse_XxeBlocked_Throws()
    {
        var xxe = """<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status></samlp:Response>""";
        Assert.Throws<InvalidOperationException>(() =>
            SamlResponse.Parse(ToBase64(xxe), MakeProvider(), NullLogger.Instance));
    }
}
