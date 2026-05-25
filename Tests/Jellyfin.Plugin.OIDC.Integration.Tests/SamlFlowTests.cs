using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Threading.Tasks;
using System.Xml;
using Jellyfin.Data;
using Jellyfin.Database.Implementations.Enums;
using Jellyfin.Plugin.OIDC.Api;
using Jellyfin.Plugin.OIDC.Configuration;
using Microsoft.AspNetCore.Mvc;
using Xunit;

namespace Jellyfin.Plugin.OIDC.Integration.Tests;

/// <summary>
/// End-to-end tests for the SAML 2.0 ACS endpoint. Uses an unsigned-but-shaped SAML
/// response (no IdP certificate configured → signature verification is skipped) so we
/// can exercise the full XML parse → user provision → Jellyfin auth pipeline without
/// pulling in a real SAML signer.
/// </summary>
public sealed class SamlFlowTests : IClassFixture<MockIdpFixture>
{
    private readonly MockIdpFixture _idp;
    public SamlFlowTests(MockIdpFixture idp) => _idp = idp;

    private const string ProviderId = "saml-test";

    // Shared self-signed cert used to sign the test SAML responses. Tests must call
    // AddSignedSamlProvider() to register a provider whose IdpCertificate trusts this signer.
    private static readonly (X509Certificate2 Cert, RSA Key, string PemB64) Signer = CreateSigner();

    private static (X509Certificate2, RSA, string) CreateSigner()
    {
        var rsa = RSA.Create(2048);
        var req = new CertificateRequest(
            "CN=integration-test-saml-signer",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        var pemB64 = Convert.ToBase64String(cert.Export(X509ContentType.Cert));
        return (cert, rsa, pemB64);
    }

    private static SamlProviderConfig AddSignedSamlProvider(TestFixture fixture, string id = ProviderId)
    {
        var p = fixture.AddSamlProvider(id);
        p.IdpCertificate = Signer.PemB64;
        return p;
    }

    private static string SignAndEncode(string xml, string idToSign = "_assert1")
    {
        var doc = new XmlDocument { PreserveWhitespace = true };
        doc.LoadXml(xml);
        var signedXml = new SignedXml(doc) { SigningKey = Signer.Key };
        signedXml.SignedInfo!.SignatureMethod = SignedXml.XmlDsigRSASHA256Url;
        signedXml.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;
        var reference = new Reference { Uri = "#" + idToSign, DigestMethod = "http://www.w3.org/2001/04/xmlenc#sha256" };
        reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
        reference.AddTransform(new XmlDsigExcC14NTransform());
        signedXml.AddReference(reference);
        signedXml.ComputeSignature();
        var sig = signedXml.GetXml();
        // Insert the Signature element right after the Assertion's Issuer (SAML schema order).
        var assertion = doc.GetElementsByTagName("Assertion", "urn:oasis:names:tc:SAML:2.0:assertion")[0]!;
        var issuer = assertion.FirstChild!; // Issuer
        assertion.InsertAfter(doc.ImportNode(sig, true), issuer);
        return Convert.ToBase64String(Encoding.UTF8.GetBytes(doc.OuterXml));
    }

    // Minimal SAML response, signed with the shared test signer.
    private static string BuildSamlResponse(string nameId, IEnumerable<string> roles, string? email = null)
        => SignAndEncode(BuildSamlResponseXml(nameId, roles, email));

    private static string BuildSamlResponseXml(string nameId, IEnumerable<string> roles, string? email = null)
    {
        var sb = new StringBuilder();
        sb.AppendLine($@"<samlp:Response xmlns:samlp=""urn:oasis:names:tc:SAML:2.0:protocol"" xmlns:saml=""urn:oasis:names:tc:SAML:2.0:assertion"" ID=""_resp1"" Version=""2.0"" IssueInstant=""2025-01-01T00:00:00Z"">");
        sb.AppendLine(@"  <samlp:Status><samlp:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Success""/></samlp:Status>");
        sb.AppendLine(@"  <saml:Assertion ID=""_assert1"" Version=""2.0"" IssueInstant=""2025-01-01T00:00:00Z"">");
        sb.AppendLine(@"    <saml:Issuer>https://idp.example.com</saml:Issuer>");
        sb.AppendLine(@"    <saml:Subject>");
        sb.AppendLine($@"      <saml:NameID Format=""urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"">{nameId}</saml:NameID>");
        sb.AppendLine(@"    </saml:Subject>");
        sb.AppendLine(@"    <saml:Conditions NotBefore=""2020-01-01T00:00:00Z"" NotOnOrAfter=""2099-12-31T23:59:59Z""/>");
        sb.AppendLine(@"    <saml:AttributeStatement>");
        sb.AppendLine(@"      <saml:Attribute Name=""groups"">");
        foreach (var r in roles)
        {
            sb.AppendLine($@"        <saml:AttributeValue>{r}</saml:AttributeValue>");
        }

        sb.AppendLine(@"      </saml:Attribute>");
        if (email != null)
        {
            sb.AppendLine($@"      <saml:Attribute Name=""email""><saml:AttributeValue>{email}</saml:AttributeValue></saml:Attribute>");
        }

        sb.AppendLine(@"    </saml:AttributeStatement>");
        sb.AppendLine(@"  </saml:Assertion>");
        sb.AppendLine(@"</samlp:Response>");
        return sb.ToString();
    }

    [Fact]
    public async Task AcsFlow_ValidResponse_ProvisionsUserAndApplliesRoles()
    {
        var fixture = new TestFixture(_idp);
        AddSignedSamlProvider(fixture);
        fixture.ConfigProvider.Configuration.RoleMappings = new List<RoleMapping>
        {
            new() { RoleName = "admin", IsAdmin = true }
        };

        var samlResponse = BuildSamlResponse(nameId: "saml-user-1", roles: new[] { "admin" }, email: "samluser@example.com");
        var acsResult = await fixture.SamlController.AssertionConsumerService(
            ProviderId, samlResponse, relayState: null);
        var content = Assert.IsType<ContentResult>(acsResult);

        // The ACS returns an HTML page that POSTs back to /sso/SAML/Auth/{providerId}
        // Drive that next step manually to verify user provisioning + RBAC application
        var token = ExtractSessionToken(content);
        var authResult = await fixture.SamlController.Authenticate(
            ProviderId, new AuthenticateRequest { Token = token });
        Assert.IsType<OkObjectResult>(authResult);

        var user = fixture.UserStore.GetByName("saml-user-1");
        Assert.NotNull(user);
        Assert.Contains(user!.Permissions, p => p.Kind == PermissionKind.IsAdministrator && p.Value);
    }

    [Fact]
    public async Task AcsFlow_UnknownProvider_Returns404()
    {
        var fixture = new TestFixture(_idp);
        var samlResponse = BuildSamlResponse(nameId: "nobody", roles: Array.Empty<string>());
        var result = await fixture.SamlController.AssertionConsumerService(
            "nonexistent-provider", samlResponse, relayState: null);
        Assert.IsType<NotFoundObjectResult>(result);
    }

    [Fact]
    public async Task AcsFlow_ExpiredAssertion_Returns400()
    {
        var fixture = new TestFixture(_idp);
        AddSignedSamlProvider(fixture);

        // Build a response with NotOnOrAfter in the past, then sign it.
        var expiredXml = BuildSamlResponseXml(nameId: "alice", roles: new[] { "user" })
            .Replace("2099-12-31T23:59:59Z", "2000-01-01T00:00:00Z", StringComparison.Ordinal);
        var expired = SignAndEncode(expiredXml);

        var result = await fixture.SamlController.AssertionConsumerService(
            ProviderId, expired, relayState: null);
        Assert.IsType<BadRequestObjectResult>(result);
    }

    [Fact]
    public async Task AcsFlow_MissingSamlResponse_Returns400()
    {
        var fixture = new TestFixture(_idp);
        AddSignedSamlProvider(fixture);
        var result = await fixture.SamlController.AssertionConsumerService(
            ProviderId, samlResponse: string.Empty, relayState: null);
        Assert.IsType<BadRequestObjectResult>(result);
    }

    private static string ExtractSessionToken(ContentResult content)
    {
        const string marker = "const token = '";
        var idx = content.Content!.IndexOf(marker, StringComparison.Ordinal);
        var start = idx + marker.Length;
        var end = content.Content.IndexOf('\'', start);
        return content.Content.Substring(start, end - start);
    }
}

internal static class StringPipe
{
    public static T Pipe<T>(this string s, Func<string, T> f) => f(s);
}
