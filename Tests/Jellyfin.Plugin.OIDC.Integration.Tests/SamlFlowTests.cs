using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using System.Xml;
using Jellyfin.Data;
using Jellyfin.Database.Implementations.Enums;
using Jellyfin.Plugin.OIDC.Api;
using Jellyfin.Plugin.OIDC.Configuration;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Xunit;

namespace Jellyfin.Plugin.OIDC.Integration.Tests;

/// <summary>
/// End-to-end tests for the SAML 2.0 ACS endpoint. Drives the full SP-initiated flow
/// (Start → IdP POSTs signed Response → ACS → Authenticate) so the new
/// Destination/Recipient/InResponseTo/Audience validation runs against real wiring.
/// </summary>
public sealed class SamlFlowTests : IClassFixture<MockIdpFixture>
{
    private readonly MockIdpFixture _idp;
    public SamlFlowTests(MockIdpFixture idp) => _idp = idp;

    private const string ProviderId = "saml-test";
    private const string IdpEntityId = "https://idp.example.com";
    private const string SpEntityId = "https://jellyfin.test";
    private const string AcsUrl = "https://jellyfin.test/sso/SAML/ACS/saml-test";

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

    /// <summary>
    /// Build a fully-shaped SAML Response (Destination, Issuer, InResponseTo, SubjectConfirmation
    /// bearer with Recipient + InResponseTo + NotOnOrAfter, Conditions with AudienceRestriction +
    /// NotOnOrAfter), sign the assertion, and return base64.
    /// </summary>
    private static string BuildAndSignResponse(string nameId, IEnumerable<string> roles, string requestId,
        string? email = null, string assertionId = "_assert1")
    {
        var groupValues = string.Join(string.Empty,
            roles.Select(r => $"<saml:AttributeValue>{r}</saml:AttributeValue>"));
        var emailAttr = email == null
            ? string.Empty
            : $"<saml:Attribute Name=\"email\"><saml:AttributeValue>{email}</saml:AttributeValue></saml:Attribute>";

        var xml =
            $"<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" " +
            $"ID=\"_resp1\" Version=\"2.0\" IssueInstant=\"2025-01-01T00:00:00Z\" Destination=\"{AcsUrl}\" InResponseTo=\"{requestId}\">" +
            $"<saml:Issuer>{IdpEntityId}</saml:Issuer>" +
            "<samlp:Status><samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/></samlp:Status>" +
            $"<saml:Assertion ID=\"{assertionId}\" Version=\"2.0\" IssueInstant=\"2025-01-01T00:00:00Z\">" +
            $"<saml:Issuer>{IdpEntityId}</saml:Issuer>" +
            "<saml:Subject>" +
            $"<saml:NameID Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified\">{nameId}</saml:NameID>" +
            "<saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\">" +
            $"<saml:SubjectConfirmationData Recipient=\"{AcsUrl}\" InResponseTo=\"{requestId}\" NotOnOrAfter=\"2099-12-31T23:59:59Z\"/>" +
            "</saml:SubjectConfirmation>" +
            "</saml:Subject>" +
            "<saml:Conditions NotBefore=\"2020-01-01T00:00:00Z\" NotOnOrAfter=\"2099-12-31T23:59:59Z\">" +
            $"<saml:AudienceRestriction><saml:Audience>{SpEntityId}</saml:Audience></saml:AudienceRestriction>" +
            "</saml:Conditions>" +
            "<saml:AttributeStatement>" +
            $"<saml:Attribute Name=\"groups\">{groupValues}</saml:Attribute>" +
            emailAttr +
            "</saml:AttributeStatement>" +
            "</saml:Assertion>" +
            "</samlp:Response>";

        var doc = new XmlDocument { PreserveWhitespace = true };
        doc.LoadXml(xml);
        SignAssertion(doc, assertionId);
        return Convert.ToBase64String(Encoding.UTF8.GetBytes(doc.OuterXml));
    }

    private static void SignAssertion(XmlDocument doc, string id)
    {
        var signedXml = new SignedXml(doc) { SigningKey = Signer.Key };
        signedXml.SignedInfo!.SignatureMethod = SignedXml.XmlDsigRSASHA256Url;
        signedXml.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;
        var reference = new Reference("#" + id) { DigestMethod = "http://www.w3.org/2001/04/xmlenc#sha256" };
        reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
        reference.AddTransform(new XmlDsigExcC14NTransform());
        signedXml.AddReference(reference);
        signedXml.ComputeSignature();
        var sig = signedXml.GetXml();

        var assertion = doc.GetElementsByTagName("Assertion", "urn:oasis:names:tc:SAML:2.0:assertion")[0]!;
        var issuer = assertion.FirstChild!;
        assertion.InsertAfter(doc.ImportNode(sig, true), issuer);
    }

    /// <summary>Drive Start → return the relayState the IdP would echo back, and the request ID.</summary>
    private static (string RelayState, string RequestId) InitiateSpFlow(TestFixture fixture)
    {
        var startResult = fixture.SamlController.Start(ProviderId);
        var redirect = Assert.IsType<RedirectResult>(startResult);
        var qs = HttpUtility.ParseQueryString(new Uri(redirect.Url).Query);
        var relayState = qs["RelayState"]!;
        // The state manager stashed the request ID as Nonce under the relayState key; we can read
        // it (without consuming) by going through the public API once the ACS hits. For the test
        // we know what BuildRedirectUrl included as an ID, but it's an opaque "_<guid>". Parse the
        // SAMLRequest deflated XML for the ID attribute.
        var samlRequestB64 = qs["SAMLRequest"]!;
        var requestId = ExtractRequestId(samlRequestB64);
        return (relayState, requestId);
    }

    private static string ExtractRequestId(string deflatedBase64)
    {
        var compressed = Convert.FromBase64String(deflatedBase64);
        using var inStream = new System.IO.MemoryStream(compressed);
        using var deflate = new System.IO.Compression.DeflateStream(inStream, System.IO.Compression.CompressionMode.Decompress);
        using var reader = new System.IO.StreamReader(deflate, Encoding.UTF8);
        var xml = reader.ReadToEnd();
        var doc = new XmlDocument();
        doc.LoadXml(xml);
        return doc.DocumentElement!.GetAttribute("ID");
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

        var (relayState, requestId) = InitiateSpFlow(fixture);

        var samlResponse = BuildAndSignResponse(
            nameId: "saml-user-1", roles: new[] { "admin" }, requestId: requestId, email: "samluser@example.com");
        var acsResult = await fixture.SamlController.AssertionConsumerService(
            ProviderId, samlResponse, relayState);
        var content = Assert.IsType<ContentResult>(acsResult);

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
        var samlResponse = BuildAndSignResponse(nameId: "nobody", roles: Array.Empty<string>(), requestId: "_x");
        var result = await fixture.SamlController.AssertionConsumerService(
            "nonexistent-provider", samlResponse, relayState: null);
        Assert.IsType<NotFoundObjectResult>(result);
    }

    [Fact]
    public async Task AcsFlow_ExpiredAssertion_Returns400()
    {
        var fixture = new TestFixture(_idp);
        AddSignedSamlProvider(fixture);
        var (relayState, requestId) = InitiateSpFlow(fixture);

        // Build a response then rewrite NotOnOrAfter to the past, then sign.
        var groupValues = "<saml:AttributeValue>user</saml:AttributeValue>";
        var xml =
            $"<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" " +
            $"ID=\"_resp1\" Version=\"2.0\" IssueInstant=\"2025-01-01T00:00:00Z\" Destination=\"{AcsUrl}\" InResponseTo=\"{requestId}\">" +
            $"<saml:Issuer>{IdpEntityId}</saml:Issuer>" +
            "<samlp:Status><samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/></samlp:Status>" +
            "<saml:Assertion ID=\"_assert1\" Version=\"2.0\" IssueInstant=\"2025-01-01T00:00:00Z\">" +
            $"<saml:Issuer>{IdpEntityId}</saml:Issuer>" +
            "<saml:Subject>" +
            "<saml:NameID>alice</saml:NameID>" +
            "<saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\">" +
            $"<saml:SubjectConfirmationData Recipient=\"{AcsUrl}\" InResponseTo=\"{requestId}\" NotOnOrAfter=\"2099-12-31T23:59:59Z\"/>" +
            "</saml:SubjectConfirmation>" +
            "</saml:Subject>" +
            "<saml:Conditions NotBefore=\"2020-01-01T00:00:00Z\" NotOnOrAfter=\"2000-01-01T00:00:00Z\">" +
            $"<saml:AudienceRestriction><saml:Audience>{SpEntityId}</saml:Audience></saml:AudienceRestriction>" +
            "</saml:Conditions>" +
            $"<saml:AttributeStatement><saml:Attribute Name=\"groups\">{groupValues}</saml:Attribute></saml:AttributeStatement>" +
            "</saml:Assertion>" +
            "</samlp:Response>";
        var doc = new XmlDocument { PreserveWhitespace = true };
        doc.LoadXml(xml);
        SignAssertion(doc, "_assert1");
        var expired = Convert.ToBase64String(Encoding.UTF8.GetBytes(doc.OuterXml));

        var result = await fixture.SamlController.AssertionConsumerService(
            ProviderId, expired, relayState);
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

    [Fact]
    public async Task AcsFlow_OversizedSamlResponse_Returns400()
    {
        var fixture = new TestFixture(_idp);
        AddSignedSamlProvider(fixture);
        // 300 KB junk — well over the 256 KB cap.
        var oversized = new string('A', 300 * 1024);
        var result = await fixture.SamlController.AssertionConsumerService(
            ProviderId, oversized, relayState: null);
        Assert.IsType<BadRequestObjectResult>(result);
    }

    [Fact]
    public async Task AcsFlow_MissingRelayState_RejectedByDefault()
    {
        var fixture = new TestFixture(_idp);
        AddSignedSamlProvider(fixture);
        // Even a well-formed response is rejected when RelayState is absent and AllowIdpInitiated
        // is off (default).
        var samlResponse = BuildAndSignResponse(nameId: "alice", roles: new[] { "user" }, requestId: "_x");
        var result = await fixture.SamlController.AssertionConsumerService(
            ProviderId, samlResponse, relayState: null);
        Assert.IsType<BadRequestObjectResult>(result);
    }

    [Fact]
    public async Task AcsFlow_ReplayedAssertion_Rejected()
    {
        var fixture = new TestFixture(_idp);
        AddSignedSamlProvider(fixture);

        // First submit: legitimate flow.
        var (relayState1, requestId1) = InitiateSpFlow(fixture);
        var saml1 = BuildAndSignResponse("alice", new[] { "user" }, requestId1, assertionId: "_assert-replay");
        var first = await fixture.SamlController.AssertionConsumerService(ProviderId, saml1, relayState1);
        Assert.IsType<ContentResult>(first);

        // Second submit: new SP-initiated request, but same captured AssertionID. The replay cache
        // must reject even though the cryptographic + validity checks would otherwise pass.
        var (relayState2, requestId2) = InitiateSpFlow(fixture);
        var saml2 = BuildAndSignResponse("alice", new[] { "user" }, requestId2, assertionId: "_assert-replay");
        var second = await fixture.SamlController.AssertionConsumerService(ProviderId, saml2, relayState2);
        Assert.IsType<BadRequestObjectResult>(second);
    }

    [Fact]
    public async Task AuthFlow_ValidToken_ReturnsRealJellyfinAccessToken()
    {
        var fixture = new TestFixture(_idp);
        AddSignedSamlProvider(fixture);

        var (relayState, requestId) = InitiateSpFlow(fixture);
        var samlResponse = BuildAndSignResponse(
            nameId: "saml-session-user", roles: new[] { "user" }, requestId: requestId);
        var acsResult = await fixture.SamlController.AssertionConsumerService(
            ProviderId, samlResponse, relayState);
        var token = ExtractSessionToken(Assert.IsType<ContentResult>(acsResult));

        // POST the session token to /Auth with device fields, exactly like the callback page JS.
        var authResult = await fixture.SamlController.Authenticate(
            ProviderId,
            new AuthenticateRequest
            {
                Token = token,
                DeviceId = "saml-device",
                DeviceName = "saml-test-agent",
                App = "Jellyfin Web",
                AppVersion = "1.2.3"
            });

        var ok = Assert.IsType<OkObjectResult>(authResult);
        var jellyfinAuth = Assert.IsType<MediaBrowser.Controller.Authentication.AuthenticationResult>(ok.Value);
        Assert.NotNull(jellyfinAuth.AccessToken);
        Assert.NotEmpty(jellyfinAuth.AccessToken);
        Assert.NotEqual(Guid.Empty, jellyfinAuth.User!.Id);
    }

    [Fact]
    public void StartAndAcsUrl_HonorForwardedProtoAndHost_WhenProxyTrusted()
    {
        var fixture = new TestFixture(_idp);
        var provider = AddSignedSamlProvider(fixture);

        // Trust the immediate peer as a reverse proxy and let it dictate the external scheme/host.
        fixture.ConfigProvider.Configuration.TrustForwardedHeaders = true;
        fixture.ConfigProvider.Configuration.TrustedProxyCidrs = new List<string> { "10.0.0.0/8" };

        var ctx = fixture.SamlController.ControllerContext.HttpContext;
        ctx.Connection.RemoteIpAddress = System.Net.IPAddress.Parse("10.1.2.3");
        ctx.Request.Headers["X-Forwarded-Proto"] = "https";
        ctx.Request.Headers["X-Forwarded-Host"] = "sso.public.example";

        // The AuthnRequest's ACS URL (in /Start) must reflect the forwarded values.
        var startResult = fixture.SamlController.Start(ProviderId);
        var redirect = Assert.IsType<RedirectResult>(startResult);
        var samlRequestB64 = HttpUtility.ParseQueryString(new Uri(redirect.Url).Query)["SAMLRequest"]!;
        var acsInRequest = ExtractAcsUrl(samlRequestB64);
        Assert.Equal("https://sso.public.example/sso/SAML/ACS/" + ProviderId, acsInRequest);

        // GetProviders' StartUrl must also reflect the forwarded values.
        var providersResult = fixture.SamlController.GetProviders();
        var ok = Assert.IsType<OkObjectResult>(providersResult);
        var json = System.Text.Json.JsonSerializer.Serialize(ok.Value);
        Assert.Contains(
            "https://sso.public.example/sso/SAML/Start/" + provider.Id,
            json);
    }

    [Fact]
    public async Task AcsCallback_SetsFrameProtectionHeaders()
    {
        var fixture = new TestFixture(_idp);
        AddSignedSamlProvider(fixture);

        var (relayState, requestId) = InitiateSpFlow(fixture);
        var samlResponse = BuildAndSignResponse(
            nameId: "frame-user", roles: new[] { "user" }, requestId: requestId);
        var acsResult = await fixture.SamlController.AssertionConsumerService(
            ProviderId, samlResponse, relayState);
        Assert.IsType<ContentResult>(acsResult);

        var headers = fixture.SamlController.ControllerContext.HttpContext.Response.Headers;
        Assert.Equal("DENY", headers["X-Frame-Options"].ToString());
        Assert.Contains("frame-ancestors 'none'", headers["Content-Security-Policy"].ToString());
    }

    private static string ExtractAcsUrl(string deflatedBase64)
    {
        var compressed = Convert.FromBase64String(deflatedBase64);
        using var inStream = new System.IO.MemoryStream(compressed);
        using var deflate = new System.IO.Compression.DeflateStream(inStream, System.IO.Compression.CompressionMode.Decompress);
        using var reader = new System.IO.StreamReader(deflate, Encoding.UTF8);
        var xml = reader.ReadToEnd();
        var doc = new XmlDocument();
        doc.LoadXml(xml);
        return doc.DocumentElement!.GetAttribute("AssertionConsumerServiceURL");
    }

    private static string ExtractSessionToken(ContentResult content) =>
        TestFixture.ExtractSessionTokenFromHtml(content.Content ?? string.Empty);
}

internal static class StringPipe
{
    public static T Pipe<T>(this string s, Func<string, T> f) => f(s);
}
