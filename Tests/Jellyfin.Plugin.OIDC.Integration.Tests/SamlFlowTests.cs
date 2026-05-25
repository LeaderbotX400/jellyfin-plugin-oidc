using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
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

    // Minimal SAML response (no signature — IdpCertificate is empty in the test provider)
    private static string BuildSamlResponse(string nameId, IEnumerable<string> roles, string? email = null)
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
        return Convert.ToBase64String(Encoding.UTF8.GetBytes(sb.ToString()));
    }

    [Fact]
    public async Task AcsFlow_ValidResponse_ProvisionsUserAndApplliesRoles()
    {
        var fixture = new TestFixture(_idp);
        fixture.AddSamlProvider(ProviderId);
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
        fixture.AddSamlProvider(ProviderId);

        // Build a response with NotOnOrAfter in the past
        var expired = BuildSamlResponse(nameId: "alice", roles: new[] { "user" })
            .Pipe(b64 => Encoding.UTF8.GetString(Convert.FromBase64String(b64)))
            .Replace("2099-12-31T23:59:59Z", "2000-01-01T00:00:00Z", StringComparison.Ordinal)
            .Pipe(xml => Convert.ToBase64String(Encoding.UTF8.GetBytes(xml)));

        var result = await fixture.SamlController.AssertionConsumerService(
            ProviderId, expired, relayState: null);
        Assert.IsType<BadRequestObjectResult>(result);
    }

    [Fact]
    public async Task AcsFlow_MissingSamlResponse_Returns400()
    {
        var fixture = new TestFixture(_idp);
        fixture.AddSamlProvider(ProviderId);
        var result = await fixture.SamlController.AssertionConsumerService(
            ProviderId, samlResponse: string.Empty, relayState: null);
        Assert.IsType<BadRequestObjectResult>(result);
    }

    private static string ExtractSessionToken(ContentResult content) =>
        TestFixture.ExtractSessionTokenFromHtml(content.Content ?? string.Empty);
}

internal static class StringPipe
{
    public static T Pipe<T>(this string s, Func<string, T> f) => f(s);
}
