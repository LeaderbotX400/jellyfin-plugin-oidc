using System;
using System.Text;
using Jellyfin.Plugin.OIDC.Configuration;
using Jellyfin.Plugin.OIDC.Saml;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Jellyfin.Plugin.OIDC.Tests;

public class SamlResponseTests
{
    // Minimal SAML response (no signature — for unit testing XML parsing logic)
    private const string MinimalResponse = """
        <samlp:Response
            xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
            xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
            ID="_resp1"
            Version="2.0"
            IssueInstant="2025-01-01T00:00:00Z">
            <samlp:Status>
                <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
            </samlp:Status>
            <saml:Assertion ID="_assert1" Version="2.0" IssueInstant="2025-01-01T00:00:00Z">
                <saml:Issuer>https://idp.example.com</saml:Issuer>
                <saml:Subject>
                    <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">alice</saml:NameID>
                </saml:Subject>
                <saml:Conditions
                    NotBefore="2020-01-01T00:00:00Z"
                    NotOnOrAfter="2099-12-31T23:59:59Z">
                </saml:Conditions>
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
        </samlp:Response>
        """;

    private static SamlProviderConfig MakeProvider() => new()
    {
        IdpCertificate = string.Empty, // skip signature check
        UsernameClaim = "NameID",
        RoleClaim = "groups"
    };

    private static string ToBase64(string xml) =>
        Convert.ToBase64String(Encoding.UTF8.GetBytes(xml));

    [Fact]
    public void Parse_ValidResponse_ExtractsNameId()
    {
        var assertion = SamlResponse.Parse(ToBase64(MinimalResponse), MakeProvider(), NullLogger.Instance);
        Assert.Equal("alice", assertion.NameId);
    }

    [Fact]
    public void Parse_ValidResponse_ExtractsRoles()
    {
        var assertion = SamlResponse.Parse(ToBase64(MinimalResponse), MakeProvider(), NullLogger.Instance);
        Assert.Contains("admin", assertion.Roles);
        Assert.Contains("viewers", assertion.Roles);
    }

    [Fact]
    public void Parse_ValidResponse_ExtractsAttributes()
    {
        var assertion = SamlResponse.Parse(ToBase64(MinimalResponse), MakeProvider(), NullLogger.Instance);
        Assert.True(assertion.Attributes.ContainsKey("email"));
        Assert.Equal("alice@example.com", assertion.Attributes["email"][0]);
    }

    [Fact]
    public void Parse_ExpiredAssertion_Throws()
    {
        var expired = MinimalResponse.Replace(
            "NotOnOrAfter=\"2099-12-31T23:59:59Z\"",
            "NotOnOrAfter=\"2000-01-01T00:00:00Z\"",
            StringComparison.Ordinal);
        Assert.Throws<InvalidOperationException>(() =>
            SamlResponse.Parse(ToBase64(expired), MakeProvider(), NullLogger.Instance));
    }

    [Fact]
    public void Parse_NotYetValidAssertion_Throws()
    {
        var future = MinimalResponse.Replace(
            "NotBefore=\"2020-01-01T00:00:00Z\"",
            "NotBefore=\"2099-01-01T00:00:00Z\"",
            StringComparison.Ordinal);
        Assert.Throws<InvalidOperationException>(() =>
            SamlResponse.Parse(ToBase64(future), MakeProvider(), NullLogger.Instance));
    }

    [Fact]
    public void Parse_FailureStatus_Throws()
    {
        var failed = MinimalResponse.Replace(
            "urn:oasis:names:tc:SAML:2.0:status:Success",
            "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed",
            StringComparison.Ordinal);
        Assert.Throws<InvalidOperationException>(() =>
            SamlResponse.Parse(ToBase64(failed), MakeProvider(), NullLogger.Instance));
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
        // A response with a DOCTYPE (XXE attempt) should be rejected
        var xxe = """<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status></samlp:Response>""";
        Assert.Throws<InvalidOperationException>(() =>
            SamlResponse.Parse(ToBase64(xxe), MakeProvider(), NullLogger.Instance));
    }

    [Fact]
    public void Parse_SignatureRequired_NoSig_Throws()
    {
        // With a certificate configured but no Signature element, should reject
        var provider = new SamlProviderConfig { IdpCertificate = "MIIB...", UsernameClaim = "NameID", RoleClaim = "groups" }; // non-empty = require sig
        Assert.Throws<InvalidOperationException>(() =>
            SamlResponse.Parse(ToBase64(MinimalResponse), provider, NullLogger.Instance));
    }
}
