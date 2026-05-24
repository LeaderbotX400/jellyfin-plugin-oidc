using System;
using System.IO;
using System.IO.Compression;
using System.Text;
using System.Xml;
using Jellyfin.Plugin.OIDC.Configuration;

namespace Jellyfin.Plugin.OIDC.Saml;

/// <summary>Builds SAML 2.0 AuthnRequest messages (SP-initiated SSO, HTTP-Redirect binding).</summary>
public static class SamlRequest
{
    /// <summary>
    /// Builds the redirect URL for an HTTP-Redirect-bound AuthnRequest.
    /// The returned URL can be used directly as a Location header value.
    /// </summary>
    public static string BuildRedirectUrl(SamlProviderConfig provider, string acsUrl, string requestId, string? relayState = null)
    {
        var samlRequest = BuildAuthnRequestXml(provider, acsUrl, requestId);
        var compressed = DeflateAndBase64(samlRequest);
        var url = $"{provider.SsoUrl}?SAMLRequest={Uri.EscapeDataString(compressed)}";
        if (!string.IsNullOrEmpty(relayState))
        {
            url += $"&RelayState={Uri.EscapeDataString(relayState)}";
        }

        return url;
    }

    private static string BuildAuthnRequestXml(SamlProviderConfig provider, string acsUrl, string requestId)
    {
        var sb = new StringBuilder();
        var settings = new XmlWriterSettings { Indent = false, OmitXmlDeclaration = true };
        using var writer = XmlWriter.Create(sb, settings);

        writer.WriteStartElement("samlp", "AuthnRequest", "urn:oasis:names:tc:SAML:2.0:protocol");
        writer.WriteAttributeString("ID", requestId);
        writer.WriteAttributeString("Version", "2.0");
        writer.WriteAttributeString("IssueInstant", DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ"));
        writer.WriteAttributeString("AssertionConsumerServiceURL", acsUrl);
        writer.WriteAttributeString("ProtocolBinding", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");
        writer.WriteAttributeString("xmlns", "saml", null, "urn:oasis:names:tc:SAML:2.0:assertion");

        writer.WriteStartElement("saml", "Issuer", "urn:oasis:names:tc:SAML:2.0:assertion");
        writer.WriteString(provider.EntityId);
        writer.WriteEndElement();

        writer.WriteEndElement();
        writer.Flush();

        return sb.ToString();
    }

    private static string DeflateAndBase64(string xml)
    {
        var bytes = Encoding.UTF8.GetBytes(xml);
        using var output = new MemoryStream();
        using (var deflate = new DeflateStream(output, CompressionMode.Compress, leaveOpen: true))
        {
            deflate.Write(bytes, 0, bytes.Length);
        }

        return Convert.ToBase64String(output.ToArray());
    }
}
