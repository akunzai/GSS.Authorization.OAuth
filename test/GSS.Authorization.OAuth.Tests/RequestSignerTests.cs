using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Primitives;
using Xunit;
using static System.Net.Http.HttpMethod;
using static GSS.Authorization.OAuth.OAuthDefaults;

namespace GSS.Authorization.OAuth.Tests;

public class RequestSignerTests
{
    private readonly IRequestSigner _signer = new HmacSha1RequestSigner();

    // see https://www.rfc-editor.org/rfc/rfc5849#section-3.4.1.3.2
    [Fact]
    public void GetBaseString()
    {
        // Arrange
        var parameter = new Dictionary<string, StringValues>
        {
            ["b5"] = "=%3D",
            ["a3"] = new[] { "a", "2 q" },
            ["c@"] = "",
            ["a2"] = "r b",
            [OAuthConsumerKey] = "9djdj82h48djs9d2",
            [OAuthToken] = "kkk9d7dh3k39sjv7",
            [OAuthSignatureMethod] = _signer.MethodName,
            [OAuthTimestamp] = "137131201",
            [OAuthNonce] = "7d8f3e4a",
            ["c2"] = ""
        };
        const string expected =
            "POST&http%3A%2F%2Fexample.com%2Frequest&a2%3Dr%2520b%26a3%3D2%2520q%26a3%3Da%26b5%3D%253D%25253D%26c%2540%3D%26c2%3D%26oauth_consumer_key%3D9djdj82h48djs9d2%26oauth_nonce%3D7d8f3e4a%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D137131201%26oauth_token%3Dkkk9d7dh3k39sjv7";

        // Act
        var actual = ((RequestSignerBase)_signer).GetBaseString(Post,
            new Uri("http://example.com/request?b5=%3D%253D&a3=a&c%40=&a2=r%20b"), parameter);

        // Assert
        Assert.Equal(expected, actual);
    }

    [Fact]
    public void GetSignatureForTemporaryCredentials()
    {
        // Arrange
        const string expected = "74KNZJeDHnMBp0EMJ9ZHt/XKycU=";
        var clientCredentials = new OAuthCredential("dpf43f3p2l4k3l03", "kd94hf93k423kf44");
        var uri = new Uri("https://photos.example.net/initiate");
        var parameters = new Dictionary<string, StringValues>
        {
            [Realm] = "Photos",
            [OAuthConsumerKey] = clientCredentials.Key,
            [OAuthSignatureMethod] = _signer.MethodName,
            [OAuthTimestamp] = "137131200",
            [OAuthNonce] = "wIjqoS",
            [OAuthCallback] = "http://printer.example.com/ready",
            [OAuthSignature] = expected
        };

        // Act
        var actual = _signer.GetSignature(Post, uri,
            parameters, clientCredentials.Secret);

        // Assert
        Assert.Equal(expected, actual);
    }

    [Fact]
    public void GetSignatureForTokenCredentials()
    {
        // Arrange
        const string expected = "gKgrFCywp7rO0OXSjdot/IHF7IU=";
        var clientCredentials = new OAuthCredential("dpf43f3p2l4k3l03", "kd94hf93k423kf44");
        var temporaryCredentials = new OAuthCredential("hh5s93j4hdidpola", "hdhd0244k9j7ao03");
        var uri = new Uri("https://photos.example.net/token");
        var parameters = new Dictionary<string, StringValues>
        {
            [Realm] = "Photos",
            [OAuthConsumerKey] = clientCredentials.Key,
            [OAuthToken] = temporaryCredentials.Key,
            [OAuthSignatureMethod] = _signer.MethodName,
            [OAuthTimestamp] = "137131201",
            [OAuthNonce] = "walatlh",
            [OAuthVerifier] = "hfdp7dh39dks9884",
            [OAuthSignature] = expected
        };

        // Act
        var actual = _signer.GetSignature(Post, uri,
            parameters, clientCredentials.Secret, temporaryCredentials.Secret);

        // Assert
        Assert.Equal(expected, actual);
    }

    [Fact]
    public void GetSignatureForResource()
    {
        // Arrange
        const string expected = "MdpQcU8iPSUjWoN/UDMsK2sui9I=";
        var clientCredentials = new OAuthCredential("dpf43f3p2l4k3l03", "kd94hf93k423kf44");
        var tokenCredentials = new OAuthCredential("nnch734d00sl2jdk", "pfkkdhi9sl3r4s00");
        var uri = new Uri("http://photos.example.net/photos?file=vacation.jpg&size=original");

        var parameters = QueryHelpers.ParseQuery(uri.Query);
        parameters[OAuthConsumerKey] = clientCredentials.Key;
        parameters[OAuthToken] = tokenCredentials.Key;
        parameters[OAuthNonce] = "chapoH";
        parameters[OAuthTimestamp] = "137131202";
        parameters[OAuthSignatureMethod] = _signer.MethodName;

        // Act
        var actual = _signer.GetSignature(Get, uri,
            parameters, clientCredentials.Secret, tokenCredentials.Secret);

        // Assert
        Assert.Equal(expected, actual);
    }
}