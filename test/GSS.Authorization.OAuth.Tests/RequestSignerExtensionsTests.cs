using System;
using System.Collections.Generic;
using Microsoft.Extensions.Primitives;
using Xunit;
using static System.Net.Http.HttpMethod;
using static GSS.Authorization.OAuth.OAuthDefaults;

namespace GSS.Authorization.OAuth.Tests;

public class RequestSignerExtensionsTests
{
    private readonly IRequestSigner _signer = new HmacSha1RequestSigner();
    private readonly OAuthOptions _options = new()
    {
        ClientCredentials = new OAuthCredential("dpf43f3p2l4k3l03", "kd94hf93k423kf44"),
        NonceProvider = () => "kllo9940pd9333jh",
        TimestampProvider = () => "1191242096",
        Realm = "Photos"
    };

    [Fact]
    public void GetAuthorizationHeader_WithNullOptions_ShouldThrowArgumentNullException()
    {
        // Arrange
        var uri = new Uri("http://photos.example.net/photos");

        // Act & Assert
        var exception = Assert.Throws<ArgumentNullException>(() =>
            _signer.GetAuthorizationHeader(Get, uri, null!));
        Assert.Equal("options", exception.ParamName);
    }

    [Fact]
    public void GetAuthorizationHeader_WithValidParameters_ShouldReturnCorrectHeader()
    {
        // Arrange
        var uri = new Uri("http://photos.example.net/photos?file=vacation.jpg&size=original");
        var tokenCredentials = new OAuthCredential("nnch734d00sl2jdk", "pfkkdhi9sl3r4s00");

        // Act
        var header = _signer.GetAuthorizationHeader(Get, uri, _options, null, tokenCredentials);

        // Assert
        Assert.Equal("OAuth", header.Scheme);
        Assert.NotNull(header.Parameter);
        Assert.Contains("realm=", header.Parameter);
        Assert.Contains("oauth_consumer_key=", header.Parameter);
        Assert.Contains("oauth_nonce=", header.Parameter);
        Assert.Contains("oauth_signature_method=", header.Parameter);
        Assert.Contains("oauth_timestamp=", header.Parameter);
        Assert.Contains("oauth_token=", header.Parameter);
        Assert.Contains("oauth_signature=", header.Parameter);
    }

    [Fact]
    public void GetAuthorizationHeader_WithoutRealm_ShouldNotIncludeRealm()
    {
        // Arrange
        var uri = new Uri("http://photos.example.net/photos");
        var optionsWithoutRealm = new OAuthOptions
        {
            ClientCredentials = _options.ClientCredentials,
            NonceProvider = _options.NonceProvider,
            TimestampProvider = _options.TimestampProvider
        };

        // Act
        var header = _signer.GetAuthorizationHeader(Get, uri, optionsWithoutRealm);

        // Assert
        Assert.Equal("OAuth", header.Scheme);
        Assert.NotNull(header.Parameter);
        Assert.DoesNotContain("realm=", header.Parameter);
    }

    [Fact]
    public void GetAuthorizationHeader_WithEmptyRealm_ShouldNotIncludeRealm()
    {
        // Arrange
        var uri = new Uri("http://photos.example.net/photos");
        var optionsWithEmptyRealm = new OAuthOptions
        {
            ClientCredentials = _options.ClientCredentials,
            NonceProvider = _options.NonceProvider,
            TimestampProvider = _options.TimestampProvider,
            Realm = ""
        };

        // Act
        var header = _signer.GetAuthorizationHeader(Get, uri, optionsWithEmptyRealm);

        // Assert
        Assert.Equal("OAuth", header.Scheme);
        Assert.NotNull(header.Parameter);
        Assert.DoesNotContain("realm=", header.Parameter);
    }

    [Fact]
    public void GetAuthorizationHeader_WithWhitespaceRealm_ShouldNotIncludeRealm()
    {
        // Arrange
        var uri = new Uri("http://photos.example.net/photos");
        var optionsWithWhitespaceRealm = new OAuthOptions
        {
            ClientCredentials = _options.ClientCredentials,
            NonceProvider = _options.NonceProvider,
            TimestampProvider = _options.TimestampProvider,
            Realm = "   "
        };

        // Act
        var header = _signer.GetAuthorizationHeader(Get, uri, optionsWithWhitespaceRealm);

        // Assert
        Assert.Equal("OAuth", header.Scheme);
        Assert.NotNull(header.Parameter);
        Assert.DoesNotContain("realm=", header.Parameter);
    }

    [Fact]
    public void AppendAuthorizationParameters_WithNullSigner_ShouldThrowArgumentNullException()
    {
        // Arrange
        var uri = new Uri("http://photos.example.net/photos");

        // Act & Assert
        var exception = Assert.Throws<ArgumentNullException>(() =>
            ((IRequestSigner)null!).AppendAuthorizationParameters(Get, uri, _options));
        Assert.Equal("signer", exception.ParamName);
    }

    [Fact]
    public void AppendAuthorizationParameters_WithNullOptions_ShouldThrowArgumentNullException()
    {
        // Arrange
        var uri = new Uri("http://photos.example.net/photos");

        // Act & Assert
        var exception = Assert.Throws<ArgumentNullException>(() =>
            _signer.AppendAuthorizationParameters(Get, uri, null!));
        Assert.Equal("options", exception.ParamName);
    }

    [Fact]
    public void AppendAuthorizationParameters_WithNullParameters_ShouldCreateNewDictionary()
    {
        // Arrange
        var uri = new Uri("http://photos.example.net/photos");

        // Act
        var parameters = _signer.AppendAuthorizationParameters(Get, uri, _options);

        // Assert
        Assert.NotNull(parameters);
        Assert.Contains(OAuthConsumerKey, parameters.Keys);
        Assert.Contains(OAuthNonce, parameters.Keys);
        Assert.Contains(OAuthTimestamp, parameters.Keys);
        Assert.Contains(OAuthSignatureMethod, parameters.Keys);
        Assert.Contains(OAuthSignature, parameters.Keys);
    }

    [Fact]
    public void AppendAuthorizationParameters_WithTokenCredentials_ShouldIncludeToken()
    {
        // Arrange
        var uri = new Uri("http://photos.example.net/photos");
        var tokenCredentials = new OAuthCredential("token123", "secret456");

        // Act
        var parameters = _signer.AppendAuthorizationParameters(Get, uri, _options, null, tokenCredentials);

        // Assert
        Assert.Contains(OAuthToken, parameters.Keys);
        Assert.Equal("token123", parameters[OAuthToken].ToString());
    }

    [Fact]
    public void AppendAuthorizationParameters_WithEmptyTokenKey_ShouldNotIncludeToken()
    {
        // Arrange
        var uri = new Uri("http://photos.example.net/photos");
        var tokenCredentials = new OAuthCredential("", "secret456");

        // Act
        var parameters = _signer.AppendAuthorizationParameters(Get, uri, _options, null, tokenCredentials);

        // Assert
        Assert.DoesNotContain(OAuthToken, parameters.Keys);
    }

    [Fact]
    public void AppendAuthorizationParameters_WithProvideVersion_ShouldIncludeVersion()
    {
        // Arrange
        var uri = new Uri("http://photos.example.net/photos");
        var optionsWithVersion = new OAuthOptions
        {
            ClientCredentials = _options.ClientCredentials,
            NonceProvider = _options.NonceProvider,
            TimestampProvider = _options.TimestampProvider,
            ProvideVersion = true
        };

        // Act
        var parameters = _signer.AppendAuthorizationParameters(Get, uri, optionsWithVersion);

        // Assert
        Assert.Contains(OAuthVersion, parameters.Keys);
        Assert.Equal(Version1, parameters[OAuthVersion].ToString());
    }

    [Fact]
    public void AppendAuthorizationParameters_WithoutProvideVersion_ShouldNotIncludeVersion()
    {
        // Arrange
        var uri = new Uri("http://photos.example.net/photos");

        // Act
        var parameters = _signer.AppendAuthorizationParameters(Get, uri, _options);

        // Assert
        Assert.DoesNotContain(OAuthVersion, parameters.Keys);
    }

    [Fact]
    public void AppendAuthorizationParameters_WithExistingParameters_ShouldMergeParameters()
    {
        // Arrange
        var uri = new Uri("http://photos.example.net/photos");
        var existingParameters = new Dictionary<string, StringValues>
        {
            ["custom_param"] = "custom_value",
            ["another_param"] = "another_value"
        };

        // Act
        var parameters = _signer.AppendAuthorizationParameters(Get, uri, _options, existingParameters);

        // Assert
        Assert.Contains("custom_param", parameters.Keys);
        Assert.Contains("another_param", parameters.Keys);
        Assert.Contains(OAuthConsumerKey, parameters.Keys);
        Assert.Equal("custom_value", parameters["custom_param"].ToString());
        Assert.Equal("another_value", parameters["another_param"].ToString());
    }
}