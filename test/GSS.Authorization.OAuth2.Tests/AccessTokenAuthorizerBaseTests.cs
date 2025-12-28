using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using Microsoft.Extensions.Options;
using Xunit;

namespace GSS.Authorization.OAuth2.Tests;

public class AccessTokenAuthorizerBaseTests
{
    [Fact]
    public void Constructor_WithNullOptions_ShouldThrowArgumentNullException()
    {
        // Act & Assert
        var exception = Assert.Throws<ArgumentNullException>(() =>
            new TestAccessTokenAuthorizer(new HttpClient(), null!));
        Assert.Equal("options", exception.ParamName);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Constructor_WithInvalidClientId_ShouldThrowArgumentNullException(string? clientId)
    {
        // Arrange
        var options = new AuthorizerOptions
        {
            ClientId = clientId!,
            ClientSecret = "test_secret",
            AccessTokenEndpoint = new Uri("https://example.com/token")
        };

        // Act & Assert
        var exception = Assert.Throws<ArgumentNullException>(() =>
            new TestAccessTokenAuthorizer(new HttpClient(), Options.Create(options)));
        Assert.Contains("ClientId", exception.Message);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Constructor_WithInvalidClientSecret_ShouldThrowArgumentNullException(string? clientSecret)
    {
        // Arrange
        var options = new AuthorizerOptions
        {
            ClientId = "test_client",
            ClientSecret = clientSecret!,
            AccessTokenEndpoint = new Uri("https://example.com/token")
        };

        // Act & Assert
        var exception = Assert.Throws<ArgumentNullException>(() =>
            new TestAccessTokenAuthorizer(new HttpClient(), Options.Create(options)));
        Assert.Contains("ClientSecret", exception.Message);
    }

    [Fact]
    public void Constructor_WithNullAccessTokenEndpoint_ShouldThrowArgumentNullException()
    {
        // Arrange
        var options = new AuthorizerOptions
        {
            ClientId = "test_client",
            ClientSecret = "test_secret",
            AccessTokenEndpoint = null!
        };

        // Act & Assert
        var exception = Assert.Throws<ArgumentNullException>(() =>
            new TestAccessTokenAuthorizer(new HttpClient(), Options.Create(options)));
        Assert.Contains("AccessTokenEndpoint", exception.Message);
    }

    [Fact]
    public void Constructor_WithValidOptions_ShouldSetProperties()
    {
        // Arrange
        var options = new AuthorizerOptions
        {
            ClientId = "test_client",
            ClientSecret = "test_secret",
            AccessTokenEndpoint = new Uri("https://example.com/token"),
            Scopes = ["read", "write"]
        };

        // Act
        var authorizer = new TestAccessTokenAuthorizer(new HttpClient(), Options.Create(options));

        // Assert
        Assert.Equal("test_client", authorizer.TestOptions.ClientId);
        Assert.Equal("test_secret", authorizer.TestOptions.ClientSecret);
        Assert.Equal("https://example.com/token", authorizer.TestOptions.AccessTokenEndpoint.ToString());
        Assert.Equal(2, authorizer.TestOptions.Scopes?.Count());
    }

    // Test class to expose protected members for testing
    private class TestAccessTokenAuthorizer : AccessTokenAuthorizerBase
    {
        public TestAccessTokenAuthorizer(HttpClient client, IOptions<AuthorizerOptions> options)
            : base(client, options)
        {
        }

        public AuthorizerOptions TestOptions => Options;

        protected override void PrepareFormData(IDictionary<string, string> formData)
        {
            formData["grant_type"] = "test_grant";
        }
    }
}