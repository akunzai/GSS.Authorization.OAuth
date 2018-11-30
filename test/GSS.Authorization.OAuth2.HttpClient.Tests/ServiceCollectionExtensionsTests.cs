using System;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Net;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;

namespace GSS.Authorization.OAuth2.HttpClient.Tests
{
    public class ServiceCollectionExtensionsTests
    {
        [Fact]
        public void AddOAuth2HttpClient_WithoutNullConfigureOptions_ShouldThrows()
        {
            // Arrange
            var collection = new ServiceCollection();

            // Act & Assert
            Assert.Throws<ArgumentNullException>(() => collection.AddOAuth2HttpClient(null));
        }

        [Fact]
        public void AddOAuth2HttpClient_WithConfigureOptions_ShouldReturnHttpClientBuilder()
        {
            // Arrange
            var collection = new ServiceCollection();

            // Act
            var builder = collection.AddOAuth2HttpClient((resolver, options) => { });

            // Assert
            Assert.NotNull(builder);
            Assert.IsAssignableFrom<IHttpClientBuilder>(builder);
        }

        [Fact]
        public void AddOAuth2HttpClient_WithConfigureOptions_ShouldAddDefaultAuthorizorToCollection()
        {
            // Arrange
            var collection = new ServiceCollection();
            var builder = collection.AddOAuth2HttpClient((resolver, options) => { });

            // Act
            var descriptor = builder.Services.Where(x => x.ServiceType == typeof(IAuthorizer)).FirstOrDefault();

            // Assert
            Assert.NotNull(descriptor);
        }

        [Fact]
        public void AddOAuth2HttpClient_WithEmptyConfigureOptions_ShouldThrowsOnAccessOptionValue()
        {
            // Arrange
            var collection = new ServiceCollection();
            var services = collection.AddOAuth2HttpClient((resolver, options) => { }).Services.BuildServiceProvider();

            // Act
            var ex = Assert.Throws<ValidationException>(() => services.GetRequiredService<IOptions<AuthorizerOptions>>().Value);

            // Assert
            Assert.IsType<RequiredAttribute>(ex.ValidationAttribute);
            Assert.Equal(nameof(AuthorizerOptions.AccessTokenEndpoint), ex.ValidationResult.MemberNames.First());
        }

        [Fact]
        public void AddOAuth2HttpClient_WithoutClientId_ShouldThrowsOnAccessOptionValue()
        {
            // Arrange
            var collection = new ServiceCollection();
            var services = collection.AddOAuth2HttpClient((resolver, options) =>
            {
                options.AccessTokenEndpoint = new Uri("https://example.com");
            }).Services.BuildServiceProvider();

            // Act
            var ex = Assert.Throws<ValidationException>(() => services.GetRequiredService<IOptions<AuthorizerOptions>>().Value);

            // Assert
            Assert.IsType<RequiredAttribute>(ex.ValidationAttribute);
            Assert.Equal(nameof(AuthorizerOptions.ClientId), ex.ValidationResult.MemberNames.First());
        }

        [Fact]
        public void AddOAuth2HttpClient_WithoutClientSecret_ShouldThrowsOnAccessOptionValue()
        {
            // Arrange
            var collection = new ServiceCollection();
            var services = collection.AddOAuth2HttpClient((resolver, options) =>
            {
                options.AccessTokenEndpoint = new Uri("https://example.com");
                options.ClientId = "foo";
            }).Services.BuildServiceProvider();

            // Act
            var ex = Assert.Throws<ValidationException>(() => services.GetRequiredService<IOptions<AuthorizerOptions>>().Value);

            // Assert
            Assert.IsType<RequiredAttribute>(ex.ValidationAttribute);
            Assert.Equal(nameof(AuthorizerOptions.ClientSecret), ex.ValidationResult.MemberNames.First());
        }

        [Fact]
        public void AddOAuth2HttpClient_WithValidConfigureOptions_ShouldNotThrows()
        {
            // Arrange
            var collection = new ServiceCollection();
            var services = collection.AddOAuth2HttpClient((resolver, options) =>
            {
                options.AccessTokenEndpoint = new Uri("https://example.com");
                options.ClientId = "foo";
                options.ClientSecret = "bar";
            }).Services.BuildServiceProvider();

            // Act
            var authorizerOptions = services.GetRequiredService<IOptions<AuthorizerOptions>>().Value;

            // Assert
            Assert.NotNull(authorizerOptions);
        }

        [Fact]
        public void AddOAuth2HttpClient_WithoutCredentials_ShouldThorwsForResourceOwnerCredentialsAuthorizer()
        {
            // Arrange
            var collection = new ServiceCollection();
            var services = collection.AddOAuth2HttpClient((resolver, options) =>
            {
                options.AccessTokenEndpoint = new Uri("https://example.com");
                options.ClientId = "foo";
                options.ClientSecret = "bar";
            }).Services.BuildServiceProvider();

            // Act
            var ex = Assert.Throws<ArgumentNullException>(() => services.GetRequiredService<IAuthorizer>());

            // Assert
            Assert.Equal(nameof(AuthorizerOptions.Credentials), ex.ParamName);
        }

        [Fact]
        public void AddOAuth2HttpClient_WithCredentials_ShouldNotThorwsForResourceOwnerCredentialsAuthorizer()
        {
            // Arrange
            var collection = new ServiceCollection();
            var services = collection.AddOAuth2HttpClient((resolver, options) =>
            {
                options.AccessTokenEndpoint = new Uri("https://example.com");
                options.ClientId = "foo";
                options.ClientSecret = "bar";
                options.Credentials = new NetworkCredential("name", "pass");
            }).Services.BuildServiceProvider();

            // Act
            var authorizer = services.GetRequiredService<IAuthorizer>();

            // Assert
            Assert.IsType<ResourceOwnerCredentialsAuthorizer>(authorizer);
        }

        [Fact]
        public void AddOAuth2HttpClient_AfterAddClientCredentialsAuthorizer_ShouldNotThrows()
        {
            // Arrange
            var collection = new ServiceCollection();
            collection.AddTransient<IAuthorizer, ClientCredentialsAuthorizer>();
            var services = collection.AddOAuth2HttpClient((resolver, options) =>
            {
                options.AccessTokenEndpoint = new Uri("https://example.com");
                options.ClientId = "foo";
                options.ClientSecret = "bar";
            }).Services.BuildServiceProvider();

            // Act
            var authorizer = services.GetRequiredService<IAuthorizer>();

            // Assert
            Assert.IsType<ClientCredentialsAuthorizer>(authorizer);
        }
    }
}
