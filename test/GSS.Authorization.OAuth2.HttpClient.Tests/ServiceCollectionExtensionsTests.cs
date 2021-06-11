using System;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Net;
using System.Net.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Http;
using Microsoft.Extensions.Options;
using RichardSzalay.MockHttp;
using Xunit;

namespace GSS.Authorization.OAuth2.HttpClient.Tests
{
    public class ServiceCollectionExtensionsTests
    {
        [Fact]
        public void AddOAuth2HttpClient_WithoutConfigureOptions_ShouldThrows()
        {
            // Arrange
            var collection = new ServiceCollection();

            // Act & Assert
            Assert.Throws<ArgumentNullException>(() => collection.AddOAuth2HttpClient<OAuth2HttpClient, ClientCredentialsAuthorizer>(null));
        }

        [Fact]
        public void AddOAuth2HttpClient_WithConfigureOptions_ShouldReturnHttpClientBuilder()
        {
            // Arrange
            var collection = new ServiceCollection();

            // Act
            var builder = collection.AddOAuth2HttpClient<OAuth2HttpClient, ClientCredentialsAuthorizer>((_, __) => { });

            // Assert
            Assert.NotNull(builder);
            Assert.IsAssignableFrom<IHttpClientBuilder>(builder);
        }

        [Fact]
        public void AddOAuth2HttpClient_WithEmptyConfigureOptions_ShouldThrowsOnAccessOptionValue()
        {
            // Arrange
            var collection = new ServiceCollection();
            var services = collection.AddOAuth2HttpClient<OAuth2HttpClient, ClientCredentialsAuthorizer>((_, __) => { }).Services.BuildServiceProvider();

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
            var services = collection.AddOAuth2HttpClient<OAuth2HttpClient, ClientCredentialsAuthorizer>((_, options) => options.AccessTokenEndpoint = new Uri("https://example.com"))
                .Services.BuildServiceProvider();

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
            var services = collection.AddOAuth2HttpClient<OAuth2HttpClient, ClientCredentialsAuthorizer>((_, options) =>
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
            var services = collection.AddOAuth2HttpClient<OAuth2HttpClient, ClientCredentialsAuthorizer>((_, options) =>
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
        public void AddOAuth2HttpClient_WithGenericConfigurePrimaryHttpMessageHandler_ShouldAddInHttpMessageHandlerBuilderActions()
        {   
            // Arrange
            var mockHttp = new MockHttpMessageHandler();
            var collection = new ServiceCollection();
            var builder = collection
                .AddSingleton(mockHttp)
                .AddOAuth2HttpClient<OAuth2HttpClient, ClientCredentialsAuthorizer>((_, options) =>
                {
                    options.AccessTokenEndpoint = new Uri("https://example.com");
                    options.ClientId = "foo";
                    options.ClientSecret = "bar";
                }).ConfigurePrimaryHttpMessageHandler<MockHttpMessageHandler>();
            var services = builder.Services.BuildServiceProvider();
            
            // Act
            var optionsMonitor = services.GetRequiredService<IOptionsMonitor<HttpClientFactoryOptions>>();
            
            // Assert
            var httpClientFactoryOptions = optionsMonitor.Get(builder.Name);
            Assert.Contains(httpClientFactoryOptions.HttpMessageHandlerBuilderActions, x => x.Target?.ToString()?.Contains("MockHttpMessageHandler") == true);
        }

        [Fact]
        public void AddOAuth2HttpClient_WithoutCredentials_ShouldThrowsForResourceOwnerCredentialsAuthorizer()
        {
            // Arrange
            var collection = new ServiceCollection();
            var services = collection.AddOAuth2HttpClient<OAuth2HttpClient, ResourceOwnerCredentialsAuthorizer>((_, options) =>
            {
                options.AccessTokenEndpoint = new Uri("https://example.com");
                options.ClientId = "foo";
                options.ClientSecret = "bar";
            }).Services.BuildServiceProvider();

            // Act
            var ex = Assert.Throws<ArgumentNullException>(() => services.GetRequiredService<ResourceOwnerCredentialsAuthorizer>());

            // Assert
            Assert.Equal(nameof(AuthorizerOptions.Credentials), ex.ParamName);
        }

        [Fact]
        public void AddOAuth2HttpClient_WithCredentials_ShouldNotThrowsForResourceOwnerCredentialsAuthorizer()
        {
            // Arrange
            var collection = new ServiceCollection();
            var services = collection.AddOAuth2HttpClient<OAuth2HttpClient, ResourceOwnerCredentialsAuthorizer>((_, options) =>
            {
                options.AccessTokenEndpoint = new Uri("https://example.com");
                options.ClientId = "foo";
                options.ClientSecret = "bar";
                options.Credentials = new NetworkCredential("name", "pass");
            }).Services.BuildServiceProvider();

            // Act
            var authorizer = services.GetService<ResourceOwnerCredentialsAuthorizer>();

            // Assert
            Assert.NotNull(authorizer);
            Assert.IsAssignableFrom<Authorizer>(authorizer);
        }

        [Fact]
        public void AddOAuth2HttpClient_WithClientCredentialsAuthorizer_ShouldAddInServiceProvider()
        {
            // Arrange
            var collection = new ServiceCollection();
            var services = collection.AddOAuth2HttpClient<OAuth2HttpClient, ClientCredentialsAuthorizer>((_, options) =>
            {
                options.AccessTokenEndpoint = new Uri("https://example.com");
                options.ClientId = "foo";
                options.ClientSecret = "bar";
            }).Services.BuildServiceProvider();

            // Act
            var client = services.GetService<OAuth2HttpClient>();

            // Assert
            Assert.NotNull(client);
        }

        [Fact]
        public void AddNamedOAuth2HttpClient_WithClientCredentialsAuthorizer_ShouldAddInHttpClientFactory()
        {
            // Arrange
            const string name = "demo";
            var collection = new ServiceCollection();
            var services = collection.AddOAuth2HttpClient<ClientCredentialsAuthorizer>(name, (_, options) =>
            {
                options.AccessTokenEndpoint = new Uri("https://example.com");
                options.ClientId = "foo";
                options.ClientSecret = "bar";
            }).Services.BuildServiceProvider();
            var factory = services.GetRequiredService<IHttpClientFactory>();

            // Act
            var client = factory.CreateClient(name);

            // Assert
            Assert.NotNull(client);
        }

        private class DemoOAuthClient
        {
            private readonly System.Net.Http.HttpClient _client;

            public DemoOAuthClient(System.Net.Http.HttpClient client)
            {
                _client = client;
            }
        }

        [Fact]
        public void AddTypedOAuth2HttpClient_WithClientCredentialsAuthorizer_ShouldAddInServiceProvider()
        {
            // Arrange
            var collection = new ServiceCollection();
            var services = collection.AddOAuth2HttpClient<DemoOAuthClient, ClientCredentialsAuthorizer>((_, options) =>
            {
                options.AccessTokenEndpoint = new Uri("https://example.com");
                options.ClientId = "foo";
                options.ClientSecret = "bar";
            }).Services.BuildServiceProvider();

            // Act
            var client = services.GetService<DemoOAuthClient>();

            // Assert
            Assert.NotNull(client);
        }

        [Fact]
        public void AddOAuth2HttpClients_WithDifferentAuthorizers_ShouldAddAuthorizersInServiceProvider()
        {
            // Arrange
            var collection = new ServiceCollection();
            var services = collection.AddOAuth2HttpClient<ClientCredentialsAuthorizer>("client1", (_, options) =>
            {
                options.AccessTokenEndpoint = new Uri("https://example.com");
                options.ClientId = "foo";
                options.ClientSecret = "bar";
            }).Services.AddOAuth2HttpClient<ResourceOwnerCredentialsAuthorizer>("client2", (_, options) =>
            {
                options.AccessTokenEndpoint = new Uri("https://example.com");
                options.ClientId = "foo";
                options.ClientSecret = "bar";
                options.Credentials = new NetworkCredential("name", "pass");
            }).Services.BuildServiceProvider();

            // Act
            var authorizer1 = services.GetService<ClientCredentialsAuthorizer>();
            var authorizer2 = services.GetService<ResourceOwnerCredentialsAuthorizer>();

            // Assert
            Assert.NotNull(authorizer1);
            Assert.NotNull(authorizer2);
        }

        [Fact]
        public void AddOAuth2HttpClients_WithSameAuthorizer_ShouldNotThrows()
        {
            // Arrange
            var collection = new ServiceCollection();
            var services = collection.AddOAuth2HttpClient<ClientCredentialsAuthorizer>("client1", (_, options) =>
            {
                options.AccessTokenEndpoint = new Uri("https://example.com");
                options.ClientId = "foo";
                options.ClientSecret = "bar";
            }).Services.AddOAuth2HttpClient<ClientCredentialsAuthorizer>("client2", (_, options) =>
            {
                options.AccessTokenEndpoint = new Uri("https://example.com");
                options.ClientId = "foo";
                options.ClientSecret = "bar";
            }).Services.BuildServiceProvider();

            // Act
            var authorizer = services.GetService<ClientCredentialsAuthorizer>();

            // Assert
            Assert.NotNull(authorizer);
        }
    }
}
