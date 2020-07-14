using System;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;

namespace GSS.Authorization.OAuth.HttpClient.Tests
{
    public class ServiceCollectionExtensionsTests
    {
        [Fact]
        public void AddOAuthHttpClient_WithoutConfigureOptions_ShouldThrows()
        {
            // Arrange
            var collection = new ServiceCollection();

            // Act & Assert
            Assert.Throws<ArgumentNullException>(() => collection.AddOAuthHttpClient<OAuthHttpClient>(null));
        }

        [Fact]
        public void AddOAuthHttpClient_WithConfigureOptions_ShouldReturnHttpClientBuilder()
        {
            // Arrange
            var collection = new ServiceCollection();

            // Act
            var builder = collection.AddOAuthHttpClient<OAuthHttpClient>((_, __) => { });

            // Assert
            Assert.NotNull(builder);
            Assert.IsAssignableFrom<IHttpClientBuilder>(builder);
        }

        [Fact]
        public void AddOAuthHttpClient_WithEmptyConfigureOptions_ShouldThrowsOnAccessOptionValue()
        {
            // Arrange
            var collection = new ServiceCollection();
            var services = collection.AddOAuthHttpClient<OAuthHttpClient>((_, __) => { }).Services.BuildServiceProvider();

            // Act
            var ex = Assert.Throws<ArgumentNullException>(() => services.GetRequiredService<IOptions<OAuthHttpHandlerOptions>>().Value);

            // Assert
            Assert.Equal($"{nameof(OAuthHttpHandlerOptions.ClientCredentials)}.{nameof(OAuthHttpHandlerOptions.ClientCredentials.Key)}", ex.ParamName);
        }

        [Fact]
        public void AddOAuthHttpClient_WithoutClientSecret_ShouldThrowsOnAccessOptionValue()
        {
            // Arrange
            var collection = new ServiceCollection();
            var services = collection.AddOAuthHttpClient<OAuthHttpClient>((_, options) =>
            {
                options.ClientCredentials = new OAuthCredential("foo", null);
            }).Services.BuildServiceProvider();

            // Act
            var ex = Assert.Throws<ArgumentNullException>(() => services.GetRequiredService<IOptions<OAuthHttpHandlerOptions>>().Value);

            // Assert
            Assert.Equal($"{nameof(OAuthHttpHandlerOptions.ClientCredentials)}.{nameof(OAuthHttpHandlerOptions.ClientCredentials.Secret)}", ex.ParamName);
        }

        [Fact]
        public void AddOAuthHttpClient_WithoutTokenId_ShouldThrowsOnAccessOptionValue()
        {
            // Arrange
            var collection = new ServiceCollection();
            var services = collection.AddOAuthHttpClient<OAuthHttpClient>((_, options) =>
            {
                options.ClientCredentials = new OAuthCredential("foo", "bar");
                options.TokenCredentials = new OAuthCredential(null, "bar");
            }).Services.BuildServiceProvider();

            // Act
            var ex = Assert.Throws<ArgumentNullException>(() => services.GetRequiredService<IOptions<OAuthHttpHandlerOptions>>().Value);

            // Assert
            Assert.Equal($"{nameof(OAuthHttpHandlerOptions.TokenCredentials)}.{nameof(OAuthHttpHandlerOptions.TokenCredentials.Key)}", ex.ParamName);
        }

        [Fact]
        public void AddOAuthHttpClient_WithoutTokenSecret_ShouldThrowsOnAccessOptionValue()
        {
            // Arrange
            var collection = new ServiceCollection();
            var services = collection.AddOAuthHttpClient<OAuthHttpClient>((_, options) =>
            {
                options.ClientCredentials = new OAuthCredential("foo", "bar");
                options.TokenCredentials = new OAuthCredential("foo", null);
            }).Services.BuildServiceProvider();

            // Act
            var ex = Assert.Throws<ArgumentNullException>(() => services.GetRequiredService<IOptions<OAuthHttpHandlerOptions>>().Value);

            // Assert
            Assert.Equal($"{nameof(OAuthHttpHandlerOptions.TokenCredentials)}.{nameof(OAuthHttpHandlerOptions.TokenCredentials.Secret)}", ex.ParamName);
        }

        [Fact]
        public void AddOAuthHttpClient_WithValidConfigureOptions_ShouldNotThrows()
        {
            // Arrange
            var collection = new ServiceCollection();
            var services = collection.AddOAuthHttpClient<OAuthHttpClient>((_, options) =>
            {
                options.ClientCredentials = new OAuthCredential("foo", "bar");
                options.TokenCredentials = new OAuthCredential("foo", "bar");
            }).Services.BuildServiceProvider();

            // Act
            var options = services.GetRequiredService<IOptions<OAuthHttpHandlerOptions>>().Value;

            // Assert
            Assert.NotNull(options);
        }

        [Fact]
        public void AddOAuthHttpClient_WithValidConfigureOptions_ShouldAddInServiceProvider()
        {
            // Arrange
            var collection = new ServiceCollection();
            var services = collection.AddOAuthHttpClient<OAuthHttpClient>((_, options) =>
            {
                options.ClientCredentials = new OAuthCredential("foo", "bar");
                options.TokenCredentials = new OAuthCredential("foo", "bar");
            }).Services.BuildServiceProvider();

            // Act
            var client = services.GetRequiredService<OAuthHttpClient>();

            // Assert
            Assert.NotNull(client);
        }

        [Fact]
        public void AddNamedOAuthHttpClient_WithValidConfigureOptions_ShouldAddInHttpClientFactory()
        {
            // Arrange
            const string name = "demo";
            var collection = new ServiceCollection();
            var services = collection.AddOAuthHttpClient(name, (_, options) =>
            {
                options.ClientCredentials = new OAuthCredential("foo", "bar");
                options.TokenCredentials = new OAuthCredential("foo", "bar");
            }).Services.BuildServiceProvider();
            var factory = services.GetRequiredService<IHttpClientFactory>();

            // Act
            var client = factory.CreateClient(name);

            // Assert
            Assert.NotNull(client);
        }

        private class DemoOAuthClient
        {
#pragma warning disable IDE0052 // Remove unread private members
            private readonly System.Net.Http.HttpClient _client;
#pragma warning restore IDE0052 // Remove unread private members

            public DemoOAuthClient(System.Net.Http.HttpClient client)
            {
                _client = client;
            }
        }

        [Fact]
        public void AddTypedOAuthHttpClient_WithValidConfigureOptions_ShouldAddInServiceProvider()
        {
            // Arrange
            var collection = new ServiceCollection();
            var services = collection.AddOAuthHttpClient<DemoOAuthClient>((_, options) =>
            {
                options.ClientCredentials = new OAuthCredential("foo", "bar");
                options.TokenCredentials = new OAuthCredential("foo", "bar");
            }).Services.BuildServiceProvider();

            // Act
            var client = services.GetService<DemoOAuthClient>();

            // Assert
            Assert.NotNull(client);
        }

        [Fact]
        public void AddTypedOAuthHttpClients_WithDifferenctSigners_ShouldAddInServiceProvider()
        {
            // Arrange
            var collection = new ServiceCollection();
            var services = collection.AddOAuthHttpClient<OAuthHttpClient, HmacSha1RequestSigner>((_, options) =>
             {
                 options.ClientCredentials = new OAuthCredential("foo", "bar");
                 options.TokenCredentials = new OAuthCredential("foo", "bar");
             }).Services.AddOAuthHttpClient<DemoOAuthClient, PlainTextRequestSigner>((_, options) =>
            {
                options.ClientCredentials = new OAuthCredential("foo", "bar");
                options.TokenCredentials = new OAuthCredential("foo", "bar");
            }).Services.BuildServiceProvider();

            // Act
            var client1 = services.GetService<OAuthHttpClient>();
            var client2 = services.GetService<DemoOAuthClient>();
            var signer1 = services.GetService<HmacSha1RequestSigner>();
            var signer2 = services.GetService<PlainTextRequestSigner>();

            // Assert
            Assert.NotNull(client1);
            Assert.NotNull(client2);
            Assert.NotNull(signer1);
            Assert.NotNull(signer2);
        }

        [Fact]
        public void AddNamedOAuthHttpClients_WithDifferenctSigners_ShouldAddInServiceProvider()
        {
            // Arrange
            var collection = new ServiceCollection();
            var services = collection.AddOAuthHttpClient<HmacSha1RequestSigner>("client1", (_, options) =>
            {
                options.ClientCredentials = new OAuthCredential("foo", "bar");
                options.TokenCredentials = new OAuthCredential("foo", "bar");
            }).Services.AddOAuthHttpClient<PlainTextRequestSigner>("client2", (_, options) =>
            {
                options.ClientCredentials = new OAuthCredential("foo", "bar");
                options.TokenCredentials = new OAuthCredential("foo", "bar");
            }).Services.BuildServiceProvider();

            // Act
            var factory = services.GetRequiredService<IHttpClientFactory>();
            var client1 = factory.CreateClient("client1");
            var client2 = factory.CreateClient("client2");
            var signer1 = services.GetService<HmacSha1RequestSigner>();
            var signer2 = services.GetService<PlainTextRequestSigner>();

            // Assert
            Assert.NotNull(client1);
            Assert.NotNull(client2);
            Assert.NotNull(signer1);
            Assert.NotNull(signer2);
        }
    }
}
