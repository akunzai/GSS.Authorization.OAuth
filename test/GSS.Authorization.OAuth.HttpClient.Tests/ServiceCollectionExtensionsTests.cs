using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Http;
using Microsoft.Extensions.Options;
using RichardSzalay.MockHttp;
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
#pragma warning disable CS8625 // Cannot convert null literal to non-nullable reference type.
            Assert.Throws<ArgumentNullException>(() => collection.AddOAuthHttpClient<OAuthHttpClient>(null));
#pragma warning restore CS8625 // Cannot convert null literal to non-nullable reference type.
        }

        [Fact]
        public void AddOAuthHttpClient_WithConfigureOptions_ShouldReturnHttpClientBuilder()
        {
            // Arrange
            var collection = new ServiceCollection();

            // Act
            var builder = collection.AddOAuthHttpClient<OAuthHttpClient>((_, _) => { });

            // Assert
            Assert.NotNull(builder);
            Assert.IsAssignableFrom<IHttpClientBuilder>(builder);
        }

        [Fact]
        public void AddOAuthHttpClient_WithEmptyConfigureOptions_ShouldThrowsOnAccessOptionValue()
        {
            // Arrange
            var collection = new ServiceCollection();
            var services = collection.AddOAuthHttpClient<OAuthHttpClient>((_, _) => { }).Services
                .BuildServiceProvider();

            // Act
            var ex = Assert.Throws<ArgumentNullException>(() =>
                services.GetRequiredService<IOptions<OAuthHttpHandlerOptions>>().Value);

            // Assert
            Assert.Equal(
                $"{nameof(OAuthHttpHandlerOptions.ClientCredentials)}.{nameof(OAuthHttpHandlerOptions.ClientCredentials.Key)}",
                ex.ParamName);
        }

        [Fact]
        public void AddOAuthHttpClient_WithoutClientSecret_ShouldThrowsOnAccessOptionValue()
        {
            // Arrange
            var collection = new ServiceCollection();
#pragma warning disable CS8625 // Cannot convert null literal to non-nullable reference type.
            var services = collection
                .AddOAuthHttpClient<OAuthHttpClient>((_, options) =>
                    options.ClientCredentials = new OAuthCredential("foo", null)).Services.BuildServiceProvider();
#pragma warning restore CS8625 // Cannot convert null literal to non-nullable reference type.

            // Act
            var ex = Assert.Throws<ArgumentNullException>(() =>
                services.GetRequiredService<IOptions<OAuthHttpHandlerOptions>>().Value);

            // Assert
            Assert.Equal(
                $"{nameof(OAuthHttpHandlerOptions.ClientCredentials)}.{nameof(OAuthHttpHandlerOptions.ClientCredentials.Secret)}",
                ex.ParamName);
        }

        [Fact]
        public void AddOAuthHttpClient_WithoutTokenId_ShouldThrowsOnAccessOptionValue()
        {
            // Arrange
            var collection = new ServiceCollection();
            var services = collection.AddOAuthHttpClient<OAuthHttpClient>((_, options) =>
            {
                options.ClientCredentials = new OAuthCredential("foo", "bar");
#pragma warning disable CS8625 // Cannot convert null literal to non-nullable reference type.
                options.TokenCredentials = new OAuthCredential(null, "bar");
#pragma warning restore CS8625 // Cannot convert null literal to non-nullable reference type.
            }).Services.BuildServiceProvider();

            // Act
            var ex = Assert.Throws<ArgumentNullException>(() =>
                services.GetRequiredService<IOptions<OAuthHttpHandlerOptions>>().Value);

            // Assert
            Assert.Equal(
                $"{nameof(OAuthHttpHandlerOptions.TokenCredentials)}.{nameof(OAuthHttpHandlerOptions.TokenCredentials.Key)}",
                ex.ParamName);
        }

        [Fact]
        public void AddOAuthHttpClient_WithoutTokenSecret_ShouldThrowsOnAccessOptionValue()
        {
            // Arrange
            var collection = new ServiceCollection();
            var services = collection.AddOAuthHttpClient<OAuthHttpClient>((_, options) =>
            {
                options.ClientCredentials = new OAuthCredential("foo", "bar");
#pragma warning disable CS8625 // Cannot convert null literal to non-nullable reference type.
                options.TokenCredentials = new OAuthCredential("foo", null);
#pragma warning restore CS8625 // Cannot convert null literal to non-nullable reference type.
            }).Services.BuildServiceProvider();

            // Act
            var ex = Assert.Throws<ArgumentNullException>(() =>
                services.GetRequiredService<IOptions<OAuthHttpHandlerOptions>>().Value);

            // Assert
            Assert.Equal(
                $"{nameof(OAuthHttpHandlerOptions.TokenCredentials)}.{nameof(OAuthHttpHandlerOptions.TokenCredentials.Secret)}",
                ex.ParamName);
        }

        [Fact]
        public void AddOAuthHttpClient_WithValidConfigureOptions_ShouldNotThrows()
        {
            // Arrange
            var collection = new ServiceCollection();
            var services = collection.AddOAuthHttpClient<OAuthHttpClient>((_, o) =>
            {
                o.ClientCredentials = new OAuthCredential("foo", "bar");
                o.TokenCredentials = new OAuthCredential("foo", "bar");
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
        public void
            AddOAuthHttpClient_WithGenericConfigurePrimaryHttpMessageHandler_ShouldAddInHttpMessageHandlerBuilderActions()
        {
            // Arrange
            var mockHttp = new MockHttpMessageHandler();
            var collection = new ServiceCollection();
            var builder = collection
                .AddSingleton(mockHttp)
                .AddOAuthHttpClient<OAuthHttpClient>((_, options) =>
                {
                    options.ClientCredentials = new OAuthCredential("foo", "bar");
                    options.TokenCredentials = new OAuthCredential("foo", "bar");
                }).ConfigurePrimaryHttpMessageHandler<MockHttpMessageHandler>();
            var services = builder.Services.BuildServiceProvider();

            // Act
            var optionsMonitor = services.GetRequiredService<IOptionsMonitor<HttpClientFactoryOptions>>();

            // Assert
            var httpClientFactoryOptions = optionsMonitor.Get(builder.Name);
            Assert.Contains(httpClientFactoryOptions.HttpMessageHandlerBuilderActions,
                x => x.Target?.ToString()?.Contains("MockHttpMessageHandler") == true);
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
        public void AddTypedOAuthHttpClient_WithCustomConfigureOptions_ShouldAddInServiceProvider()
        {
            // Arrange
            var baseAddress = new Uri("https://example.com");
            var clientCredentials = new OAuthCredential(Guid.NewGuid().ToString("N"), Guid.NewGuid().ToString());
            var tokenCredentials = new OAuthCredential(Guid.NewGuid().ToString("N"), Guid.NewGuid().ToString());
            var collection = new ServiceCollection();
            var services = collection.AddOAuthHttpClient<DemoOAuthClient, DemoOptions>((_, options) =>
            {
                options.BaseAddress = baseAddress;
                options.ClientCredentials = clientCredentials;
                options.TokenCredentials = tokenCredentials;
            }).Services.BuildServiceProvider();

            // Act
            var actual = services.GetService<IOptions<DemoOptions>>()?.Value;

            // Assert
            Assert.Equal(baseAddress, actual?.BaseAddress);
            Assert.Equal(clientCredentials.Key, actual?.ClientCredentials.Key);
            Assert.Equal(clientCredentials.Secret, actual?.ClientCredentials.Secret);
            Assert.Equal(tokenCredentials.Key, actual?.TokenCredentials.Key);
            Assert.Equal(tokenCredentials.Secret, actual?.TokenCredentials.Secret);
        }

        [Fact]
        public void AddNamedOAuthHttpClient_WithCustomConfigureOptions_ShouldAddInServiceProvider()
        {
            // Arrange
            var baseAddress = new Uri("https://example.com");
            var clientCredentials = new OAuthCredential(Guid.NewGuid().ToString("N"), Guid.NewGuid().ToString());
            var tokenCredentials = new OAuthCredential(Guid.NewGuid().ToString("N"), Guid.NewGuid().ToString());
            var collection = new ServiceCollection();
            var services = collection.AddOAuthHttpClient<DemoOptions>("client1", (_, options) =>
            {
                options.BaseAddress = baseAddress;
                options.ClientCredentials = clientCredentials;
                options.TokenCredentials = tokenCredentials;
            }).Services.BuildServiceProvider();

            // Act
            var actual = services.GetService<IOptions<DemoOptions>>()?.Value;

            // Assert
            Assert.Equal(baseAddress, actual?.BaseAddress);
            Assert.Equal(clientCredentials.Key, actual?.ClientCredentials.Key);
            Assert.Equal(clientCredentials.Secret, actual?.ClientCredentials.Secret);
            Assert.Equal(tokenCredentials.Key, actual?.TokenCredentials.Key);
            Assert.Equal(tokenCredentials.Secret, actual?.TokenCredentials.Secret);
        }

        [Fact]
        public void AddTypedOAuthHttpClients_WithDifferentSigners_ShouldAddInServiceProvider()
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
        public void AddNamedOAuthHttpClients_WithDifferentSigners_ShouldAddInServiceProvider()
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

        private class DemoOptions : OAuthHttpHandlerOptions
        {
            public Uri BaseAddress { get; set; } = default!;
        }
    }
}
