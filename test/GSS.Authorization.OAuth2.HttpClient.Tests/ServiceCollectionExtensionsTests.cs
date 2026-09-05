using System.ComponentModel.DataAnnotations;
using System.Net;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Http;
using Microsoft.Extensions.Options;
using RichardSzalay.MockHttp;
using Xunit;

namespace GSS.Authorization.OAuth2.HttpClient.Tests;

public class ServiceCollectionExtensionsTests
{
    [Fact]
    public void AddOAuth2HttpClient_WithoutConfigureOptions_ShouldThrows()
    {
        // Arrange
        var collection = new ServiceCollection();

        // Act & Assert
#pragma warning disable CS8625 // Cannot convert null literal to non-nullable reference type.
        Assert.Throws<ArgumentNullException>(() =>
            collection.AddOAuth2HttpClient<OAuth2HttpClient, ClientCredentialsAuthorizer>(null));
#pragma warning restore CS8625 // Cannot convert null literal to non-nullable reference type.
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
        var services = collection.AddOAuth2HttpClient<OAuth2HttpClient, ClientCredentialsAuthorizer>((_, __) => { })
            .Services.BuildServiceProvider();

        // Act
        var ex = Assert.Throws<ValidationException>(() =>
            services.GetRequiredService<IOptions<AuthorizerOptions>>().Value);

        // Assert
        Assert.IsType<RequiredAttribute>(ex.ValidationAttribute);
        Assert.Equal(nameof(AuthorizerOptions.AccessTokenEndpoint), ex.ValidationResult.MemberNames.First());
    }

    [Fact]
    public void AddOAuth2HttpClient_WithoutClientId_ShouldThrowsOnAccessOptionValue()
    {
        // Arrange
        var collection = new ServiceCollection();
        var services = collection.AddOAuth2HttpClient<OAuth2HttpClient, ClientCredentialsAuthorizer>((_, options) =>
                options.AccessTokenEndpoint = new Uri("https://example.com"))
            .Services.BuildServiceProvider();

        // Act
        var ex = Assert.Throws<ValidationException>(() =>
            services.GetRequiredService<IOptions<AuthorizerOptions>>().Value);

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
        var ex = Assert.Throws<ValidationException>(() =>
            services.GetRequiredService<IOptions<AuthorizerOptions>>().Value);

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
    public void
        AddOAuth2HttpClient_WithGenericConfigurePrimaryHttpMessageHandler_ShouldAddInHttpMessageHandlerBuilderActions()
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
        Assert.Contains(httpClientFactoryOptions.HttpMessageHandlerBuilderActions,
            x => x.Target?.ToString()?.Contains("MockHttpMessageHandler") == true);
    }

    [Fact]
    public void AddOAuth2HttpClient_WithoutCredentials_ShouldThrowsForResourceOwnerCredentialsAuthorizer()
    {
        // Arrange
        var collection = new ServiceCollection();
        var services = collection.AddOAuth2HttpClient<OAuth2HttpClient, ResourceOwnerCredentialsAuthorizer>(
            (_, options) =>
            {
                options.AccessTokenEndpoint = new Uri("https://example.com");
                options.ClientId = "foo";
                options.ClientSecret = "bar";
            }).Services.BuildServiceProvider();

        // Act
        var ex = Assert.Throws<ArgumentNullException>(() =>
            services.GetRequiredService<ResourceOwnerCredentialsAuthorizer>());

        // Assert
        Assert.Equal(nameof(AuthorizerOptions.Credentials), ex.ParamName);
    }

    [Fact]
    public void AddOAuth2HttpClient_WithCredentials_ShouldNotThrowsForResourceOwnerCredentialsAuthorizer()
    {
        // Arrange
        var collection = new ServiceCollection();
        var services = collection.AddOAuth2HttpClient<OAuth2HttpClient, ResourceOwnerCredentialsAuthorizer>(
            (_, options) =>
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
    public async Task AddOAuth2HttpClients_WithSameAuthorizer_ShouldRequestOwnAccessTokenEndpoint()
    {
        // Arrange
        using var mockHttp = new MockHttpMessageHandler();
        // Expectations are matched in order, which is also the order the two clients run in.
        mockHttp.Expect(HttpMethod.Post, "https://example.com/token1")
            .Respond("application/json", "{\"access_token\":\"token-1\"}");
        mockHttp.Expect(HttpMethod.Get, "https://example.com/resource")
            .WithHeaders("Authorization", "Bearer token-1").Respond(HttpStatusCode.OK);
        mockHttp.Expect(HttpMethod.Post, "https://example.com/token2")
            .Respond("application/json", "{\"access_token\":\"token-2\"}");
        mockHttp.Expect(HttpMethod.Get, "https://example.com/resource")
            .WithHeaders("Authorization", "Bearer token-2").Respond(HttpStatusCode.OK);
        var collection = new ServiceCollection();
        var services = collection.AddOAuth2HttpClient<ClientCredentialsAuthorizer>("client1", (_, options) =>
            {
                options.AccessTokenEndpoint = new Uri("https://example.com/token1");
                options.ClientId = "foo";
                options.ClientSecret = "bar";
            }, authorizer => authorizer.ConfigurePrimaryHttpMessageHandler(_ => mockHttp))
            .ConfigurePrimaryHttpMessageHandler(_ => mockHttp)
            .Services.AddOAuth2HttpClient<ClientCredentialsAuthorizer>("client2", (_, options) =>
            {
                options.AccessTokenEndpoint = new Uri("https://example.com/token2");
                options.ClientId = "foo";
                options.ClientSecret = "bar";
            }, authorizer => authorizer.ConfigurePrimaryHttpMessageHandler(_ => mockHttp))
            .ConfigurePrimaryHttpMessageHandler(_ => mockHttp)
            .Services.BuildServiceProvider();
        var factory = services.GetRequiredService<IHttpClientFactory>();

        // Act
        await factory.CreateClient("client1")
            .GetAsync("https://example.com/resource", TestContext.Current.CancellationToken);
        await factory.CreateClient("client2")
            .GetAsync("https://example.com/resource", TestContext.Current.CancellationToken);

        // Assert
        mockHttp.VerifyNoOutstandingExpectation();
    }

    [Fact]
    public void AddOAuth2HttpClients_WithSameAuthorizer_ShouldConfigureEachAuthorizerClient()
    {
        // Arrange
        var configured = new List<string>();
        var collection = new ServiceCollection();

        // Act
        collection.AddOAuth2HttpClient<ClientCredentialsAuthorizer>("client1", (_, options) =>
            {
                options.AccessTokenEndpoint = new Uri("https://example.com/token1");
                options.ClientId = "foo";
                options.ClientSecret = "bar";
            }, authorizer => configured.Add(authorizer.Name))
            .Services.AddOAuth2HttpClient<ClientCredentialsAuthorizer>("client2", (_, options) =>
            {
                options.AccessTokenEndpoint = new Uri("https://example.com/token2");
                options.ClientId = "foo";
                options.ClientSecret = "bar";
            }, authorizer => configured.Add(authorizer.Name));

        // Assert
        Assert.Equal(2, configured.Count);
        Assert.Contains(nameof(ClientCredentialsAuthorizer), configured);
        Assert.Contains($"client2:{nameof(ClientCredentialsAuthorizer)}", configured);
    }

    [Fact]
    public async Task AddOAuth2HttpClients_WithConfigureHandler_ShouldUseOwnAccessTokenPlacement()
    {
        // Arrange
        using var mockHttp = new MockHttpMessageHandler();
        mockHttp.Expect(HttpMethod.Post, "https://example.com/token1")
            .Respond("application/json", "{\"access_token\":\"token-1\"}");
        mockHttp.Expect(HttpMethod.Get, "https://example.com/resource")
            .WithHeaders("Authorization", "Bearer token-1").Respond(HttpStatusCode.OK);
        mockHttp.Expect(HttpMethod.Post, "https://example.com/token2")
            .Respond("application/json", "{\"access_token\":\"token-2\"}");
        mockHttp.Expect(HttpMethod.Get, "https://example.com/resource")
            .WithQueryString("access_token", "token-2").Respond(HttpStatusCode.OK);
        var collection = new ServiceCollection();
        var services = collection.AddOAuth2HttpClient<ClientCredentialsAuthorizer>("client1", (_, options) =>
            {
                options.AccessTokenEndpoint = new Uri("https://example.com/token1");
                options.ClientId = "foo";
                options.ClientSecret = "bar";
            }, authorizer => authorizer.ConfigurePrimaryHttpMessageHandler(_ => mockHttp))
            .ConfigurePrimaryHttpMessageHandler(_ => mockHttp)
            .Services.AddOAuth2HttpClient<ClientCredentialsAuthorizer>("client2", (_, options) =>
            {
                options.AccessTokenEndpoint = new Uri("https://example.com/token2");
                options.ClientId = "foo";
                options.ClientSecret = "bar";
            }, authorizer => authorizer.ConfigurePrimaryHttpMessageHandler(_ => mockHttp),
            (_, handlerOptions) => handlerOptions.SendAccessTokenInQuery = true)
            .ConfigurePrimaryHttpMessageHandler(_ => mockHttp)
            .Services.BuildServiceProvider();
        var factory = services.GetRequiredService<IHttpClientFactory>();

        // Act
        await factory.CreateClient("client1")
            .GetAsync("https://example.com/resource", TestContext.Current.CancellationToken);
        await factory.CreateClient("client2")
            .GetAsync("https://example.com/resource", TestContext.Current.CancellationToken);

        // Assert
        mockHttp.VerifyNoOutstandingExpectation();
    }

    [Fact]
    public async Task AddOAuth2HttpClients_WithSameAuthorizer_ShouldCacheAccessTokenPerClientName()
    {
        // Arrange
        var authorizations = new List<string?>();
        using var mockHttp = new MockHttpMessageHandler();
        var token1 = mockHttp.When(HttpMethod.Post, "https://example.com/token1")
            .Respond("application/json", "{\"access_token\":\"token-1\",\"expires_in\":600}");
        var token2 = mockHttp.When(HttpMethod.Post, "https://example.com/token2")
            .Respond("application/json", "{\"access_token\":\"token-2\",\"expires_in\":600}");
        mockHttp.When(HttpMethod.Get, "https://example.com/resource").Respond(request =>
        {
            authorizations.Add(request.Headers.Authorization?.ToString());
            return new HttpResponseMessage(HttpStatusCode.OK);
        });
        var collection = new ServiceCollection();
        var services = collection.AddOAuth2HttpClient<ClientCredentialsAuthorizer>("client1", (_, options) =>
            {
                options.AccessTokenEndpoint = new Uri("https://example.com/token1");
                options.ClientId = "foo";
                options.ClientSecret = "bar";
            }, authorizer => authorizer.ConfigurePrimaryHttpMessageHandler(_ => mockHttp))
            .ConfigurePrimaryHttpMessageHandler(_ => mockHttp)
            .Services.AddOAuth2HttpClient<ClientCredentialsAuthorizer>("client2", (_, options) =>
            {
                options.AccessTokenEndpoint = new Uri("https://example.com/token2");
                options.ClientId = "foo";
                options.ClientSecret = "bar";
            }, authorizer => authorizer.ConfigurePrimaryHttpMessageHandler(_ => mockHttp))
            .ConfigurePrimaryHttpMessageHandler(_ => mockHttp)
            .Services.BuildServiceProvider();
        var factory = services.GetRequiredService<IHttpClientFactory>();

        // Act
        foreach (var name in new[] { "client1", "client2", "client1", "client2" })
        {
            await factory.CreateClient(name)
                .GetAsync("https://example.com/resource", TestContext.Current.CancellationToken);
        }

        // Assert
        Assert.Equal(1, mockHttp.GetMatchCount(token1));
        Assert.Equal(1, mockHttp.GetMatchCount(token2));
        Assert.Equal(
            ["Bearer token-1", "Bearer token-2", "Bearer token-1", "Bearer token-2"],
            authorizations);
    }

    private class DemoOAuthClient(System.Net.Http.HttpClient client)
    {
        private readonly System.Net.Http.HttpClient _client = client;
    }
}