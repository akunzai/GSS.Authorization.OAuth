using System.Net;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using Xunit;

namespace GSS.Authorization.OAuth2.HttpClient.Tests;

public class OAuth2HttpHandlerTests
{
    [Fact]
    public async Task SendAsync_WithFormContent_ShouldAddAccessTokenToBody()
    {
        // Arrange
        var innerHandler = new RecordingHandler();
        using var client = CreateClient(
            new OAuth2HttpHandlerOptions { SendAccessTokenInBody = true },
            _ => Task.FromResult(new AccessToken { Token = "access-token" }),
            innerHandler);
        using var request = new HttpRequestMessage(HttpMethod.Post, "https://example.com/resource")
        {
            Content = new FormUrlEncodedContent([
                new KeyValuePair<string, string>("name", "value-1"),
                new KeyValuePair<string, string>("name", "value-2")
            ])
        };

        // Act
        await client.SendAsync(request, TestContext.Current.CancellationToken);

        // Assert
        Assert.Equal("name=value-1&name=value-2&access_token=access-token", innerHandler.Content);
        Assert.Null(Assert.Single(innerHandler.Authorizations));
    }

    [Fact]
    public async Task SendAsync_WithNonFormContent_ShouldFallBackToQuery()
    {
        // Arrange
        var innerHandler = new RecordingHandler();
        using var client = CreateClient(
            new OAuth2HttpHandlerOptions { SendAccessTokenInBody = true, SendAccessTokenInQuery = true },
            _ => Task.FromResult(new AccessToken { Token = "access-token" }),
            innerHandler);
        using var request = new HttpRequestMessage(HttpMethod.Post, "https://example.com/resource?name=value")
        {
            Content = new StringContent("content")
        };

        // Act
        await client.SendAsync(request, TestContext.Current.CancellationToken);

        // Assert
        Assert.Equal("?name=value&access_token=access-token", innerHandler.RequestUri?.Query);
        Assert.Null(Assert.Single(innerHandler.Authorizations));
    }

    [Fact]
    public async Task SendAsync_WithNonFormContentAndQueryDisabled_ShouldFallBackToHeader()
    {
        // Arrange
        var innerHandler = new RecordingHandler();
        using var client = CreateClient(
            new OAuth2HttpHandlerOptions { SendAccessTokenInBody = true },
            _ => Task.FromResult(new AccessToken { Token = "access-token" }),
            innerHandler);
        using var request = new HttpRequestMessage(HttpMethod.Post, "https://example.com/resource")
        {
            Content = new StringContent("content")
        };

        // Act
        await client.SendAsync(request, TestContext.Current.CancellationToken);

        // Assert
        Assert.Equal("Bearer access-token", Assert.Single(innerHandler.Authorizations));
    }

    private static System.Net.Http.HttpClient CreateClient(
        OAuth2HttpHandlerOptions options,
        Func<CancellationToken, Task<AccessToken>> getAccessToken,
        HttpMessageHandler innerHandler)
    {
        var handler = new OAuth2HttpHandler(
            Options.Create(options),
            new StubAuthorizer(getAccessToken),
            new MemoryCache(new MemoryCacheOptions()))
        {
            InnerHandler = innerHandler
        };
        return new System.Net.Http.HttpClient(handler);
    }

    private sealed class StubAuthorizer(Func<CancellationToken, Task<AccessToken>> getAccessToken) : IAuthorizer
    {
        public Task<AccessToken> GetAccessTokenAsync(CancellationToken cancellationToken = default)
        {
            return getAccessToken(cancellationToken);
        }
    }

    private sealed class RecordingHandler : HttpMessageHandler
    {
        public List<string?> Authorizations { get; } = [];

        public string? Content { get; private set; }

        public Uri? RequestUri { get; private set; }

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            lock (Authorizations)
            {
                Authorizations.Add(request.Headers.Authorization?.ToString());
            }
            Content = request.Content == null
                ? null
                : await request.Content.ReadAsStringAsync(cancellationToken);
            RequestUri = request.RequestUri;
            return new HttpResponseMessage(HttpStatusCode.OK);
        }
    }
}
