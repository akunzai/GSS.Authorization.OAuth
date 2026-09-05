using System.Net;
using Microsoft.Extensions.Options;
using Xunit;

namespace GSS.Authorization.OAuth.HttpClient.Tests;

public class OAuthHttpHandlerTests
{
    [Fact]
    public async Task SendAsync_WithNonFormContent_ShouldFallBackToQuery()
    {
        // Arrange
        var innerHandler = new RecordingHandler();
        using var client = CreateClient(
            new OAuthHttpHandlerOptions { SignedAsBody = true, SignedAsQuery = true },
            innerHandler);
        using var request = new HttpRequestMessage(HttpMethod.Post, "https://example.com/resource?name=value")
        {
            Content = new StringContent("content")
        };

        // Act
        await client.SendAsync(request, TestContext.Current.CancellationToken);

        // Assert
        Assert.Contains($"{OAuthDefaults.OAuthSignature}=", innerHandler.RequestUri?.Query);
        Assert.Contains("name=value", innerHandler.RequestUri?.Query);
        Assert.Null(innerHandler.Authorization);
    }

    [Fact]
    public async Task SendAsync_WithNonFormContentAndQueryDisabled_ShouldFallBackToHeader()
    {
        // Arrange
        var innerHandler = new RecordingHandler();
        using var client = CreateClient(
            new OAuthHttpHandlerOptions { SignedAsBody = true },
            innerHandler);
        using var request = new HttpRequestMessage(HttpMethod.Post, "https://example.com/resource?name=value")
        {
            Content = new StringContent("content")
        };

        // Act
        await client.SendAsync(request, TestContext.Current.CancellationToken);

        // Assert
        Assert.StartsWith(OAuthDefaults.OAuthScheme, innerHandler.Authorization);
        Assert.Equal("?name=value", innerHandler.RequestUri?.Query);
    }

    private static System.Net.Http.HttpClient CreateClient(
        OAuthHttpHandlerOptions options,
        HttpMessageHandler innerHandler)
    {
        options.ClientCredentials = new OAuthCredential("client-key", "client-secret");
        options.TokenCredentials = new OAuthCredential("token-key", "token-secret");
        options.NonceProvider = () => "nonce";
        options.TimestampProvider = () => "1234567890";
        var handler = new OAuthHttpHandler(Options.Create(options), new HmacSha1RequestSigner())
        {
            InnerHandler = innerHandler
        };
        return new System.Net.Http.HttpClient(handler);
    }

    private sealed class RecordingHandler : HttpMessageHandler
    {
        public string? Authorization { get; private set; }

        public Uri? RequestUri { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            Authorization = request.Headers.Authorization?.ToString();
            RequestUri = request.RequestUri;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
        }
    }
}
