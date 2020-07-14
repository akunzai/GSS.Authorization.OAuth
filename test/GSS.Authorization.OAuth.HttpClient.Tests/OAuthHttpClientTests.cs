using System;
using System.Collections.Generic;
using System.Globalization;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using RichardSzalay.MockHttp;
using Xunit;

namespace GSS.Authorization.OAuth.HttpClient.Tests
{
    public class OAuthHttpClientTests : IClassFixture<OAuthFixture>
    {
        private readonly MockHttpMessageHandler _mockHttp;
        private readonly IRequestSigner _signer = new HmacSha1RequestSigner();
        private readonly IConfiguration _configuration;
        private readonly OAuthCredential _tokenCredentials;

        public OAuthHttpClientTests(OAuthFixture fixture)
        {
            _configuration = fixture.Configuration;
            _tokenCredentials = new OAuthCredential(
                _configuration["OAuth:TokenId"],
                _configuration["OAuth:TokenSecret"]);
            if (_configuration.GetValue("HttpClient:Mock", true))
            {
                _mockHttp = new MockHttpMessageHandler();
                _mockHttp.Fallback.Respond(HttpStatusCode.Unauthorized);
            }
        }

        [Fact]
        public async Task HttpClient_AccessProtectedResourceWithAuthorizationHeader_ShouldAuthorized()
        {
            // Arrange
            var services = new ServiceCollection()
                .AddOAuthHttpClient<OAuthHttpClient>((_, options) =>
                {
                    options.ClientCredentials = new OAuthCredential(
                        _configuration["OAuth:ClientId"],
                        _configuration["OAuth:ClientSecret"]);
                    options.TokenCredentials = _tokenCredentials;
                    if (_mockHttp != null)
                    {
                        var timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture);
                        var nonce = new Random().Next(123400, 9999999).ToString(CultureInfo.InvariantCulture);
                        options.TimestampProvider = () => timestamp;
                        options.NonceProvider = () => nonce;
                    }
                })
                .ConfigurePrimaryHttpMessageHandler(_ => (HttpMessageHandler)_mockHttp ?? new HttpClientHandler())
            .Services.BuildServiceProvider();
            var client = services.GetRequiredService<OAuthHttpClient>();
            var options = services.GetRequiredService<IOptions<OAuthHttpHandlerOptions>>();
            var resourceUri = _configuration.GetValue<Uri>("OAuth:ResourceUri");
            _mockHttp?.Expect(HttpMethod.Get, resourceUri.AbsoluteUri)
                .WithHeaders("Authorization", _signer.GetAuthorizationHeader(
                    HttpMethod.Get, resourceUri, options.Value, resourceUri.ParseQueryString(), _tokenCredentials).ToString())
                .Respond(HttpStatusCode.OK);

            // Act
            var response = await client.HttpClient.GetAsync(resourceUri).ConfigureAwait(false);

            // Assert
            Assert.NotEqual(HttpStatusCode.Unauthorized, response.StatusCode);
            _mockHttp?.VerifyNoOutstandingExpectation();
            _mockHttp?.VerifyNoOutstandingRequest();
        }

        [Fact]
        public async Task HttpClient_AccessProtectedResourceWithQueryString_ShouldAuthorized()
        {
            // Arrange
            var services = new ServiceCollection()
                .AddOAuthHttpClient<OAuthHttpClient>((_, options) =>
                {
                    options.ClientCredentials = new OAuthCredential(
                        _configuration["OAuth:ClientId"],
                        _configuration["OAuth:ClientSecret"]);
                    options.TokenCredentials = _tokenCredentials;
                    options.SignedAsQuery = true;
                    if (_mockHttp != null)
                    {
                        var timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture);
                        var nonce = new Random().Next(123400, 9999999).ToString(CultureInfo.InvariantCulture);
                        options.TimestampProvider = () => timestamp;
                        options.NonceProvider = () => nonce;
                    }
                })
                .ConfigurePrimaryHttpMessageHandler(_ => (HttpMessageHandler)_mockHttp ?? new HttpClientHandler())
            .Services.BuildServiceProvider();
            var client = services.GetRequiredService<OAuthHttpClient>();
            var options = services.GetRequiredService<IOptions<OAuthHttpHandlerOptions>>();
            var resourceUri = new UriBuilder(_configuration["OAuth:ResourceUri"]);
            resourceUri.Query += resourceUri.Query.Contains("?") ? "&foo=v1&foo=v2" : "?foo=v1&foo=v2";
            var query = _signer.AppendAuthorizationParameters(HttpMethod.Get, resourceUri.Uri,
                options.Value, resourceUri.Uri.ParseQueryString(), _tokenCredentials);
            var values = new List<string>();
            foreach (var key in query.AllKeys)
            {
                foreach (var value in query.GetValues(key))
                {
                    values.Add($"{Uri.EscapeDataString(key)}={Uri.EscapeDataString(value)}");
                }
            }
            _mockHttp?.Expect(HttpMethod.Get, resourceUri.Uri.AbsoluteUri)
                .WithQueryString("?" + string.Join("&", values))
                .Respond(HttpStatusCode.OK);

            // Act
            var response = await client.HttpClient.GetAsync(resourceUri.Uri).ConfigureAwait(false);

            // Assert
            Assert.NotEqual(HttpStatusCode.Unauthorized, response.StatusCode);
            _mockHttp?.VerifyNoOutstandingExpectation();
            _mockHttp?.VerifyNoOutstandingRequest();
        }
    }
}