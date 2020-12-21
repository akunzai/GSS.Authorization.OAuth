using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Globalization;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
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
        private static readonly RNGCryptoServiceProvider _rngCrypto = new RNGCryptoServiceProvider();
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
                        var nonce = generateNonce();
                        options.TimestampProvider = () => timestamp;
                        options.NonceProvider = () => nonce;
                    }
                })
                .ConfigurePrimaryHttpMessageHandler(_ => (HttpMessageHandler)_mockHttp ?? new HttpClientHandler())
            .Services.BuildServiceProvider();
            var client = services.GetRequiredService<OAuthHttpClient>();
            var options = services.GetRequiredService<IOptions<OAuthHttpHandlerOptions>>();
            var resourceUri = _configuration.GetValue<Uri>("Request:Uri");
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
                        var nonce = generateNonce();
                        options.TimestampProvider = () => timestamp;
                        options.NonceProvider = () => nonce;
                    }
                })
                .ConfigurePrimaryHttpMessageHandler(_ => (HttpMessageHandler)_mockHttp ?? new HttpClientHandler())
            .Services.BuildServiceProvider();
            var client = services.GetRequiredService<OAuthHttpClient>();
            var options = services.GetRequiredService<IOptions<OAuthHttpHandlerOptions>>();
            var resourceUri = new UriBuilder(_configuration["Request:Uri"]);
            resourceUri.Query += resourceUri.Query.Contains("?", StringComparison.Ordinal) ? "&foo=v1&foo=v2" : "?foo=v1&foo=v2";
            var parameters = _signer.AppendAuthorizationParameters(HttpMethod.Get, resourceUri.Uri,
                options.Value, resourceUri.Uri.ParseQueryString(), _tokenCredentials);
            var values = new List<string>();
            foreach (var key in parameters.AllKeys)
            {
                foreach (var value in parameters.GetValues(key))
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

        [Fact]
        public async Task HttpClient_AccessProtectedResourceWithFormBody_ShouldAuthorized()
        {
            // Arrange
            var services = new ServiceCollection()
                .AddOAuthHttpClient<OAuthHttpClient>((_, options) =>
                {
                    options.ClientCredentials = new OAuthCredential(
                        _configuration["OAuth:ClientId"],
                        _configuration["OAuth:ClientSecret"]);
                    options.TokenCredentials = _tokenCredentials;
                    options.SignedAsBody = true;
                    if (_mockHttp != null)
                    {
                        var timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture);
                        var nonce = generateNonce();
                        options.TimestampProvider = () => timestamp;
                        options.NonceProvider = () => nonce;
                    }
                })
                .ConfigurePrimaryHttpMessageHandler(_ => (HttpMessageHandler)_mockHttp ?? new HttpClientHandler())
            .Services.BuildServiceProvider();
            var client = services.GetRequiredService<OAuthHttpClient>();
            var options = services.GetRequiredService<IOptions<OAuthHttpHandlerOptions>>();
            var resourceUri = new UriBuilder(_configuration["Request:Uri"]);
            var queryString = resourceUri.Uri.ParseQueryString();
            var body = _configuration.GetSection("Request:Body").Get<IDictionary<string, string>>();
            var formData = new NameValueCollection();
            foreach (var (key, value) in body)
            {
                formData.Add(key, value);
            }
            foreach (var key in queryString.AllKeys)
            {
                if (formData.Get(key) == null)
                {
                    formData.Add(key, queryString[key]);
                }
            }
            var parameters = _signer.AppendAuthorizationParameters(HttpMethod.Post, resourceUri.Uri,
                options.Value, formData, _tokenCredentials);
            var values = new Dictionary<string, string>();
            foreach (var key in parameters.AllKeys)
            {
                if (queryString.Get(key) == null)
                {
                    values.Add(key, parameters[key]);
                }
            }
            _mockHttp?.Expect(HttpMethod.Post, resourceUri.Uri.AbsoluteUri)
                .WithFormData(values)
                .Respond(HttpStatusCode.OK);

            // Act
            using var content = new FormUrlEncodedContent(body);
            var response = await client.HttpClient.PostAsync(resourceUri.Uri, content).ConfigureAwait(false);

            // Assert
            Assert.NotEqual(HttpStatusCode.Unauthorized, response.StatusCode);
            _mockHttp?.VerifyNoOutstandingExpectation();
            _mockHttp?.VerifyNoOutstandingRequest();
        }

        private string generateNonce()
        {
            var bytes = new byte[16];
            _rngCrypto.GetNonZeroBytes(bytes);
            return Convert.ToBase64String(bytes);
        }
    }
}
