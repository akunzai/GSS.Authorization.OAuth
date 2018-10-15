using System;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Newtonsoft.Json;
using RichardSzalay.MockHttp;
using Xunit;

namespace GSS.Authorization.OAuth2
{
    public class OAuth2HttpClientTests : IClassFixture<OAuth2HttpClientFixture>
    {
        private readonly OAuth2HttpClient _client;
        private readonly MockHttpMessageHandler _mockHttp;
        private readonly Uri _resourceEndpoint;

        public OAuth2HttpClientTests(OAuth2HttpClientFixture fixture)
        {
            _client = fixture.Services.GetRequiredService<OAuth2HttpClient>();
            var options = fixture.Services.GetService<IOptions<AuthorizerOptions>>().Value;
            var configuration = fixture.Services.GetRequiredService<IConfiguration>();
            _resourceEndpoint = configuration.GetValue<Uri>("OAuth2:ResourceEndpoint");
            _mockHttp = fixture.Services.GetService<MockHttpMessageHandler>();
            _mockHttp?.When(HttpMethod.Post, options.AccessTokenEndpoint.AbsoluteUri)
                .WithFormData(AuthorizerDefaults.ClientId, options.ClientId)
                .WithFormData(AuthorizerDefaults.ClientSecret, options.ClientSecret)
                .Respond("application/json", JsonConvert.SerializeObject(new AccessToken
                {
                    Token = Guid.NewGuid().ToString(),
                    ExpiresInSeconds = 86400
                }));
        }

        [Fact]
        public async Task HttpClient_GetResourceEndpoint_ShouldReponseOK()
        {
            // Arrange
            var requestUri = QueryHelpers.AddQueryString(_resourceEndpoint.AbsoluteUri, "_", Guid.NewGuid().ToString());
            _mockHttp?.Expect(HttpMethod.Get, requestUri)
                .Respond(HttpStatusCode.OK);

            // Act
            var response = await _client.HttpClient.GetAsync(requestUri).ConfigureAwait(false);

            // Assert
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            _mockHttp?.VerifyNoOutstandingExpectation();
            _mockHttp?.VerifyNoOutstandingRequest();
        }

        [Fact]
        public async Task HttpClient_GetResourceEndpoint_ShouldCachingAccessToken()
        {
            // Arrange
            var requestUri = QueryHelpers.AddQueryString(_resourceEndpoint.AbsoluteUri, "_", Guid.NewGuid().ToString());
            _mockHttp?.Expect(HttpMethod.Get, requestUri)
                .Respond(HttpStatusCode.OK);
            _mockHttp?.Expect(HttpMethod.Get, requestUri)
                .Respond(HttpStatusCode.OK);

            // Act
            var response = await _client.HttpClient.GetAsync(requestUri).ConfigureAwait(false);
            var response2 = await _client.HttpClient.GetAsync(requestUri).ConfigureAwait(false);

            // Assert
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal(HttpStatusCode.OK, response2.StatusCode);
            _mockHttp?.VerifyNoOutstandingExpectation();
            _mockHttp?.VerifyNoOutstandingRequest();
        }
    }
}
