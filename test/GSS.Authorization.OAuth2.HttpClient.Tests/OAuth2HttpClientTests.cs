using System;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Newtonsoft.Json;
using RichardSzalay.MockHttp;
using Xunit;

namespace GSS.Authorization.OAuth2.HttpClient.Tests
{
    public class OAuth2HttpClientTests : IClassFixture<OAuth2Fixture>
    {
        private readonly OAuth2HttpClient _client;
        private readonly MockHttpMessageHandler _mockHttp;
        private readonly Uri _resourceEndpoint;
        private readonly AuthorizerOptions _options;

        public OAuth2HttpClientTests(OAuth2Fixture fixture)
        {
            var services = fixture.BuildServiceProvider();
            _client = services.GetRequiredService<OAuth2HttpClient>();
            _options = services.GetRequiredService<IOptions<AuthorizerOptions>>().Value;
            _mockHttp = services.GetService<MockHttpMessageHandler>();
            _resourceEndpoint = fixture.Configuration.GetValue<Uri>("OAuth2:ResourceEndpoint");
        }

        [Fact]
        public async Task HttpClient_AccessProtectedResourceWithValidAccessToken_ShouldAuthorized()
        {
            // Arrange
            var accessToken = new AccessToken
            {
                Token = Guid.NewGuid().ToString(),
                ExpiresInSeconds = 10
            };
            _mockHttp?.ResetExpectations();
            _mockHttp?.Expect(HttpMethod.Post, _options.AccessTokenEndpoint.AbsoluteUri)
                .WithFormData(AuthorizerDefaults.ClientId, _options.ClientId)
                .WithFormData(AuthorizerDefaults.ClientSecret, _options.ClientSecret)
                .Respond("application/json", JsonConvert.SerializeObject(accessToken));
            _mockHttp?.Expect(HttpMethod.Get, _resourceEndpoint.AbsoluteUri)
                .WithHeaders("Authorization", $"{AuthorizerDefaults.Bearer} {accessToken.Token}")
                .Respond(HttpStatusCode.OK);

            // Act
            var response = await _client.HttpClient.GetAsync(_resourceEndpoint).ConfigureAwait(false);

            // Assert
            Assert.NotEqual(HttpStatusCode.Unauthorized, response.StatusCode);
            _mockHttp?.VerifyNoOutstandingExpectation();
            _mockHttp?.VerifyNoOutstandingRequest();
        }

        [SkippableFact]
        public async Task HttpClient_AccessProtectedResourceWithPredefinedAuthorizationHeader_ShouldSkipAuthorized()
        {
            Skip.If(_mockHttp == null);

            // Arrange
            var invalidToken = "TEST";
            _mockHttp?.ResetExpectations();
            _mockHttp.Expect(HttpMethod.Get, _resourceEndpoint.AbsoluteUri)
                .WithHeaders("Authorization", $"{AuthorizerDefaults.Bearer} {invalidToken}")
                .Respond(HttpStatusCode.Forbidden);

            // Act
            var request = new HttpRequestMessage(HttpMethod.Get, _resourceEndpoint);
            request.Headers.Authorization = new AuthenticationHeaderValue(AuthorizerDefaults.Bearer, invalidToken);
            var response = await _client.HttpClient.SendAsync(request).ConfigureAwait(false);

            // Assert
            Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
            _mockHttp.VerifyNoOutstandingExpectation();
            _mockHttp.VerifyNoOutstandingRequest();
        }

        [SkippableFact]
        public async Task HttpClient_AccessProtectedResourceWithoutAccessToken_ShouldPassThrough()
        {
            Skip.If(_mockHttp == null);

            // Arrange
            _mockHttp?.ResetExpectations();
            _mockHttp.Expect(HttpMethod.Get, _resourceEndpoint.AbsoluteUri)
                .Respond(HttpStatusCode.Forbidden);

            // Act
            var response = await _client.HttpClient.GetAsync(_resourceEndpoint).ConfigureAwait(false);

            // Assert
            Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
            _mockHttp.VerifyNoOutstandingExpectation();
            _mockHttp.VerifyNoOutstandingRequest();
        }

        [SkippableFact]
        public async Task HttpClient_AccessProtectedResourceWithUnauthorizedResponse_ShouldAuthorized()
        {
            Skip.If(_mockHttp == null);

            // Arrange
            _mockHttp?.ResetExpectations();
            _mockHttp.Expect(HttpMethod.Get, _resourceEndpoint.AbsoluteUri)
                .Respond(HttpStatusCode.Unauthorized);
            var accessToken = new AccessToken
            {
                Token = Guid.NewGuid().ToString(),
                ExpiresInSeconds = 10
            };
            _mockHttp.Expect(HttpMethod.Post, _options.AccessTokenEndpoint.AbsoluteUri)
                .WithFormData(AuthorizerDefaults.ClientId, _options.ClientId)
                .WithFormData(AuthorizerDefaults.ClientSecret, _options.ClientSecret)
                .Respond("application/json", JsonConvert.SerializeObject(accessToken));
            _mockHttp.Expect(HttpMethod.Get, _resourceEndpoint.AbsoluteUri)
                .WithHeaders("Authorization", $"{AuthorizerDefaults.Bearer} {accessToken.Token}")
                .Respond(HttpStatusCode.OK);

            // Act
            var response = await _client.HttpClient.GetAsync(_resourceEndpoint).ConfigureAwait(false);

            // Assert
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            _mockHttp.VerifyNoOutstandingExpectation();
            _mockHttp.VerifyNoOutstandingRequest();
        }

        [Fact]
        public async Task HttpClient_AccessProtectedResourceWithCachedAccessToken_ShouldAuthorizedOnce()
        {
            // Arrange
            var accessToken = new AccessToken
            {
                Token = Guid.NewGuid().ToString(),
                ExpiresInSeconds = 10
            };
            _mockHttp?.ResetExpectations();
            _mockHttp?.Expect(HttpMethod.Post, _options.AccessTokenEndpoint.AbsoluteUri)
                .WithFormData(AuthorizerDefaults.ClientId, _options.ClientId)
                .WithFormData(AuthorizerDefaults.ClientSecret, _options.ClientSecret)
                .Respond("application/json", JsonConvert.SerializeObject(accessToken));
            _mockHttp?.Expect(HttpMethod.Get, _resourceEndpoint.AbsoluteUri)
                .WithHeaders("Authorization", $"{AuthorizerDefaults.Bearer} {accessToken.Token}")
                .Respond(HttpStatusCode.OK);
            _mockHttp?.Expect(HttpMethod.Get, _resourceEndpoint.AbsoluteUri)
                .WithHeaders("Authorization", $"{AuthorizerDefaults.Bearer} {accessToken.Token}")
                .Respond(HttpStatusCode.OK);

            // Act
            var response = await _client.HttpClient.GetAsync(_resourceEndpoint).ConfigureAwait(false);
            var response2 = await _client.HttpClient.GetAsync(_resourceEndpoint).ConfigureAwait(false);

            // Assert
            Assert.NotEqual(HttpStatusCode.Unauthorized, response.StatusCode);
            Assert.NotEqual(HttpStatusCode.Unauthorized, response2.StatusCode);
            _mockHttp?.VerifyNoOutstandingExpectation();
            _mockHttp?.VerifyNoOutstandingRequest();
        }

        [SkippableFact]
        public async Task HttpClient_AccessProtectedResourceWithExpiredAccessToken_ShouldReAuthorized()
        {
            Skip.If(_mockHttp == null);

            // Arrange
            var accessToken = new AccessToken
            {
                Token = Guid.NewGuid().ToString(),
                ExpiresInSeconds = 1
            };
            var accessToken2 = new AccessToken
            {
                Token = Guid.NewGuid().ToString(),
                ExpiresInSeconds = 2
            };
            _mockHttp?.ResetExpectations();
            _mockHttp.Expect(HttpMethod.Post, _options.AccessTokenEndpoint.AbsoluteUri)
                .WithFormData(AuthorizerDefaults.ClientId, _options.ClientId)
                .WithFormData(AuthorizerDefaults.ClientSecret, _options.ClientSecret)
                .Respond("application/json", JsonConvert.SerializeObject(accessToken));
            _mockHttp.Expect(HttpMethod.Get, _resourceEndpoint.AbsoluteUri)
                .WithHeaders("Authorization", $"{AuthorizerDefaults.Bearer} {accessToken.Token}")
                .Respond(HttpStatusCode.OK);
            _mockHttp.Expect(HttpMethod.Post, _options.AccessTokenEndpoint.AbsoluteUri)
                .WithFormData(AuthorizerDefaults.ClientId, _options.ClientId)
                .WithFormData(AuthorizerDefaults.ClientSecret, _options.ClientSecret)
                .Respond("application/json", JsonConvert.SerializeObject(accessToken2));
            _mockHttp.Expect(HttpMethod.Get, _resourceEndpoint.AbsoluteUri)
                .WithHeaders("Authorization", $"{AuthorizerDefaults.Bearer} {accessToken2.Token}")
                .Respond(HttpStatusCode.OK);

            // Act
            var response = await _client.HttpClient.GetAsync(_resourceEndpoint).ConfigureAwait(false);
            await Task.Delay(TimeSpan.FromSeconds(1)).ConfigureAwait(false);
            var response2 = await _client.HttpClient.GetAsync(_resourceEndpoint).ConfigureAwait(false);

            // Assert
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal(HttpStatusCode.OK, response2.StatusCode);
            _mockHttp.VerifyNoOutstandingExpectation();
            _mockHttp.VerifyNoOutstandingRequest();
        }
    }
}
