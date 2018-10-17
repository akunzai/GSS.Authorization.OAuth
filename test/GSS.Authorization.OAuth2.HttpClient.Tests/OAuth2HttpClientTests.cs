using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Newtonsoft.Json;
using RichardSzalay.MockHttp;
using Xunit;

namespace GSS.Authorization.OAuth2
{
    public class OAuth2HttpClientTests
    {
        private readonly OAuth2HttpClient _client;
        private readonly MockHttpMessageHandler _mockHttp;
        private readonly Uri _resourceEndpoint;
        private readonly AuthorizerOptions _options;

        public OAuth2HttpClientTests()
        {
            var env = Environment.GetEnvironmentVariable("ENVIRONMENT") ?? "Production";
            var configuration = new ConfigurationBuilder()
                .AddJsonFile("appsettings.json")
                .AddJsonFile($"appsettings.{env}.json", optional: true)
                .Build();
            if (configuration.GetValue("HttpClient:Mock", true))
            {
                _mockHttp = new MockHttpMessageHandler();
            }
            var services = new ServiceCollection()
            .AddLogging(logging =>
            {
                logging.AddConfiguration(configuration.GetSection("Logging"));
                logging.AddDebug();
            })
            .AddTransient<IAuthorizer>(sp =>
            {
                var grantType = configuration.GetValue("OAuth2:GrantFlow", "ClientCredentials");
                if (grantType.Contains("ResourceOwner"))
                {
                    return ActivatorUtilities.CreateInstance<ResourceOwnerCredentialsAuthorizer>(sp);
                }
                return ActivatorUtilities.CreateInstance<ClientCredentialsAuthorizer>(sp);
            })
            .AddOptions<AuthorizerOptions>().Configure(options =>
            {
                options.AccessTokenEndpoint = configuration.GetValue<Uri>("OAuth2:AccessTokenEndpoint");
                options.ClientId = configuration["OAuth2:ClientId"];
                options.ClientSecret = configuration["OAuth2:ClientSecret"];
                options.Credentials = new NetworkCredential(configuration["OAuth2:Credentials:UserName"], configuration["OAuth2:Credentials:Password"]);
                options.Scopes = configuration.GetSection("OAuth2:Scopes").Get<IEnumerable<string>>();
            })
            .Services.AddHttpClient<AuthorizerHttpClient>()
                .ConfigurePrimaryHttpMessageHandler(sp => _mockHttp as HttpMessageHandler ?? new HttpClientHandler())
            .Services.AddHttpClient<OAuth2HttpClient>()
                .AddHttpMessageHandler(sp => ActivatorUtilities.CreateInstance<OAuth2HttpHandler>(sp))
                .ConfigurePrimaryHttpMessageHandler(sp => _mockHttp as HttpMessageHandler ?? new HttpClientHandler())
             .Services.BuildServiceProvider();
            _client = services.GetRequiredService<OAuth2HttpClient>();
            _options = services.GetService<IOptions<AuthorizerOptions>>().Value;
            _resourceEndpoint = configuration.GetValue<Uri>("OAuth2:ResourceEndpoint");
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
