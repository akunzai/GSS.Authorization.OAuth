using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
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
    public class ClientCredentialsAuthorizerTests
    {
        private readonly IAuthorizer _authorizer;
        private readonly MockHttpMessageHandler _mockHttp;
        private readonly AuthorizerOptions _options;
        private HttpStatusCode _errorStatusCode;
        private string _errorMessage;

        public ClientCredentialsAuthorizerTests()
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
            .AddOptions<AuthorizerOptions>().Configure(options =>
            {
                options.AccessTokenEndpoint = configuration.GetValue<Uri>("OAuth2:AccessTokenEndpoint");
                options.ClientId = configuration["OAuth2:ClientId"];
                options.ClientSecret = configuration["OAuth2:ClientSecret"];
                options.Credentials = new NetworkCredential(configuration["OAuth2:Credentials:UserName"], configuration["OAuth2:Credentials:Password"]);
                options.Scopes = configuration.GetSection("OAuth2:Scopes").Get<IEnumerable<string>>();
                options.OnError = (c, m) =>
                {
                    _errorStatusCode = c;
                    _errorMessage = m;
                };
            })
            .Services.AddHttpClient<AuthorizerHttpClient>()
                .ConfigurePrimaryHttpMessageHandler(sp => _mockHttp as HttpMessageHandler ?? new HttpClientHandler())
             .Services.BuildServiceProvider();
            _options = services.GetService<IOptions<AuthorizerOptions>>().Value;
            _authorizer = ActivatorUtilities.CreateInstance<ClientCredentialsAuthorizer>(services);
        }

        [Fact]
        public async Task Authorizer_GetAccessToken_ShouldNotNull()
        {
            // Arrange
            _mockHttp?.Expect(HttpMethod.Post, _options.AccessTokenEndpoint.AbsoluteUri)
                .WithFormData(AuthorizerDefaults.ClientId, _options.ClientId)
                .WithFormData(AuthorizerDefaults.ClientSecret, _options.ClientSecret)
                .WithFormData(AuthorizerDefaults.GrantType, AuthorizerDefaults.ClientCredentials)
                .Respond("application/json", JsonConvert.SerializeObject(new AccessToken
                {
                    Token = Guid.NewGuid().ToString(),
                    ExpiresInSeconds = 10
                }));

            // Act
            var accessToken = await _authorizer.GetAccessTokenAsync().ConfigureAwait(false);

            // Assert
            Assert.NotNull(accessToken);
            _mockHttp?.VerifyNoOutstandingExpectation();
        }

        [Fact]
        public async Task Authorizer_GetAccessToken_ShouldNotEmpty()
        {
            // Arrange
            _mockHttp?.Expect(HttpMethod.Post, _options.AccessTokenEndpoint.AbsoluteUri)
                .WithFormData(AuthorizerDefaults.ClientId, _options.ClientId)
                .WithFormData(AuthorizerDefaults.ClientSecret, _options.ClientSecret)
                .WithFormData(AuthorizerDefaults.GrantType, AuthorizerDefaults.ClientCredentials)
                .Respond("application/json", JsonConvert.SerializeObject(new AccessToken
                {
                    Token = Guid.NewGuid().ToString(),
                    ExpiresInSeconds = 10
                }));

            // Act
            var accessToken = await _authorizer.GetAccessTokenAsync().ConfigureAwait(false);

            // Assert
            Assert.NotEmpty(accessToken.Token);
            _mockHttp?.VerifyNoOutstandingExpectation();
        }

        [SkippableFact]
        public async Task Authorizer_GetAccessTokenWithException_ShouldReturnNull()
        {
            Skip.If(_mockHttp == null);

            // Arrange
            _mockHttp.Expect(HttpMethod.Post, _options.AccessTokenEndpoint.AbsoluteUri)
                .WithFormData(AuthorizerDefaults.ClientId, _options.ClientId)
                .WithFormData(AuthorizerDefaults.ClientSecret, _options.ClientSecret)
                .WithFormData(AuthorizerDefaults.GrantType, AuthorizerDefaults.ClientCredentials)
                .Respond(HttpStatusCode.InternalServerError);

            // Act
            var accessToken = await _authorizer.GetAccessTokenAsync().ConfigureAwait(false);

            // Assert
            Assert.Null(accessToken);
            _mockHttp.VerifyNoOutstandingExpectation();
        }

        [SkippableFact]
        public async Task Authorizer_GetAccessTokenWithException_ShouldInvokeErrorHandler()
        {
            Skip.If(_mockHttp == null);

            // Arrange
            var expectedErrorMessage = Guid.NewGuid().ToString();
            _mockHttp.Expect(HttpMethod.Post, _options.AccessTokenEndpoint.AbsoluteUri)
                .WithFormData(AuthorizerDefaults.ClientId, _options.ClientId)
                .WithFormData(AuthorizerDefaults.ClientSecret, _options.ClientSecret)
                .WithFormData(AuthorizerDefaults.GrantType, AuthorizerDefaults.ClientCredentials)
                .Respond(HttpStatusCode.InternalServerError,new StringContent(expectedErrorMessage));

            // Act
            await _authorizer.GetAccessTokenAsync().ConfigureAwait(false);

            // Assert
            Assert.Equal(HttpStatusCode.InternalServerError, _errorStatusCode);
            Assert.Equal(expectedErrorMessage, _errorMessage);
            _mockHttp.VerifyNoOutstandingExpectation();
        }
    }
}
