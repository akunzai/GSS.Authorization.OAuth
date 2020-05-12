using System;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using RichardSzalay.MockHttp;
using Xunit;

namespace GSS.Authorization.OAuth2.Tests
{
    public class ResourceOwnerCredentialsAuthorizerTests : IClassFixture<AuthorizerFixture>
    {
        private readonly IAuthorizer _authorizer;
        private readonly AuthorizerError _error;
        private readonly MockHttpMessageHandler _mockHttp;
        private readonly AuthorizerOptions _options;

        public ResourceOwnerCredentialsAuthorizerTests(AuthorizerFixture fixture)
        {
            if (fixture == null)
                throw new ArgumentNullException(nameof(fixture));
            var services = fixture.BuildServiceProvider();
            _authorizer = services.GetRequiredService<ResourceOwnerCredentialsAuthorizer>();
            _error = services.GetRequiredService<AuthorizerError>();
            _mockHttp = services.GetRequiredService<HttpMessageHandler>() as MockHttpMessageHandler;
            _options = services.GetRequiredService<IOptions<AuthorizerOptions>>().Value;
        }

        [Fact]
        public async Task Authorizer_GetAccessToken_ShouldNotNull()
        {
            // Arrange
            _mockHttp?.Expect(HttpMethod.Post, _options.AccessTokenEndpoint.AbsoluteUri)
                .WithFormData(AuthorizerDefaults.ClientId, _options.ClientId)
                .WithFormData(AuthorizerDefaults.ClientSecret, _options.ClientSecret)
                .WithFormData(AuthorizerDefaults.GrantType, AuthorizerDefaults.Password)
                .WithFormData(AuthorizerDefaults.Username, _options.Credentials.UserName)
                .WithFormData(AuthorizerDefaults.Password, _options.Credentials.Password)
                .Respond("application/json", JsonSerializer.Serialize(new AccessToken
                {
                    Token = Guid.NewGuid().ToString(),
                    ExpiresInSeconds = 10
                }));

            // Act
            var accessToken = await _authorizer.GetAccessTokenAsync().ConfigureAwait(false);

            // Assert
            Assert.NotNull(accessToken.Token);
            _mockHttp?.VerifyNoOutstandingExpectation();
        }

        [Fact]
        public async Task Authorizer_GetAccessToken_ShouldNotEmpty()
        {
            // Arrange
            _mockHttp?.Expect(HttpMethod.Post, _options.AccessTokenEndpoint.AbsoluteUri)
                .WithFormData(AuthorizerDefaults.ClientId, _options.ClientId)
                .WithFormData(AuthorizerDefaults.ClientSecret, _options.ClientSecret)
                .WithFormData(AuthorizerDefaults.GrantType, AuthorizerDefaults.Password)
                .WithFormData(AuthorizerDefaults.Username, _options.Credentials.UserName)
                .WithFormData(AuthorizerDefaults.Password, _options.Credentials.Password)
                .Respond("application/json", JsonSerializer.Serialize(new AccessToken
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
                .WithFormData(AuthorizerDefaults.GrantType, AuthorizerDefaults.Password)
                .WithFormData(AuthorizerDefaults.Username, _options.Credentials.UserName)
                .WithFormData(AuthorizerDefaults.Password, _options.Credentials.Password)
                .Respond(HttpStatusCode.InternalServerError);

            // Act
            var accessToken = await _authorizer.GetAccessTokenAsync().ConfigureAwait(false);

            // Assert
            Assert.Null(accessToken?.Token);
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
                .WithFormData(AuthorizerDefaults.GrantType, AuthorizerDefaults.Password)
                .WithFormData(AuthorizerDefaults.Username, _options.Credentials.UserName)
                .WithFormData(AuthorizerDefaults.Password, _options.Credentials.Password)
                .Respond(HttpStatusCode.InternalServerError, "application/json", expectedErrorMessage);

            // Act
            await _authorizer.GetAccessTokenAsync().ConfigureAwait(false);

            // Assert
            Assert.Equal(HttpStatusCode.InternalServerError, _error.StatusCode);
            Assert.Equal(expectedErrorMessage, _error.Message);
            _mockHttp.VerifyNoOutstandingExpectation();
        }
    }
}
