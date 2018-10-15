using System;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Newtonsoft.Json;
using RichardSzalay.MockHttp;
using Xunit;

namespace GSS.Authorization.OAuth2
{
    public class ResourceOwnerCredentialsAuthorizerTests : IClassFixture<AuthorizerFixture>
    {
        private readonly IAuthorizer _authorizer;
        private readonly MockHttpMessageHandler _mockHttp;
        private readonly AuthorizerOptions _options;

        public ResourceOwnerCredentialsAuthorizerTests(AuthorizerFixture fixture)
        {
            _authorizer = ActivatorUtilities.CreateInstance<ResourceOwnerCredentialsAuthorizer>(fixture.Services);
            _mockHttp = fixture.Services.GetService<MockHttpMessageHandler>();
            _options = fixture.Services.GetService<IOptions<AuthorizerOptions>>().Value;
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
                .WithFormData(AuthorizerDefaults.Password,_options.Credentials.Password)
                .Respond("application/json", JsonConvert.SerializeObject(new AccessToken
                {
                    Token = Guid.NewGuid().ToString(),
                    ExpiresInSeconds = 86400
                }));

            // Act
            var accessToken = await _authorizer.GetAccessTokenAsync().ConfigureAwait(false);

            // Assert
            Assert.NotNull(accessToken);
            Assert.NotEmpty(accessToken.Token);
            _mockHttp?.VerifyNoOutstandingExpectation();
        }
    }
}
