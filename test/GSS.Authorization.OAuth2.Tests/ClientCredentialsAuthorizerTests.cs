using System.Net;
using System.Net.Mime;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.Net.Http.Headers;
using RichardSzalay.MockHttp;
using Xunit;

namespace GSS.Authorization.OAuth2.Tests;

public class ClientCredentialsAuthorizerTests : IClassFixture<AuthorizerFixture>
{
    private readonly IAuthorizer _authorizer;
    private readonly string _basicAuthHeaderValue;
    private readonly MockHttpMessageHandler? _mockHttp;
    private readonly AuthorizerOptions _options;
    private string? _errorMessage;
    private HttpStatusCode _errorStatusCode;

    public ClientCredentialsAuthorizerTests(AuthorizerFixture fixture)
    {
        if (fixture.Configuration.GetValue("HttpClient:Mock", true))
        {
            _mockHttp = new MockHttpMessageHandler();
        }

        var services = fixture.BuildAuthorizer<ClientCredentialsAuthorizer>(_mockHttp, (code, s) =>
        {
            _errorStatusCode = code;
            _errorMessage = s;
        });
        _authorizer = services.GetRequiredService<ClientCredentialsAuthorizer>();
        _options = services.GetRequiredService<IOptions<AuthorizerOptions>>().Value;
        _basicAuthHeaderValue =
            $"Basic {Convert.ToBase64String(Encoding.ASCII.GetBytes($"{_options.ClientId}:{_options.ClientSecret}"))}";
    }

    [Fact]
    public async Task Authorizer_GetAccessToken_ShouldNotNull()
    {
        // Arrange
        _mockHttp?.Expect(HttpMethod.Post, _options.AccessTokenEndpoint.AbsoluteUri)
            .WithHeaders(HeaderNames.Authorization, _basicAuthHeaderValue)
            .WithFormData(AuthorizerDefaults.GrantType, AuthorizerDefaults.ClientCredentials)
            .Respond(MediaTypeNames.Application.Json,
                JsonSerializer.Serialize(new AccessToken
                {
                    Token = Guid.NewGuid().ToString(), ExpiresInSeconds = 10
                }));

        // Act
        var accessToken = await _authorizer.GetAccessTokenAsync();

        // Assert
        Assert.NotNull(accessToken.Token);
        _mockHttp?.VerifyNoOutstandingExpectation();
    }

    [Fact]
    public async Task Authorizer_GetAccessToken_ShouldNotEmpty()
    {
        // Arrange
        _mockHttp?.Expect(HttpMethod.Post, _options.AccessTokenEndpoint.AbsoluteUri)
            .WithHeaders(HeaderNames.Authorization, _basicAuthHeaderValue)
            .WithFormData(AuthorizerDefaults.GrantType, AuthorizerDefaults.ClientCredentials)
            .Respond(MediaTypeNames.Application.Json,
                JsonSerializer.Serialize(new AccessToken
                {
                    Token = Guid.NewGuid().ToString(), ExpiresInSeconds = 10
                }));

        // Act
        var accessToken = await _authorizer.GetAccessTokenAsync();

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
            .WithHeaders(HeaderNames.Authorization, _basicAuthHeaderValue)
            .WithFormData(AuthorizerDefaults.GrantType, AuthorizerDefaults.ClientCredentials)
            .Respond(HttpStatusCode.InternalServerError);

        // Act
        var accessToken = await _authorizer.GetAccessTokenAsync();

        // Assert
        Assert.Null(accessToken.Token);
        _mockHttp.VerifyNoOutstandingExpectation();
    }

    [SkippableFact]
    public async Task Authorizer_GetAccessTokenWithException_ShouldInvokeErrorHandler()
    {
        Skip.If(_mockHttp == null);

        // Arrange
        var expectedErrorMessage = Guid.NewGuid().ToString();
        _mockHttp.Expect(HttpMethod.Post, _options.AccessTokenEndpoint.AbsoluteUri)
            .WithHeaders(HeaderNames.Authorization, _basicAuthHeaderValue)
            .WithFormData(AuthorizerDefaults.GrantType, AuthorizerDefaults.ClientCredentials)
            .Respond(HttpStatusCode.InternalServerError, MediaTypeNames.Application.Json, expectedErrorMessage);

        // Act
        await _authorizer.GetAccessTokenAsync();

        // Assert
        Assert.Equal(HttpStatusCode.InternalServerError, _errorStatusCode);
        Assert.Equal(expectedErrorMessage, _errorMessage);
        _mockHttp.VerifyNoOutstandingExpectation();
    }
}