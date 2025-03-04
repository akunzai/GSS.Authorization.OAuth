using System.Net;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.Net.Http.Headers;
using RichardSzalay.MockHttp;
using Xunit;
using static System.Net.Http.HttpMethod;
using static System.Net.HttpStatusCode;
using static System.Net.Mime.MediaTypeNames;
using static GSS.Authorization.OAuth2.AuthorizerDefaults;

namespace GSS.Authorization.OAuth2.Tests;

public class ClientCredentialsAuthorizerTests : IClassFixture<AuthorizerFixture>
{
    private readonly ClientCredentialsAuthorizer _authorizer;
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
        _mockHttp?.Expect(Post, _options.AccessTokenEndpoint.AbsoluteUri)
            .WithHeaders(HeaderNames.Authorization, _basicAuthHeaderValue)
            .WithFormData(GrantType, ClientCredentials)
            .Respond(Application.Json,
                JsonSerializer.Serialize(new AccessToken { Token = Guid.NewGuid().ToString(), ExpiresInSeconds = 10 }));

        // Act
        var accessToken = await _authorizer.GetAccessTokenAsync(TestContext.Current.CancellationToken);

        // Assert
        Assert.NotNull(accessToken.Token);
        _mockHttp?.VerifyNoOutstandingExpectation();
    }

    [Fact]
    public async Task Authorizer_GetAccessToken_ShouldNotEmpty()
    {
        // Arrange
        _mockHttp?.Expect(Post, _options.AccessTokenEndpoint.AbsoluteUri)
            .WithHeaders(HeaderNames.Authorization, _basicAuthHeaderValue)
            .WithFormData(GrantType, ClientCredentials)
            .Respond(Application.Json,
                JsonSerializer.Serialize(new AccessToken { Token = Guid.NewGuid().ToString(), ExpiresInSeconds = 10 }));

        // Act
        var accessToken = await _authorizer.GetAccessTokenAsync(TestContext.Current.CancellationToken);

        // Assert
        Assert.NotEmpty(accessToken.Token);
        _mockHttp?.VerifyNoOutstandingExpectation();
    }

    [Fact]
    public async Task Authorizer_GetAccessTokenWithException_ShouldReturnNull()
    {
        Assert.SkipWhen(_mockHttp is null, "MockHttpMessageHandler is not available");

        // Arrange
        _mockHttp.Expect(Post, _options.AccessTokenEndpoint.AbsoluteUri)
            .WithHeaders(HeaderNames.Authorization, _basicAuthHeaderValue)
            .WithFormData(GrantType, ClientCredentials)
            .Respond(InternalServerError);

        // Act
        var accessToken = await _authorizer.GetAccessTokenAsync(TestContext.Current.CancellationToken);

        // Assert
        Assert.Null(accessToken.Token);
        _mockHttp.VerifyNoOutstandingExpectation();
    }

    [Fact]
    public async Task Authorizer_GetAccessTokenWithException_ShouldInvokeErrorHandler()
    {
        Assert.SkipWhen(_mockHttp is null, "MockHttpMessageHandler is not available");

        // Arrange
        var expectedErrorMessage = Guid.NewGuid().ToString();
        _mockHttp.Expect(Post, _options.AccessTokenEndpoint.AbsoluteUri)
            .WithHeaders(HeaderNames.Authorization, _basicAuthHeaderValue)
            .WithFormData(GrantType, ClientCredentials)
            .Respond(InternalServerError, Application.Json, expectedErrorMessage);

        // Act
        await _authorizer.GetAccessTokenAsync(TestContext.Current.CancellationToken);

        // Assert
        Assert.Equal(InternalServerError, _errorStatusCode);
        Assert.Equal(expectedErrorMessage, _errorMessage);
        _mockHttp.VerifyNoOutstandingExpectation();
    }
}