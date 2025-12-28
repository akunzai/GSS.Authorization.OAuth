using System.Net.Http.Headers;
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

namespace GSS.Authorization.OAuth2.HttpClient.Tests;

public class OAuth2HttpClientTests : IClassFixture<OAuth2Fixture>
{
    private readonly OAuth2HttpClient _client;
    private readonly OAuth2HttpHandlerOptions _handlerOptions;
    private readonly MockHttpMessageHandler? _mockHttp;
    private readonly AuthorizerOptions _options;
    private readonly Uri _resourceEndpoint;

    public OAuth2HttpClientTests(OAuth2Fixture fixture)
    {
        if (fixture.Configuration.GetValue("HttpClient:Mock", true))
        {
            _mockHttp = new MockHttpMessageHandler();
        }

        var services = fixture.BuildOAuth2HttpClient(_mockHttp);
        _client = services.GetRequiredService<OAuth2HttpClient>();
        _options = services.GetRequiredService<IOptions<AuthorizerOptions>>().Value;
        _handlerOptions = services.GetRequiredService<IOptions<OAuth2HttpHandlerOptions>>().Value;
        _resourceEndpoint = fixture.Configuration.GetValue<Uri>("OAuth2:ResourceEndpoint")!;
    }

    [Fact]
    public async Task HttpClient_AccessProtectedResourceWithValidAccessToken_ShouldAuthorized()
    {
        // Arrange
        var accessToken = new AccessToken { Token = Guid.NewGuid().ToString(), ExpiresInSeconds = 10 };
        _mockHttp?.Expect(Post, _options.AccessTokenEndpoint.AbsoluteUri)
            .WithFormData(ClientId, _options.ClientId)
            .WithFormData(ClientSecret, _options.ClientSecret)
            .Respond(Application.Json, JsonSerializer.Serialize(accessToken));

        ExpectSendAccessTokenInRequestAndResponseOk(accessToken);

        // Act
        var response = await _client.HttpClient.GetAsync(_resourceEndpoint, TestContext.Current.CancellationToken);

        // Assert
        Assert.NotEqual(Unauthorized, response.StatusCode);
        _mockHttp?.VerifyNoOutstandingExpectation();
        _mockHttp?.VerifyNoOutstandingRequest();
    }

    [Fact]
    public async Task HttpClient_AccessProtectedResourceWithPredefinedAuthorizationHeader_ShouldPassThrough()
    {
        Assert.SkipWhen(_mockHttp is null, "MockHttpMessageHandler is not available");

        // Arrange
        var basicAuth =
            Convert.ToBase64String(Encoding.ASCII.GetBytes($"{_options.ClientId}:{_options.ClientSecret}"));
        _mockHttp.Expect(Get, _resourceEndpoint.AbsoluteUri)
            .WithHeaders(HeaderNames.Authorization, $"{Basic} {basicAuth}")
            .Respond(Forbidden);

        // Act
        using var request = new HttpRequestMessage(Get, _resourceEndpoint);
        request.Headers.Authorization = new AuthenticationHeaderValue(Basic, basicAuth);
        var response = await _client.HttpClient.SendAsync(request, TestContext.Current.CancellationToken);

        // Assert
        Assert.Equal(Forbidden, response.StatusCode);
        _mockHttp.VerifyNoOutstandingExpectation();
        _mockHttp.VerifyNoOutstandingRequest();
    }

    [Fact]
    public async Task HttpClient_AccessProtectedResourceWithoutAccessToken_ShouldPassThrough()
    {
        Assert.SkipWhen(_mockHttp is null, "MockHttpMessageHandler is not available");

        // Arrange
        _mockHttp.Expect(Post, _options.AccessTokenEndpoint.AbsoluteUri)
            .Respond(NotFound);
        _mockHttp.Expect(Get, _resourceEndpoint.AbsoluteUri)
            .Respond(Forbidden);

        // Act
        var response = await _client.HttpClient.GetAsync(_resourceEndpoint, TestContext.Current.CancellationToken);

        // Assert
        Assert.Equal(Forbidden, response.StatusCode);
        _mockHttp.VerifyNoOutstandingExpectation();
        _mockHttp.VerifyNoOutstandingRequest();
    }

    [Fact]
    public async Task HttpClient_AccessProtectedResourceWithUnauthorizedResponse_ShouldAuthorized()
    {
        Assert.SkipWhen(_mockHttp is null, "MockHttpMessageHandler is not available");

        // Arrange
        var accessToken = new AccessToken { Token = Guid.NewGuid().ToString(), ExpiresInSeconds = 10 };
        _mockHttp.Expect(Post, _options.AccessTokenEndpoint.AbsoluteUri)
            .WithFormData(ClientId, _options.ClientId)
            .WithFormData(ClientSecret, _options.ClientSecret)
            .Respond(Application.Json, JsonSerializer.Serialize(accessToken));
        _mockHttp.Expect(Get, _resourceEndpoint.AbsoluteUri)
            .Respond(Unauthorized);
        _mockHttp.Expect(Post, _options.AccessTokenEndpoint.AbsoluteUri)
            .WithFormData(ClientId, _options.ClientId)
            .WithFormData(ClientSecret, _options.ClientSecret)
            .Respond(Application.Json, JsonSerializer.Serialize(accessToken));
        ExpectSendAccessTokenInRequestAndResponseOk(accessToken);

        // Act
        var response = await _client.HttpClient.GetAsync(_resourceEndpoint, TestContext.Current.CancellationToken);

        // Assert
        Assert.Equal(OK, response.StatusCode);
        _mockHttp.VerifyNoOutstandingExpectation();
        _mockHttp.VerifyNoOutstandingRequest();
    }

    [Fact]
    public async Task HttpClient_AccessProtectedResourceWithUnmatchedWwwAuthenticateScheme_ShouldPassThrough()
    {
        Assert.SkipWhen(_mockHttp is null, "MockHttpMessageHandler is not available");

        // Arrange
        _mockHttp.Expect(Post, _options.AccessTokenEndpoint.AbsoluteUri)
            .Respond(NotFound);
        _mockHttp.Expect(Get, _resourceEndpoint.AbsoluteUri)
            .Respond(_ =>
            {
                var res = new HttpResponseMessage(Unauthorized);
                res.Headers.TryAddWithoutValidation(HeaderNames.WWWAuthenticate,
                    "Basic realm=\"authentication required\"");
                return res;
            });

        // Act
        var response = await _client.HttpClient.GetAsync(_resourceEndpoint, TestContext.Current.CancellationToken);

        // Assert
        Assert.Equal(Unauthorized, response.StatusCode);
        _mockHttp.VerifyNoOutstandingExpectation();
        _mockHttp.VerifyNoOutstandingRequest();
    }

    [Fact]
    public async Task HttpClient_AccessProtectedResourceWithMatchedWwwAuthenticateScheme_ShouldAuthorized()
    {
        Assert.SkipWhen(_mockHttp is null, "MockHttpMessageHandler is not available");

        // Arrange
        var accessToken = new AccessToken { Token = Guid.NewGuid().ToString(), ExpiresInSeconds = 10 };
        _mockHttp.Expect(Post, _options.AccessTokenEndpoint.AbsoluteUri)
            .WithFormData(ClientId, _options.ClientId)
            .WithFormData(ClientSecret, _options.ClientSecret)
            .Respond(Application.Json, JsonSerializer.Serialize(accessToken));
        _mockHttp.Expect(Get, _resourceEndpoint.AbsoluteUri)
            .Respond(_ =>
            {
                var res = new HttpResponseMessage(Unauthorized);
                res.Headers.TryAddWithoutValidation(HeaderNames.WWWAuthenticate,
                    @"Bearer realm=""oauth2-resource"", error=""unauthorized"", error_description=""Full authentication is required to access this resource""");
                return res;
            });
        _mockHttp.Expect(Post, _options.AccessTokenEndpoint.AbsoluteUri)
            .WithFormData(ClientId, _options.ClientId)
            .WithFormData(ClientSecret, _options.ClientSecret)
            .Respond(Application.Json, JsonSerializer.Serialize(accessToken));
        ExpectSendAccessTokenInRequestAndResponseOk(accessToken);

        // Act
        var response = await _client.HttpClient.GetAsync(_resourceEndpoint, TestContext.Current.CancellationToken);

        // Assert
        Assert.Equal(OK, response.StatusCode);
        _mockHttp.VerifyNoOutstandingExpectation();
        _mockHttp.VerifyNoOutstandingRequest();
    }

    [Fact]
    public async Task HttpClient_AccessProtectedResourceWithCachedAccessToken_ShouldAuthorizedOnce()
    {
        // Arrange
        var accessToken = new AccessToken { Token = Guid.NewGuid().ToString(), ExpiresInSeconds = 10 };
        _mockHttp?.Expect(Post, _options.AccessTokenEndpoint.AbsoluteUri)
            .WithFormData(ClientId, _options.ClientId)
            .WithFormData(ClientSecret, _options.ClientSecret)
            .Respond(Application.Json, JsonSerializer.Serialize(accessToken));
        ExpectSendAccessTokenInRequestAndResponseOk(accessToken, 2);

        // Act
        var response = await _client.HttpClient.GetAsync(_resourceEndpoint, TestContext.Current.CancellationToken);
        var response2 = await _client.HttpClient.GetAsync(_resourceEndpoint, TestContext.Current.CancellationToken);

        // Assert
        Assert.NotEqual(Unauthorized, response.StatusCode);
        Assert.NotEqual(Unauthorized, response2.StatusCode);
        _mockHttp?.VerifyNoOutstandingExpectation();
        _mockHttp?.VerifyNoOutstandingRequest();
    }

    [Fact]
    public async Task
        HttpClient_AccessProtectedResourceWithCachedAccessToken_ShouldReAuthorizedWithUnauthorizedResponse()
    {
        Assert.SkipWhen(_mockHttp is null, "MockHttpMessageHandler is not available");

        // Arrange
        var accessToken = new AccessToken { Token = Guid.NewGuid().ToString(), ExpiresInSeconds = 1 };
        var accessToken2 = new AccessToken { Token = Guid.NewGuid().ToString(), ExpiresInSeconds = 2 };
        _mockHttp.Expect(Post, _options.AccessTokenEndpoint.AbsoluteUri)
            .WithFormData(ClientId, _options.ClientId)
            .WithFormData(ClientSecret, _options.ClientSecret)
            .Respond(Application.Json, JsonSerializer.Serialize(accessToken));
        _mockHttp.Expect(Get, _resourceEndpoint.AbsoluteUri)
            .Respond(Unauthorized);
        _mockHttp.Expect(Post, _options.AccessTokenEndpoint.AbsoluteUri)
            .WithFormData(ClientId, _options.ClientId)
            .WithFormData(ClientSecret, _options.ClientSecret)
            .Respond(Application.Json, JsonSerializer.Serialize(accessToken2));
        ExpectSendAccessTokenInRequestAndResponseOk(accessToken2);

        // Act
        var response = await _client.HttpClient.GetAsync(_resourceEndpoint, TestContext.Current.CancellationToken);

        // Assert
        Assert.Equal(OK, response.StatusCode);
        _mockHttp.VerifyNoOutstandingExpectation();
        _mockHttp.VerifyNoOutstandingRequest();
    }

    [Fact]
    public async Task HttpClient_AccessProtectedResourceWithExpiredAccessToken_ShouldReAuthorized()
    {
        Assert.SkipWhen(_mockHttp is null, "MockHttpMessageHandler is not available");

        // Arrange
        var accessToken = new AccessToken { Token = Guid.NewGuid().ToString(), ExpiresInSeconds = 1 };
        var accessToken2 = new AccessToken { Token = Guid.NewGuid().ToString(), ExpiresInSeconds = 2 };
        _mockHttp.Expect(Post, _options.AccessTokenEndpoint.AbsoluteUri)
            .WithFormData(ClientId, _options.ClientId)
            .WithFormData(ClientSecret, _options.ClientSecret)
            .Respond(Application.Json, JsonSerializer.Serialize(accessToken));
        ExpectSendAccessTokenInRequestAndResponseOk(accessToken);
        _mockHttp.Expect(Post, _options.AccessTokenEndpoint.AbsoluteUri)
            .WithFormData(ClientId, _options.ClientId)
            .WithFormData(ClientSecret, _options.ClientSecret)
            .Respond(Application.Json, JsonSerializer.Serialize(accessToken2));
        ExpectSendAccessTokenInRequestAndResponseOk(accessToken2);

        // Act
        var response = await _client.HttpClient.GetAsync(_resourceEndpoint, TestContext.Current.CancellationToken);
        await Task.Delay(TimeSpan.FromSeconds(2), TestContext.Current.CancellationToken);
        var response2 = await _client.HttpClient.GetAsync(_resourceEndpoint, TestContext.Current.CancellationToken);

        // Assert
        Assert.Equal(OK, response.StatusCode);
        Assert.Equal(OK, response2.StatusCode);
        _mockHttp.VerifyNoOutstandingExpectation();
        _mockHttp.VerifyNoOutstandingRequest();
    }

    [Fact]
    public async Task HttpClient_AccessProtectedResourceWithAccessTokenNoExpiry_ShouldCacheIndefinitely()
    {
        Assert.SkipWhen(_mockHttp is null, "MockHttpMessageHandler is not available");

        // Arrange
        var accessToken = new AccessToken { Token = Guid.NewGuid().ToString(), ExpiresInSeconds = 0 };
        _mockHttp.Expect(Post, _options.AccessTokenEndpoint.AbsoluteUri)
            .WithFormData(ClientId, _options.ClientId)
            .WithFormData(ClientSecret, _options.ClientSecret)
            .Respond(Application.Json, JsonSerializer.Serialize(accessToken));
        ExpectSendAccessTokenInRequestAndResponseOk(accessToken, 2);

        // Act
        var response = await _client.HttpClient.GetAsync(_resourceEndpoint, TestContext.Current.CancellationToken);
        var response2 = await _client.HttpClient.GetAsync(_resourceEndpoint, TestContext.Current.CancellationToken);

        // Assert
        Assert.Equal(OK, response.StatusCode);
        Assert.Equal(OK, response2.StatusCode);
        _mockHttp.VerifyNoOutstandingExpectation();
        _mockHttp.VerifyNoOutstandingRequest();
    }

    private void ExpectSendAccessTokenInRequestAndResponseOk(AccessToken accessToken, int repeatCount = 1)
    {
        for (var i = 0; i < repeatCount; i++)
        {
            if (_handlerOptions.SendAccessTokenInQuery)
            {
                _mockHttp?.Expect(Get, _resourceEndpoint.AbsoluteUri)
                    .WithQueryString(AuthorizerDefaults.AccessToken, accessToken.Token)
                    .Respond(OK);
            }
            else
            {
                _mockHttp?.Expect(Get, _resourceEndpoint.AbsoluteUri)
                    .WithHeaders(HeaderNames.Authorization, $"{Bearer} {accessToken.Token}")
                    .Respond(OK);
            }
        }
    }
}