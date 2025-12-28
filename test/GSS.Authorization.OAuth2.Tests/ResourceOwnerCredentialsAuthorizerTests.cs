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
using OptionsPattern = Microsoft.Extensions.Options.Options;
using static System.Net.HttpStatusCode;
using static System.Net.Mime.MediaTypeNames;
using static GSS.Authorization.OAuth2.AuthorizerDefaults;

namespace GSS.Authorization.OAuth2.Tests;

public class ResourceOwnerCredentialsAuthorizerTests : IClassFixture<AuthorizerFixture>
{
    private readonly ResourceOwnerCredentialsAuthorizer _authorizer;
    private readonly string _basicAuthHeaderValue;
    private readonly MockHttpMessageHandler? _mockHttp;
    private readonly AuthorizerOptions _options;
    private string? _errorMessage;
    private HttpStatusCode _errorStatusCode;

    public ResourceOwnerCredentialsAuthorizerTests(AuthorizerFixture fixture)
    {
        if (fixture.Configuration.GetValue("HttpClient:Mock", true))
        {
            _mockHttp = new MockHttpMessageHandler();
        }

        var services = fixture.BuildAuthorizer<ResourceOwnerCredentialsAuthorizer>(_mockHttp, (code, s) =>
        {
            _errorStatusCode = code;
            _errorMessage = s;
        });
        _authorizer = services.GetRequiredService<ResourceOwnerCredentialsAuthorizer>();
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
            .WithFormData(GrantType, Password)
            .WithFormData(Username, _options.Credentials?.UserName!)
            .WithFormData(Password, _options.Credentials?.Password!)
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
            .WithFormData(GrantType, Password)
            .WithFormData(Username, _options.Credentials?.UserName!)
            .WithFormData(Password, _options.Credentials?.Password!)
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
            .WithFormData(GrantType, Password)
            .WithFormData(Username, _options.Credentials?.UserName!)
            .WithFormData(Password, _options.Credentials?.Password!)
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
            .WithFormData(GrantType, Password)
            .WithFormData(Username, _options.Credentials?.UserName!)
            .WithFormData(Password, _options.Credentials?.Password!)
            .Respond(InternalServerError, Application.Json, expectedErrorMessage);

        // Act
        await _authorizer.GetAccessTokenAsync(TestContext.Current.CancellationToken);

        // Assert
        Assert.Equal(InternalServerError, _errorStatusCode);
        Assert.Equal(expectedErrorMessage, _errorMessage);
        _mockHttp.VerifyNoOutstandingExpectation();
    }

    [Fact]
    public void Constructor_WithNullCredentials_ShouldThrowArgumentNullException()
    {
        // Arrange
        var options = new AuthorizerOptions
        {
            ClientId = "test_client",
            ClientSecret = "test_secret",
            AccessTokenEndpoint = new Uri("https://example.com/token"),
            Credentials = null
        };

        // Act & Assert
        var exception = Assert.Throws<ArgumentNullException>(() =>
            new ResourceOwnerCredentialsAuthorizer(new HttpClient(), OptionsPattern.Create(options)));
        Assert.Contains("Credentials", exception.Message);
    }

    [Theory]
    [InlineData(null, "password")]
    [InlineData("", "password")]
    [InlineData("   ", "password")]
    public void Constructor_WithInvalidUserName_ShouldThrowArgumentNullException(string? userName, string password)
    {
        // Arrange
        var options = new AuthorizerOptions
        {
            ClientId = "test_client",
            ClientSecret = "test_secret",
            AccessTokenEndpoint = new Uri("https://example.com/token"),
            Credentials = new NetworkCredential(userName, password)
        };

        // Act & Assert
        var exception = Assert.Throws<ArgumentNullException>(() =>
            new ResourceOwnerCredentialsAuthorizer(new HttpClient(), OptionsPattern.Create(options)));
        Assert.Contains("UserName", exception.Message);
    }

    [Theory]
    [InlineData("username", null)]
    [InlineData("username", "")]
    [InlineData("username", "   ")]
    public void Constructor_WithInvalidPassword_ShouldThrowArgumentNullException(string userName, string? password)
    {
        // Arrange
        var options = new AuthorizerOptions
        {
            ClientId = "test_client",
            ClientSecret = "test_secret",
            AccessTokenEndpoint = new Uri("https://example.com/token"),
            Credentials = new NetworkCredential(userName, password)
        };

        // Act & Assert
        var exception = Assert.Throws<ArgumentNullException>(() =>
            new ResourceOwnerCredentialsAuthorizer(new HttpClient(), OptionsPattern.Create(options)));
        Assert.Contains("Password", exception.Message);
    }

    [Fact]
    public void PrepareFormData_WithNullFormData_ShouldThrowArgumentNullException()
    {
        // Arrange
        var options = new AuthorizerOptions
        {
            ClientId = "test_client",
            ClientSecret = "test_secret",
            AccessTokenEndpoint = new Uri("https://example.com/token"),
            Credentials = new NetworkCredential("user", "pass")
        };
        var authorizer = new TestResourceOwnerCredentialsAuthorizer(new HttpClient(), OptionsPattern.Create(options));

        // Act & Assert
        var exception = Assert.Throws<ArgumentNullException>(() =>
            authorizer.TestPrepareFormData(null!));
        Assert.Equal("formData", exception.ParamName);
    }

    // Test class to expose protected methods
    private class TestResourceOwnerCredentialsAuthorizer : ResourceOwnerCredentialsAuthorizer
    {
        public TestResourceOwnerCredentialsAuthorizer(HttpClient client, IOptions<AuthorizerOptions> options)
            : base(client, options)
        {
        }

        public void TestPrepareFormData(IDictionary<string, string> formData)
        {
            PrepareFormData(formData);
        }
    }
}