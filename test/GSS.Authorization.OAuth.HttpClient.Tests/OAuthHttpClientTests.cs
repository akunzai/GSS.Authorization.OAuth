using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using Microsoft.Net.Http.Headers;
using RichardSzalay.MockHttp;
using Xunit;

namespace GSS.Authorization.OAuth.HttpClient.Tests;

public class OAuthHttpClientTests : IClassFixture<OAuthFixture>
{
    private static readonly RandomNumberGenerator _randomNumberGenerator = RandomNumberGenerator.Create();
    private readonly OAuthCredential _clientCredentials;
    private readonly IConfiguration _configuration;

    private readonly MockHttpMessageHandler? _mockHttp;
    private readonly IRequestSigner _signer = new HmacSha1RequestSigner();
    private readonly OAuthCredential _tokenCredentials;

    public OAuthHttpClientTests(OAuthFixture fixture)
    {
        _configuration = fixture.Configuration;
        _clientCredentials = new OAuthCredential(
            _configuration["OAuth:ClientId"],
            _configuration["OAuth:ClientSecret"]);
        _tokenCredentials = new OAuthCredential(
            _configuration["OAuth:TokenId"],
            _configuration["OAuth:TokenSecret"]);
        if (!_configuration.GetValue("HttpClient:Mock", true)) return;
        _mockHttp = new MockHttpMessageHandler();
        _mockHttp.Fallback.Respond(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task HttpClient_AccessProtectedResourceWithAuthorizationHeader_ShouldAuthorized()
    {
        // Arrange
        var services = new ServiceCollection()
            .AddOAuthHttpClient<OAuthHttpClient>((_, handlerOptions) =>
            {
                handlerOptions.ClientCredentials = _clientCredentials;
                handlerOptions.TokenCredentials = _tokenCredentials;
                if (_mockHttp == null) return;
                var timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds()
                    .ToString(CultureInfo.InvariantCulture);
                var nonce = GenerateNonce();
                handlerOptions.TimestampProvider = () => timestamp;
                handlerOptions.NonceProvider = () => nonce;
            })
            .ConfigurePrimaryHttpMessageHandler(_ => _mockHttp ?? new HttpClientHandler() as HttpMessageHandler)
            .Services.BuildServiceProvider();
        var client = services.GetRequiredService<OAuthHttpClient>();
        var options = services.GetRequiredService<IOptions<OAuthHttpHandlerOptions>>();
        var resourceUri = _configuration.GetValue<Uri>("Request:Uri");
        _mockHttp?.Expect(HttpMethod.Get, resourceUri.AbsoluteUri)
            .WithHeaders(HeaderNames.Authorization, _signer.GetAuthorizationHeader(
                HttpMethod.Get, resourceUri, options.Value, QueryHelpers.ParseQuery(resourceUri.Query),
                _tokenCredentials).ToString())
            .Respond(HttpStatusCode.OK);

        // Act
        var response = await client.HttpClient.GetAsync(resourceUri).ConfigureAwait(false);

        // Assert
        Assert.NotEqual(HttpStatusCode.Unauthorized, response.StatusCode);
        _mockHttp?.VerifyNoOutstandingExpectation();
        _mockHttp?.VerifyNoOutstandingRequest();
    }

    [Fact]
    public async Task HttpClient_AccessProtectedResourceWithPredefinedAuthorizationHeader_ShouldPassThrough()
    {
        // Arrange
        var services = new ServiceCollection()
            .AddOAuthHttpClient<OAuthHttpClient>((_, handlerOptions) =>
            {
                handlerOptions.ClientCredentials = _clientCredentials;
                handlerOptions.TokenCredentials = _tokenCredentials;
            })
            .ConfigurePrimaryHttpMessageHandler(_ => _mockHttp ?? new HttpClientHandler() as HttpMessageHandler)
            .Services.BuildServiceProvider();
        var client = services.GetRequiredService<OAuthHttpClient>();
        var resourceUri = _configuration.GetValue<Uri>("Request:Uri");
        var basicAuth =
            Convert.ToBase64String(
                Encoding.ASCII.GetBytes($"{_clientCredentials.Key}:{_clientCredentials.Secret}"));
        _mockHttp?.Expect(HttpMethod.Get, resourceUri.AbsoluteUri)
            .WithHeaders(HeaderNames.Authorization, $"Basic {basicAuth}")
            .Respond(HttpStatusCode.Forbidden);

        // Act
        using var request = new HttpRequestMessage(HttpMethod.Get, resourceUri);
        request.Headers.Authorization = new AuthenticationHeaderValue("Basic", basicAuth);
        var response = await client.HttpClient.SendAsync(request).ConfigureAwait(false);

        // Assert
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        _mockHttp?.VerifyNoOutstandingExpectation();
        _mockHttp?.VerifyNoOutstandingRequest();
    }

    [Fact]
    public async Task HttpClient_AccessProtectedResourceWithQueryString_ShouldAuthorized()
    {
        // Arrange
        var services = new ServiceCollection()
            .AddOAuthHttpClient<OAuthHttpClient>((_, handlerOptions) =>
            {
                handlerOptions.ClientCredentials = _clientCredentials;
                handlerOptions.TokenCredentials = _tokenCredentials;
                handlerOptions.SignedAsQuery = true;
                if (_mockHttp == null) return;
                var timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds()
                    .ToString(CultureInfo.InvariantCulture);
                var nonce = GenerateNonce();
                handlerOptions.TimestampProvider = () => timestamp;
                handlerOptions.NonceProvider = () => nonce;
            })
            .ConfigurePrimaryHttpMessageHandler(_ => _mockHttp ?? new HttpClientHandler() as HttpMessageHandler)
            .Services.BuildServiceProvider();
        var client = services.GetRequiredService<OAuthHttpClient>();
        var options = services.GetRequiredService<IOptions<OAuthHttpHandlerOptions>>();
        var resourceUri = new UriBuilder(_configuration["Request:Uri"]);
        resourceUri.Query += resourceUri.Query.Contains('?', StringComparison.Ordinal)
            ? "&foo=v1&foo=v2"
            : "?foo=v1&foo=v2";
        var parameters = _signer.AppendAuthorizationParameters(HttpMethod.Get, resourceUri.Uri,
            options.Value, QueryHelpers.ParseQuery(resourceUri.Uri.Query), _tokenCredentials);
        var values = (from parameter in parameters
            from value in parameter.Value
            select $"{Uri.EscapeDataString(parameter.Key)}={Uri.EscapeDataString(value)}").ToList();

        _mockHttp?.Expect(HttpMethod.Get, resourceUri.Uri.AbsoluteUri)
            .WithQueryString("?" + string.Join("&", values))
            .Respond(HttpStatusCode.OK);

        // Act
        var response = await client.HttpClient.GetAsync(resourceUri.Uri).ConfigureAwait(false);

        // Assert
        Assert.NotEqual(HttpStatusCode.Unauthorized, response.StatusCode);
        _mockHttp?.VerifyNoOutstandingExpectation();
        _mockHttp?.VerifyNoOutstandingRequest();
    }

    [Fact]
    public async Task HttpClient_AccessProtectedResourceWithFormBody_ShouldAuthorized()
    {
        // Arrange
        var services = new ServiceCollection()
            .AddOAuthHttpClient<OAuthHttpClient>((_, handlerOptions) =>
            {
                handlerOptions.ClientCredentials = _clientCredentials;
                handlerOptions.TokenCredentials = _tokenCredentials;
                handlerOptions.SignedAsBody = true;
                if (_mockHttp == null) return;
                var timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds()
                    .ToString(CultureInfo.InvariantCulture);
                var nonce = GenerateNonce();
                handlerOptions.TimestampProvider = () => timestamp;
                handlerOptions.NonceProvider = () => nonce;
            })
            .ConfigurePrimaryHttpMessageHandler(_ => _mockHttp ?? new HttpClientHandler() as HttpMessageHandler)
            .Services.BuildServiceProvider();
        var client = services.GetRequiredService<OAuthHttpClient>();
        var options = services.GetRequiredService<IOptions<OAuthHttpHandlerOptions>>();
        var resourceUri = new UriBuilder(_configuration["Request:Uri"]);
        var queryString = QueryHelpers.ParseQuery(resourceUri.Uri.Query);
        var body = _configuration.GetSection("Request:Body").Get<IDictionary<string, string>>();
        var formData = new Dictionary<string, StringValues>();
        foreach (var (key, value) in body)
        {
            formData.Add(key, value);
        }

        foreach (var query in queryString)
        {
            if (!formData.ContainsKey(query.Key))
            {
                formData.Add(query.Key, query.Value);
            }
        }

        var parameters = _signer.AppendAuthorizationParameters(HttpMethod.Post, resourceUri.Uri,
            options.Value, formData, _tokenCredentials);
        var values = new List<KeyValuePair<string, string>>();
        foreach (var parameter in parameters)
        {
            if (!queryString.ContainsKey(parameter.Key))
            {
                values.AddRange(parameter.Value.Select(value => new KeyValuePair<string, string>(parameter.Key, value)));
            }
        }

        _mockHttp?.Expect(HttpMethod.Post, resourceUri.Uri.AbsoluteUri)
            .WithFormData(values)
            .Respond(HttpStatusCode.OK);

        // Act
        using var content = new FormUrlEncodedContent(body);
        var response = await client.HttpClient.PostAsync(resourceUri.Uri, content).ConfigureAwait(false);

        // Assert
        Assert.NotEqual(HttpStatusCode.Unauthorized, response.StatusCode);
        _mockHttp?.VerifyNoOutstandingExpectation();
        _mockHttp?.VerifyNoOutstandingRequest();
    }

    private static string GenerateNonce()
    {
        var bytes = new byte[16];
        _randomNumberGenerator.GetNonZeroBytes(bytes);
        return Convert.ToBase64String(bytes);
    }
}