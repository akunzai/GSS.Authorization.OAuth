using System.Net.Http;

namespace GSS.Authorization.OAuth;

/// <summary>
/// Typed HttpClient for OAuth protected resource
/// </summary>
public class OAuthHttpClient(HttpClient httpClient)
{
    public HttpClient HttpClient { get; } = httpClient;
}