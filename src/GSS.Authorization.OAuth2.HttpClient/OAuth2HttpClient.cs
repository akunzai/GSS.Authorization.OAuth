using System.Net.Http;

namespace GSS.Authorization.OAuth2;

/// <summary>
/// Typed HttpClient for OAuth2 protected resource
/// </summary>
public class OAuth2HttpClient(HttpClient httpClient)
{
    public HttpClient HttpClient { get; } = httpClient;
}