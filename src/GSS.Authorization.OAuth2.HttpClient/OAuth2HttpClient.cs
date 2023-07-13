using System.Net.Http;

namespace GSS.Authorization.OAuth2;

/// <summary>
/// Typed HttpClient for OAuth2 protected resource
/// </summary>
public class OAuth2HttpClient
{
    public OAuth2HttpClient(HttpClient httpClient)
    {
        HttpClient = httpClient;
    }

    public HttpClient HttpClient { get; }
}