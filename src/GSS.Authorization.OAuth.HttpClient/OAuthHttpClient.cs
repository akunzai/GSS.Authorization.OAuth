using System.Net.Http;

namespace GSS.Authorization.OAuth;

/// <summary>
/// Typed HttpClient for OAuth protected resource
/// </summary>
public class OAuthHttpClient
{
    public OAuthHttpClient(HttpClient httpClient)
    {
        HttpClient = httpClient;
    }

    public HttpClient HttpClient { get; }
}