using System;
using System.Net.Http;

namespace GSS.Authorization.OAuth2
{
    /// <summary>
    /// Typed HttpClient for Authenticator to grant access
    /// </summary>
    [Obsolete("This is obsolete and will be removed in a future version.")]
    public class AuthorizerHttpClient
    {
        public AuthorizerHttpClient(HttpClient httpClient)
        {
            HttpClient = httpClient;
        }

        public HttpClient HttpClient { get; }
    }
}
