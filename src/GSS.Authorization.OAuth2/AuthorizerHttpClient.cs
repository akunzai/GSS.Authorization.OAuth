using System.Net.Http;

namespace GSS.Authorization.OAuth2
{
    /// <summary>
    /// Typed HttpClient for Authenticator to grant access
    /// </summary>
    public class AuthorizerHttpClient
    {
        public AuthorizerHttpClient(HttpClient httClient)
        {
            HttClient = httClient;
        }
        
        public HttpClient HttClient { get; }
    }
}
