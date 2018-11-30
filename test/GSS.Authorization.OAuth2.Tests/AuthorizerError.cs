using System.Net;

namespace GSS.Authorization.OAuth2.Tests
{
    internal class AuthorizerError
    {
        public HttpStatusCode StatusCode { get; set; }

        public string Message { get; set; }
    }
}
