using System;
using System.Collections.Generic;
using System.Net;

namespace GSS.Authorization.OAuth2
{
    public class AuthorizerOptions
    {
        public Uri AccessTokenEndpoint { get; set; }

        public string ClientId { get; set; }

        public string ClientSecret { get; set; }

        public IEnumerable<string> Scopes { get; set; }

        /// <summary>
        /// Resource Owner Credentials
        /// </summary>
        public NetworkCredential Credentials { get; set; }
    }
}
