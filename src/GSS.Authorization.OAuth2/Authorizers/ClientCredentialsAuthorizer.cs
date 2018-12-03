using System;
using System.Collections.Generic;
using System.Net.Http;
using Microsoft.Extensions.Options;

namespace GSS.Authorization.OAuth2
{
    public class ClientCredentialsAuthorizer : AccessTokenAuthorizerBase
    {
        public ClientCredentialsAuthorizer(HttpClient client, IOptions<AuthorizerOptions> options) : base(client, options)
        {
        }

        [Obsolete("This is obsolete and will be removed in a future version.")]
        public ClientCredentialsAuthorizer(AuthorizerHttpClient client, IOptions<AuthorizerOptions> options) : base(client.HttpClient,options)
        {
        }

        protected override void PrepareFormData(IDictionary<string, string> formData)
        {
            formData[AuthorizerDefaults.GrantType] = AuthorizerDefaults.ClientCredentials;
        }
    }
}
