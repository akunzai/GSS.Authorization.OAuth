using System.Collections.Generic;
using Microsoft.Extensions.Options;

namespace GSS.Authorization.OAuth2
{
    public class ClientCredentialsAuthorizer : AccessTokenAuthorizerBase
    {
        public ClientCredentialsAuthorizer(AuthorizerHttpClient client, IOptions<AuthorizerOptions> options) : base(client,options)
        {
        }

        protected override void PrepareFormData(IDictionary<string, string> formData)
        {
            formData[AuthorizerDefaults.GrantType] = AuthorizerDefaults.ClientCredentials;
        }
    }
}
