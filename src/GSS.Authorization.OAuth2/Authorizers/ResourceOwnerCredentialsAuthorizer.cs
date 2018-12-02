using System;
using System.Collections.Generic;
using System.Net.Http;
using Microsoft.Extensions.Options;

namespace GSS.Authorization.OAuth2
{
    public class ResourceOwnerCredentialsAuthorizer : AccessTokenAuthorizerBase
    {
        public ResourceOwnerCredentialsAuthorizer(
            HttpClient client,
            IOptions<AuthorizerOptions> options) : base(client, options)
        {
            if (options.Value.Credentials == null)
            {
                throw new ArgumentNullException(nameof(options.Value.Credentials));
            }
            if (string.IsNullOrWhiteSpace(options.Value.Credentials.UserName))
            {
                throw new ArgumentNullException(nameof(options.Value.Credentials.UserName));
            }
            if (string.IsNullOrWhiteSpace(options.Value.Credentials.Password))
            {
                throw new ArgumentNullException(nameof(options.Value.Credentials.Password));
            }
        }

        [Obsolete("This is obsolete and will be removed in a future version.")]
        public ResourceOwnerCredentialsAuthorizer(
            AuthorizerHttpClient client,
            IOptions<AuthorizerOptions> options) : this(client.HttClient, options)
        {
        }

        protected override void PrepareFormData(IDictionary<string, string> formData)
        {
            formData[AuthorizerDefaults.GrantType] = AuthorizerDefaults.Password;
            formData[AuthorizerDefaults.Username] = Options.Credentials.UserName;
            formData[AuthorizerDefaults.Password] = Options.Credentials.Password;
        }
    }
}
