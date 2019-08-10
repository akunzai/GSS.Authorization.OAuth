using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Options;

namespace GSS.Authorization.OAuth2
{
    public abstract class AccessTokenAuthorizerBase : Authorizer
    {
        protected AccessTokenAuthorizerBase(HttpClient client, IOptions<AuthorizerOptions> options) : base(client)
        {
            Options = options.Value;
            if (string.IsNullOrWhiteSpace(Options.ClientId))
            {
                throw new ArgumentNullException(nameof(Options.ClientId));
            }
            if (string.IsNullOrWhiteSpace(Options.ClientSecret))
            {
                throw new ArgumentNullException(nameof(Options.ClientSecret));
            }
            if (Options.AccessTokenEndpoint == null)
            {
                throw new ArgumentNullException(nameof(Options.AccessTokenEndpoint));
            }
        }

        public AuthorizerOptions Options { get; }

        public override async Task<AccessToken> GetAccessTokenAsync(CancellationToken cancellationToken = default)
        {
            var formData = new Dictionary<string, string>
            {
                [AuthorizerDefaults.ClientId] = Options.ClientId,
                [AuthorizerDefaults.ClientSecret] = Options.ClientSecret
            };
            if (Options.Scopes != null)
            {
                formData.Add(AuthorizerDefaults.Scope, string.Join(AuthorizerDefaults.ScopeSeparator, Options.Scopes));
            }
            PrepareFormData(formData);
            var request = new HttpRequestMessage(HttpMethod.Post, Options.AccessTokenEndpoint)
            {
                Content = new FormUrlEncodedContent(formData)
            };
            var response = await Client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);

            if (response.IsSuccessStatusCode)
            {
                return await response.Content.ReadAsAsync<AccessToken>(cancellationToken).ConfigureAwait(false);
            }

            if (Options.OnError == null)
            {
                return AccessToken.Empty;
            }

            var errorMessage = response.Content == null ? null : await response.Content.ReadAsStringAsync().ConfigureAwait(false);
            Options.OnError(response.StatusCode, string.IsNullOrWhiteSpace(errorMessage) ? response.ReasonPhrase : errorMessage);
            return AccessToken.Empty;
        }

        protected abstract void PrepareFormData(IDictionary<string, string> formData);
    }
}
