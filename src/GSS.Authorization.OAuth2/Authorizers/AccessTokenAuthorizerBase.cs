using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Options;
using Newtonsoft.Json;

namespace GSS.Authorization.OAuth2
{
    public abstract class AccessTokenAuthorizerBase : IAuthorizer
    {
        protected AccessTokenAuthorizerBase(AuthorizerHttpClient client, IOptions<AuthorizerOptions> options)
        {
            Client = client;
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

        protected AuthorizerHttpClient Client { get; }
        protected AuthorizerOptions Options { get; }

        public virtual async Task<AccessToken> GetAccessTokenAsync(CancellationToken cancellationToken = default)
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
            var response = await Client.HttClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                if (Options.OnError != null)
                {
                    var errorMessage = response.Content == null ? null : await response.Content.ReadAsStringAsync().ConfigureAwait(false);
                    Options.OnError(response.StatusCode, string.IsNullOrWhiteSpace(errorMessage) ? response.ReasonPhrase : errorMessage);
                }
                return null;
            }
            var json = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
            return JsonConvert.DeserializeObject<AccessToken>(json);
        }

        protected abstract void PrepareFormData(IDictionary<string, string> formData);
    }
}
