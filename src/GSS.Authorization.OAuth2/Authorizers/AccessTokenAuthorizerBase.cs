using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Options;

// ReSharper disable once CheckNamespace
namespace GSS.Authorization.OAuth2;

public abstract class AccessTokenAuthorizerBase : Authorizer
{
    protected AccessTokenAuthorizerBase(
        HttpClient client,
        IOptions<AuthorizerOptions> options)
        : base(client)
    {
        if (options == null)
            throw new ArgumentNullException(nameof(options));
        Options = options.Value;
#pragma warning disable CA2208 // Instantiate argument exceptions correctly
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
#pragma warning restore CA2208 // Instantiate argument exceptions correctly
    }

    protected AuthorizerOptions Options { get; }

    public override async Task<AccessToken> GetAccessTokenAsync(CancellationToken cancellationToken = default)
    {
        var formData = new Dictionary<string, string>();
        if (Options.Scopes != null)
        {
            formData.Add(AuthorizerDefaults.Scope, string.Join(AuthorizerDefaults.ScopeSeparator, Options.Scopes));
        }

        if (Options.SendClientCredentialsInRequestBody)
        {
            formData.Add(AuthorizerDefaults.ClientId, Options.ClientId);
            formData.Add(AuthorizerDefaults.ClientSecret, Options.ClientSecret);
        }

        PrepareFormData(formData);

        using var request = new HttpRequestMessage(HttpMethod.Post, Options.AccessTokenEndpoint);
        request.Content = new FormUrlEncodedContent(formData);
        if (!Options.SendClientCredentialsInRequestBody)
        {
            request.Headers.Authorization = new AuthenticationHeaderValue(AuthorizerDefaults.Basic,
                Convert.ToBase64String(Encoding.ASCII.GetBytes($"{Options.ClientId}:{Options.ClientSecret}")));
        }

        var response = await Client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken)
            .ConfigureAwait(false);

        if (response.IsSuccessStatusCode)
        {
            var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
            return await JsonSerializer.DeserializeAsync<AccessToken>(stream, cancellationToken: cancellationToken)
                .ConfigureAwait(false) ?? AccessToken.Empty;
        }

        if (Options.OnError == null) return AccessToken.Empty;
        var errorMessage = response.Content == null
            ? response.ReasonPhrase
            : await response.Content.ReadAsStringAsync().ConfigureAwait(false);
        if (!string.IsNullOrWhiteSpace(errorMessage))
        {
            Options.OnError?.Invoke(response.StatusCode, errorMessage);
        }

        return AccessToken.Empty;
    }

    protected abstract void PrepareFormData(IDictionary<string, string> formData);
}