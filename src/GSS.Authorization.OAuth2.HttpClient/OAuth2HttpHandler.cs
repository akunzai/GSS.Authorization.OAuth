using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;

namespace GSS.Authorization.OAuth2;

public class OAuth2HttpHandler : DelegatingHandler
{
    private static readonly MediaTypeHeaderValue _urlEncodedContentType =
        MediaTypeHeaderValue.Parse("application/x-www-form-urlencoded");

    private readonly AccessTokenCache _accessTokens;

    private readonly OAuth2HttpHandlerOptions _options;

    public OAuth2HttpHandler(
        IOptions<OAuth2HttpHandlerOptions> options,
        IAuthorizer authorizer,
        IMemoryCache memoryCache)
        // Handlers built by hand keep the access token to themselves, as they always have.
        : this(options, new AccessTokenCache(() => authorizer, memoryCache, Guid.NewGuid().ToString()))
    {
    }

    internal OAuth2HttpHandler(IOptions<OAuth2HttpHandlerOptions> options, AccessTokenCache accessTokens)
    {
        _options = options.Value;
        _accessTokens = accessTokens;
    }

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        if (request == null)
            throw new ArgumentNullException(nameof(request));
        if (request.Headers.Authorization != null)
            return await base.SendAsync(request, cancellationToken).ConfigureAwait(false);

        var accessToken = await _accessTokens.GetAsync(cancellationToken).ConfigureAwait(false);
        await SendAccessTokenInRequestAsync(accessToken, request).ConfigureAwait(false);
        var response = await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
        // https://www.rfc-editor.org/rfc/rfc6750#section-3
        var challenges = response.Headers.WwwAuthenticate;
        if (response.StatusCode != HttpStatusCode.Unauthorized ||
            (challenges.Count != 0 && !challenges.Any(c => c.Scheme.Equals(AuthorizerDefaults.Bearer))))
            return response;
        accessToken = await _accessTokens.RenewAsync(accessToken, cancellationToken).ConfigureAwait(false);
        await SendAccessTokenInRequestAsync(accessToken, request).ConfigureAwait(false);
        return await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
    }

    private async Task SendAccessTokenInRequestAsync(
        AccessToken accessToken,
        HttpRequestMessage request)
    {
        if (string.IsNullOrWhiteSpace(accessToken.Token)) return;
        if (_options.SendAccessTokenInBody && request.Content != null && string.Equals(
                request.Content.Headers?.ContentType?.MediaType,
                _urlEncodedContentType.MediaType, StringComparison.OrdinalIgnoreCase))
        {
            var parameters =
                QueryHelpers.ParseQuery(await request.Content.ReadAsStringAsync().ConfigureAwait(false));
            parameters[AuthorizerDefaults.AccessToken] = accessToken.Token;
            var values = new List<KeyValuePair<string?, string?>>();
            foreach (var parameter in parameters)
            {
                values.AddRange(parameter.Value.Select(value =>
                    new KeyValuePair<string?, string?>(parameter.Key, value)));
            }

            request.Content = new FormUrlEncodedContent(values);
        }
        else if (_options.SendAccessTokenInQuery)
        {
            request.RequestUri = new Uri(QueryHelpers.AddQueryString(request.RequestUri.OriginalString,
                AuthorizerDefaults.AccessToken, accessToken.Token));
        }
        else
        {
            request.Headers.Authorization =
                new AuthenticationHeaderValue(AuthorizerDefaults.Bearer, accessToken.Token);
        }
    }
}
