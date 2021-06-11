using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;

namespace GSS.Authorization.OAuth
{
    public class OAuthHttpHandler : DelegatingHandler
    {
        private const string ApplicationFormUrlEncoded = "application/x-www-form-urlencoded";
        private readonly OAuthHttpHandlerOptions _options;
        private readonly IRequestSigner _signer;

        public OAuthHttpHandler(IOptions<OAuthHttpHandlerOptions> options, IRequestSigner signer)
        {
            if (options == null)
                throw new ArgumentNullException(nameof(options));
            _options = options.Value;
            _signer = signer;
        }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            if (request == null)
                throw new ArgumentNullException(nameof(request));
            var tokenCredentials = await _options.TokenCredentialProvider(request).ConfigureAwait(false);
            var queryString = QueryHelpers.ParseQuery(request.RequestUri?.Query);
            if (_options.SignedAsBody && request.Content != null && string.Equals(request.Content.Headers?.ContentType?.MediaType,
                ApplicationFormUrlEncoded, StringComparison.OrdinalIgnoreCase))
            {
                var urlEncoded = await request.Content.ReadAsStringAsync().ConfigureAwait(false);
                var formData = QueryHelpers.ParseQuery(urlEncoded);
                foreach (var query in queryString)
                {
                    if (!formData.ContainsKey(query.Key))
                    {
                        formData.Add(query.Key, query.Value);
                    }
                }

                var parameters = _signer.AppendAuthorizationParameters(request.Method, request.RequestUri!, _options,
                    formData, tokenCredentials);
                var values = new List<KeyValuePair<string?, string?>>();
                foreach (var parameter in parameters)
                {
                    if (!queryString.ContainsKey(parameter.Key))
                    {
                        values.AddRange(parameter.Value.Select(value =>
                            new KeyValuePair<string?, string?>(parameter.Key, value)));
                    }
                }

                // The form-encoded httpContent, see https://tools.ietf.org/html/rfc5849#section-3.5.2
                request.Content = new FormUrlEncodedContent(values);
            }
            else if (_options.SignedAsQuery)
            {
                var parameters = _signer.AppendAuthorizationParameters(request.Method, request.RequestUri!, _options,
                    queryString, tokenCredentials);
                var values = new List<string>();
                foreach (var parameter in parameters)
                {
                    foreach (var value in parameter.Value)
                    {
                        values.Add($"{Uri.EscapeDataString(parameter.Key)}={Uri.EscapeDataString(value)}");
                    }
                }

                request.RequestUri = new UriBuilder(request.RequestUri!) { Query = "?" + string.Join("&", values) }.Uri;
            }
            else
            {
                request.Headers.Authorization = _signer.GetAuthorizationHeader(
                    request.Method,
                    request.RequestUri!,
                    _options,
                    queryString,
                    tokenCredentials);
            }

            return await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
        }
    }
}