using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Options;

namespace GSS.Authorization.OAuth
{
    public class OAuthHttpHandler : DelegatingHandler
    {
        private readonly OAuthHttpHandlerOptions _options;
        private readonly IRequestSigner _signer;

        public OAuthHttpHandler(IOptions<OAuthHttpHandlerOptions> options, IRequestSigner signer)
        {
            if (options == null)
                throw new ArgumentNullException(nameof(options));
            _options = options.Value;
            _signer = signer;
        }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (request == null)
                throw new ArgumentNullException(nameof(request));
            var tokenCredentials = await _options.TokenCredentialProvider(request).ConfigureAwait(false);
            var parameters = request.RequestUri.ParseQueryString();
            if (_options.SignedAsQuery)
            {
                var query = _signer.AppendAuthorizationParameters(request.Method, request.RequestUri, _options, parameters, tokenCredentials);
                var values = new List<string>();
                foreach (var key in query.AllKeys)
                {
                    foreach (var value in query.GetValues(key))
                    {
                        values.Add($"{Uri.EscapeDataString(key)}={Uri.EscapeDataString(value)}");
                    }
                }
                request.RequestUri = new UriBuilder(request.RequestUri)
                {
                    Query = "?" + string.Join("&", values)
                }.Uri;
            }
            else
            {
                request.Headers.Authorization = _signer.GetAuthorizationHeader(
                        request.Method,
                        request.RequestUri,
                        _options,
                        parameters,
                        tokenCredentials);
            }
            return await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
        }
    }
}
