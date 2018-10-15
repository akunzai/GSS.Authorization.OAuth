using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading;
using System.Threading.Tasks;

namespace GSS.Authorization.OAuth2
{
    public class OAuth2HttpHandler : DelegatingHandler
    {
        private readonly SemaphoreSlim _semaphore = new SemaphoreSlim(1, 1);
        private readonly IAuthorizer _authorizer;
        private AccessToken _accessTokenCache;

        public OAuth2HttpHandler(IAuthorizer authorizer)
        {
            _authorizer = authorizer;
        }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (request.Headers.Authorization == null)
            {
                _accessTokenCache = _accessTokenCache ?? await GetAccessTokenAsync(cancellationToken).ConfigureAwait(false);
                SetAuthorizationHeaderToRequest(request);
            }

            var response = await base.SendAsync(request, cancellationToken).ConfigureAwait(false);

            if (response.StatusCode == HttpStatusCode.Unauthorized)
            {
                _accessTokenCache = _accessTokenCache ?? await GetAccessTokenAsync(cancellationToken).ConfigureAwait(false);
                SetAuthorizationHeaderToRequest(request);
                response = await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
            }

            return response;
        }

        private async Task<AccessToken> GetAccessTokenAsync(CancellationToken cancellationToken)
        {
            try
            {
                await _semaphore.WaitAsync(cancellationToken).ConfigureAwait(false);
                return await _authorizer.GetAccessTokenAsync(cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                _semaphore.Release();
            }
        }

        private void SetAuthorizationHeaderToRequest(HttpRequestMessage request)
        {
            if (_accessTokenCache != null && !string.IsNullOrWhiteSpace(_accessTokenCache.Token))
            {
                request.Headers.Authorization = new AuthenticationHeaderValue(AuthorizerDefaults.Bearer, _accessTokenCache.Token);
            }
        }
    }
}
