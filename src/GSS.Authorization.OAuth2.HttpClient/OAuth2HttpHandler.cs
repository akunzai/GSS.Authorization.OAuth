using System;
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
        private DateTime _accessTokenExpiredTime;

        public OAuth2HttpHandler(IAuthorizer authorizer)
        {
            _authorizer = authorizer;
        }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (request.Headers.Authorization == null)
            {
                _accessTokenCache = await GetAccessTokenAsync(cancellationToken).ConfigureAwait(false);
                TrySetAuthorizationHeaderToRequest(request);
            }

            var response = await base.SendAsync(request, cancellationToken).ConfigureAwait(false);

            if (response.StatusCode == HttpStatusCode.Unauthorized)
            {
                _accessTokenCache = await GetAccessTokenAsync(cancellationToken).ConfigureAwait(false);
                TrySetAuthorizationHeaderToRequest(request);
                return await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
            }

            return response;
        }

        private async ValueTask<AccessToken> GetAccessTokenAsync(CancellationToken cancellationToken)
        {
            if (_accessTokenCache != null && _accessTokenExpiredTime > DateTime.Now)
            {
                return _accessTokenCache;
            }
            await _semaphore.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                _accessTokenCache = await _authorizer.GetAccessTokenAsync(cancellationToken).ConfigureAwait(false);
                _accessTokenExpiredTime = _accessTokenCache?.ExpiresInSeconds > 0
                    ? DateTime.Now.AddSeconds(_accessTokenCache.ExpiresInSeconds)
                    : _accessTokenExpiredTime;
                return _accessTokenCache;
            }
            finally
            {
                _semaphore.Release();
            }
        }

        private void TrySetAuthorizationHeaderToRequest(HttpRequestMessage request)
        {
            if (_accessTokenCache != null && !string.IsNullOrWhiteSpace(_accessTokenCache.Token))
            {
                request.Headers.Authorization = new AuthenticationHeaderValue(AuthorizerDefaults.Bearer, _accessTokenCache.Token);
            }
        }
    }
}
