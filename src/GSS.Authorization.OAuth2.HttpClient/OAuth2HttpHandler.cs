using System;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Caching.Memory;

namespace GSS.Authorization.OAuth2
{
    public class OAuth2HttpHandler : DelegatingHandler
    {
        private readonly SemaphoreSlim _semaphore = new(1, 1);
        private readonly IAuthorizer _authorizer;
        private readonly IMemoryCache _memoryCache;
        private readonly string _cacheKey;

        public OAuth2HttpHandler(IAuthorizer authorizer, IMemoryCache memoryCache)
        {
            _authorizer = authorizer;
            _memoryCache = memoryCache;
            _cacheKey = Guid.NewGuid().ToString();
        }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            if (request == null)
                throw new ArgumentNullException(nameof(request));
            if (request.Headers.Authorization == null)
            {
                TrySetAuthorizationHeaderToRequest(await GetAccessTokenAsync(cancellationToken).ConfigureAwait(false), request);
            }
            var response = await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
            // https://tools.ietf.org/html/rfc6750#section-3
            var authenticateError = response.Headers.WwwAuthenticate.FirstOrDefault()?.Parameter;
            if (string.IsNullOrWhiteSpace(authenticateError) && response.StatusCode != HttpStatusCode.Unauthorized)
                return response;
            TrySetAuthorizationHeaderToRequest(await GetAccessTokenAsync(cancellationToken, forceRenew: true).ConfigureAwait(false), request);
            return await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
        }

        private async ValueTask<AccessToken> GetAccessTokenAsync(CancellationToken cancellationToken,
            bool forceRenew = false)
        {
            if (!forceRenew && _memoryCache.TryGetValue<AccessToken>(_cacheKey, out var accessTokenCache))
            {
                return accessTokenCache;
            }

            await _semaphore.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                var accessToken = await _authorizer.GetAccessTokenAsync(cancellationToken).ConfigureAwait(false);
                if (accessToken.ExpiresInSeconds > 0)
                {
                    _memoryCache.Set(_cacheKey, accessToken, accessToken.ExpiresIn);
                }
                else
                {
                    _memoryCache.Set(_cacheKey, accessToken);
                }
                return accessToken;
            }
            finally
            {
                _semaphore.Release();
            }
        }

        private static void TrySetAuthorizationHeaderToRequest(AccessToken accessToken, HttpRequestMessage request)
        {
            if (!string.IsNullOrWhiteSpace(accessToken.Token))
            {
                request.Headers.Authorization =
                    new AuthenticationHeaderValue(AuthorizerDefaults.Bearer, accessToken.Token);
            }
        }
    }
}