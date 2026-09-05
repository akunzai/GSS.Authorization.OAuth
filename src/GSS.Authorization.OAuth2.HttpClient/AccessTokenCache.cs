using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Caching.Memory;

namespace GSS.Authorization.OAuth2;

/// <summary>
/// Holds the access token of a single client name: obtains it on demand, keeps it until it
/// expires, and collapses concurrent callers onto a single authorization request.
/// </summary>
internal sealed class AccessTokenCache
{
    // A factory, not an instance: the authorizer holds an HttpClient from IHttpClientFactory, and
    // this cache outlives the handlers it serves. Holding one would pin a single HttpClient past
    // its rotation.
    private readonly Func<IAuthorizer> _authorizer;
    private readonly string _cacheKey;
    private readonly IMemoryCache _memoryCache;

    // Deliberately never disposed. SemaphoreSlim.Dispose only releases AvailableWaitHandle, which
    // is created lazily the first time that property is read; this class only ever uses
    // WaitAsync/Release, so there is nothing to release.
    private readonly SemaphoreSlim _semaphore = new SemaphoreSlim(1, 1);

    public AccessTokenCache(Func<IAuthorizer> authorizer, IMemoryCache memoryCache, string key)
    {
        _authorizer = authorizer;
        _memoryCache = memoryCache;
        _cacheKey = $"{typeof(AccessTokenCache).FullName}:{key}";
    }

    /// <summary>
    /// The current access token, obtaining one if the cache holds none.
    /// </summary>
    public async ValueTask<AccessToken> GetAsync(CancellationToken cancellationToken = default)
    {
        if (_memoryCache.TryGetValue<AccessToken>(_cacheKey, out var cached))
        {
            return cached ?? AccessToken.Empty;
        }

        await _semaphore.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_memoryCache.TryGetValue<AccessToken>(_cacheKey, out cached))
            {
                return cached!;
            }

            return await AuthorizeAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _semaphore.Release();
        }
    }

    /// <summary>
    /// Replaces <paramref name="staleToken" /> with a freshly obtained access token. Callers that
    /// hand in the same stale token concurrently share one authorization request.
    /// </summary>
    public async ValueTask<AccessToken> RenewAsync(
        AccessToken staleToken,
        CancellationToken cancellationToken = default)
    {
        await _semaphore.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            // Someone else may have renewed the very token we were handed while we waited.
            if (_memoryCache.TryGetValue<AccessToken>(_cacheKey, out var cached) &&
                cached != null &&
                !string.Equals(cached.Token, staleToken?.Token, StringComparison.Ordinal))
            {
                return cached;
            }

            return await AuthorizeAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _semaphore.Release();
        }
    }

    private async Task<AccessToken> AuthorizeAsync(CancellationToken cancellationToken)
    {
        var accessToken = await _authorizer().GetAccessTokenAsync(cancellationToken).ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(accessToken.Token))
        {
            return accessToken;
        }

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
}
