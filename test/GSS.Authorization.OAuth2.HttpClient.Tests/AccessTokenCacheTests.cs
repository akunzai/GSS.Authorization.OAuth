using Microsoft.Extensions.Caching.Memory;
using Xunit;

namespace GSS.Authorization.OAuth2.HttpClient.Tests;

public class AccessTokenCacheTests
{
    [Fact]
    public async Task GetAsync_WhenCached_ShouldNotCallAuthorizer()
    {
        // Arrange
        var calls = 0;
        var cache = CreateCache(_ =>
        {
            Interlocked.Increment(ref calls);
            return Task.FromResult(new AccessToken { Token = "access-token", ExpiresInSeconds = 60 });
        });

        // Act
        var first = await cache.GetAsync(TestContext.Current.CancellationToken);
        var second = await cache.GetAsync(TestContext.Current.CancellationToken);

        // Assert
        Assert.Equal(1, calls);
        Assert.Equal("access-token", first.Token);
        Assert.Same(first, second);
    }

    [Fact]
    public async Task GetAsync_WithConcurrentCallers_ShouldCallAuthorizerOnce()
    {
        // Arrange
        var calls = 0;
        var cache = CreateCache(async cancellationToken =>
        {
            Interlocked.Increment(ref calls);
            await Task.Delay(50, cancellationToken);
            return new AccessToken { Token = "access-token", ExpiresInSeconds = 60 };
        });

        // Act
        var tokens = await Task.WhenAll(Enumerable.Range(0, 5)
            .Select(_ => cache.GetAsync(TestContext.Current.CancellationToken).AsTask()));

        // Assert
        Assert.Equal(1, calls);
        Assert.All(tokens, token => Assert.Equal("access-token", token.Token));
    }

    [Fact]
    public async Task GetAsync_WhenExpired_ShouldCallAuthorizerAgain()
    {
        // Arrange
        var calls = 0;
        var cache = CreateCache(_ =>
        {
            var call = Interlocked.Increment(ref calls);
            return Task.FromResult(new AccessToken { Token = $"token-{call}", ExpiresInSeconds = 1 });
        });

        // Act
        var first = await cache.GetAsync(TestContext.Current.CancellationToken);
        await Task.Delay(1200, TestContext.Current.CancellationToken);
        var second = await cache.GetAsync(TestContext.Current.CancellationToken);

        // Assert
        Assert.Equal("token-1", first.Token);
        Assert.Equal("token-2", second.Token);
    }

    [Fact]
    public async Task GetAsync_WithoutToken_ShouldNotCache()
    {
        // Arrange
        var calls = 0;
        var cache = CreateCache(_ =>
        {
            Interlocked.Increment(ref calls);
            return Task.FromResult(AccessToken.Empty);
        });

        // Act
        await cache.GetAsync(TestContext.Current.CancellationToken);
        await cache.GetAsync(TestContext.Current.CancellationToken);

        // Assert
        Assert.Equal(2, calls);
    }

    [Fact]
    public async Task RenewAsync_WithConcurrentCallers_ShouldCallAuthorizerOnce()
    {
        // Arrange
        var calls = 0;
        var cache = CreateCache(async cancellationToken =>
        {
            var call = Interlocked.Increment(ref calls);
            await Task.Delay(50, cancellationToken);
            return new AccessToken { Token = $"token-{call}", ExpiresInSeconds = 60 };
        });
        var stale = await cache.GetAsync(TestContext.Current.CancellationToken);

        // Act
        var tokens = await Task.WhenAll(Enumerable.Range(0, 5)
            .Select(_ => cache.RenewAsync(stale, TestContext.Current.CancellationToken).AsTask()));

        // Assert
        Assert.Equal(2, calls);
        Assert.All(tokens, token => Assert.Equal("token-2", token.Token));
    }

    [Fact]
    public async Task RenewAsync_WhenTokenAlreadyReplaced_ShouldNotCallAuthorizer()
    {
        // Arrange
        var calls = 0;
        var cache = CreateCache(_ =>
        {
            var call = Interlocked.Increment(ref calls);
            return Task.FromResult(new AccessToken { Token = $"token-{call}", ExpiresInSeconds = 60 });
        });
        var stale = await cache.GetAsync(TestContext.Current.CancellationToken);
        var renewed = await cache.RenewAsync(stale, TestContext.Current.CancellationToken);

        // Act
        var again = await cache.RenewAsync(stale, TestContext.Current.CancellationToken);

        // Assert
        Assert.Equal(2, calls);
        Assert.Same(renewed, again);
    }

    private static AccessTokenCache CreateCache(Func<CancellationToken, Task<AccessToken>> getAccessToken)
    {
        return new AccessTokenCache(
            new StubAuthorizer(getAccessToken),
            new MemoryCache(new MemoryCacheOptions()),
            "test");
    }

    private sealed class StubAuthorizer(Func<CancellationToken, Task<AccessToken>> getAccessToken) : IAuthorizer
    {
        public Task<AccessToken> GetAccessTokenAsync(CancellationToken cancellationToken = default)
        {
            return getAccessToken(cancellationToken);
        }
    }
}
