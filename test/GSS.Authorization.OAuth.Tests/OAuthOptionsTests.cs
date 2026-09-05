using Xunit;

namespace GSS.Authorization.OAuth.Tests;

public class OAuthOptionsTests
{
    [Fact]
    public void NonceProvider_ShouldProduceANonceServersAccept()
    {
        // Arrange
        var options = new OAuthOptions();

        // Act
        var nonces = Enumerable.Range(0, 50).Select(_ => options.NonceProvider()).ToList();

        // Assert
        // oauthlib, which backs a large share of OAuth 1.0 servers, rejects a nonce that is not
        // 20 to 30 letters and digits. Base64 fails it on '+', '/' and '='.
        Assert.All(nonces, nonce =>
        {
            Assert.InRange(nonce.Length, 20, 30);
            Assert.All(nonce, character => Assert.True(char.IsLetterOrDigit(character),
                $"'{character}' is not a letter or digit"));
        });
        Assert.Equal(nonces.Count, nonces.Distinct().Count());
    }
}
