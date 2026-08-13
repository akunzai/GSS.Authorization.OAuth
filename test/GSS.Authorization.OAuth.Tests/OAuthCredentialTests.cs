using Xunit;

namespace GSS.Authorization.OAuth.Tests;

public class OAuthCredentialTests
{
    [Fact]
    public void Equality_WithMatchingCredentials_ShouldUseValueSemantics()
    {
        // Arrange
        var credential = new OAuthCredential("key", "secret");
        var matchingCredential = new OAuthCredential("key", "secret");
        var differentCredential = new OAuthCredential("other-key", "secret");

        // Act & Assert
        Assert.True(credential.Equals((object)matchingCredential));
        Assert.True(credential.Equals(matchingCredential));
        Assert.True(credential == matchingCredential);
        Assert.False(credential != matchingCredential);
        Assert.Equal(credential.GetHashCode(), matchingCredential.GetHashCode());
        Assert.NotEqual(credential, differentCredential);
        Assert.False(credential.Equals("key"));
    }
}
