using Microsoft.Extensions.Options;
using Xunit;

namespace GSS.Authorization.OAuth.Tests;

public class InteractiveConsoleAuthorizerTests
{
    [Fact]
    public async Task GetVerificationCodeAsync_WithNullAuthorizationUri_ShouldThrowArgumentNullException()
    {
        // Arrange
        var authorizer = new InteractiveConsoleAuthorizer(
            Options.Create(new AuthorizerOptions()),
            new System.Net.Http.HttpClient(),
            new HmacSha1RequestSigner());

        // Act
        var exception = await Assert.ThrowsAsync<ArgumentNullException>(() =>
            authorizer.GetVerificationCodeAsync(null!, TestContext.Current.CancellationToken));

        // Assert
        Assert.Equal("authorizationUri", exception.ParamName);
    }
}
