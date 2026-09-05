using Microsoft.Extensions.Options;
using Xunit;

namespace GSS.Authorization.OAuth.Tests;

public class InteractiveConsoleAuthorizerTests
{
    [Fact]
    public async Task GetVerificationCodeAsync_WhenInputEnds_ShouldThrowInsteadOfLooping()
    {
        // Arrange
        var authorizer = CreateAuthorizer();
        var originalIn = Console.In;
        var originalOut = Console.Out;
        Console.SetIn(new StringReader(string.Empty));
        Console.SetOut(TextWriter.Null);
        try
        {
            // Act & Assert
            // Console.ReadLine returns null at end of input; the loop used to prompt forever.
            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                authorizer.GetVerificationCodeAsync(new Uri("https://example.com/authorize"),
                    TestContext.Current.CancellationToken));
        }
        finally
        {
            Console.SetIn(originalIn);
            Console.SetOut(originalOut);
        }
    }

    [Fact]
    public async Task GetVerificationCodeAsync_ShouldSkipBlankLinesUntilACodeIsEntered()
    {
        // Arrange
        var authorizer = CreateAuthorizer();
        var originalIn = Console.In;
        var originalOut = Console.Out;
        Console.SetIn(new StringReader("\n   \nverifier\n"));
        Console.SetOut(TextWriter.Null);
        try
        {
            // Act
            var code = await authorizer.GetVerificationCodeAsync(new Uri("https://example.com/authorize"),
                TestContext.Current.CancellationToken);

            // Assert
            Assert.Equal("verifier", code);
        }
        finally
        {
            Console.SetIn(originalIn);
            Console.SetOut(originalOut);
        }
    }

    private static InteractiveConsoleAuthorizer CreateAuthorizer()
    {
        return new InteractiveConsoleAuthorizer(
            Options.Create(new AuthorizerOptions()),
            new System.Net.Http.HttpClient(),
            new HmacSha1RequestSigner())
        {
            // Never launch a real browser from a test.
            BrowserLauncher = _ => { }
        };
    }

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
