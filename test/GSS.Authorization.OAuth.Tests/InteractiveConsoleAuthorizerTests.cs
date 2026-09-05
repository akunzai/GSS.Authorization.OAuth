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

    [Fact]
    public async Task GetVerificationCodeAsync_ShouldPrintTheUriAndOnlyOpenABrowserForAHuman()
    {
        // Arrange
        var launched = 0;
        var authorizer = CreateAuthorizer();
        authorizer.BrowserLauncher = _ => launched++;
        var output = new StringWriter();
        var originalIn = Console.In;
        var originalOut = Console.Out;
        Console.SetIn(new StringReader("verifier\n"));
        Console.SetOut(output);
        try
        {
            // Act
            await authorizer.GetVerificationCodeAsync(new Uri("https://example.com/authorize?oauth_token=abc"),
                TestContext.Current.CancellationToken);
        }
        finally
        {
            Console.SetIn(originalIn);
            Console.SetOut(originalOut);
        }

        // Assert
        // The URI is always printed, so a script can read it and a human can copy it.
        Assert.Contains("https://example.com/authorize?oauth_token=abc", output.ToString(), StringComparison.Ordinal);
        // Redirected input means a script is driving this and no one is watching a browser.
        Assert.Equal(Console.IsInputRedirected ? 0 : 1, launched);
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
