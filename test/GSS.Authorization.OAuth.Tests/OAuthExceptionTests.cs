using System;
using Xunit;

namespace GSS.Authorization.OAuth.Tests;

public class OAuthExceptionTests
{
    [Fact]
    public void DefaultConstructor_ShouldCreateException()
    {
        // Act
        var exception = new OAuthException();

        // Assert
        Assert.NotNull(exception);
        Assert.IsType<OAuthException>(exception);
        Assert.NotNull(exception.Message);
    }

    [Fact]
    public void Constructor_WithMessage_ShouldSetMessage()
    {
        // Arrange
        const string expectedMessage = "OAuth authentication failed";

        // Act
        var exception = new OAuthException(expectedMessage);

        // Assert
        Assert.Equal(expectedMessage, exception.Message);
    }

    [Fact]
    public void Constructor_WithMessageAndInnerException_ShouldSetBoth()
    {
        // Arrange
        const string expectedMessage = "OAuth authentication failed";
        var innerException = new ArgumentException("Invalid parameter");

        // Act
        var exception = new OAuthException(expectedMessage, innerException);

        // Assert
        Assert.Equal(expectedMessage, exception.Message);
        Assert.Same(innerException, exception.InnerException);
    }

    [Fact]
    public void OAuthException_ShouldInheritFromHttpRequestException()
    {
        // Act
        var exception = new OAuthException();

        // Assert
        Assert.IsAssignableFrom<System.Net.Http.HttpRequestException>(exception);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("Parameter absent")]
    [InlineData("Invalid consumer key")]
    public void Constructor_WithVariousMessages_ShouldSetMessage(string message)
    {
        // Act
        var exception = new OAuthException(message);

        // Assert
        Assert.Equal(message, exception.Message);
    }
}