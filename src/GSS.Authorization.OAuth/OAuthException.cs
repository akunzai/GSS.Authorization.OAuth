using System;
using System.Net.Http;

namespace GSS.Authorization.OAuth;

public class OAuthException : HttpRequestException
{
    public OAuthException()
    {
    }

    public OAuthException(string message) : base(message)
    {
    }

    public OAuthException(string message, Exception innerException) : base(message, innerException)
    {
    }
}