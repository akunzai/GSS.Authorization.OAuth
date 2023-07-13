namespace GSS.Authorization.OAuth2;

public class OAuth2HttpHandlerOptions
{
    /// <summary>
    /// sending access token in query parameter ? (default: Authorization header)
    /// , see https://www.rfc-editor.org/rfc/rfc6750#section-2.3
    /// </summary>
    public bool SendAccessTokenInQuery { get; set; }

    /// <summary>
    /// sending access token in form-encoded body ? (default: Authorization header)
    /// , see https://www.rfc-editor.org/rfc/rfc6750#section-2.2
    /// </summary>
    public bool SendAccessTokenInBody { get; set; }
}