namespace GSS.Authorization.OAuth2;

public class OAuth2HttpHandlerOptions
{
    /// <summary>
    /// sending access token in query parameter ? (default: Authorization header)
    /// , see https://www.rfc-editor.org/rfc/rfc6750#section-2.3
    /// </summary>
    /// <remarks>
    /// Considered only when <see cref="SendAccessTokenInBody" /> does not apply. See that property
    /// for the order the three options are tried in.
    /// </remarks>
    public bool SendAccessTokenInQuery { get; set; }

    /// <summary>
    /// sending access token in form-encoded body ? (default: Authorization header)
    /// , see https://www.rfc-editor.org/rfc/rfc6750#section-2.2
    /// </summary>
    /// <remarks>
    /// Applies only to requests whose content is <c>application/x-www-form-urlencoded</c>; a request
    /// with any other content, or none, falls through to the next option. The three are tried in
    /// order: form-encoded body, then <see cref="SendAccessTokenInQuery" />, then the Authorization
    /// header. The fall-through is silent, since one client may legitimately send requests of
    /// several content types.
    /// </remarks>
    public bool SendAccessTokenInBody { get; set; }
}