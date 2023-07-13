using System;
using System.ComponentModel.DataAnnotations;

namespace GSS.Authorization.OAuth;

public class AuthorizerOptions : OAuthOptions
{
    /// <summary>
    /// Resource Owner Authorization endpoint
    /// </summary>
    [Required]
    public Uri ResourceOwnerAuthorizeUri { get; set; } = default!;

    [Required]
    public Uri TokenRequestUri { get; set; } = default!;

    /// <summary>
    /// Temporary Credential Request endpoint
    /// </summary>
    [Required]
    public Uri TemporaryCredentialRequestUri { get; set; } = default!;

    /// <summary>
    /// callback URI according to http://tools.ietf.org/html/rfc5849#section-2.1
    /// </summary>
    public Uri? CallBack { get; set; }
}