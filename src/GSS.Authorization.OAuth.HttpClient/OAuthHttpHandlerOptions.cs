using System;
using System.ComponentModel.DataAnnotations;
using System.Net.Http;
using System.Threading.Tasks;

namespace GSS.Authorization.OAuth;

public class OAuthHttpHandlerOptions : OAuthOptions
{
    private Func<HttpRequestMessage, ValueTask<OAuthCredential>>? _tokenCredentialProvider;

    [Required]
    public OAuthCredential TokenCredentials { get; set; }

    public Func<HttpRequestMessage, ValueTask<OAuthCredential>> TokenCredentialProvider
    {
        get => _tokenCredentialProvider ?? (_ => new ValueTask<OAuthCredential>(TokenCredentials));
        set => _tokenCredentialProvider = value;
    }

    /// <summary>
    /// sign request as query parameter ? (default: Authorization header)
    /// , see https://www.rfc-editor.org/rfc/rfc5849#section-3.5.3
    /// </summary>
    /// <remarks>
    /// Considered only when <see cref="SignedAsBody" /> does not apply. See that property for the
    /// order the three options are tried in.
    /// </remarks>
    public bool SignedAsQuery { get; set; }

    /// <summary>
    /// sign request as form-encoded body ? (default: Authorization header)
    /// , see https://www.rfc-editor.org/rfc/rfc5849#section-3.5.2
    /// </summary>
    /// <remarks>
    /// Applies only to requests whose content is <c>application/x-www-form-urlencoded</c>; a request
    /// with any other content, or none, falls through to the next option. The three are tried in
    /// order: form-encoded body, then <see cref="SignedAsQuery" />, then the Authorization header.
    /// The fall-through is silent, since one client may legitimately send requests of several
    /// content types.
    /// </remarks>
    public bool SignedAsBody { get; set; }
}