using System;
using System.Collections.Generic;
using System.Net.Http;
using Microsoft.Extensions.Primitives;

namespace GSS.Authorization.OAuth;

/// <remarks>
/// An implementation that percent-encodes while computing the signature must use the same
/// <see cref="OAuthOptions.PercentEncoder" /> as the <see cref="OAuthOptions" /> its callers pass to
/// <see cref="RequestSignerExtensions" />. The signature base string and the authorization header are
/// encoded separately, and two different encoders yield a signature the server cannot reconstruct.
/// Implementations deriving from <see cref="RequestSignerBase" /> are checked at signing time; others
/// cannot be inspected and are trusted to honour this.
/// </remarks>
public interface IRequestSigner
{
    string MethodName { get; }

    /// <summary>
    /// generate request signature, see http://tools.ietf.org/html/rfc5849#section-3.4
    /// </summary>
    /// <param name='method'>HTTP request method.</param>
    /// <param name='uri'>The request resource URI.</param>
    /// <param name='parameters'>Request Parameters, see http://tools.ietf.org/html/rfc5849#section-3.4.1.3 </param>
    /// <param name='consumerSecret'>Consumer secret.</param>
    /// <param name='tokenSecret'>Token secret.</param>
    /// <returns>The signature.</returns>
    string GetSignature(
        HttpMethod method,
        Uri uri,
        IEnumerable<KeyValuePair<string, StringValues>> parameters,
        string consumerSecret,
        string? tokenSecret = null);
}