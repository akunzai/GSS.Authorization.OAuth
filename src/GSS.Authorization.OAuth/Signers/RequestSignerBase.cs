using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net.Http;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Primitives;

// ReSharper disable once CheckNamespace
namespace GSS.Authorization.OAuth;

[DebuggerDisplay("Method = {MethodName}")]
public abstract class RequestSignerBase(OAuthOptions options) : IRequestSigner
{
    protected RequestSignerBase() : this(new OAuthOptions())
    {
    }

    protected OAuthOptions Options { get; } = options;

    public abstract string MethodName { get; }

    public abstract string GetSignature(HttpMethod method,
        Uri uri,
        IEnumerable<KeyValuePair<string, StringValues>> parameters,
        string consumerSecret,
        string? tokenSecret = null);

    /// <summary>
    /// Signature Base String, see http://tools.ietf.org/html/rfc5849#section-3.4.1
    /// </summary>
    /// <param name='method'>HTTP request method.</param>
    /// <param name='uri'>The request resource URI.</param>
    /// <param name='parameters'>Request Parameters, see http://tools.ietf.org/html/rfc5849#section-3.4.1.3 </param>
    /// <returns>The signature base string.</returns>
    /// <exception cref="ArgumentNullException"></exception>
    protected internal string GetBaseString(HttpMethod method,
        Uri uri,
        IEnumerable<KeyValuePair<string, StringValues>> parameters)
    {
        if (method == null)
            throw new ArgumentNullException(nameof(method));
        if (parameters == null)
        {
            throw new ArgumentNullException(nameof(parameters));
        }

        var baseUri = GetBaseStringUri(uri);
        // Parameters Normalization, see https://www.rfc-editor.org/rfc/rfc5849#section-3.4.1.3.2
        var normalizationParameters = new List<KeyValuePair<string, string>>();
        foreach (var parameter in parameters
                     // the `oauth_signature`,`realm` parameter MUST be excluded
                     .Where(p => !(p.Key.Equals(OAuthDefaults.OAuthSignature, StringComparison.Ordinal) ||
                                   p.Key.Equals(OAuthDefaults.Realm, StringComparison.Ordinal))))
        {
            normalizationParameters.AddRange(parameter.Value.OfType<string>().Select(value => new KeyValuePair<string, string>(Options.PercentEncoder(parameter.Key), Options.PercentEncoder(value))));
        }

        var values = normalizationParameters
            .OrderBy(x => PadNumbers(x.Key), StringComparer.Ordinal)
            .ThenBy(x => x.Value).Select(x =>
                $"{x.Key}={x.Value}");
        var parts = new List<string>
        {
            method.Method.ToUpperInvariant(),
            Options.PercentEncoder(baseUri),
            Options.PercentEncoder(string.Join("&", values))
        };
        return string.Join("&", parts);
    }

    /// <summary>
    /// Base String URI, see https://www.rfc-editor.org/rfc/rfc5849#section-3.4.1.2
    /// </summary>
    /// <param name="uri"></param>
    /// <returns></returns>
    protected static string GetBaseStringUri(Uri uri)
    {
        var builder = new UriBuilder(uri) { Query = string.Empty, Fragment = string.Empty };
        if (!builder.Host.Equals(builder.Host.ToLowerInvariant(), StringComparison.Ordinal))
        {
            builder.Host = builder.Host.ToLowerInvariant();
        }

        return builder.Uri.AbsoluteUri;
    }

    protected static string PadNumbers(string input)
    {
        return Regex.Replace(input, "[0-9]+", match => match.Value.PadLeft(10, '0'));
    }
}