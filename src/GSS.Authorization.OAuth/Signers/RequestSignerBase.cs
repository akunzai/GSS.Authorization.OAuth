using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Diagnostics;
using System.Linq;
using System.Net.Http;
using System.Text.RegularExpressions;

namespace GSS.Authorization.OAuth
{
    [DebuggerDisplay("Method = {MethodName}")]
    public abstract class RequestSignerBase : IRequestSigner
    {
        protected RequestSignerBase(OAuthOptions options)
        {
            Options = options ?? new OAuthOptions();
        }

        protected RequestSignerBase()
        {
            Options = new OAuthOptions();
        }

        protected OAuthOptions Options { get; }

        public abstract string MethodName { get; }

        public abstract string GetSignature(HttpMethod method, Uri uri, NameValueCollection parameters, string consumerSecret, string? tokenSecret = null);

        /// <summary>
		/// Signature Base String, see http://tools.ietf.org/html/rfc5849#section-3.4.1
		/// </summary>
		/// <returns>The signature base string.</returns>
		/// <param name='method'>HTTP request method.</param>
		/// <param name='uri'>The request resource URI.</param>
		/// <param name='parameters'>Request Parameters, see http://tools.ietf.org/html/rfc5849#section-3.4.1.3 </param>
		protected internal string GetBaseString(HttpMethod method, Uri uri, NameValueCollection parameters)
        {
            if (method == null)
                throw new ArgumentNullException(nameof(method));
            if (parameters == null)
            {
                throw new ArgumentNullException(nameof(parameters));
            }
            var baseUri = GetBaseStringUri(uri);
            // Parameters Normalization, see https://tools.ietf.org/html/rfc5849#section-3.4.1.3.2
            var normalizationParameters = new List<KeyValuePair<string, string>>();
            foreach (var key in parameters.AllKeys
                // the `oauth_signature`,`realm` parameter MUST be excluded
                .Where(k => !(k.Equals(OAuthDefaults.OAuthSignature, StringComparison.Ordinal) || k.Equals(OAuthDefaults.Realm, StringComparison.Ordinal))))
            {
                foreach (var value in parameters.GetValues(key))
                {
                    normalizationParameters.Add(new KeyValuePair<string, string>(Options.PercentEncodeProvider(key), Options.PercentEncodeProvider(value)));
                }
            }
            var values = normalizationParameters
                .OrderBy(x => PadNumbers(x.Key), StringComparer.Ordinal)
                .ThenBy(x => x.Value).Select(x =>
                  $"{x.Key}={x.Value}");
            var parts = new List<string>
            {
                method.Method.ToUpperInvariant(),
                Options.PercentEncodeProvider(baseUri),
                Options.PercentEncodeProvider(string.Join("&", values))
            };
            return string.Join("&", parts);
        }

        /// <summary>
        /// Base String URI, see https://tools.ietf.org/html/rfc5849#section-3.4.1.2
        /// </summary>
        /// <param name="uri"></param>
        /// <returns></returns>
        protected static string GetBaseStringUri(Uri uri)
        {
            var builder = new UriBuilder(uri)
            {
                Query = string.Empty,
                Fragment = string.Empty
            };
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
}
