using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;

namespace GSS.Authorization.OAuth
{
    public static class RequestSignerExtensions
    {
        /// <summary>
        /// Gets the authorization header for a signed request.
        /// </summary>
        /// <returns>The authorization header.</returns>
        /// <param name="signer">The request signer.</param>
        /// <param name='method'>HTTP request method.</param>
        /// <param name='uri'>The request resource URI.</param>
        /// <param name="options">The OAuth options.</param>
        /// <param name='parameters'>Request Parameters, see http://tools.ietf.org/html/rfc5849#section-3.4.1.3 </param>
        /// <param name="tokenCredentials">Token Credentials.</param>
        public static AuthenticationHeaderValue GetAuthorizationHeader(this IRequestSigner signer,
            HttpMethod method,
            Uri uri,
            OAuthOptions options,
            NameValueCollection? parameters = null,
            OAuthCredential? tokenCredentials = null)
        {
            if (options == null)
                throw new ArgumentNullException(nameof(options));
            var query = AppendAuthorizationParameters(signer, method, uri, options, parameters, tokenCredentials);
            var values = new List<string>();
            foreach (var key in query.AllKeys.Where(x => x.StartsWith(OAuthDefaults.OAuthPrefix, StringComparison.Ordinal)))
            {
                foreach (var value in query.GetValues(key))
                {
                    values.Add($"{OAuthEncoder.PercentEncode(key)}=\"{OAuthEncoder.PercentEncode(value)}\"");
                }
            }
            var headerValue = string.Join(",", values);
            if (!string.IsNullOrEmpty(options.Realm))
            {
                return new AuthenticationHeaderValue(OAuthDefaults.OAuthScheme, $"{OAuthDefaults.Realm}=\"{OAuthEncoder.PercentEncode(options.Realm)}\",{headerValue}");
            }
            return new AuthenticationHeaderValue(OAuthDefaults.OAuthScheme, headerValue);
        }

        /// <summary>
        /// Gets the authorization query for a signed request.
        /// </summary>
        /// <returns>The authorization header.</returns>
        /// <param name="signer">The request signer.</param>
        /// <param name='method'>HTTP request method.</param>
        /// <param name='uri'>The request resource URI.</param>
        /// <param name="options">The OAuth options.</param>
        /// <param name='parameters'>Request Parameters, see http://tools.ietf.org/html/rfc5849#section-3.4.1.3 </param>
        /// <param name="tokenCredentials">Token Credentials.</param>
        public static NameValueCollection AppendAuthorizationParameters(
            this IRequestSigner signer, HttpMethod method, Uri uri, OAuthOptions options,
            NameValueCollection? parameters = null, OAuthCredential? tokenCredentials = null)
        {
            if (options == null)
                throw new ArgumentNullException(nameof(options));
            parameters ??= new NameValueCollection();
            if (tokenCredentials != null && !string.IsNullOrWhiteSpace(tokenCredentials.Value.Key))
            {
                parameters[OAuthDefaults.OAuthToken] = tokenCredentials.Value.Key;
            }

            parameters[OAuthDefaults.OAuthNonce] = options.NonceProvider();
            parameters[OAuthDefaults.OAuthTimestamp] = options.TimestampProvider();
            if (options.ProvideVersion)
            {
                parameters[OAuthDefaults.OAuthVersion] = OAuthDefaults.Version1;
            }
            parameters[OAuthDefaults.OAuthConsumerKey] = options.ClientCredentials.Key;
            parameters[OAuthDefaults.OAuthSignatureMethod] = signer.MethodName;
            parameters[OAuthDefaults.OAuthSignature] = signer.GetSignature(method, uri, parameters, options.ClientCredentials.Secret, tokenCredentials?.Secret);
            return parameters;
        }
    }
}
