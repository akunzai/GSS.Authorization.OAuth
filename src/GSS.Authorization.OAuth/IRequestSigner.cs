using System;
using System.Collections.Specialized;
using System.Net.Http;

namespace GSS.Authorization.OAuth
{
    public interface IRequestSigner
    {
        string MethodName { get; }

        /// <summary>
		/// generate request signature, see http://tools.ietf.org/html/rfc5849#section-3.4
		/// </summary>
		/// <returns>The signature.</returns>
		/// <param name='method'>HTTP request method.</param>
		/// <param name='uri'>The request resource URI.</param>
        /// <param name='parameters'>Request Parameters, see http://tools.ietf.org/html/rfc5849#section-3.4.1.3 </param>
		/// <param name='consumerSecret'>Consumer secret.</param>
		/// <param name='tokenSecret'>Token secret.</param>
        string GetSignature(
            HttpMethod method,
            Uri uri,
            NameValueCollection parameters,
            string consumerSecret,
            string? tokenSecret = null);
    }
}
