using System;
using System.Collections.Specialized;
using System.Net.Http;

namespace GSS.Authorization.OAuth
{
    /// <summary>
    /// PLAINTEXT signature algorithm, see https://tools.ietf.org/html/rfc5849#section-3.4.4
    /// </summary>
    public class PlainTextRequestSigner : RequestSignerBase
    {
        public override string MethodName => "PLAINTEXT";

        public override string GetSignature(HttpMethod method, Uri uri, NameValueCollection parameters, string consumerSecret, string? tokenSecret = null)
        {
            return $"{consumerSecret}&{tokenSecret}";
        }
    }
}
