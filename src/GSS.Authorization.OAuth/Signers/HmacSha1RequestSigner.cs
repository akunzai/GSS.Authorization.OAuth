using System;
using System.Collections.Specialized;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;

namespace GSS.Authorization.OAuth
{
    /// <summary>
    /// HMAC-SHA1 signature algorithm, see https://tools.ietf.org/html/rfc5849#section-3.4.2
    /// </summary>
    public class HmacSha1RequestSigner : RequestSignerBase
    {
        public HmacSha1RequestSigner(OAuthOptions options) : base(options)
        {
        }

        public HmacSha1RequestSigner()
        {
        }

        public override string MethodName => "HMAC-SHA1";

        public override string GetSignature(
            HttpMethod method,
            Uri uri,
            NameValueCollection parameters,
            string consumerSecret,
            string? tokenSecret = null)
        {
            var key = new StringBuilder(Options.PercentEncoder(consumerSecret)).Append("&");
            if (tokenSecret != null)
            {
                key.Append(Options.PercentEncoder(tokenSecret));
            }
#pragma warning disable CA5350 // Do Not Use Weak Cryptographic Algorithms
            using var hmacSha1 = new HMACSHA1(Encoding.ASCII.GetBytes(key.ToString()));
#pragma warning restore CA5350 // Do Not Use Weak Cryptographic Algorithms
            var text = GetBaseString(method, uri, parameters);
            var digest = hmacSha1.ComputeHash(Encoding.ASCII.GetBytes(text));
            return Convert.ToBase64String(digest);
        }
    }
}
