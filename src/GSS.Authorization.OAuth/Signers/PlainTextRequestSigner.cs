using System;
using System.Collections.Generic;
using System.Net.Http;
using Microsoft.Extensions.Primitives;

namespace GSS.Authorization.OAuth
{
    /// <summary>
    /// PLAINTEXT signature algorithm, see https://tools.ietf.org/html/rfc5849#section-3.4.4
    /// </summary>
    public class PlainTextRequestSigner : RequestSignerBase
    {
        public override string MethodName => "PLAINTEXT";

        public override string GetSignature(HttpMethod method, Uri uri, IEnumerable<KeyValuePair<string, StringValues>> parameters, string consumerSecret,
            string? tokenSecret = null)
        {
            return $"{consumerSecret}&{tokenSecret}";
        }
    }
}
