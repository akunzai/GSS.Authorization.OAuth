using System;
using System.ComponentModel.DataAnnotations;
using System.Net.Http;
using System.Threading.Tasks;

namespace GSS.Authorization.OAuth
{
    public class OAuthHttpHandlerOptions : OAuthOptions
    {
        [Required]
        public Func<HttpRequestMessage, ValueTask<OAuthCredential>> TokenCredentialProvider { get; set; } = default!;

        /// <summary>
        /// sign request as query parameter ? (default: Authorization header)
        /// , see https://tools.ietf.org/html/rfc5849#section-3.5
        /// </summary>
        public bool SignedAsQuery { get; set; }
    }
}
