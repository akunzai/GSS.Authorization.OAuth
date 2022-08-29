using System;
using System.ComponentModel.DataAnnotations;
using System.Net.Http;
using System.Threading.Tasks;

namespace GSS.Authorization.OAuth
{
    public class OAuthHttpHandlerOptions : OAuthOptions
    {
        private Func<HttpRequestMessage, ValueTask<OAuthCredential>>? _tokenCredentialProvider;

        [Required]
        public OAuthCredential TokenCredentials { get; set; }

        public Func<HttpRequestMessage, ValueTask<OAuthCredential>> TokenCredentialProvider
        {
            get
            {
                return _tokenCredentialProvider ?? (_ => new ValueTask<OAuthCredential>(TokenCredentials));
            }
            set
            {
                _tokenCredentialProvider = value;
            }
        }

        /// <summary>
        /// sign request as query parameter ? (default: Authorization header)
        /// , see https://www.rfc-editor.org/rfc/rfc5849#section-3.5.3
        /// </summary>
        public bool SignedAsQuery { get; set; }

        /// <summary>
        /// sign request as form-encoded body ? (default: Authorization header)
        /// , see https://www.rfc-editor.org/rfc/rfc5849#section-3.5.2
        /// </summary>
        public bool SignedAsBody { get; set; }
    }
}