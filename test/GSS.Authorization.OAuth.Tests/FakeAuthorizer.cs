using System;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.WebUtilities;

namespace GSS.Authorization.OAuth.Tests
{
    internal class FakeAuthorizer : AuthorizerBase
    {
        private readonly AuthorizerOptions _options;

        public FakeAuthorizer(AuthorizerOptions options, HttpClient httpClient, IRequestSigner signer) : base(options, httpClient, signer)
        {
            _options = options;
        }

        public string VerificationCode { get; set; }

        public string AuthorizeHtml { get; set; }

        public override async Task<HttpResponseMessage> AuthorizeAsync(NetworkCredential resourceOwnerCredentials, OAuthCredential requestToken, HttpContent authorizePage,
            CancellationToken cancellationToken = default)
        {
            AuthorizeHtml = await authorizePage.ReadAsStringAsync().ConfigureAwait(false);
            var response = new HttpResponseMessage();
            var callbackUri = QueryHelpers.AddQueryString(_options.CallBack == null ? string.Empty : _options.CallBack.AbsoluteUri,
                OAuthDefaults.OAuthVerifier, VerificationCode);
            response.Headers.Location = new Uri(callbackUri);
            return response;
        }
    }
}
