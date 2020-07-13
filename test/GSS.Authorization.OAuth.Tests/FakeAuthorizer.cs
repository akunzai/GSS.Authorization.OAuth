using System;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Options;

namespace GSS.Authorization.OAuth.Tests
{
    internal class FakeAuthorizer : AuthorizerBase
    {
        public FakeAuthorizer(IOptions<AuthorizerOptions> options, HttpClient httpClient, IRequestSigner signer) : base(options, httpClient, signer)
        {
        }

        public string VerificationCode { get; set; }

        public override Task<string> GetVerificationCodeAsync(Uri authorizeUri, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(VerificationCode);
        }
    }
}
