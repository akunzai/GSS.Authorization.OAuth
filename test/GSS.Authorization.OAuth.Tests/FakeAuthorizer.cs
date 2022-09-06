using Microsoft.Extensions.Options;

namespace GSS.Authorization.OAuth.Tests
{
    internal class FakeAuthorizer : AuthorizerBase
    {
        public FakeAuthorizer(
            IOptions<AuthorizerOptions> options,
            HttpClient httpClient,
            IRequestSigner signer)
            : base(options, httpClient, signer)
        {
        }

        public string VerificationCode { get; set; } = default!;

        public override Task<string> GetVerificationCodeAsync(Uri authorizeUri,
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult(VerificationCode);
        }
    }
}