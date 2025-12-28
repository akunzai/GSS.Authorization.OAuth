using System.Net.Http;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;

namespace GSS.Authorization.OAuth.Tests;

internal class FakeAuthorizer(
    IOptions<AuthorizerOptions> options,
    HttpClient httpClient,
    IRequestSigner signer)
    : AuthorizerBase(options, httpClient, signer)
{
    public string VerificationCode { get; set; } = default!;

    public override Task<string> GetVerificationCodeAsync(Uri authorizeUri,
        CancellationToken cancellationToken = default)
    {
        return Task.FromResult(VerificationCode);
    }

    // Expose protected method for testing
    public void TestHandleOAuthException(HttpResponseMessage response, IDictionary<string, StringValues> formData)
    {
        HandleOAuthException(response, formData);
    }
}