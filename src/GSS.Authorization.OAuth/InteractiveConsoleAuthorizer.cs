using System;
using System.Diagnostics;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Options;

namespace GSS.Authorization.OAuth;

public class InteractiveConsoleAuthorizer : AuthorizerBase
{
    public InteractiveConsoleAuthorizer(
        IOptions<AuthorizerOptions> options,
        HttpClient httpClient,
        IRequestSigner signer) : base(options, httpClient, signer)
    {
    }

    public override Task<string> GetVerificationCodeAsync(Uri authorizationUri,
        CancellationToken cancellationToken = default)
    {
        if (authorizationUri == null)
            throw new ArgumentNullException(nameof(authorizationUri));
        OpenBrowser(authorizationUri);
        var verificationCode = string.Empty;
        while (string.IsNullOrWhiteSpace(verificationCode))
        {
            Console.Write("Please complete login and authorization in browser and paste the verification code: ");
            verificationCode = Console.ReadLine();
        }

        return Task.FromResult(verificationCode);
    }

    // https://github.com/dotnet/runtime/issues/17938
    private static void OpenBrowser(Uri uri)
    {
        try
        {
            Process.Start(new ProcessStartInfo { FileName = uri.AbsoluteUri, UseShellExecute = true });
        }
        catch when (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
        {
            Process.Start("xdg-open", uri.AbsoluteUri);
        }
    }
}