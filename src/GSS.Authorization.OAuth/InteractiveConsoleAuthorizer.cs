using System;
using System.Diagnostics;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Options;

namespace GSS.Authorization.OAuth;

public class InteractiveConsoleAuthorizer(
    IOptions<AuthorizerOptions> options,
    HttpClient httpClient,
    IRequestSigner signer)
    : AuthorizerBase(options, httpClient, signer)
{
    /// <summary>
    /// Launches the browser. Replaceable in tests so they do not open one.
    /// </summary>
    internal Action<Uri> BrowserLauncher { get; set; } = OpenBrowser;

    public override Task<string> GetVerificationCodeAsync(Uri authorizationUri,
        CancellationToken cancellationToken = default)
    {
        if (authorizationUri == null)
            throw new ArgumentNullException(nameof(authorizationUri));
        // Printed whether or not the browser opens: it may land in the wrong profile, on the
        // wrong display, or nowhere at all in a container.
        Console.WriteLine($"Open this URL to authorize: {authorizationUri.AbsoluteUri}");
        if (!Console.IsInputRedirected)
        {
            // Redirected input means a script is driving this, so nobody is watching a browser.
            BrowserLauncher(authorizationUri);
        }
        while (true)
        {
            Console.Write("Please complete login and authorization in browser and paste the verification code: ");
            var verificationCode = Console.ReadLine();
            if (verificationCode == null)
            {
                // Console.ReadLine returns null once standard input ends. Prompting again would
                // spin forever, printing the prompt until something runs out of memory.
                throw new InvalidOperationException(
                    "Standard input ended before a verification code was entered.");
            }

            if (!string.IsNullOrWhiteSpace(verificationCode))
            {
                return Task.FromResult(verificationCode);
            }
        }
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
            try
            {
                Process.Start("xdg-open", uri.AbsoluteUri);
            }
            catch (Exception exception)
            {
                // No browser and no xdg-open, which is normal in a container. The caller has
                // already printed the URI, so the grant can still continue.
                Console.WriteLine($"Could not open a browser ({exception.Message}).");
            }
        }
    }
}