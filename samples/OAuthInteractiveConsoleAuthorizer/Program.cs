using System;
using System.ComponentModel.DataAnnotations;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using GSS.Authorization.OAuth;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace OAuthInteractiveConsoleGrantTool
{
    public class Program
    {
        private readonly IAuthorizer _authorizer;

        public Program(IAuthorizer authorizer)
        {
            _authorizer = authorizer;
        }

        public static async Task<int> Main(string[] args)
        {
            var mainModule = Process.GetCurrentProcess().MainModule;
            var hostBuilder = Host.CreateDefaultBuilder();
            if (mainModule != null)
            {
                hostBuilder.ConfigureAppConfiguration(config =>
                {
                    config.SetBasePath(Path.GetDirectoryName(mainModule.FileName));
                });
            }
            return await hostBuilder.ConfigureServices((context, services) =>
                {
                    services.AddOptions<AuthorizerOptions>()
                        .Configure(options =>
                        {
                            options.ClientCredentials = new OAuthCredential(
                                context.Configuration["OAuth:ClientId"],
                                context.Configuration["OAuth:ClientSecret"]);
                            options.CallBack = context.Configuration.GetValue<Uri>("OAuth:Callback");
                            options.TemporaryCredentialRequestUri = context.Configuration.GetValue<Uri>("OAuth:TemporaryCredentialRequestUri");
                            options.ResourceOwnerAuthorizeUri = context.Configuration.GetValue<Uri>("OAuth:ResourceOwnerAuthorizeUri");
                            options.TokenRequestUri = context.Configuration.GetValue<Uri>("OAuth:TokenRequestUri");
                        })
                        .PostConfigure(options =>
                        {
                            Validator.ValidateObject(options, new ValidationContext(options), true);
                        });
                    services.AddSingleton<IRequestSigner, HmacSha1RequestSigner>();
                    services.AddHttpClient<InteractiveConsoleAuthorizer>()
                        .ConfigureHttpClient(client =>
                        {
                            client.BaseAddress = context.Configuration.GetValue<Uri>("OAuth:BaseAddress");
                        });
                    services.AddTransient<IAuthorizer>(resolver => resolver.GetRequiredService<InteractiveConsoleAuthorizer>());
                })
                .RunCommandLineApplicationAsync<Program>(args).ConfigureAwait(false);
        }

        private async Task OnExecuteAsync(CancellationToken cancellationToken = default)
        {
            var tokenCredentials = await _authorizer.GrantAccessAsync(cancellationToken).ConfigureAwait(false);
            Console.WriteLine("Token Credentials ...");
            Console.WriteLine($"Key: {tokenCredentials.Key}");
            Console.WriteLine($"Secret: {tokenCredentials.Secret}");
            Console.WriteLine("Press any key to exit...");
            Console.ReadKey();
        }
    }
}
