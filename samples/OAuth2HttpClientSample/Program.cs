using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http.Headers;
using System.Threading.Tasks;
using GSS.Authorization.OAuth2;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace OAuth2HttpClientSample
{
    public class Program
    {
        public static async Task Main(string[] args)
        {
            var host = Host.CreateDefaultBuilder(args)
                .ConfigureServices((hostContext, services) =>
                {
                    var clientBuilder =
                        hostContext.Configuration.GetValue("OAuth2:GrantFlow", "ClientCredentials")
                            .Equals("ClientCredentials", StringComparison.OrdinalIgnoreCase)
                            ? services.AddOAuth2HttpClient<OAuth2HttpClient, ClientCredentialsAuthorizer>(
                                ConfigureAuthorizerOptions)
                            : services.AddOAuth2HttpClient<OAuth2HttpClient, ResourceOwnerCredentialsAuthorizer>(
                                ConfigureAuthorizerOptions);
                    clientBuilder.ConfigureHttpClient(client =>
                    {
                        client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                    });
                }).Build();
            var configuration = host.Services.GetRequiredService<IConfiguration>();

            Console.WriteLine("Creating a client...");
            var oauth2Client = host.Services.GetRequiredService<OAuth2HttpClient>();

            Console.WriteLine("Sending a request...");
            var response = await oauth2Client.HttpClient.GetAsync(configuration.GetValue<Uri>("OAuth2:ResourceEndpoint")).ConfigureAwait(false);
            var data = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
            Console.WriteLine("Response data:");
            Console.WriteLine(data);
        }

        private static void ConfigureAuthorizerOptions(IServiceProvider resolver, AuthorizerOptions options)
        {
            var configuration = resolver.GetRequiredService<IConfiguration>();
            options.AccessTokenEndpoint = configuration.GetValue<Uri>("OAuth2:AccessTokenEndpoint");
            options.ClientId = configuration["OAuth2:ClientId"];
            options.ClientSecret = configuration["OAuth2:ClientSecret"];
            options.Credentials = new NetworkCredential(
                configuration["OAuth2:Credentials:UserName"],
                configuration["OAuth2:Credentials:Password"]);
            options.Scopes = configuration.GetSection("OAuth2:Scopes").Get<IEnumerable<string>>();
        }
    }
}
