using System;
using System.Collections.Generic;
using System.Net;
using System.Threading.Tasks;
using GSS.Authorization.OAuth2;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace OAuth2HttpClientSample
{
    public class Program
    {
        public static async Task Main()
        {
            Configuration = new ConfigurationBuilder()
                .AddJsonFile("appsettings.json")
                .AddJsonFile($"appsettings.{Environment.GetEnvironmentVariable("ENVIRONMENT") ?? "Production"}.json", optional: true)
                .Build();
            var services = ConfigureServices(new ServiceCollection()).BuildServiceProvider();

            Console.WriteLine("Creating a client...");
            var oauth2Client = services.GetRequiredService<OAuth2HttpClient>();

            Console.WriteLine("Sending a request...");
            var response = await oauth2Client.HttpClient.GetAsync(Configuration["OAuth2:ResourceEndpoint"]).ConfigureAwait(false);
            var data = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
            Console.WriteLine("Response data:");
            Console.WriteLine(data);
        }

        private static IConfiguration Configuration { get; set; }

        private static IServiceCollection ConfigureServices(IServiceCollection services)
        {
            services.AddSingleton(Configuration);
            services.AddLogging(logging =>
            {
                logging.AddConfiguration(Configuration.GetSection("Logging"));
                logging.AddDebug();
            });

            if (Configuration.GetValue("OAuth2:GrantFlow", "ClientCredentials").Equals("ClientCredentials"))
            {
                services.AddOAuth2HttpClient<OAuth2HttpClient, ClientCredentialsAuthorizer>((resolver, options) =>
                {
                    ConfigureAuthorizerOptions(options);
                });
            }
            else
            {
                services.AddOAuth2HttpClient<OAuth2HttpClient, ResourceOwnerCredentialsAuthorizer>((resolver, options) =>
                {
                    ConfigureAuthorizerOptions(options);
                });
            }

            return services;
        }

        private static void ConfigureAuthorizerOptions(AuthorizerOptions options)
        {
            options.AccessTokenEndpoint = Configuration.GetValue<Uri>("OAuth2:AccessTokenEndpoint");
            options.ClientId = Configuration["OAuth2:ClientId"];
            options.ClientSecret = Configuration["OAuth2:ClientSecret"];
            options.Credentials = new NetworkCredential(
                Configuration["OAuth2:Credentials:UserName"],
                Configuration["OAuth2:Credentials:Password"]);
            options.Scopes = Configuration.GetSection("OAuth2:Scopes").Get<IEnumerable<string>>();
        }
    }
}
