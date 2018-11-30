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
            var services = new ServiceCollection();
            ConfigureServices(services);
            var provider = services.BuildServiceProvider();

            Console.WriteLine("Creating a client...");
            var oauth2Client = provider.GetRequiredService<OAuth2HttpClient>();

            Console.WriteLine("Sending a request...");
            var response = await oauth2Client.HttpClient.GetAsync(Configuration["OAuth2:ResourceEndpoint"]).ConfigureAwait(false);
            var data = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
            Console.WriteLine("Response data:");
            Console.WriteLine(data);

            Console.WriteLine("Press the ANY key to exit...");
            Console.ReadKey();
        }

        private static IConfiguration Configuration { get; set; }

        private static void ConfigureServices(IServiceCollection services)
        {
            services.AddSingleton(Configuration);
            services.AddLogging(logging =>
            {
                logging.AddConfiguration(Configuration.GetSection("Logging"));
                logging.AddDebug();
            });

            if (Configuration.GetValue("OAuth2:GrantFlow", "ResourceOwnerCredentials").Equals("ClientCredentials"))
            {
                // override the IAuthorizer
                services.AddTransient<IAuthorizer, ClientCredentialsAuthorizer>();
            }

            services.AddOAuth2HttpClient<OAuth2HttpClient, ResourceOwnerCredentialsAuthorizer>((resolver, options) =>
            {
                var configuration = resolver.GetRequiredService<IConfiguration>();
                options.AccessTokenEndpoint = configuration.GetValue<Uri>("OAuth2:AccessTokenEndpoint");
                options.ClientId = configuration["OAuth2:ClientId"];
                options.ClientSecret = configuration["OAuth2:ClientSecret"];
                options.Credentials = new NetworkCredential(configuration["OAuth2:Credentials:UserName"], configuration["OAuth2:Credentials:Password"]);
                options.Scopes = configuration.GetSection("OAuth2:Scopes").Get<IEnumerable<string>>();
            });
        }
    }
}
