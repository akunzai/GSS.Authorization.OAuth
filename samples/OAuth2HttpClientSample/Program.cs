using System;
using System.Collections.Generic;
using System.Net;
using System.Threading.Tasks;
using GSS.Authorization.OAuth2;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace OAuth2HttpClientSample
{
    public class Program
    {
        private static IConfiguration Configuration;

        public static async Task Main(string[] args)
        {
            var env = Environment.GetEnvironmentVariable("ENVIRONMENT") ?? "Production";
            Configuration = new ConfigurationBuilder()
                .AddJsonFile("appsettings.json")
                .AddJsonFile($"appsettings.{env}.json", optional: true)
                .Build();

            var serviceCollection = new ServiceCollection();
            serviceCollection.AddSingleton(Configuration);
            Configure(serviceCollection);
            var services = serviceCollection.BuildServiceProvider();

            Console.WriteLine("Creating a client...");
            var oauth2Client = services.GetRequiredService<OAuth2HttpClient>();

            Console.WriteLine("Sending a request...");
            var response = await oauth2Client.HttpClient.GetAsync(Configuration["OAuth2:ResourceEndpoint"]).ConfigureAwait(false);
            var data = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
            Console.WriteLine("Response data:");
            Console.WriteLine(data);

            Console.WriteLine("Press the ANY key to exit...");
            Console.ReadKey();
        }

        public static void Configure(IServiceCollection services)
        {
            services.AddOptions<AuthorizerOptions>().Configure(options =>
            {
                options.AccessTokenEndpoint = Configuration.GetValue<Uri>("OAuth2:AccessTokenEndpoint");
                options.ClientId = Configuration["OAuth2:ClientId"];
                options.ClientSecret = Configuration["OAuth2:ClientSecret"];
                options.Credentials = new NetworkCredential(Configuration["OAuth2:Credentials:UserName"], Configuration["OAuth2:Credentials:Password"]);
                options.Scopes = Configuration.GetSection("OAuth2:Scopes").Get<IEnumerable<string>>();
            });
            services.AddTransient<IAuthorizer>(sp =>
            {
                var grantType = Configuration.GetValue("OAuth2:GrantFlow", "ClientCredentials");
                if (grantType.Contains("ResourceOwner"))
                {
                    return ActivatorUtilities.CreateInstance<ResourceOwnerCredentialsAuthorizer>(sp);
                }
                return ActivatorUtilities.CreateInstance<ClientCredentialsAuthorizer>(sp);
            });
            services.AddHttpClient<AuthorizerHttpClient>();
            services.AddHttpClient<OAuth2HttpClient>()
            .AddHttpMessageHandler(sp => ActivatorUtilities.CreateInstance<OAuth2HttpHandler>(sp));
        }
    }
}
