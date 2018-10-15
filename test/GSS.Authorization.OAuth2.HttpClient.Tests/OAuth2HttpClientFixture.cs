using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using RichardSzalay.MockHttp;

namespace GSS.Authorization.OAuth2
{
    public class OAuth2HttpClientFixture
    {
        private readonly IHost _host;

        public OAuth2HttpClientFixture()
        {
            _host = new HostBuilder()
                .ConfigureHostConfiguration(config => config.AddEnvironmentVariables())
                .ConfigureAppConfiguration((hostingContext, config) =>
                {
                    var env = hostingContext.HostingEnvironment;
                    config.AddJsonFile("appsettings.json");
                    config.AddJsonFile($"appsettings.{env.EnvironmentName}.json", optional: true);
                })
                .ConfigureLogging((hostingContext, logging) =>
                {
                    logging.AddConfiguration(hostingContext.Configuration.GetSection("Logging"));
                    logging.AddDebug();
                })
                .ConfigureServices((hostingContext, services) =>
                {
                    if (hostingContext.Configuration.GetValue("HttpClient:Mock", true))
                    {
                        services.AddSingleton(new MockHttpMessageHandler(BackendDefinitionBehavior.Always));
                    }
                    services.AddOptions<AuthorizerOptions>().Configure<IConfiguration>((options, configuration) =>
                    {
                        options.AccessTokenEndpoint = configuration.GetValue<Uri>("OAuth2:AccessTokenEndpoint");
                        options.ClientId = configuration["OAuth2:ClientId"];
                        options.ClientSecret = configuration["OAuth2:ClientSecret"];
                        options.Credentials = new NetworkCredential(configuration["OAuth2:Credentials:UserName"], configuration["OAuth2:Credentials:Password"]);
                        options.Scopes = configuration.GetSection("OAuth2:Scopes").Get<IEnumerable<string>>();
                    });
                    services.AddHttpClient<AuthorizerHttpClient>()
                    .ConfigurePrimaryHttpMessageHandler(sp => sp.GetService<MockHttpMessageHandler>() as HttpMessageHandler ?? new HttpClientHandler());
                    services.AddTransient<IAuthorizer>(sp =>
                    {
                        var grantType = hostingContext.Configuration.GetValue("OAuth2:GrantFlow", "ClientCredentials");
                        if (grantType.Contains("ResourceOwner"))
                        {
                            return ActivatorUtilities.CreateInstance<ResourceOwnerCredentialsAuthorizer>(sp);
                        }
                        return ActivatorUtilities.CreateInstance<ClientCredentialsAuthorizer>(sp);
                    });
                    services.AddHttpClient<OAuth2HttpClient>()
                    .AddHttpMessageHandler(sp => ActivatorUtilities.CreateInstance<OAuth2HttpHandler>(sp))
                    .ConfigurePrimaryHttpMessageHandler(sp => sp.GetService<MockHttpMessageHandler>() as HttpMessageHandler ?? new HttpClientHandler());
                })
                .Build();
        }

        public IServiceProvider Services => _host.Services;
    }
}
