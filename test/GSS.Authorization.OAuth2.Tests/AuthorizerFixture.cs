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
    public class AuthorizerFixture
    {
        private readonly IHost _host;

        public AuthorizerFixture()
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
                        services.AddSingleton<MockHttpMessageHandler>();
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
                })
                .Build();
        }

        public IServiceProvider Services => _host.Services;
    }
}
