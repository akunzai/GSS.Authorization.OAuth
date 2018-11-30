using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using RichardSzalay.MockHttp;

namespace GSS.Authorization.OAuth2.Tests
{
    public class AuthorizerFixture
    {
        public AuthorizerFixture()
        {
            Configuration = new ConfigurationBuilder()
                .AddJsonFile("appsettings.json")
                .AddJsonFile($"appsettings.{Environment.GetEnvironmentVariable("ENVIRONMENT") ?? "Production"}.json", optional: true)
                .Build();
        }

        public IConfiguration Configuration { get; }

        public IServiceProvider BuildServiceProvider()
        {
            var services = new ServiceCollection();
            services.AddSingleton(Configuration);
            services.AddLogging(logging =>
            {
                 logging.AddConfiguration(Configuration.GetSection("Logging"));
                 logging.AddDebug();
            });

            if (Configuration.GetValue("HttpClient:Mock", true))
            {
                services.AddSingleton(new MockHttpMessageHandler());
            }

            services.AddSingleton<AuthorizerError>();
            services.AddOptions<AuthorizerOptions>().Configure<IConfiguration, AuthorizerError>((options, configuration, errorState) =>
            {
                options.AccessTokenEndpoint = configuration.GetValue<Uri>("OAuth2:AccessTokenEndpoint");
                options.ClientId = configuration["OAuth2:ClientId"];
                options.ClientSecret = configuration["OAuth2:ClientSecret"];
                options.Credentials = new NetworkCredential(configuration["OAuth2:Credentials:UserName"], configuration["OAuth2:Credentials:Password"]);
                options.Scopes = configuration.GetSection("OAuth2:Scopes").Get<IEnumerable<string>>();
                options.OnError = (c, m) =>
                {
                    errorState.StatusCode = c;
                    errorState.Message = m;
                };
            });

            services.AddHttpClient<AuthorizerHttpClient>()
                .ConfigurePrimaryHttpMessageHandler(resolver => resolver.GetService<MockHttpMessageHandler>() as HttpMessageHandler ?? new HttpClientHandler());

            return services.BuildServiceProvider();
        }
    }
}
