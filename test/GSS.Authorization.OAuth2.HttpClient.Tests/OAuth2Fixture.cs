using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using RichardSzalay.MockHttp;

namespace GSS.Authorization.OAuth2.HttpClient.Tests
{
    public class OAuth2Fixture
    {
        public OAuth2Fixture()
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

            if (Configuration.GetValue("OAuth2:GrantFlow", "ResourceOwnerCredentials").Equals("ClientCredentials"))
            {
                services.AddTransient<IAuthorizer, ClientCredentialsAuthorizer>();
            }

            services.AddOAuth2HttpClient((resolver, options) =>
            {
                var configuration = resolver.GetRequiredService<IConfiguration>();
                options.AccessTokenEndpoint = configuration.GetValue<Uri>("OAuth2:AccessTokenEndpoint");
                options.ClientId = configuration["OAuth2:ClientId"];
                options.ClientSecret = configuration["OAuth2:ClientSecret"];
                options.Credentials = new NetworkCredential(configuration["OAuth2:Credentials:UserName"], configuration["OAuth2:Credentials:Password"]);
                options.Scopes = configuration.GetSection("OAuth2:Scopes").Get<IEnumerable<string>>();
            }, configureAuthorizerHttpClient: authorizer =>
            {
                authorizer.ConfigurePrimaryHttpMessageHandler(resolver => resolver.GetService<MockHttpMessageHandler>() as HttpMessageHandler ?? new HttpClientHandler());
            })
            .ConfigurePrimaryHttpMessageHandler(resolver => resolver.GetService<MockHttpMessageHandler>() as HttpMessageHandler ?? new HttpClientHandler());

            return services.BuildServiceProvider();
        }
    }
}
