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
                services.AddOAuth2HttpClient<OAuth2HttpClient, ClientCredentialsAuthorizer>((resolver, options) =>
                {
                    ConfigureAuthroizerOptions(options);
                }, configureAuthorizer: authorizer =>
                {
                    authorizer.ConfigurePrimaryHttpMessageHandler(resolver => resolver.GetService<MockHttpMessageHandler>() as HttpMessageHandler ?? new HttpClientHandler());
                })
                .ConfigurePrimaryHttpMessageHandler(resolver => resolver.GetService<MockHttpMessageHandler>() as HttpMessageHandler ?? new HttpClientHandler());
            }
            else
            {
                services.AddOAuth2HttpClient<OAuth2HttpClient, ResourceOwnerCredentialsAuthorizer>((resolver, options) =>
                {
                    ConfigureAuthroizerOptions(options);
                }, configureAuthorizer: authorizer =>
                {
                    authorizer.ConfigurePrimaryHttpMessageHandler(resolver => resolver.GetService<MockHttpMessageHandler>() as HttpMessageHandler ?? new HttpClientHandler());
                })
                .ConfigurePrimaryHttpMessageHandler(resolver => resolver.GetService<MockHttpMessageHandler>() as HttpMessageHandler ?? new HttpClientHandler());
            }

            return services.BuildServiceProvider();
        }

        private void ConfigureAuthroizerOptions(AuthorizerOptions options)
        {
            options.AccessTokenEndpoint = Configuration.GetValue<Uri>("OAuth2:AccessTokenEndpoint");
            options.ClientId = Configuration["OAuth2:ClientId"];
            options.ClientSecret = Configuration["OAuth2:ClientSecret"];
            options.Credentials = new NetworkCredential(Configuration["OAuth2:Credentials:UserName"], Configuration["OAuth2:Credentials:Password"]);
            options.Scopes = Configuration.GetSection("OAuth2:Scopes").Get<IEnumerable<string>>();
        }
    }
}
