using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using RichardSzalay.MockHttp;

namespace GSS.Authorization.OAuth2.HttpClient.Tests
{
    public class OAuth2Fixture
    {
        public IServiceProvider BuildServiceProvider()
        {
            return Host.CreateDefaultBuilder()
            .ConfigureServices((context, services) =>
            {
                var handler = context.Configuration.GetValue("HttpClient:Mock", true)
                            ? (HttpMessageHandler)new MockHttpMessageHandler()
                            : new HttpClientHandler();
                services.AddSingleton(handler);
                if (context.Configuration.GetValue("OAuth2:GrantFlow", "ResourceOwnerCredentials").Equals("ClientCredentials", StringComparison.OrdinalIgnoreCase))
                {
                    services.AddOAuth2HttpClient<OAuth2HttpClient, ClientCredentialsAuthorizer>(ConfigureAuthroizerOptions,
                        configureAuthorizer: authorizer => authorizer.ConfigurePrimaryHttpMessageHandler(_ => handler))
                    .ConfigurePrimaryHttpMessageHandler(_ => handler);
                }
                else
                {
                    services.AddOAuth2HttpClient<OAuth2HttpClient, ResourceOwnerCredentialsAuthorizer>(ConfigureAuthroizerOptions,
                        configureAuthorizer: authorizer => authorizer.ConfigurePrimaryHttpMessageHandler(_ => handler))
                    .ConfigurePrimaryHttpMessageHandler(_ => handler);
                }

            }).Build().Services;
        }

        private void ConfigureAuthroizerOptions(IServiceProvider resolver, AuthorizerOptions options)
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
