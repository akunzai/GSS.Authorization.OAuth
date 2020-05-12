using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Net;
using System.Net.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using RichardSzalay.MockHttp;

namespace GSS.Authorization.OAuth2.Tests
{
    public class AuthorizerFixture
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
                }).PostConfigure(options => Validator.ValidateObject(options, new ValidationContext(options), validateAllProperties: true));

                services.AddHttpClient<ClientCredentialsAuthorizer>()
                    .ConfigurePrimaryHttpMessageHandler(_ => handler);

                services.AddHttpClient<ResourceOwnerCredentialsAuthorizer>()
                    .ConfigurePrimaryHttpMessageHandler(_ => handler);
            })
            .Build().Services;
        }
    }
}
