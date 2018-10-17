# GSS.Authorization.OAuth

OAuth authorized HttpClient, friendly with HttpClientFactory

[![Build status](https://ci.appveyor.com/api/projects/status/9s6628wsosi4a6gu?svg=true)](https://ci.appveyor.com/project/akunzai/gss-authorization-oauth)

## NuGet Packages

- [GSS.Authorization.OAuth2 ![NuGet version](https://img.shields.io/nuget/v/GSS.Authorization.OAuth2.svg?style=flat-square)](https://www.nuget.org/packages/GSS.Authorization.OAuth2/)
- [GSS.Authorization.OAuth2.HttpClient ![NuGet version](https://img.shields.io/nuget/v/GSS.Authorization.OAuth2.HttpClient.svg?style=flat-square)](https://www.nuget.org/packages/GSS.Authorization.OAuth2.HttpClient/)

## Installation

```shell
# Package Manager
Install-Package GSS.Authorization.OAuth2.HttpClient

# .NET CLI
dotnet add package GSS.Authorization.OAuth2.HttpClient
```

## Limits

Currently, only `Client-Credentials` grant flow and `Resource-Owner-Credentials` grant flow are supported, You can implement `GSS.Authorization.OAuth2.IAuthorizer` to support more grant flows.

## Usage


```csharp
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
        public static async Task Main(string[] args)
        {
            var env = Environment.GetEnvironmentVariable("ENVIRONMENT") ?? "Production";
            var configuration = new ConfigurationBuilder()
                .AddJsonFile("appsettings.json")
                .AddJsonFile($"appsettings.{env}.json", optional: true)
                .Build();
            var services = new ServiceCollection()
            .AddLogging(logging =>
            {
                logging.AddConfiguration(configuration.GetSection("Logging"));
                logging.AddDebug();
            })
            .AddTransient<IAuthorizer>(sp =>
            {
                var grantType = configuration.GetValue("OAuth2:GrantFlow", "ClientCredentials");
                if (grantType.Contains("ResourceOwner"))
                {
                    return ActivatorUtilities.CreateInstance<ResourceOwnerCredentialsAuthorizer>(sp);
                }
                return ActivatorUtilities.CreateInstance<ClientCredentialsAuthorizer>(sp);
            })
            .AddOptions<AuthorizerOptions>().Configure(options =>
            {
                options.AccessTokenEndpoint = configuration.GetValue<Uri>("OAuth2:AccessTokenEndpoint");
                options.ClientId = configuration["OAuth2:ClientId"];
                options.ClientSecret = configuration["OAuth2:ClientSecret"];
                options.Credentials = new NetworkCredential(configuration["OAuth2:Credentials:UserName"], configuration["OAuth2:Credentials:Password"]);
                options.Scopes = configuration.GetSection("OAuth2:Scopes").Get<IEnumerable<string>>();
            })
            .Services.AddHttpClient<AuthorizerHttpClient>()
            .Services.AddHttpClient<OAuth2HttpClient>()
                .AddHttpMessageHandler(sp => ActivatorUtilities.CreateInstance<OAuth2HttpHandler>(sp))
            .Services.BuildServiceProvider();

            Console.WriteLine("Creating a client...");
            var oauth2Client = services.GetRequiredService<OAuth2HttpClient>();

            Console.WriteLine("Sending a request...");
            var response = await oauth2Client.HttpClient.GetAsync(configuration["OAuth2:ResourceEndpoint"]).ConfigureAwait(false);
            var data = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
            Console.WriteLine("Response data:");
            Console.WriteLine(data);

            Console.WriteLine("Press the ANY key to exit...");
            Console.ReadKey();
        }
    }
}
```