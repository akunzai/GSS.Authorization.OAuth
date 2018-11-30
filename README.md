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

## Getting Started

Use AddOAuth2HttpClient extension method to register OAuth2HttpClient service

```csharp
...
using GSS.Authorization.OAuth2;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
...

public void ConfigureServices(IServiceCollection services)
{
    services.AddOAuth2HttpClient((resolver, options) =>
    {
        var configuration = resolver.GetRequiredService<IConfiguration>();
        options.AccessTokenEndpoint = configuration.GetValue<Uri>("OAuth2:AccessTokenEndpoint");
        options.ClientId = configuration["OAuth2:ClientId"];
        options.ClientSecret = configuration["OAuth2:ClientSecret"];
        options.Credentials = new NetworkCredential(configuration["OAuth2:Credentials:UserName"], configuration["OAuth2:Credentials:Password"]);
        options.Scopes = configuration.GetSection("OAuth2:Scopes").Get<IEnumerable<string>>();
    });
}
```

default grant flow is `Resource-Owner-Credentials`, you can override it by register `IAuthorizer` before AddOAuth2HttpClient

```csharp
...
using GSS.Authorization.OAuth2;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
...

public void ConfigureServices(IServiceCollection services)
{
    services.AddTransient<IAuthorizer, ClientCredentialsAuthorizer>();

    services.AddOAuth2HttpClient((resolver, options) =>
    {
        var configuration = resolver.GetRequiredService<IConfiguration>();
        options.AccessTokenEndpoint = configuration.GetValue<Uri>("OAuth2:AccessTokenEndpoint");
        options.ClientId = configuration["OAuth2:ClientId"];
        options.ClientSecret = configuration["OAuth2:ClientSecret"];
        options.Credentials = new NetworkCredential(configuration["OAuth2:Credentials:UserName"], configuration["OAuth2:Credentials:Password"]);
        options.Scopes = configuration.GetSection("OAuth2:Scopes").Get<IEnumerable<string>>();
    });
}
```

Finally, your can use the HttpClient to access protected resource by OAUTH2 protocol, it will transparently exchange and cache the access token before HttpClientFactory disposing it. 

```csharp
...
using GSS.Authorization.OAuth2;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
...

namespace OAuth2HttpClientSample
{
    public static async Task Main()
    {
        ...
        var oauth2Client = provider.GetRequiredService<OAuth2HttpClient>();
        var response = await oauth2Client.HttpClient.GetAsync(Configuration["OAuth2:ResourceEndpoint"]).ConfigureAwait(false);
        ...
    }
}
...
```