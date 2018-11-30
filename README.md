# GSS.Authorization.OAuth

OAuth authorized HttpClient, friendly with [HttpClientFactory](https://docs.microsoft.com/aspnet/core/fundamentals/http-requests)

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

> please read [HttpClientFactory usage](https://docs.microsoft.com/aspnet/core/fundamentals/http-requests) first.

Named OAuth2 HttpClients

```csharp
services.AddOAuth2HttpClient<ClientCredentialsAuthorizer>("oauth2",(resolver, options) =>
{
    var configuration = resolver.GetRequiredService<IConfiguration>();
    options.AccessTokenEndpoint = configuration.GetValue<Uri>("OAuth2:AccessTokenEndpoint");
    options.ClientId = configuration["OAuth2:ClientId"];
    options.ClientSecret = configuration["OAuth2:ClientSecret"];
    options.Credentials = new NetworkCredential(configuration["OAuth2:Credentials:UserName"], configuration["OAuth2:Credentials:Password"]);
    options.Scopes = configuration.GetSection("OAuth2:Scopes").Get<IEnumerable<string>>();
});
```

Typed OAuth2 HttpClients

```csharp
services.AddOAuth2HttpClient<OAuth2HttpClient, ResourceOwnerCredentialsAuthorizer>((resolver, options) =>
{
    var configuration = resolver.GetRequiredService<IConfiguration>();
    options.AccessTokenEndpoint = configuration.GetValue<Uri>("OAuth2:AccessTokenEndpoint");
    options.ClientId = configuration["OAuth2:ClientId"];
    options.ClientSecret = configuration["OAuth2:ClientSecret"];
    options.Credentials = new NetworkCredential(configuration["OAuth2:Credentials:UserName"], configuration["OAuth2:Credentials:Password"]);
    options.Scopes = configuration.GetSection("OAuth2:Scopes").Get<IEnumerable<string>>();
});
```