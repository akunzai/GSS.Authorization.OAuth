# GSS.Authorization.OAuth

[![Build Status][build-badge]][build] [![Code Coverage][codecov-badge]][codecov]

[build]: https://github.com/akunzai/GSS.Authorization.OAuth/actions/workflows/build.yml
[build-badge]: https://github.com/akunzai/GSS.Authorization.OAuth/actions/workflows/build.yml/badge.svg
[codecov]: https://codecov.io/gh/akunzai/GSS.Authorization.OAuth
[codecov-badge]: https://codecov.io/gh/akunzai/GSS.Authorization.OAuth/branch/main/graph/badge.svg?token=YHAPVX7R97

OAuth authorized HttpClient, friendly
with [HttpClientFactory](https://docs.microsoft.com/aspnet/core/fundamentals/http-requests)

## NuGet Packages

- [GSS.Authorization.OAuth ![NuGet version](https://img.shields.io/nuget/v/GSS.Authorization.OAuth.svg?style=flat-square)](https://www.nuget.org/packages/GSS.Authorization.OAuth/)
- [GSS.Authorization.OAuth.HttpClient ![NuGet version](https://img.shields.io/nuget/v/GSS.Authorization.OAuth.HttpClient.svg?style=flat-square)](https://www.nuget.org/packages/GSS.Authorization.OAuth.HttpClient/)
- [GSS.Authorization.OAuth2 ![NuGet version](https://img.shields.io/nuget/v/GSS.Authorization.OAuth2.svg?style=flat-square)](https://www.nuget.org/packages/GSS.Authorization.OAuth2/)
- [GSS.Authorization.OAuth2.HttpClient ![NuGet version](https://img.shields.io/nuget/v/GSS.Authorization.OAuth2.HttpClient.svg?style=flat-square)](https://www.nuget.org/packages/GSS.Authorization.OAuth2.HttpClient/)

## Installation

```shell
# OAuth 1.0 protocol
dotnet add package GSS.Authorization.OAuth.HttpClient

# OAuth 2.0 protocol
dotnet add package GSS.Authorization.OAuth2.HttpClient
```

## Limits

### OAuth 1.0 protocol

- Only provide `HMAC-SHA1` and `PLAINTEXT` signature method. You can implement `GSS.Authorization.OAuth.IRequestSigner`
  to support more signature methods.
- Only provide `InteractiveConsoleAuthorizer` grant flow. You can implement `GSS.Authorization.OAuth.IAuthorizer` to
  support more grant flows.

### OAuth 2.0 protocol

- Only provide `Client-Credentials` and `Resource-Owner-Credentials` grant flow, You can
  implement `GSS.Authorization.OAuth2.IAuthorizer` to support more grant flows.

## Usage

Check out these [samples](./samples/) to learn the basics and key features.

### Named OAuth 1.0 HttpClient

```csharp
services.AddOAuthHttpClient("oauth",(resolver, options) =>
{
    var configuration = resolver.GetRequiredService<IConfiguration>();
    options.ClientCredentials = new OAuthCredential(configuration["OAuth:ClientId"], configuration["OAuth:ClientSecret"]);
    options.TokenCredentials = new OAuthCredential(configuration["OAuth:TokenId"],configuration["OAuth:TokenSecret"]);
    options.SignedAsQuery = configuration.GetValue("OAuth:SignedAsQuery", false);
});
```

### Typed OAuth 1.0 HttpClient

```csharp
services.AddOAuthHttpClient<OAuthHttpClient>((resolver, options) =>
{
    var configuration = resolver.GetRequiredService<IConfiguration>();
    options.ClientCredentials = new OAuthCredential(configuration["OAuth:ClientId"], configuration["OAuth:ClientSecret"]);
    options.TokenCredentials = new OAuthCredential(configuration["OAuth:TokenId"],configuration["OAuth:TokenSecret"]);
    options.SignedAsQuery = configuration.GetValue("OAuth:SignedAsQuery", false);
});
```

### Named OAuth 2.0 HttpClient

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

### Typed OAuth 2.0 HttpClient

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