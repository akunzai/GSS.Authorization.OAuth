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

## Getting started

Register a typed `HttpClient` that signs every request:

```csharp
// OAuth 1.0
services.AddOAuthHttpClient<OAuthHttpClient>((_, options) =>
{
    options.ClientCredentials = new OAuthCredential("client-id", "client-secret");
    options.TokenCredentials = new OAuthCredential("token-id", "token-secret");
});

// OAuth 2.0
services.AddOAuth2HttpClient<OAuth2HttpClient, ClientCredentialsAuthorizer>((_, options) =>
{
    options.AccessTokenEndpoint = new Uri("https://example.com/oauth2/token");
    options.ClientId = "client-id";
    options.ClientSecret = "client-secret";
});
```

Each client name owns its own credential and, for OAuth 2.0, its own cached access token.

## Documentation

- [Usage guide](https://github.com/akunzai/GSS.Authorization.OAuth/blob/main/docs/usage.md) —
  named and typed clients, multiple clients, credential placement, access token caching, and
  writing your own request signer
- [Samples](https://github.com/akunzai/GSS.Authorization.OAuth/tree/main/samples) — runnable
  console applications, one per package

## Limits

### OAuth 1.0 protocol

- Only `HMAC-SHA1` and `PLAINTEXT` signature methods are provided. Implement
  `GSS.Authorization.OAuth.IRequestSigner` to support more — see
  [writing your own request signer](https://github.com/akunzai/GSS.Authorization.OAuth/blob/main/docs/usage.md#writing-your-own-request-signer)
  for the contract it has to honour.
- Only the `InteractiveConsoleAuthorizer` grant flow is provided. Implement
  `GSS.Authorization.OAuth.IAuthorizer` to support more.

### OAuth 2.0 protocol

- Only the `Client-Credentials` and `Resource-Owner-Credentials` grant flows are provided.
  Implement `GSS.Authorization.OAuth2.IAuthorizer` to support more.
