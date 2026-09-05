# Usage

Runnable versions of everything here live in [samples](../samples/).

## Registering a client

Every registration takes a delegate that configures the options from whatever configuration source
you use. The four shapes below differ only in whether the `HttpClient` is named or typed, and in
which protocol it speaks.

### Named OAuth 1.0 HttpClient

```csharp
services.AddOAuthHttpClient("oauth", (resolver, options) =>
{
    var configuration = resolver.GetRequiredService<IConfiguration>();
    options.ClientCredentials = new OAuthCredential(configuration["OAuth:ClientId"], configuration["OAuth:ClientSecret"]);
    options.TokenCredentials = new OAuthCredential(configuration["OAuth:TokenId"], configuration["OAuth:TokenSecret"]);
    options.SignedAsQuery = configuration.GetValue("OAuth:SignedAsQuery", false);
});
```

### Typed OAuth 1.0 HttpClient

```csharp
services.AddOAuthHttpClient<OAuthHttpClient>((resolver, options) =>
{
    var configuration = resolver.GetRequiredService<IConfiguration>();
    options.ClientCredentials = new OAuthCredential(configuration["OAuth:ClientId"], configuration["OAuth:ClientSecret"]);
    options.TokenCredentials = new OAuthCredential(configuration["OAuth:TokenId"], configuration["OAuth:TokenSecret"]);
    options.SignedAsQuery = configuration.GetValue("OAuth:SignedAsQuery", false);
});
```

### Named OAuth 2.0 HttpClient

```csharp
services.AddOAuth2HttpClient<ClientCredentialsAuthorizer>("oauth2", (resolver, options) =>
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

## Multiple clients

Each client name gets its own options, request signer or authorizer, and credential:

```csharp
services.AddOAuthHttpClient("reporting", (_, options) =>
{
    options.ClientCredentials = new OAuthCredential("reporting-id", "reporting-secret");
    options.TokenCredentials = new OAuthCredential("reporting-token", "reporting-token-secret");
});

services.AddOAuthHttpClient("ingest", (_, options) =>
{
    options.ClientCredentials = new OAuthCredential("ingest-id", "ingest-secret");
    options.TokenCredentials = new OAuthCredential("ingest-token", "ingest-token-secret");
});
```

For a typed client the name is the one `HttpClientFactory` derives, e.g. `OAuthHttpClient`.

The first client registered also keeps the unnamed `IOptions<T>` and the container registration of
the request signer or authorizer, so resolving those directly still yields that client's
configuration. Options of any later client are only reachable through `IOptionsMonitor<T>.Get(name)`,
and they are validated when that client is first created rather than at registration time.

OAuth 2.0 clients can also configure where the access token is sent, per client:

```csharp
services.AddOAuth2HttpClient<ClientCredentialsAuthorizer>("ingest",
    configureOptions: (_, options) => { /* ... */ },
    configureAuthorizer: null,
    configureHandler: (_, options) => options.SendAccessTokenInQuery = true);
```

Without `configureHandler` a client reads the unnamed `OAuth2HttpHandlerOptions`.

## Where the credential is placed

Both protocols try three placements in order — form-encoded body, query string, `Authorization`
header. The body option applies only to requests whose content is
`application/x-www-form-urlencoded`; anything else falls through to the next option silently, since
one client may legitimately send requests of several content types.

| Protocol | Body | Query |
| --- | --- | --- |
| OAuth 1.0 | `SignedAsBody` | `SignedAsQuery` |
| OAuth 2.0 | `SendAccessTokenInBody` | `SendAccessTokenInQuery` |

## Access token caching

Each OAuth 2.0 client name keeps one access token, obtained on first use and reused until it
expires. The token belongs to the registration rather than to an individual handler, so it survives
the handler rotation `HttpClientFactory` performs instead of being re-fetched every couple of
minutes.

Concurrent requests that find no cached token share a single request to the authorization server,
and so do concurrent requests rejected with `401` and a `Bearer` challenge: the token is renewed
once for the whole batch rather than once per request.

Handlers constructed by hand — `new OAuth2HttpHandler(options, authorizer, memoryCache)` — keep
their token to themselves.

## Writing your own request signer

`GSS.Authorization.OAuth.IRequestSigner` is the extension point for signature methods beyond
`HMAC-SHA1` and `PLAINTEXT`.

A signer must hold the same `OAuthOptions.PercentEncoder` as the `OAuthOptions` its callers pass
alongside it. The signature base string and the authorization header are encoded separately, so two
different encoders produce a signature the server cannot verify. Signers deriving from
`RequestSignerBase` are checked at signing time and throw `InvalidOperationException` on a mismatch;
signers implementing the interface directly cannot be inspected and are trusted to honour it.

```csharp
services.AddSingleton<IRequestSigner>(resolver =>
    new HmacSha1RequestSigner(resolver.GetRequiredService<IOptions<AuthorizerOptions>>().Value));
```
