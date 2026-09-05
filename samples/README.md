# Samples

Runnable console applications, one per package. Each reads its settings from `appsettings.json`
next to the executable.

| Sample | Shows |
| --- | --- |
| [OAuthHttpClientSample](./OAuthHttpClientSample/) | An OAuth 1.0 typed `HttpClient` signing requests to a protected resource |
| [OAuth2HttpClientSample](./OAuth2HttpClientSample/) | An OAuth 2.0 typed `HttpClient` obtaining and attaching an access token |
| [OAuthInteractiveConsoleAuthorizer](./OAuthInteractiveConsoleAuthorizer/) | The OAuth 1.0 three-step grant, with the resource owner authorizing in a browser |

## Running

```shell
dotnet run --project samples/OAuthHttpClientSample
```

## Publishing as a single executable

Each sample sets `PublishSingleFile`, so publishing produces one executable with no loose
assemblies beside it:

```shell
dotnet publish samples/OAuthHttpClientSample -c Release -o out
```

`appsettings.json` stays outside the bundle so it can be edited after publishing. The build is
framework-dependent (`SelfContained=false`), so the target machine needs a matching .NET runtime;
add `--self-contained` if it should not.
