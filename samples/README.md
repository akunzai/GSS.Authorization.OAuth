# Samples

Runnable console applications, one per package. Each reads its settings from `appsettings.json`
next to the executable, and by default talks to the OAuth servers in
[`compose.yml`](../compose.yml).

| Sample | Shows |
| --- | --- |
| [OAuthHttpClientSample](./OAuthHttpClientSample/) | An OAuth 1.0 typed `HttpClient` signing requests to a protected resource |
| [OAuth2HttpClientSample](./OAuth2HttpClientSample/) | An OAuth 2.0 typed `HttpClient` obtaining and attaching an access token |
| [OAuthInteractiveConsoleAuthorizer](./OAuthInteractiveConsoleAuthorizer/) | The OAuth 1.0 three-step grant, with the resource owner authorizing in a browser |

## Running

Start the servers, then run a sample **from its own directory** — the configuration is loaded
relative to the working directory, so `dotnet run --project samples/...` from the repository root
finds no `appsettings.json`:

```shell
docker compose up -d
cd samples/OAuth2HttpClientSample && dotnet run
```

The dev container in [`.devcontainer/`](../.devcontainer/) starts those servers for you and reaches
them by service name, which is what the committed `appsettings.json` files use. From the host
instead, override the addresses — the OAuth 1.0 server is published on 5001, because 5000 is taken
by AirPlay Receiver on macOS:

```shell
cd samples/OAuth2HttpClientSample
OAuth2__AccessTokenEndpoint=http://localhost:8080/default/token \
OAuth2__ResourceEndpoint=http://localhost:8080/default/userinfo \
dotnet run
```

## OAuth 1.0 token credentials

`OAuthHttpClientSample` signs with token credentials that a resource owner has already granted, so
something has to grant them first. `scripts/oauth1-token.sh` runs the three-step flow and writes the
result into `appsettings.Development.json`, which is gitignored:

```shell
scripts/oauth1-token.sh          # walk through it, approving in a browser
scripts/oauth1-token.sh --ci     # approve over HTTP, no human, no browser
```

`--ci` (or `CI=true`) is there so an agent can exercise the sample unattended. Both modes drive
`OAuthInteractiveConsoleAuthorizer` for the signed steps, so what they verify is the real client.

## Publishing as a single executable

Each sample sets `PublishSingleFile`, so publishing produces one executable with no loose
assemblies beside it:

```shell
dotnet publish samples/OAuthHttpClientSample -c Release -o out
```

`appsettings.json` stays outside the bundle so it can be edited after publishing. The build is
framework-dependent (`SelfContained=false`), so the target machine needs a matching .NET runtime;
add `--self-contained` if it should not.
