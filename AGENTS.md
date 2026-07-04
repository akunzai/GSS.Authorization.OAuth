# GSS.Authorization.OAuth — Agent Guidelines

OAuth 1.0 / OAuth 2.0 authorized `HttpClient`, friendly with `HttpClientFactory`. Published as 4 NuGet packages:
`GSS.Authorization.OAuth`, `GSS.Authorization.OAuth.HttpClient`, `GSS.Authorization.OAuth2`, `GSS.Authorization.OAuth2.HttpClient`.

See [README.md](README.md) for usage/samples and [CONTRIBUTING.md](CONTRIBUTING.md) for the PR workflow.

## Commands

- Build: `dotnet build -c Release`
- Test (all): `dotnet test`
- Test (single): `dotnet test --filter "FullyQualifiedName~ClassName.MethodName"`
- Coverage (as run in CI): `dotnet test --collect:"XPlat Code Coverage" && dotnet tool restore && dotnet tool run reportgenerator`

## Architecture

- `OAuth.slnx` — solution file (slnx format, not `.sln`).
- `src/GSS.Authorization.OAuth{,2}` — core signer/authorizer (`netstandard2.0;netcoreapp3.1`).
- `src/GSS.Authorization.OAuth{,2}.HttpClient` — `DelegatingHandler` + `HttpClientFactory` integration; `ProjectReference`s the matching core lib above.
- `test/*.Tests` mirrors each `src` project 1:1, targets `net8.0;net10.0`, uses xunit v3.
- `samples/` — runnable console samples, one per package.

## Code Style

Conventions are enforced via `.editorconfig` and analyzers (`Nullable` enabled, file-scoped namespaces, `var` preferred) — follow it rather than restating rules here.

## Dependency & Package-Version Compatibility Policy

This is a published-library repo, so the version chosen in `Directory.Packages.props` becomes a floor forced on every downstream consumer — treat it very differently from an app's dependency choices.

- **Central Package Management**: all versions live in `Directory.Packages.props` (`ManagePackageVersionsCentrally=true`); never inline a `Version` in a `.csproj`.
- **Plain version numbers are intentional** (e.g. `Version="8.0.2"`, no `[8.0.2]` brackets). NuGet packs this as a *minimum* dependency, not an exact pin — consumers can still resolve to a newer compatible version. Don't add exact-version brackets.
- The `netstandard2.0`-conditioned `PackageVersion` group (`Microsoft.AspNetCore.WebUtilities`, `Microsoft.Extensions.*`, `System.ComponentModel.Annotations`, `System.Text.Encodings.Web`, `System.Text.Json`, `System.Threading.Tasks.Extensions`) is the production compatibility floor. Only raise one of these when actually required — a security advisory, an out-of-support runtime (e.g. a [dotnet/announcements](https://github.com/dotnet/announcements) EOL notice), or a new API the code needs. Do not bump it just because a newer version is available.
- `Directory.Build.props` sets `NuGetAuditMode=all` / `NuGetAuditLevel=moderate`, which surfaces known vulnerabilities at restore time — that's the real trigger for a floor bump, not Dependabot's weekly cadence.
- `.github/dependabot.yml` encodes this split: the production-floor packages above are grouped separately and major/minor version updates are `ignore`d (patch and GitHub security-advisory updates still flow through); test/build-only tooling (`xunit.*`, `coverlet.collector`, `Microsoft.NET.Test.Sdk`, `Microsoft.SourceLink.GitHub`) has no restriction and auto-tracks latest since it never reaches consumers.
- For the `netcoreapp3.1` TFM, prefer `<FrameworkReference Include="Microsoft.AspNetCore.App" />` over an explicit `PackageReference` when the API already ships in the ASP.NET Core shared framework (see `GSS.Authorization.OAuth.csproj` / `GSS.Authorization.OAuth2.csproj`) — this avoids adding an extra floor package for that TFM.

## Claude Code Compatibility

> [!NOTE]
> This repository maintains compatibility with Claude Code. The file `CLAUDE.md` is a symbolic link pointing to `AGENTS.md`.
> All commands, style guides, and workflows defined in `AGENTS.md` apply to both other agentic assistants and Claude Code.
> **DO NOT** delete the `CLAUDE.md` symbolic link or edit it independently; all guidelines must be updated directly in `AGENTS.md`.
