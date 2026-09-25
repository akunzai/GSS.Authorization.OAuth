# Dependency & Package-Version Compatibility Policy

This is a published-library repo, so the version chosen in `Directory.Packages.props` becomes a floor forced on every downstream consumer — treat it very differently from an app's dependency choices.

## Guidelines

- **Central Package Management**: all versions live in `Directory.Packages.props` (`ManagePackageVersionsCentrally=true`); never inline a `Version` in a `.csproj`.
- **Plain version numbers are intentional** (e.g. `Version="8.0.2"`, no `[8.0.2]` brackets). NuGet packs this as a *minimum* dependency, not an exact pin — consumers can still resolve to a newer compatible version. Don't add exact-version brackets.
- The `netstandard2.0`-conditioned `PackageVersion` group (`Microsoft.AspNetCore.WebUtilities`, `Microsoft.Extensions.*`, `System.ComponentModel.Annotations`, `System.Text.Encodings.Web`, `System.Text.Json`, `System.Threading.Tasks.Extensions`) is the production compatibility floor. Only raise one of these when actually required — a security advisory, an out-of-support runtime (e.g. a [dotnet/announcements](https://github.com/dotnet/announcements) EOL notice), or a new API the code needs. Do not bump it just because a newer version is available.
- `Directory.Build.props` sets `NuGetAuditMode=all` / `NuGetAuditLevel=moderate`, which surfaces known vulnerabilities at restore time — that's the real trigger for a floor bump, not Dependabot's weekly cadence.
- `.github/dependabot.yml` encodes this split: the production-floor packages above are grouped separately and major/minor version updates are `ignore`d (patch and GitHub security-advisory updates still flow through); test/build-only tooling (`xunit.*`, `Microsoft.Testing.Extensions.CodeCoverage`, `Microsoft.NET.Test.Sdk`, `Microsoft.SourceLink.GitHub`) has no restriction and auto-tracks latest since it never reaches consumers.
- For the `netcoreapp3.1` TFM, prefer `<FrameworkReference Include="Microsoft.AspNetCore.App" />` over an explicit `PackageReference` when the API already ships in the ASP.NET Core shared framework (see `src/GSS.Authorization.OAuth/GSS.Authorization.OAuth.csproj` / `src/GSS.Authorization.OAuth2/GSS.Authorization.OAuth2.csproj`) — this avoids adding an extra floor package for that TFM.

## Related Pointers

- Central package management: `Directory.Packages.props`
- Global build and audit configuration: `Directory.Build.props`
- Dependabot configuration: `.github/dependabot.yml`
