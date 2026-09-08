# GSS.Authorization.OAuth — Agent Guidelines

OAuth 1.0 / OAuth 2.0 authorized `HttpClient`, friendly with `HttpClientFactory`. Published as 4 NuGet packages:
`GSS.Authorization.OAuth`, `GSS.Authorization.OAuth.HttpClient`, `GSS.Authorization.OAuth2`, `GSS.Authorization.OAuth2.HttpClient`.

## Commands

- Build: `dotnet build -c Release`
- Test (all): `dotnet test`
- Test (single): `dotnet test --filter "FullyQualifiedName~ClassName.MethodName" --ignore-exit-code 8`
- Coverage (CI): `dotnet test --coverage --coverage-output-format cobertura && dotnet tool restore && dotnet tool run reportgenerator`

## Pointers

- Domain glossary: @CONTEXT.md
- Domain docs consumer rules: @docs/agents/domain.md
- Dependency policy: @docs/agents/dependencies.md
- Issue tracker (GitHub): @docs/agents/issue-tracker.md
- Triage labels: @docs/agents/triage-labels.md
- Usage guide: @docs/usage.md
- PR workflow and guidelines: @CONTRIBUTING.md
- Release label validation: @.github/workflows/release-label.yml
- Code style and analyzer rules: @.editorconfig

## Architecture

- `OAuth.slnx` — solution file (slnx format, not `.sln`).
- `src/GSS.Authorization.OAuth{,2}` — core signer/authorizer (`netstandard2.0;netcoreapp3.1`).
- `src/GSS.Authorization.OAuth{,2}.HttpClient` — `DelegatingHandler` + `HttpClientFactory` integration; `ProjectReference`s the matching core lib above.
- `test/*.Tests` mirrors each `src` project 1:1, targets `net8.0;net10.0`, uses xunit v3.
- `samples/` — runnable console samples, one per package.

## Prevent Recurrence

- **Candidate**: Name who hits this again, in which file, on what change. No such scenario, nothing to propose.
- **Promote**: Offer the first tier that reaches them and only that one, pending confirmation — enforce it (assert/type/test) with its size quoted, else a comment at that site, else an agent-facing doc (`docs/agents/<topic>.md`, else `docs/agents/lessons-learned.md`) with one `@path` line under Pointers and one sentence on why the tiers above cannot hold it. Never two places at once.
- **Prune**: When adding to a file, audit the rest of it in the same pass. Drop entries once stale (obsolete version, now enforced, duplicated, or a transcript) — not by a fixed count.

## Claude Code Compatibility

`CLAUDE.md` is a symbolic link pointing to `AGENTS.md`. Edit `AGENTS.md` directly.
