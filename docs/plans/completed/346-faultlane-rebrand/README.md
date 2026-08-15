# FaultLane rebrand

Issue: [#346](https://github.com/ishtms/faultlane/issues/346)

Status: Completed through PR #347 on August 14, 2026. No production deployment was performed.

## Context

The GitHub repository has already been renamed to `ishtms/faultlane`, but the checked-in product, packages, binaries, configuration, fixtures, documentation, and current planning metadata still use the former identity. The local `origin` now points at the renamed repository.

The current tracked tree contains 361 case-insensitive text matches across 65 files. Three checked-in Windows fixture binaries also contain the former product token. Renaming text files alone would leave stale package contracts, executable names, fixture metadata, and operational defaults.

## Acceptance criteria

- Display copy uses `FaultLane`; machine-readable names use `faultlane` with the separator required by each ecosystem.
- Rust packages, crate imports, CLI and server binaries, npm packages, environment variables, Compose defaults, database and bucket defaults, service identifiers, temporary paths, repository URLs, OpenAPI paths, and web module paths are renamed together.
- The CLI executable is `faultlane`, the server package and executable are `faultlane-server`, and the web package is `@faultlane/web`.
- Configuration accepts only the new `FAULTLANE_*` names. Compatibility aliases are not retained because the requested outcome is a clean pre-release rename.
- The synthetic Windows PE, PDB, and minidump fixture is rebuilt under the new identity. Exact identity matching, readable frames, source paths, upload coverage, and reprocessing tests continue to pass.
- Product, architecture, security, operations, decision, completed-plan, README, issue-template, workflow, and API text in the tracked tree uses the new name and repository URL.
- Current open issue bodies, relevant label descriptions, milestone descriptions, and the shipping project use the new name.
- Existing local databases, buckets, Compose volumes, ignored environment files, and worktrees are not deleted or rewritten.
- A case-insensitive text, path, and binary scan over every tracked file finds no former product token.
- Focused package, CLI, web, fixture, Compose, API, smoke, and complete repository checks pass.

## Risk and blast radius

Risk: R3.

This is a repository-wide, breaking configuration and local/self-hosted infrastructure rename. It changes executable names, Cargo and npm package identities, environment variables, Compose project defaults, database and object-store defaults, API document paths, test fixtures, and current GitHub planning metadata. Existing callers using the former CLI or environment contract will fail until updated.

No hosted environment, GitHub environment, release, repository variable, repository secret, or production deployment exists. There is no production data migration. The blast radius is therefore source compatibility, build tooling, local development, self-hosted setup, public documentation, and current project planning surfaces.

## Current behavior and evidence

- `origin/main` and the renamed repository both resolve to commit `c18877bafec97f81ca49917b01722fad6e725766` at planning time.
- The root worktree has one existing user change in `apps/web/next-env.d.ts`; it remains untouched in an isolated rebrand worktree.
- The tracked inventory contains 361 text matches in 65 files, including Rust package names and imports, CLI output, npm scope, scripts, environment variables, Compose defaults, service names, OpenAPI content, product documents, and repository links.
- Tracked paths include the former token in the OpenAPI filename, web API module, and three Windows fixture filenames.
- The PE and minidump each contain one embedded match. The PDB contains fourteen, including the compiled source and image identity.
- Fifty-three current issue records, fifteen pull request records, three comments, one label description, one milestone description, and the shipping project contain the former name. Historical records are excluded from mutation below.
- Cloudflare R2 is already the accepted hosted object store. The rebrand changes only names and examples, not the R2 or MinIO storage design.

## Implementation sequence

1. Fetch the renamed repository, confirm `main` is current, and create an isolated `feature/faultlane-rebrand` worktree without touching the user's root worktree change.
2. Rename the Rust packages, binary targets, imports, command metadata, service identity, temporary names, fixture references, and both Cargo lockfiles. Regenerate metadata through Cargo rather than hand-editing derived dependency edges where practical.
3. Rename the root and web npm packages, filters, TypeScript module path, browser metadata, product copy, and pnpm lock data.
4. Rename every former prefixed environment contract to `FAULTLANE_*`, plus Compose project, database, user, password example, MinIO user and password example, bucket, test database, scripts, CI, smoke, and proof wiring. Do not retain hidden aliases.
5. Rename the OpenAPI file and update repository checks, API titles, bearer descriptions, service constants, and all repository URLs.
6. Update authoritative product and architecture documents, decision records, completed plans, README, workflow text, and issue templates. Preserve factual history while using the current product and repository names.
7. Rebuild the synthetic x64 Windows fixture from its checked-in source with the installed Visual Studio Build Tools. Generate a fresh PE, PDB, and minidump whose filenames, module metadata, PDB records, and source path contain only the new identity. Update exact symbolication and upload expectations.
8. Add a repository check that scans tracked text, paths, and binary bytes case-insensitively for the former token so the name cannot return accidentally.
9. Run focused Rust, CLI, web, API, fixture, Compose, smoke, and complete checks in an isolated local environment.
10. Review the exact diff and binary changes, verify author identity, commit on the feature branch, push it, and open a draft pull request with verification and rollback evidence.
11. After the code head is verified, update current open issue bodies, the CLI label description, the relevant milestone description, and the shipping project title and README. Record the prior values so those reversible metadata edits can be restored if needed.

## Tests and operational verification

- Confirm `cargo metadata --no-deps`, workspace compilation, unit tests, CLI entrypoint tests, and both lockfiles resolve only `faultlane-*` packages.
- Run the CLI help, version, parse, symbolication, reprocessing, scan, and upload behavior tests using the renamed executable.
- Run byte-stability and exact identity tests against the rebuilt fixture.
- Parse the renamed OpenAPI document and Compose configuration through existing repository checks.
- Start a new isolated Compose project with new environment names and unused ports. Run database migration, health checks, durable ingest proof, symbol upload proof, smoke, and shutdown without deleting any older volumes.
- Run `./scripts/check-fast`, `./scripts/check`, and the relevant `./scripts/smoke` modes.
- Scan `git ls-files` for old path names, scan tracked text case-insensitively, and scan every tracked file as bytes. All three scans must return zero matches.
- Inspect logs and command output for stale branding and confirm no credentials or private fixture content entered the diff.

## Data, security, and compatibility

There is no schema or stored-row change. Organization, project, crash, symbol, and token semantics remain unchanged. Tenant scoping, object keys, private bucket behavior, upload authorization, parser limits, and untrusted-input handling are not modified.

The environment-variable and executable changes are intentionally breaking. Existing ignored `.env` files must be updated manually. A new Compose project name creates new named volumes by default; older volumes remain recoverable and are not removed. Existing databases or buckets are not automatically copied, renamed, or deleted.

Example local passwords and rate-limit or bootstrap secrets receive the new prefix, but no real credentials are accessed or rotated. The fixture rebuild uses synthetic public source only. Binary review verifies that no private path or former product token is embedded.

GitHub mutations use the repository owner's existing identity through `gh`. No browser, deployment credential, hosted data, or production action is involved.

## Staging and rollout

All runtime evidence uses an isolated worktree, fresh local Compose project, unused ports, PostgreSQL, and MinIO. No hosted or production deployment is configured or attempted.

The pull request is the rollout unit. The rename must land atomically so package names, imports, scripts, environment contracts, fixtures, and documentation cannot drift across revisions. Consumers update command names and environment files when adopting that revision.

## Rollback

Before merge, close the pull request and restore the saved GitHub metadata values. After merge, revert the rebrand commit and use the former command and environment contract. Existing older Compose volumes remain available because the staging proof never deletes them. The fresh renamed local volumes can remain unused or be removed later through a separately confirmed cleanup.

No reverse schema migration, object rewrite, credential recovery, or production rollback is required.

## Out of scope

- Rewriting Git commits, tags, or reflogs
- Editing closed issues, closed pull requests, old comments, or GitHub audit and rename events
- Removing GitHub's automatic redirect from the former repository URL
- Renaming the current workspace directory, ignored local setup bundles, ignored agent files, or other user-owned paths outside the tracked tree
- Renaming third-party products or generic cache concepts that happen to contain similar words
- Deploying a hosted environment or renaming external Cloudflare resources that do not exist

These historical and local artifacts cannot be removed by an ordinary repository rebrand without destructive history rewriting or changing user-owned state. The zero-match gate applies to the current tracked tree and the explicitly listed current GitHub planning surfaces.

## Approval

Approved by Ishtmeet Singh in the task conversation on August 14, 2026. The approval is recorded on issue #346.

## Implementation evidence

- The tracked text, path, ASCII byte, UTF-16LE byte, and UTF-16BE byte scan passes with zero former-name matches. A temporary tracked regression proved the gate fails when the former token is present.
- The synthetic Windows fixture was rebuilt through the installed Visual Studio Build Tools. The CLI resolves `CrashFixture()` and its inline frame from `Z:\source.cpp`, and all 26 CLI entrypoint tests pass.
- `cargo test --workspace --all-targets`, the fuzz-target compile, web formatting, lint, type checking, and production build pass.
- `./scripts/check-fast` and `./scripts/check` pass.
- Isolated local staging used Compose project `faultlane-rebrand-346`, PostgreSQL on port 15432, MinIO on port 19000, API on port 18080, ingest on port 18081, and web on port 13000.
- Base smoke, durable ingest, duplicate ingest, state read, first symbol upload, and zero-byte second symbol upload passed. Staging stored one organization, one project, one crash event, one job, one release, two debug images, and two artifact objects.
- Runtime logs contained neither the former name nor the local bootstrap secret. Staging containers and its network were removed; the two named data volumes remain recoverable.
