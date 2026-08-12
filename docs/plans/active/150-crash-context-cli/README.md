# Crash context CLI parsing

Issue: [#150](https://github.com/ishtms/cachelane/issues/150)

## Outcome

`cachelane crash parse <path>` reads one local `CrashContext.runtime-xml` file and prints the existing versioned deterministic normalized JSON representation.

This is one bounded stage toward the M0 command-line prototype. Issue #150 remains open for real Windows report bundles, exact PDB and PE matching, and readable stacks.

## Acceptance criteria

- Valid crash-context XML up to 4 MiB and 100,000 XML nodes prints normalized JSON followed by one newline.
- The output uses the existing parser version, preserves ordered and unknown fields, and excludes command-line data.
- Missing files, oversized input, invalid UTF-8, malformed XML, DTD declarations, and wrong roots return a non-zero exit code with a small error that does not echo input content.
- Repeating the command with the same input produces byte-identical stdout.
- Synthetic CLI behavior tests cover success and each important failure boundary.
- Existing `--help` and `--version` behavior remains available.

## Risk and blast radius

Risk is R2 because the CLI gains a dependency on the Unreal parsing capability and exposes its serialized record contract through an application boundary.

The change is additive and local. It adds no third-party dependency, public HTTP API, stored data, migration, tenant boundary, credential, network call, service, deployment, or external resource. It does not parse minidumps, PDB files, PE files, or report archives, so the R3 artifact-processing gates for the remaining issue do not apply to this stage.

## Current behavior and evidence

- `apps/cli` currently supports only `--help` and `--version` and prints a readiness message when invoked.
- `crates/unreal` already rejects DTD declarations, enforces a caller-supplied node limit, returns small typed errors, extracts normalized crash-context data, excludes command lines by default, and serializes deterministic JSON.
- The completed parser-version plan records the stable parser version and serialization contract used by this stage.
- The M0 exit criterion requires a command-line prototype that emits deterministic normalized JSON. The full criterion also requires real Windows artifacts and readable stacks, which remain blocked by their R3 gates and fixture environment.

The existing parser and serializer are sufficient. The CLI only needs to compose them with bounded file reading and process-level error handling.

## Implementation sequence

1. Add existing workspace dependencies from `apps/cli` to `cachelane-unreal` and `serde_json`.
2. Add the nested `crash parse` command and keep the existing top-level help and version behavior.
3. Read at most 4 MiB plus one byte, reject oversized or invalid UTF-8 input, parse with a 100,000-node limit, and extract with default options.
4. Write deterministic JSON to stdout and report safe failures on stderr with a non-zero exit code.
5. Add a synthetic success fixture and application-boundary tests for stable output and failures.

## Verification

- `cargo test -p cachelane-cli`
- `./scripts/check-fast`
- `./scripts/check`
- `cargo run -q -p cachelane-cli -- crash parse apps/cli/tests/fixtures/crash-context.xml`
- Run the proof command twice and compare stdout byte for byte.

`./scripts/smoke` is not required for the PR stage because it checks the server and web roles, which do not change. The CLI proof exercises the changed runtime boundary directly.

## Data, security, operations, and compatibility

The XML file is sensitive untrusted local input. The command reads it through an enforced byte ceiling and passes it to the existing DTD-free, node-bounded parser. Errors do not include XML values. Command-line extraction stays disabled. Normalized comments, paths, and game data are intentionally written to local stdout and are never logged, persisted, or sent over the network by this command.

The subcommand is additive. Existing CLI help and version flags remain compatible. There is no production configuration, runtime service, database, object storage, or operational rollout.

## Rollout and rollback

Roll out through the normal reviewed CLI build. Move this plan to completed in the same pull request once verification is recorded.

Roll back by reverting the CLI dependency edges, command implementation, tests, fixture, and plan. No data migration, cleanup, credential rotation, or external action is required.

## Out of scope

- Reading compressed or archived Unreal report bundles
- Logs, minidumps, PDB files, PE files, symbol matching, stack walking, and reprocessing
- Command-line inclusion or redaction policy changes
- Persistence, HTTP ingestion, uploads, tenant data, and deployment
- Closing issue #150 or marking the M0 roadmap item complete

## Unresolved decisions

None. Later real Windows fixture evidence may justify a compatible limit change in its own reviewed stage.
