# Packaged UE 5.8 crash processing

Issue: [#294](https://github.com/ishtms/cachelane/issues/294)

## Outcome

Extend `cachelane crash process` so a developer can pass one complete UE 5.8.1 Crash Report Client request plus a local artifact tree and receive deterministic normalized JSON containing request metadata, crash context, classification evidence, a bounded log tail, module identities, and readable faulting-thread frames.

## Context

The Unreal request decoder validates and streams the installed UE 5.8.1 `CR1` envelope but currently discards file contents after inspection. The crash-context parser, log-tail extractor, artifact scanner, and Windows minidump symbolicator already provide the required bounded capabilities separately. Issue #293 adds the versioned processing result and history contract for extracted XML and minidump inputs. This issue composes those capabilities for the real request entrypoint without changing the attempt-history shape.

The private proof is available in a dedicated directory outside Git. It contains a 134,839-byte request captured from installed UE 5.8.1 changelist 56057345, a 618,748-byte minidump, a 25,254-byte crash context, a 62,907-byte log, and matching `UnrealGame.exe` and `UnrealGame.pdb` artifacts. No private fixture content or path enters product output, tests, commits, or GitHub.

## Acceptance criteria

- `cachelane crash process <request> --symbols <path> [--previous <result>]` processes the bounded `CR1` request through the real CLI entrypoint.
- Output includes the versioned request manifest, normalized crash metadata and unknown safe fields, crash classification with fixed evidence codes and confidence, a bounded log tail, module diagnostics, all available threads, readable frames, trust, inline frames, and parser, processing, symbolicator, and minidump processor versions.
- Structured `Crash`, `Assert`, and `Ensure` values retain high-confidence classification. Structured OOM fields, structured GPU crash values, and normalized error patterns produce separate likely OOM or GPU signals with explicit confidence and evidence codes.
- Request decoding retains only one bounded crash context, one bounded minidump, and one bounded log suffix while consuming the complete compressed stream. Unknown files are never retained.
- Missing crash context or minidump, malformed request, unsafe XML, invalid minidump, invalid debug artifacts, and incompatible previous results fail with fixed safe errors and no stdout.
- Identical request, artifacts, and prior result produce byte-for-byte identical JSON. Reprocessing keeps the flat ordered history contract from #293.
- Synthetic behavior tests exercise the complete request entrypoint. The private UE 5.8.1 request resolves readable frames with the matching private PE and PDB through the same command.

## Risk and blast radius

Risk: R2.

This composes decompression, XML, log, minidump, PE, and PDB handling across the Unreal, symbols, and CLI boundaries. The change adds no dependency, database, migration, network access, service, tenant boundary, credential, deployment, or production action.

The main risks are retaining too much attacker-controlled data, changing existing extracted-file processing behavior, unsafe error output, ambiguous classification, and platform-specific symbolication regressions. Existing limits, safe errors, deterministic ordering, and Windows CI remain mandatory.

## Current behavior and evidence

- `cachelane crash unpack <request>` validates the real UE 5.8.1 zlib `CR1` envelope and emits a stable manifest without file contents.
- `CrashContextParser` emits parser-versioned normalized data, preserves unknown fields, and excludes the command line by default.
- `ProjectLogTail` produces bounded source-order text with truncation and invalid UTF-8 state.
- `cachelane crash symbolicate` matches PE and PDB files by embedded identities and emits raw plus resolved frames with trust and processor versions.
- PR #340 locally passes `scripts/check` for extracted-file processing, bounded prior attempts, and partial-to-readable reprocessing. It is the only direct dependency.
- The private request and matching artifacts exist locally and previously passed the unpack and standalone symbolication stages.

## Implementation sequence

1. Add a decoded-request result in the Unreal crate that reuses the existing streaming decoder, retains only bounded critical contents, and produces a bounded first-log tail.
2. Add deterministic crash classification derived from the structured crash type, structured OOM fields, recognized GPU or OOM crash-type values, and fixed normalized error patterns. Evidence contains codes, never source payloads.
3. Add a symbolicator byte-input entrypoint that preserves the same minidump limits, worker timeout, artifact selection, output schema, and path safety as the file entrypoint.
4. After #293 merges, update this branch from current `origin/main` and extend its `crash process` command. Keep `--crash-context` as the extracted-file compatibility path and use the request path when that option is absent.
5. Add request metadata, classification, and log fields only for request processing. Keep the processing attempt and history representation compatible with #293.
6. Add capability tests for bounded content retention and classification, plus real-executable tests for readable, deterministic, malformed, missing, partial, and reprocessed request behavior.
7. Run the synthetic CLI proof, the private UE 5.8.1 proof, focused checks, `scripts/check-fast`, and one `scripts/check` for the final pull request head.

## Verification

- `cargo test -p cachelane-unreal`
- `cargo test -p cachelane-symbols`
- `cargo test -p cachelane-cli --test entrypoint`
- `cargo check --manifest-path fuzz/Cargo.toml --bins`
- Synthetic request processing twice with byte-for-byte comparison
- Synthetic missing-symbol processing followed by exact-symbol reprocessing with prior history
- Private `cachelane crash process <ue58-request> --symbols <private-artifacts>` proof with readable frames
- `bash scripts/check-fast`
- `bash scripts/check`

No service smoke test is required because this remains a local CLI feature.

## Data, security, and compatibility

The request, XML, log, minidump, PE, PDB, and previous result are sensitive untrusted local inputs. The existing 64 MiB compressed, 256 MiB expanded, 200:1 expansion, 128-file, 128 MiB per-file, 4 MiB XML, 100,000-node, artifact-tree, thread, module, frame, and 120-second symbolication limits remain in force. Retained minidumps are capped at the symbolicator's 64 MiB limit. Log output is capped at 64 KiB and 200 lines while the decoder consumes the complete log record.

Only fixed classification evidence codes are emitted. Error messages do not contain input paths, filenames, XML values, log content, dump content, symbol paths, or prior-result payloads. The private request and artifacts remain outside every worktree and are never staged.

The command targets Windows x64 reports from installed UE 5.8.1. Existing `crash parse`, `crash unpack`, `crash symbolicate`, `symbols scan`, and extracted-file `crash process` behavior remains available. Other Unreal versions and platforms remain deferred to their roadmap milestones.

## Rollout and rollback

Ship the request mode as an additive local CLI path after #293. Roll back by reverting the pull request. No state, migration, external resource, data cleanup, or production action is involved.

## Out of scope

- HTTP ingestion, request query parameters, persistence, jobs, uploads, grouping, or UI
- Hosted automatic reprocessing after artifact upload
- Log storage, download, search, or redaction configuration
- Linux, macOS, mobile, or non-x64 Windows processing
- Committing the real UE request, packaged build, minidump, PE, PDB, or raw output
- Compatibility claims outside installed UE 5.8.1

## Result

- `cachelane crash process <request> --symbols <path> [--previous <result>]` composes request decoding, normalized crash context, bounded log output, classification, and Windows symbolication through one command.
- Synthetic request tests prove exact module, function, source file, source line, inline frame, trust, processor versions, missing-symbol output, prior history, deterministic output, and fixed safe failures.
- Classification tests cover structured Crash, Assert, Ensure, OOM, and GPU evidence plus medium-confidence normalized error patterns without copying source payloads into evidence.
- The private UE 5.8.1 request produced four request records, a bounded log tail, six faulting frames, four readable frames, one matched module, and byte-identical output across repeated runs. The private files and output remained outside Git.
- The Unreal, request, symbols, CLI, and fuzz boundaries pass their focused tests and strict Clippy checks.

## Unresolved decisions

None. Request processing remains an additive mode on the result and history contract from #293.
