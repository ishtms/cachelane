# Local crash reprocessing

Issue: [#293](https://github.com/ishtms/cachelane/issues/293)

## Outcome

Add `cachelane crash process <dump> --crash-context <xml> --symbols <path> [--previous <result>]` so a developer can retain a useful partial result, add exact matching symbols, and produce a readable result for the same crash identity with the prior processing attempt preserved.

## Context

The crash-context parser already emits deterministic normalized data with parser version `1`. The Windows symbolicator already emits deterministic raw and resolved frames, artifact diagnostics, trust, inline frames, and processor versions. The CLI exposes those capabilities separately, but there is no versioned result that connects one crash identity to repeated processing attempts.

Issue #294 owns decoding and composing a complete UE 5.8 crash request, including the bounded log tail and classification evidence. This issue provides the smaller reprocessing contract that #294 can call after request extraction.

## Acceptance criteria

- The command accepts one bounded Windows x64 minidump, one bounded crash-context XML file with a crash GUID, and one bounded local artifact tree.
- A first run without matching artifacts returns partial raw frames and exact expected artifact identities.
- A second run with matching artifacts and `--previous <first-result>` returns readable frames for the same crash identity.
- The second result preserves the prior attempt, including its processing, parser, symbolicator, and minidump processor versions.
- Processing history is flat, ordered, bounded to 16 prior attempts, and does not add a duplicate when the previous current attempt equals the new current attempt.
- Identical inputs and prior result produce byte-for-byte identical JSON.
- Missing crash identity, malformed or oversized prior JSON, unsupported schema or processing versions, mismatched crash identity, excessive history, and existing parser or symbolicator failures return fixed safe errors without echoing private paths or payloads.
- A CLI behavior test exercises the real executable twice, first without symbols and then with matching symbols.

## Risk and blast radius

Risk: R2.

This composes two existing untrusted-input capabilities and adds a versioned local serialization contract. The change is limited to the CLI and its behavior tests. It adds no dependency, database, migration, network access, persistence, tenant boundary, service, credential, deployment, or production action.

## Current behavior and evidence

- `cachelane crash parse <xml>` emits stable normalized JSON with `parser_version`.
- `cachelane crash symbolicate <dump> --symbols <path>` emits stable raw and resolved stack JSON with exact artifact identities and processor versions.
- Missing or mismatched symbols already produce successful partial results rather than hiding the crash.
- The synthetic Windows fixture resolves `CrashFixture()` and its inline frame when the exact PE and PDB are available.
- The existing CLI has no local processing result, prior-result input, or history validation.
- PR #339 passed Linux, Windows, dependency review, and dependency audit checks for the symbolication base commit.

## Implementation sequence

1. Add the `crash process` CLI arguments without changing the existing parse, unpack, symbolicate, or scan commands.
2. Define version `1` local processing result and attempt records in the CLI. Each attempt stores the processing version, parser version, and complete symbolication result.
3. Reuse the existing bounded crash-context reader, parser, and Windows symbolicator to build the current result.
4. Read an optional prior result through a 64 MiB cap, validate its schema, processing version, crash identity, flat history shape, and 16-attempt limit, then carry its history and current attempt forward.
5. Avoid adding the previous current attempt to history when it equals the new attempt so unchanged reprocessing is idempotent.
6. Add real-entrypoint tests for partial-to-readable reprocessing, repeated deterministic output, unchanged-input idempotency, malformed prior results, identity mismatch, history limits, and safe errors.
7. Run focused tests, `./scripts/check-fast`, and one `./scripts/check` for the final pull request head.

## Verification

- `cargo test -p cachelane-cli --test entrypoint`
- First fixture run against an empty symbol directory returns raw frames and `missing_pe` for the fixture module.
- Second fixture run against the checked-in exact PE and PDB, using the first output as `--previous`, resolves `CrashFixture()` while retaining the partial attempt.
- Repeating the second run with unchanged inputs produces byte-for-byte identical output and does not grow history.
- Invalid prior-result cases produce nonzero exit status, no stdout, fixed error text, and no private input text.
- `./scripts/check-fast`
- `./scripts/check`

No service smoke test is required because this is a local CLI feature.

## Data, security, and compatibility

The minidump, crash context, artifact tree, and previous result remain sensitive untrusted local inputs. Existing dump, XML, artifact, thread, module, frame, filesystem, and wall-time limits remain in force. The prior-result input is capped at 64 MiB and 16 prior attempts. Errors expose only fixed categories.

The command accepts Windows x64 minidumps and result schema version `1`. It fails closed for unsupported result versions and cross-crash history. No timestamps or environment-dependent identifiers are added, preserving deterministic output.

## Rollout and rollback

Ship the command as an additive local feature. Roll back by reverting the pull request. No state, migration, external resource, or cleanup is involved.

## Out of scope

- Decoding a complete UE crash request inside `crash process`
- Extracting or emitting the project log tail
- GPU crash or OOM classification
- Automatic artifact-arrival triggers, jobs, persistence, APIs, or hosted reprocessing
- Fingerprinting, grouping, issue history, or database event identity
- Committing private Unreal reports or build artifacts

## Result

- `cachelane crash process` emits a versioned result with normalized crash context, the current symbolication attempt, and bounded prior attempts.
- Reprocessing the synthetic crash after exact PE and PDB artifacts arrive resolves `CrashFixture()` and retains the earlier missing-symbol frames and processor versions.
- Unchanged reprocessing is byte-stable and does not grow history.
- Prior results are capped at 64 MiB and 16 attempts. Malformed, nested, incompatible, excessive, and cross-crash input fails with fixed safe errors.
- The 19 CLI entrypoint tests and `scripts/check-fast` pass locally.

## Unresolved decisions

None. Issue #294 will extend the processing entrypoint from extracted files to the complete UE 5.8 request without changing this result-history contract.
