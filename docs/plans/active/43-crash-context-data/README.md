# Crash context data extraction

Issue: [#43](https://github.com/ishtms/cachelane/issues/43)

## Context

M0 requires normalized crash data from supported Unreal Windows reports. The existing Unreal crate safely parses `CrashContext.runtime-xml` and exposes version-tolerant sections and fields. The domain crate already provides crash classification and source-preserving normalization values, but nothing combines those capabilities into extracted crash context data.

This change adds the smallest library boundary needed by later deterministic JSON and parser-version work. It does not connect the parser to an application role or persistence.

## Acceptance criteria

- A parsed crash context produces owned data for crash GUID, crash type, error message, build version, engine version, platform, architecture, build configuration, command line, modules, threads, system metadata, user comment, and `GameData`.
- Crash type uses the existing domain classification, and platform and module values retain their source values alongside normalized values.
- Command-line extraction is disabled by default and requires an explicit caller option.
- Module entries and thread records preserve source order. Thread records expose call stack, crash marker, registers, thread ID, and thread name when present.
- `PlatformProperties` plus `Misc.*` and `MemoryStats.*` runtime fields are retained as system metadata. `GameData` entries retain repeated keys and source order.
- Missing, empty, reordered, and repeated fields do not panic or make the parsed document unusable.
- Synthetic tests cover complete input, missing and repeated data, command-line policy, normalization, modules, threads, system metadata, and `GameData`.
- No HTTP API, stored data, authorization rule, deployment behavior, or user-facing workflow changes.

## Risk and blast radius

Risk is R2 because `crates/unreal` gains a dependency on shared domain values and the change defines an additive extraction contract across two workspace capabilities. It does not change authentication, authorization, infrastructure, deployment, or production data.

The blast radius is limited to workspace builds and future callers of the Unreal library. There is no migration, network call, runtime role, or public HTTP contract.

## Current behavior and evidence

- `crates/unreal` parses bounded, DTD-free crash context XML and exposes direct sections and fields.
- `crates/domain` provides `CrashType` and `NormalizedValue` with stable tests.
- Completed issues #42, #45, #47, and #48 established the parser, classification, normalization, and bounded log-tail foundations used by this work.
- `docs/product/overview.md` and `PRD.md` require deterministic extraction of runtime XML, module data, threads, system metadata, comments, and `GameData`.
- `ARCHITECTURE.md` places Unreal report parsing below application roles and requires untrusted data to remain bounded.
- No current code creates an extracted crash context record.

## Implementation sequence

1. Add the existing domain crate as a dependency of the Unreal capability crate.
2. Add owned extraction types and a caller option that defaults to excluding command lines.
3. Map known runtime scalar fields through the existing classification and normalization values.
4. Extract newline-delimited modules and nested thread records in source order.
5. Collect platform, `Misc.*`, `MemoryStats.*`, and `GameData` entries without collapsing repeats.
6. Add focused synthetic tests and run the repository checks.

## Verification

- `cargo test -p cachelane-unreal`
- `./scripts/check-fast`
- `./scripts/check`

No runtime smoke check is required because no application entry point changes.

## Data, security, and compatibility

The extractor only accepts a document that already passed the XML parser's DTD and node limits. Extracted text remains untrusted and is not logged, rendered, persisted, or sent across a tenant boundary by this change. Command-line data stays excluded unless a future caller explicitly allows it.

The API is additive. Missing source fields remain absent, so documents from supported engine versions can vary without failing extraction. This change adds no third-party dependency.

## Rollout and rollback

Rollout is the normal merge of an unused library capability. Roll back by reverting the Unreal crate dependency and extraction code. No data cleanup or operational action is required.

## Out of scope

- Unknown-field JSON preservation from #44.
- Parser-version persistence from #49.
- Minidump parsing, symbolication, HTTP ingestion, database storage, and UI rendering.
- Real crash fixture validation owned by the M0 fixture issues.

## Unresolved decisions

None. Real fixture evidence may add compatible source-field aliases without changing the extraction model.
