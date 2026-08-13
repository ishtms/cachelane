# Crash context XML adapter

Issue: [#42](https://github.com/ishtms/faultlane/issues/42)

## Context

M0 requires deterministic parsing of `CrashContext.runtime-xml` from UE 5.8 Windows reports. The repository currently has shared crash classification and normalization types, but no Unreal parsing capability or XML dependency. Rust's standard library and the current workspace dependencies do not parse XML.

The architecture identifies Unreal report parsing as a capability boundary. A dedicated `crates/unreal` crate keeps the XML dependency and untrusted-input handling out of the shared domain crate.

## Acceptance criteria

- A well-formed `FGenericCrashContext` document exposes top-level sections and their direct child fields without a fixed engine version or field list.
- Reordered, missing, additional, and repeated sections or fields remain parseable and observable in document order.
- Malformed XML, an unexpected root, DTD or entity declarations, and the configured node limit return typed errors without panics or raw XML in error messages.
- Synthetic tests cover normal input, escaped and CDATA text, version-tolerant additions, malformed input, DTD rejection, wrong roots, and node-limit rejection.
- No API, stored data, authorization, deployment, or user-facing workflow changes.

## Risk and blast radius

Risk is R2 because the change adds a workspace crate and the `roxmltree` dependency at a sensitive untrusted-input boundary. The dependency is MIT or Apache-2.0 licensed, supports the workspace Rust version, disables DTD parsing by default, and provides a node limit. The change does not cross an authentication, authorization, tenant, infrastructure, deployment, or production-data boundary.

The blast radius is limited to workspace builds and future callers of the new library. There is no migration, persisted representation, runtime role, or public contract.

## Current behavior and evidence

- `crates/domain` contains only shared product values and has no XML parser.
- No current workspace dependency provides XML parsing.
- `ARCHITECTURE.md` names Unreal report parsing as a planned capability boundary.
- `PRD.md` requires a version-tolerant adapter, disabled XML entity expansion, parser fuzzing, and safe handling of malformed or recursive XML.
- `docs/security/threat-model.md` treats crash XML as sensitive untrusted input and requires DTD or external entity rejection plus resource bounds.

## Implementation sequence

1. Add `crates/unreal` to the workspace and pin `roxmltree` through workspace dependencies.
2. Add a borrowed crash-context adapter that validates the root and exposes section and field iteration without exporting parser-library types.
3. Parse with DTD support disabled, no entity resolver, and a caller-supplied node limit.
4. Map parser failures to small typed categories with source positions but no raw input values.
5. Add focused synthetic unit tests and run the repository checks.

## Verification

- `cargo test -p faultlane-unreal`
- `./scripts/check-fast`
- `./scripts/check`

No runtime smoke check is required because no application entry point changes.

## Data, security, and compatibility

The adapter borrows input and stores nothing. It has no organization or project context and cannot cross tenant boundaries. DTD parsing and external resolution remain disabled, and the caller must provide a node limit. File-size and decoding limits remain the responsibility of the future ingest boundary.

The adapter accepts unknown field names, missing known fields, repeated fields, and reordered sections. Real crash bundles remain private and are covered by separate fixture work, so this change uses synthetic XML only.

## Rollout and rollback

This is an unused library addition, so rollout is the normal merge after checks. Roll back by reverting the crate, workspace dependency, and lockfile changes. No data cleanup or operational action is required.

## Out of scope

- Extracting the complete normalized event model from PAR-02.
- Persisting unknown fields from PAR-03.
- Archive, byte-size, decompression, invalid UTF-8, fuzzing, and worker sandbox controls owned by their existing M0 issues.
- HTTP, database, object storage, CLI, and web integration.

## Unresolved decisions

None. Future fixture evidence may tune the caller-provided node limit without changing the adapter contract.

## Result

The bounded, version-tolerant crash-context XML adapter shipped in [#276](https://github.com/ishtms/faultlane/pull/276). Synthetic tests cover supported input variations, unsafe XML, malformed input, unexpected roots, and node limits.
