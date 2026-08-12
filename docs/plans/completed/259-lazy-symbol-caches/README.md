# Lazy derived symbol caches

Issue: [#259](https://github.com/ishtms/cachelane/issues/259)

## Outcome

Keep original PDB and PE artifacts as the authoritative inputs, index their identities after upload, and build versioned symbolication and unwind caches only when processing first needs them.

This resolves PRD open question 6 and advances the M0 symbol-processing path without selecting the final Windows stack-walking library or implementing artifact handling.

## Context

CacheLane must match Windows artifacts by embedded debug ID, code ID, architecture, and module metadata rather than by filename. It must also retain raw artifacts and processor versions so events can be reproduced after a parser or cache-format change.

The existing architecture places original debug artifacts and derived symbol caches in private object storage. The artifact isolation decision requires every PDB and PE parse to run in a bounded worker with no outbound network. The repository does not yet contain an artifact parser, artifact schema, symbolication crate, upload path, or worker job for this behavior.

Sentry Symbolicator provides useful primary evidence from a mature native symbolication system:

- Its [background and principles](https://getsentry.github.io/symbolicator/advanced/background-and-principles/) document that generating every SymCache and CFI cache ahead of use caused unnecessary computation and lifecycle races, especially for artifacts that never serve a crash.
- Its [caching model](https://getsentry.github.io/symbolicator/advanced/caching/) retains original debug files so derived caches can be rebuilt after format changes. It separates compact function and line caches from unwind caches and records failed conversions independently.
- Its [system architecture](https://getsentry.github.io/symbolicator/advanced/system-architecture/) keeps object metadata separate from derived caches so candidate files can be ranked before a symbolication cache is generated.

CacheLane has a different storage model because customer uploads are authoritative rather than transient downloads. The timing and separation lessons still apply.

## Decision

Use a split metadata and derived-cache pipeline.

1. Artifact upload completion durably records the original encrypted PDB or PE object, checksum, size, tenant scope, and upload provenance. It does not parse the artifact or generate a derived cache inline.
2. A bounded artifact-index job runs promptly after durable upload. It detects the format and extracts debug ID, code ID, architecture, module name, capability flags, parser version, and validation state. Only successfully indexed metadata becomes eligible for exact matching.
3. When a new valid identity matches events waiting for symbols, the indexing transaction schedules idempotent reprocessing after the metadata is visible.
4. A processing job generates a SymCache or CFI cache only when the selected artifact is first needed for that capability. The first event therefore pays the conversion cost, while unused artifacts do not.
5. A derived-cache key includes organization scope, source artifact content hash, processor version, derived format version, and cache kind. Source filenames and upload order do not participate in identity or cache selection.
6. Concurrent requests for the same key share one idempotent generation result. A unique job key or equivalent database constraint prevents duplicate durable state, while bounded duplicate computation may be tolerated if object publication remains atomic.
7. A successful cache is reused until its source artifact is deleted or its processor or format version is no longer accepted. Original artifacts remain available for deterministic rebuilding throughout their configured retention window.

The initial implementation must not prewarm every derived cache. A later release-level prewarm policy requires measured first-use latency, queue cost, and artifact reuse evidence.

## Failure behavior

- An unsupported, malformed, or resource-exhausting artifact never publishes matching metadata. It records a small typed failure and becomes invalid or quarantined according to retry policy.
- A derived-cache conversion failure is scoped to its exact cache key. It records a safe failure category and bounded retry time without logging artifact bytes, source paths, symbols, or parser payloads.
- A failed conversion does not delete or replace the original artifact. A processor upgrade can retry with a new versioned key.
- A missing derived cache is not evidence that the source artifact is missing. Processing state distinguishes lookup failure, unavailable identity, conversion failure, and cache generation in progress.
- Artifact indexing and cache generation run with CPU, memory, disk, file-size, wall-time, filesystem, and network limits. Neither operation occurs in the upload request path.

## Acceptance criteria

- Eager conversion, fully lazy inspection, and the selected split pipeline are compared using repository constraints and primary evidence.
- Original PDB and PE files remain authoritative for processor upgrades and deterministic reprocessing.
- Asynchronous bounded metadata extraction makes exact identities and validation state available before matching.
- SymCache and CFI generation is lazy, versioned, tenant-scoped, idempotent, and capability-specific.
- Malformed input, conversion failure, retry, quarantine, and safe diagnostic behavior are defined.
- Newly indexed exact matches schedule waiting-event reprocessing only after metadata is visible.
- Compatibility, rollout, verification, rollback, limitations, and implementation follow-ups are recorded.
- This decision changes no product code, dependency, API, schema, migration, service, credential, or production state.

## Risk and blast radius

Risk: R2.

This decision constrains future worker, persistence, object-storage, and symbolication behavior across components. It is additive and reversible before those components are implemented. This pull request does not parse untrusted artifacts, change a tenant boundary, add infrastructure, alter deployment, or touch production data.

Future artifact parsing and storage implementation remains R3 work because it crosses a sensitive untrusted-input and tenant-data boundary.

## Expected implementation sequence

1. Select and validate the Windows artifact and minidump library path in #260.
2. Implement bounded PDB and PE discovery and metadata extraction through #53, #56, and #57.
3. Add tenant-scoped artifact metadata and versioned cache state when the persistence boundary exists.
4. Add lazy SymCache and CFI generation with idempotent jobs and safe failure states through #66, #67, #68, #69, #71, and #72.
5. Requeue exact waiting-event matches through #59.
6. Prove the combined path against private real fixtures in #150 and the M0 fixture work.

Each implementation stage requires its own current risk gate and tracked plan where applicable.

## Verification

For this decision stage:

- Review the decision against `docs/product/overview.md`, `PRD.md`, `ARCHITECTURE.md`, `docs/security/threat-model.md`, and accepted artifact isolation constraints.
- Confirm the issue and plan keep implementation and library selection out of scope.
- Run `./scripts/check`.

Future implementation must add focused tests for identity extraction, cache-key separation, concurrent generation, atomic publication, retries, quarantine, exact matching, and reprocessing. Real Windows quality claims require private Unreal fixtures and the authoritative x64 Windows environment.

## Data, security, and compatibility

Original debug artifacts can contain proprietary code and paths. They remain private, encrypted, tenant-scoped untrusted inputs. Metadata and derived objects inherit the source artifact organization scope. Cross-organization physical deduplication must not make artifact existence observable and is not part of this decision.

Versioned derived keys allow new processors to coexist with old cache output during a compatibility window. Because originals are retained, a format upgrade creates new derivatives without rewriting the customer upload. Deleting a source artifact must eventually delete all derivatives under the same lifecycle policy.

No public API, stored schema, migration, or runtime compatibility changes in this stage.

## Rollout and rollback

The decision takes effect as a constraint on later artifact-processing plans. Later implementations should first emit metadata and cache state observability, then use measured first-use latency and cache reuse to decide whether any bounded prewarming is justified.

Roll back this stage by reverting the plan before dependent implementation lands. After implementation begins, replace it with a follow-up decision, keep original artifacts, version any changed derived format, and rebuild derivatives without destructive migration.

## Out of scope

- Selecting or adding a Rust PDB, PE, minidump, SymCache, or CFI dependency
- Implementing CLI scanning, upload, persistence, jobs, symbolication, or reprocessing
- Choosing worker sandbox technology or hosted infrastructure
- Setting artifact and cache retention durations
- External symbol servers or cross-organization deduplication
- Claiming Unreal stack quality without real fixture evidence

## Unresolved decisions

The timing policy has no unresolved product decision. Issue #260 still owns library and stack-quality selection. Retention durations, retry intervals, worker limits, and physical cache placement remain implementation and operations decisions that require measured evidence.

## Result

- Original PDB and PE files remain the authoritative inputs.
- Metadata indexing runs promptly after upload in a bounded asynchronous job.
- SymCache and CFI derivatives are created lazily per capability and reused through tenant-scoped versioned keys.
- Failed indexing or conversion retains the original input and exposes only safe typed state.
- `./scripts/check-fast` passed locally.
- `./scripts/check` passed locally.
