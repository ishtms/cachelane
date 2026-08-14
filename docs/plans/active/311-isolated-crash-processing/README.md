# Isolated crash processing workers

Issue: [#311](https://github.com/ishtms/faultlane/issues/311)

Status: Approved for implementation.

## Outcome

When FaultLane accepts a crash, the worker claims its durable job, processes the raw request in a short-lived credential-free container, publishes one versioned normalized result, and records a safe terminal or waiting state. Malformed and resource-exhausting inputs cannot stop unrelated jobs.

Artifact upload completion also moves final PE and PDB inspection into the same isolated path. This removes the temporary loopback-only upload restriction from #297 without moving untrusted parsing back into the API.

## Context

Durable ingest already stores one private raw object, event, and `process_crash` job before returning `202`. The worker role currently waits for shutdown and never claims jobs. Local crash processing already produces deterministic parser and symbolication JSON, but its timeout uses an in-process thread and cannot enforce memory, filesystem, or network isolation.

Symbol upload currently verifies a completed PE or PDB inside the API process. That behavior is deliberately limited to literal loopback hosts until this issue provides the accepted isolation boundary from decision 0003.

The authoritative sources contain one scope discrepancy. Issue #311 says an event passes through grouping, while the PRD build order and issue #298 assign fingerprints, issues, and regression state to the next change after durable processing. This plan ends #311 at a durable normalized processing result and leaves grouping to #298. The issue acceptance criteria will be corrected when this plan is approved.

## Acceptance criteria

- The `worker` role claims one eligible job with a lease and processes it without work on the ingest request.
- Every parser, minidump, PE, PDB, and derived-cache operation runs in a new isolated processor container with fixed CPU, memory, input, output, process, disk, wall-time, filesystem, and network limits.
- The processor container receives no database, object-store, API, or host credentials and no customer-controlled command arguments.
- A valid crash with matching indexed artifacts reaches `processed` with a versioned normalized stack. A valid crash without matching artifacts reaches `awaiting_symbols` with precise module diagnostics.
- Deterministically malformed input is quarantined immediately. A resource limit that repeats on a fresh attempt is quarantined. Transient database, object-store, or runner failure retries with bounded backoff.
- Leases, retries, cache creation, artifact publication, and crash-result publication are idempotent. A stale worker cannot publish after losing its lease.
- Upload completion records the original object and queues isolated artifact indexing. It does not parse the uploaded PE or PDB in the API process.
- The CLI waits for the asynchronous artifact result and preserves the deterministic release coverage and zero-byte second-upload behavior from #297.
- PDB symbol data is converted lazily into a versioned SymCache when first selected. Cache identity includes organization, source checksum, processor version, SymCache format version, and cache kind. Derived bytes do not count as customer storage.
- Repeated equivalent events may produce identical normalized results, but issue fingerprints, issue rows, grouping, and regression state remain owned by #298.
- Starting a worker without a usable immutable processor image or container runtime fails closed.

## Risk and blast radius

Risk: R3.

This change creates the execution boundary for hostile native artifacts, adds queue consumers and database transitions, reads and writes private object storage, changes artifact upload completion from synchronous verification to asynchronous indexing, adds a processor image, and publishes sensitive normalized crash data. A defect could escape the parser boundary, leak credentials or artifacts, let one tenant starve others, lose or duplicate results, publish stale work, or leave hosted upload parsing unsafe.

No hosted or production deployment, credential, customer data, or infrastructure mutation is in scope. Verification uses isolated local PostgreSQL, MinIO, and Docker resources.

## Selected isolation design

Use the existing Rust CLI capabilities inside one short-lived OCI container per processing attempt. The connected Rust worker remains the coordinator: it claims work, downloads only scoped objects into a private attempt directory, starts the processor, validates bounded JSON output, and publishes results. The processor receives only fixed guest paths and opaque internal identifiers.

The container runner uses an immutable local image ID and fixed arguments:

- no network;
- read-only root filesystem;
- one read-only input mount;
- bounded in-memory scratch space;
- non-root user;
- all Linux capabilities dropped;
- `no-new-privileges` and the default seccomp profile;
- one CPU, a hard CPU-time limit, bounded memory and swap, bounded processes and open files;
- a parent-enforced wall deadline followed by forced removal of the exact attempt container;
- no inherited environment, secrets, host sockets, database access, or object-store credentials;
- bounded stdout containing only the versioned result and bounded stderr that is never copied into customer-visible errors.

The default limits are the existing 64 MiB compressed request, 256 MiB expanded request, 128 files, 128 MiB per request file, 1 GiB per debug artifact, 4 GiB total selected artifacts, 2 GiB container memory, one CPU, 120 seconds CPU time, 150 seconds wall time, 64 processes, 256 open files, 64 MiB scratch, and 16 MiB output. Configuration may lower these values. Raising a value above the compiled ceiling requires a later reviewed change.

Docker Desktop supplies the Linux container runtime on the supported Windows development path and already hosts local PostgreSQL and MinIO. Hosted and self-hosted installations use the same OCI processor image and runner contract. The application does not mount a Docker socket inside an untrusted processor container.

### Rejected alternatives

- In-process threads enforce only a wall timeout and cannot stop memory exhaustion, filesystem access, network access, or a stuck thread.
- A Wasmtime/WASI processor would provide a useful capability model, but a compile-only check failed because the selected `minidump-unwind` and `wholesym` dependency path does not support `wasm32-wasip1`. Adopting it would require maintaining parser dependency forks.
- Cloudflare Sandbox provides per-sandbox VM isolation, but it is a paid preview and would add a TypeScript Worker, Durable Object, and hosted-only service boundary. That conflicts with the modular monolith and self-hosted requirements for this change.
- Platform-specific Windows AppContainer and Linux seccomp implementations would duplicate security-critical launcher code and require repository-owned unsafe operating-system integration.

## Worker and queue behavior

### Claims and leases

Claim one job in a short transaction using `FOR UPDATE SKIP LOCKED`. A claim writes a random lease token, owner, attempt number, and expiry. The worker renews the lease while it downloads bounded inputs and waits for the processor. Every state transition and publication query includes organization, project, job, owner, and lease token.

An expired lease is eligible for a new claim. A stale worker may delete its private scratch data but cannot update durable state. Graceful shutdown stops new claims, terminates the active processor, and releases the lease when PostgreSQL is available. Otherwise the lease expires naturally.

### Failure policy

- Invalid request, XML, minidump, PE, PDB, identity mismatch, or processor output is deterministic and quarantined without retry.
- CPU, memory, disk, output, process, or wall exhaustion retries once in a fresh container, then quarantines the event or artifact.
- Database, object-store, or container-runtime unavailability retries up to five times with bounded exponential backoff and jitter.
- Lost lease, cancellation, and cache contention do not count as parser failures.
- Exhausting transient retries marks the job dead and the event failed with a fixed safe reason. It never copies stderr, paths, object keys, symbols, comments, or raw parser text into the reason.

One project's pending or quarantined work does not block claims for another project. Initial fairness uses a bounded per-project active claim and oldest eligible work. More complex scheduling waits for measured contention.

## Processing pipeline

1. Claim a `process_crash` job and download its tenant-scoped raw object into a new private attempt directory while rechecking recorded size and SHA-256.
2. Run an isolated inspection pass with no symbols. It validates and normalizes the request, reports release fields and module identities, and produces the partial raw stack.
3. Resolve at most one exact project release from build version, platform, architecture, and configuration. Record missing or ambiguous release mapping explicitly.
4. Select only organization-scoped artifacts whose indexed debug ID, code ID, architecture, module, and release association match the processor output.
5. For each selected PDB, reuse or enqueue one `generate_symcache` job keyed by source identity and versions. Concurrent requests share the unique durable cache record. PE files remain the authoritative unwind input because the selected Windows unwinder reads PE unwind data directly.
6. When required caches are ready, download the exact PE and cache objects into a fresh attempt directory and run the isolated final pass.
7. Publish one immutable processing result and atomically point the event at it only if the lease is still current. Set the event to `processed`, `awaiting_symbols`, `failed`, or `quarantined` with a fixed reason and timestamps.
8. Remove the processor container and private attempt directory on every handled exit. Bounded maintenance reconciles abandoned attempt directories and containers owned by this worker instance.

The existing local CLI processing commands keep their current output. Shared processing-result types move to a library boundary so local and worker paths cannot drift.

## Artifact indexing and derived caches

Upload completion verifies multipart size and checksum through the storage provider, records the original private object as pending, and creates one idempotent `index_artifact` job. It returns processing state without inspecting file contents.

The isolated index job detects the file type, extracts the embedded identity, compares it with the declared manifest, and atomically publishes `available`, `mismatch`, or `quarantined`. The CLI polls bounded status endpoints until release coverage is ready or returns its existing retryable failure code.

The first processing job that needs symbols creates a `generate_symcache` job. The isolated processor uses `symbolic-debuginfo` and `symbolic-symcache` 13.3.1 with only the required Microsoft debug-format features to convert the selected PDB into SymCache format 9. Publication verifies size, checksum, embedded debug identity, processor version, and cache format before making the object visible. The symbolicator uses the SymCache for function, file, line, and inline lookup and the exact PE for Windows x64 unwind data.

Derived object keys use only internal scope and identities:

```text
org/<organization_id>/derived/<source_sha256>/<processor_version>/<format_version>/symcache
```

Original PE and PDB objects remain authoritative. A processor or format upgrade creates a new key and never overwrites an older cache. Cache rows and bytes are excluded from customer-visible artifact usage. Source deletion must later delete its derivatives through the retention work that owns deletion.

## Database changes

Use one additive migration that keeps the previous server usable:

- widen `jobs.job_type` for `index_artifact` and `generate_symcache`;
- allow artifact jobs without an event while requiring their scoped artifact or cache identity in the payload;
- add lease token, maximum attempt, heartbeat, safe failure code, and completion fields;
- add immutable versioned crash-processing results plus the current result reference on `crash_events`;
- add artifact indexing state and safe failure fields without removing the states understood by the previous application;
- add tenant-scoped derived-cache records with source object, processor version, format version, kind, object key, checksum, size, state, and uniqueness constraints;
- add the minimum indexes for eligible claims, expired leases, current results, artifact state, and cache identity.

Composite foreign keys and every application query retain organization and project scope. Cache records follow organization-level artifact deduplication and never expose cross-organization existence.

## Security analysis

| Threat | Control | Required evidence |
|---|---|---|
| Parser escapes into coordinator credentials | Fresh credential-free container, no network, no host socket, read-only root, non-root user, dropped capabilities | Processor environment, mount, network, and credential-denial tests |
| CPU, memory, disk, process, or wall exhaustion | Docker limits, ulimits, bounded input and output, parent timeout and exact container removal | Synthetic CPU, memory, output, and wall exhaustion tests |
| Filesystem traversal or host reads | One read-only private input mount, fixed guest paths, no customer arguments, read-only root | Traversal, symlink, absolute-path, and unrelated-host-file denial tests |
| Outbound access or SSRF | `--network none`, no credentials, no external symbol sources | Processor connection and DNS denial tests |
| Stale worker overwrites newer state | Random lease token on every publication query and immutable result rows | Lease expiry and stale publication tests |
| Duplicate claims or cache work | `SKIP LOCKED`, unique idempotency and cache keys, atomic publication | Concurrent worker and cache-generation tests |
| Cross-tenant artifact selection | Tenant predicates, composite keys, exact release and embedded identity matching | Two-organization crash, artifact, cache, and result tests |
| Malformed artifact becomes available | Asynchronous isolated index, declared-versus-embedded identity comparison | Mismatch, malformed, and quarantine tests |
| Processor output injects data or exhausts the host | Bounded stdout, strict versioned JSON schema, fixed safe errors, escaped downstream display | Oversized, malformed, extra-field, and control-character output tests |
| Mutable or replaced processor image | Require an immutable local image ID for the worker lifetime and never pull during a job | Startup and image-replacement tests |
| Coordinator crash leaves containers or files | Attempt ownership markers and bounded startup/periodic reconciliation | Forced termination and cleanup proof |
| Sensitive content enters logs | Log only tenant-safe IDs, versions, states, durations, and fixed codes | Captured log inspection with hostile fixtures |

## Implementation sequence

1. Record approval of this plan, including the scope correction, OCI boundary, asynchronous artifact indexing, SymCache design, retry policy, and isolated local staging interpretation.
2. Update #311 with the corrected acceptance criteria, move it to Ready, requery it, assign it to `ishtms`, and move it to In Progress.
3. Add the additive queue, processing-result, artifact-index, and derived-cache schema with constraint, concurrency, and previous-server compatibility tests.
4. Move shared local processing types behind a library boundary and add fixed internal processor operations for request inspection, artifact indexing, SymCache generation, and final processing.
5. Add the minimal pinned symbolic crates required for PDB SymCache conversion and lookup. Keep PE unwind handling on the proven minidump path.
6. Add the immutable processor image and fixed OCI runner with resource, filesystem, network, output, cleanup, and startup tests.
7. Implement claims, leases, heartbeats, expiry, cancellation, retries, fairness, quarantine, and stale-publication rejection.
8. Implement scoped object materialization, release and artifact selection, lazy cache coordination, versioned result publication, and event state transitions.
9. Move upload identity verification to `index_artifact`, update asynchronous status and CLI polling, then remove the non-loopback startup restriction only after no untrusted upload parsing remains in the API.
10. Update OpenAPI, local configuration, Docker development commands, smoke coverage, threat model, deployment notes, and rollback instructions.
11. Run focused unit and PostgreSQL tests, processor boundary tests, CLI compatibility tests, `scripts/check-fast`, `scripts/check`, and `scripts/smoke` on the final head.
12. Collect isolated staging evidence, perform a fresh security and correctness review, fix all findings, rerun invalidated checks, push, open a draft pull request, confirm CI, mark ready for human review, and stop.

## Verification and staging evidence

Behavior tests cover lease expiry, concurrent claims, stale publication, retry backoff, cancellation, shutdown, cache versioning, concurrent cache generation, artifact mismatch, release ambiguity, missing symbols, malformed output, every resource limit, and quarantine isolation.

The final proof uses a dedicated Compose project with unique PostgreSQL, MinIO, network, volumes, ports, bucket, worker scratch root, and processor image. It will:

1. apply migrations twice and start API, ingest, and worker roles on loopback;
2. upload and asynchronously index the checked-in synthetic PE and PDB fixtures;
3. submit one valid symbolicated crash and one resource-exhausting synthetic input together;
4. show that the valid event reaches `processed` with a readable frame while the unsafe event retries once and reaches `quarantined`;
5. show no ingest request performs processing and unrelated project work continues;
6. expire a lease during an attempt and prove the stale worker cannot publish;
7. start concurrent workers and prove one result and one versioned SymCache are published;
8. rerun the valid event and prove the existing cache is reused without another cache object;
9. deny processor network and unrelated filesystem reads, inspect mounts and environment, and verify CPU, memory, scratch, process, output, and wall limits;
10. stop MinIO and PostgreSQL separately, verify safe retry state, restore them, and complete the job;
11. start the pre-change server against the expanded schema and verify readiness;
12. inspect logs, rows, objects, and scratch data for tenant scope, fixed errors, and absence of credentials, source paths, raw content, or processor stderr.

All dedicated containers, networks, volumes, images, and scratch files are removed after evidence is recorded. No hosted staging target exists, so isolated local Docker staging satisfies this change's staging gate. No production deployment is performed.

## Compatibility, rollout, and rollback

The migration is additive and the prior API, ingest, CLI scan, local crash processing, and loopback symbol-upload behavior remain usable. Upload API responses add processing states without removing existing fields. The CLI continues to return final deterministic coverage after bounded polling.

Rollout is controlled by `FAULTLANE_ISOLATED_PROCESSING_ENABLED`. Keep it disabled until migrations, the immutable processor image, runtime checks, and worker health pass. Hosted symbol upload remains unavailable unless isolated processing is enabled.

Rollback disables isolated processing, stops workers and owned processor containers, restores the prior application and CLI artifacts, and leaves additive tables, original objects, derived caches, jobs, and results intact. Accepted events are not deleted. Pending artifact indexes and crash jobs remain available for a corrected worker. The prior loopback-only upload guard remains the safe fallback. Destructive cleanup or contract migrations require a later approved change.

## Out of scope

- Fingerprints, issue creation, issue grouping, and regression state from #298
- Automatic reprocessing after a new matching upload and manual bulk reprocessing from #299
- Hosted authentication and role management from #310
- Dashboard, alerting, usage, billing, retention, deletion, backup, or production deployment
- External symbol servers or any processor network access
- Linux, macOS, mobile, or non-x64 Windows crash formats
- Changing the hosted artifact provider from Cloudflare R2 or the local provider from MinIO

## Approval

Approved by Ishtmeet Singh on August 14, 2026: [approval record](https://github.com/ishtms/faultlane/issues/311#issuecomment-5288201240).

The approval covers these decisions:

1. Correct #311 to stop at a durable normalized processing result. Issue #298 remains the sole owner of grouping and regressions.
2. Use one short-lived OCI processor container per attempt with the fixed limits and credential-free boundary above.
3. Change artifact completion to asynchronous isolated indexing and preserve CLI behavior through bounded polling.
4. Generate tenant-scoped PDB SymCaches lazily, use exact PE files for Windows unwind data, and retain originals as authoritative inputs.
5. Use the retry and quarantine policy above.
6. Treat isolated local PostgreSQL, MinIO, and Docker as the R3 staging environment because no hosted staging target exists and no deployment is in scope.
