# Crash reprocessing after symbol upload

Issue: [#299](https://github.com/ishtms/faultlane/issues/299)

Status: Approved for implementation.

## Outcome

When an exact PE or PDB becomes available for a release, FaultLane finds the events that are waiting for that embedded identity and reprocesses them in the background. The event keeps the same ID and immutable raw object, the current derived result changes atomically, and prior processing attempts remain available.

An authorized operator can also start bounded reprocessing by event, issue, release, project, parser version, symbolicator version, or fingerprint version and inspect progress through the control API.

## Context

Issue #311 added isolated processing, one canonical `process_crash` job per event, immutable processing results, exact release and artifact selection, bounded retries, and lease-fenced publication. Issue #298 added release mappings, fingerprints, issue assignments, and exact issue rollups. Both changes are in review, and this change is based on their combined head.

Artifact indexing currently publishes an available manifest artifact and completes its job without looking for affected crashes. A crash that reaches `awaiting_symbols` stores the missing identities only inside its current JSON result. There is no indexed waiter relation, artifact-arrival trigger, hosted reprocessing request, or control API for progress.

The existing `jobs` table has a unique `(event_id, job_type)` row for `process_crash`. Reusing that row is safer than adding a second event processor queue. A requested generation can reactivate the row, coalesce duplicate triggers, and detect a trigger that arrives while the job is already leased. Older workers continue to understand the job type after an application rollback.

Local processing already accepts a prior result and preserves changed attempts in bounded history. The isolated processor does not yet receive the current result, even though every prior database row is immutable.

## Acceptance criteria

- A partial result records tenant-scoped waiters only for exact missing PE or PDB identities from one matched release.
- Publishing or associating an available manifest artifact creates one idempotent automatic request. It does not scan events or run crash processing in the upload request or artifact publication transaction.
- The worker pages automatic waiter selection in batches of 100 until the artifact request snapshot is exhausted. Duplicate completion, duplicate negotiation, retry, and concurrent workers do not queue duplicate event generations.
- One canonical `process_crash` job serves initial processing and reprocessing. Requests increment an event generation, concurrent requests coalesce, and a newer generation that arrives during a lease is processed after the leased generation finishes.
- Reprocessing replaces `current_result_id`, missing-symbol waiters, release evidence, grouping rollups, event state, and request progress in one lease-fenced transaction.
- The raw object and event ID never change. Immutable prior result rows remain queryable, and the isolated processor carries the prior current attempt into bounded result history when the derived attempt changes.
- Unrelated projects, releases, modules, architectures, debug IDs, code IDs, and mismatched artifacts do not wake an event.
- A reprocessing failure exposes a fixed failure code on the request event while retaining the event's last successful or partial current result. Initial processing keeps its existing failure and quarantine behavior.
- The control API creates and reads no-store reprocessing requests through the current control authorization boundary.
- Manual scopes support event, issue, release, project, parser version, symbolicator version, and fingerprint version. Version scopes select events whose current stored version equals the requested value, then run the current compiled processors.
- Manual selection is a stable snapshot ordered by event receipt time and ID. A request accepts a limit from 1 through 1,000 and an optional event cursor, reports truncation and a next cursor, and never silently schedules beyond the limit.
- Manual retries require an idempotency key. The same project and key return the original request. At most five unfinished manual requests may exist per project.
- Request responses expose scheduling, queued, running, completed, and failed counts plus bounded fixed failure-code counts. Cross-tenant IDs never enter a request selection.
- `FAULTLANE_REPROCESSING_ENABLED` stops request scheduling and event reactivation without deleting requests, waiters, jobs, results, or event state.
- The behavior proof ingests a crash without symbols, uploads its exact release artifacts, and polls the same event and request until a readable stack replaces the partial stack. It also proves mismatch, duplicates, concurrency, retry, partial failure, history, and all manual selectors.

## Risk and blast radius

Risk: R3.

This change connects private symbol publication to background processing of sensitive crash artifacts, adds authorized bulk operations, changes queue reactivation, and changes the atomic event publication transaction. A defect could wake another tenant's event, create an unbounded reprocessing storm, lose a prior useful result, publish work after a lease expires, hide request failures, or make rollback workers mishandle new work.

No hosted deployment, production credential, production data, external service, billing action, destructive migration, or production configuration is in scope. Staging uses dedicated local PostgreSQL, MinIO, API, ingest, worker, and processor resources.

## Selected design

### Identity waiters

Add `crash_symbol_waiters` with organization, project, event, current result, matched release, required artifact kind, normalized module, architecture, debug ID, and code ID. Every key and foreign key carries tenant scope.

Waiters are derived only from the validated current symbolication result:

- `missing_pdb` records a PDB waiter when a debug ID is present;
- `missing_pe` records a PE waiter only when module, architecture, debug ID, and code ID are present;
- `mismatched` records the exact PE and PDB identities that could correct the mismatch;
- matched modules, missing identities, ambiguous releases, and missing releases do not create automatic waiters.

Publishing a new result deletes the event's prior waiters and inserts the new bounded set in the same transaction. Waiter text is limited to normalized module and embedded identities. It contains no comments, logs, paths, stack functions, addresses, or raw artifact content.

### Reprocessing requests

Add `crash_reprocessing_requests` and `crash_reprocessing_request_events`.

A request records its source, scope, stable selection snapshot, input cursor, limit, selection cursor, next cursor, state, counts, fixed failure code, requester for manual work, and timestamps. Manual idempotency keys are stored only as SHA-256 digests. Automatic requests are unique by manifest artifact checksum and trigger version, so an identical upload is deduplicated while a corrected artifact at the same source path creates new work.

The request row is also the scheduling queue. It has a random lease token, owner, expiry, bounded attempts, and safe failure code. New workers claim requests with `FOR UPDATE SKIP LOCKED`. The existing worker queue remains authoritative for actual event processing.

Automatic requests select all matching waiters in pages of 100. Manual requests select at most the requested limit plus one sentinel from a fixed creation-time snapshot. The sentinel reports truncation and the next event cursor without queueing it.

The worker inserts one request-event row for each selected event, increments that event's requested generation, and reactivates its existing `process_crash` job at lower priority than new crash jobs. Resetting a terminal job clears its old attempt and failure state. A pending or leased job is not duplicated.

### Event generations and publication

Add requested and completed reprocessing generations to `crash_events`. Each request event records the generation it needs.

The worker snapshots the requested generation when it leases a process job. Publication advances the completed generation and completes every request event through that generation. If a newer generation appeared during processing, publication returns the canonical job to `pending` instead of completing it. This closes the artifact-arrival race without parallel work for one event.

The isolated processor receives a bounded `previous.json` at a fixed guest path when a current result exists. It validates the same crash identity and supported versions through the existing processing contract. A changed attempt appends the previous current attempt to bounded history; an unchanged attempt does not grow history. Once the embedded history reaches 16 attempts, it drops the oldest entry while the immutable database result remains queryable.

The publication transaction updates the immutable result row, event pointer, release mapping, waiters, grouping rollups, request events, generation, and job state under the same lease token. A stale worker changes none of them.

Issue assignment remains stable for an event already grouped under the current fingerprint version, as specified by #298. Re-fingerprinting movement, issue merge, and issue split remain separate work.

### Failure behavior

Initial processing keeps the #311 retry, quarantine, and terminal event transitions.

When an event already has a current result, a reprocessing failure updates only the request event and job with a fixed code. It does not clear `current_result_id`, overwrite the last event state, or remove current waiters. A newer requested generation still reactivates the job after the failed generation is recorded.

Request aggregate state is derived from its request-event rows:

- `pending` or `scheduling` while selection is incomplete;
- `running` while any selected event is queued or leased;
- `completed` when every selected event completed;
- `partial` when completed and failed events both exist;
- `failed` when scheduling fails or every selected event fails.

Zero-match requests complete with zero counts. Failure responses contain only checked codes and counts.

### Control API

Add:

- `POST /api/v1/projects/{project_id}/reprocessing`;
- `GET /api/v1/projects/{project_id}/reprocessing/{request_id}`.

The POST body uses a strict tagged scope and optional cursor and limit. Event scope requires an event ID. Issue and release scopes require their scoped IDs. Project scope has no value. Parser and fingerprint versions require positive integers. Symbolicator version accepts only the bounded version grammar already emitted by processing results.

The POST requires an `Idempotency-Key` header and returns `202`. Repeating the same key and identical body returns the original request. Reusing the key with a different body returns a conflict. The GET returns current request progress, bounded failure counts, selection truncation, and next cursor. Both routes use the existing loopback bootstrap authorization until #310 replaces it and return `Cache-Control: no-store`.

## Database compatibility

Use additive migrations:

- add requested and completed generations to `crash_events`;
- add the tenant-scoped waiter table and exact lookup indexes;
- add request and request-event tables, leases, bounds, state checks, idempotency digest, and scoped foreign keys;
- add indexes for request claims, project progress, event completion, manual scope selection, and exact artifact waiter lookup.
- add available-artifact identity indexes in a follow-up migration so the applied reprocessing migration remains immutable.

Do not add a new `jobs.job_type` or remove the existing unique event job. The previous application ignores the new tables and columns. The previous worker can still process a reactivated `process_crash` row if rollback occurs, though rollout disables reprocessing and drains or leaves reprocessing requests before restoring the prior application.

## Security analysis

| Threat | Control | Required evidence |
|---|---|---|
| Cross-tenant artifact wakes an event | Composite tenant keys, matched release ID, artifact-kind-specific exact identity predicates | Two-organization waiter and upload tests |
| Filename-based or partial identity match | PDB requires exact debug ID; PE requires module, architecture, debug ID, and code ID | PDB, PE, mismatch, architecture, and release split tests |
| Upload request becomes slow or unbounded | Publication inserts one unique request only; worker pages waiter selection in batches of 100 | Upload latency path inspection and backlog proof |
| Duplicate or concurrent triggers cause repeated work | One canonical event job, request idempotency, event generations, lease-fenced completion | Duplicate upload, concurrent request, and mid-lease trigger tests |
| Bulk API creates a processing storm | Existing control authorization, five active requests, stable snapshot, explicit limit up to 1,000, lower job priority | Bounds, authorization, and fairness tests |
| Failed reprocessing destroys useful state | Immutable results and raw object, current pointer unchanged on reprocessing failure | Deterministic, resource, and retry-exhaustion tests |
| Stale worker completes request progress | Random job and request lease tokens on every publication and scheduling update | Expired request and job lease tests |
| Previous result crosses crash or tenant | Current result loaded through scoped event relation and existing crash-identity validation | Cross-event and malformed previous-result tests |
| Sensitive content enters progress or logs | Fixed codes, scoped IDs, version numbers, counts, and durations only | Hostile fixture response and captured-log inspection |
| Old worker corrupts new queue work | Reuse `process_crash`; keep scheduling in new tables ignored by old code | Pre-change application and worker compatibility proof |

## Implementation sequence

1. Update #299 with the refined behavior, approval, rollback, and dependencies. Claim it and move it to In Progress.
2. Add the additive generation, waiter, request, and request-event schema with constraints and old-application compatibility coverage.
3. Add strict request scope types, idempotent creation, progress reads, control authorization, bounds, no-store responses, routes, and OpenAPI coverage.
4. Add request claiming and bounded selection for exact automatic waiters and all manual scopes. Reactivate canonical event jobs by generation at lower priority.
5. Publish waiters and request-event progress inside the existing lease-fenced crash result transaction.
6. Enqueue one automatic request when a manifest artifact becomes available through new indexing or organization-level reuse.
7. Pass the scoped current result to the isolated processor and preserve bounded changed-attempt history.
8. Preserve current event state on reprocessing failure, handle a newer mid-lease generation, and derive exact request aggregates.
9. Add the reprocessing kill switch, fixed structured logs, operations notes, and rollback behavior.
10. Extend focused PostgreSQL, worker, upload, processor, API, and OpenAPI tests for matching, mismatch, duplicates, concurrency, retry, partial failure, history, tenant isolation, all selectors, bounds, and compatibility.
11. Extend the isolated processing proof with the partial-to-readable automatic path and manual scope evidence.
12. Run focused tests, the pre-change compatibility proof, `scripts/check-fast`, `scripts/check`, and `scripts/smoke`, then perform a fresh security and correctness review before opening a draft pull request.

## Verification and staging

Unit and database tests prove:

- exact PDB and PE waiter extraction and stable identity normalization;
- mismatched release, project, architecture, module, debug ID, and code ID isolation;
- request idempotency, body conflict, active-request cap, selection limit, stable cursor, and all seven manual scopes;
- duplicate upload and organization-level artifact reuse create one automatic request;
- automatic batching reaches more than one page without loss or duplicate generations;
- concurrent scheduling and processing use one event job and exact request counts;
- a trigger during a lease causes one later generation;
- stale request and process leases publish nothing;
- success replaces the current result atomically, preserves immutable result rows and bounded history, and refreshes waiters;
- deterministic, resource, transient, and partial failures retain the prior current result and expose only fixed codes;
- initial processing failure and quarantine behavior remains unchanged;
- grouping counts stay exact when an already grouped event is reprocessed;
- disabling reprocessing leaves initial ingest and processing working.

The isolated behavior proof uses dedicated PostgreSQL, MinIO, processor image, ports, network, volumes, bucket, and scratch resources. It ingests a synthetic crash before artifacts exist, observes a partial current result and exact waiters, uploads the matching PE and PDB, observes one automatic request, and polls the same event until `CrashFixture()` has function, file, and line data. It verifies the old result remains immutable, result history contains the partial attempt once, the raw object and event ID are unchanged, and duplicate upload transfers zero bytes without another generation.

The proof also uploads a mismatched artifact, runs concurrent workers and requests, injects one reprocessing failure without losing the prior result, exercises every manual selector, interrupts PostgreSQL and MinIO, verifies recovery, and checks fixed logs and cleanup. Start the pre-change #298 server and worker against the expanded schema and show that normal initial processing still works. Remove every dedicated container, image, network, volume, log, and scratch directory afterward.

### Completed evidence

Verification completed on August 14, 2026:

- The PostgreSQL-backed server suite passed all 53 tests. It covered request idempotency and conflicts, the five-request cap, all seven manual selectors, stable cursor snapshots, tenant isolation, exact PDB and PE waiters, 501-event automatic paging, generation coalescing, a trigger during a lease, stale and exhausted leases, failure state preservation, result history, duplicate upload, artifact replacement, and artifact reuse.
- Review regressions cover both artifact and waiter commit orders, enqueue-time snapshots, checksum-aware replacement triggers, final-attempt request recovery, and rolling 16-attempt embedded history. Exact waiter and available-artifact indexes keep publication lookups scoped to one tenant, project, release, and embedded identity.
- `bash scripts/prove-isolated-processing` passed from an empty dedicated environment. The same event moved from `awaiting_symbols` to `processed`, its automatic request completed, seven manual selector requests completed, two immutable result rows remained, the prior attempt appeared once in history, and the duplicate upload transferred zero bytes without advancing the event generation.
- The behavior proof also passed processor isolation, two concurrent workers, resource quarantine, grouping and reprocessing kill switches, stale processor cleanup, PostgreSQL recovery, MinIO recovery, fixed-log inspection, and scratch cleanup. Its dedicated containers, images, network, volumes, logs, and scratch directory were removed.
- The unmodified #298 server, worker, CLI, and processor completed their full isolated processing proof after this migration was applied. Normal ingest, symbolication, grouping, retries, and outage recovery remained compatible with the expanded schema. The temporary local proof hook was removed and the #298 worktree was clean afterward.
- `bash scripts/check-fast` passed, including Clippy, formatting, web lint and type checks, and all Rust tests.
- `bash scripts/check` passed, including the production web build, repository policy checks, and release workspace build.
- `bash scripts/smoke` passed with the canonical development lifecycle while the API, ingest, worker, and web processes remained healthy. The existing development database accepted the follow-up migration without changing the checksum of the applied reprocessing migration. Application processes and the owned scratch directory were stopped and removed afterward. The two containers created by the run were removed without deleting the existing development volumes, network, or processor image.

## Rollout and rollback

Add `FAULTLANE_REPROCESSING_ENABLED`. Apply the additive migration, start the current worker with the flag disabled, verify queue and API health, then enable scheduling. Reprocessing jobs keep lower priority than newly accepted crash jobs.

Rollback disables reprocessing first. Pending request rows and requested generations remain intact. Restore the prior application and worker without reversing the migration. The old worker understands every canonical `process_crash` row and ignores the new request tables. Current results, prior results, waiters, requests, and raw objects remain available for a corrected build. Do not delete requests, reset generations, reverse the migration, or remove customer data during rollback.

## Out of scope

- Manual issue merge, split, or movement between fingerprint versions
- Background preview of issue movement
- Dashboard presentation from #300
- Alerts, usage enforcement, billing, hosted authentication, retention, deletion, backup, or production deployment
- External symbol servers or processor network access
- Other Unreal versions, non-Windows platforms, or non-x64 Windows processing

## Approval

Ishtmeet Singh authorized R3 plan approval and implementation in the active milestone instruction on August 14, 2026. The approval covers the additive schema, exact identity waiters, canonical generation-based job reuse, bounded manual API, automatic background scheduling, prior-result history, local isolated staging, feature flag, and rollback path above.

No unresolved decision blocks implementation.
