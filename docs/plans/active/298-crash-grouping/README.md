# Crash grouping and release regressions

Issue: [#298](https://github.com/ishtms/faultlane/issues/298)

Status: Ready for implementation.

## Outcome

When processed crashes describe the same failure, FaultLane assigns them to one stable issue without collapsing materially different failures. Every processed event records the fingerprint algorithm and version, issue variants remain queryable, and an issue becomes regressed only when it returns in a provably later release after being marked resolved.

## Context

Issue #311 publishes a validated, versioned processing result and updates the event under the same job lease. The result contains normalized Unreal crash context, classification evidence, module identities, and bounded symbolicated threads. It does not yet persist release mapping, a fingerprint, or an issue.

The current release lookup uses build version, normalized platform, architecture, and case-insensitive configuration only to select symbols. It returns missing symbols for both no match and multiple matches. The `releases` table already stores build timestamps, but `crash_events` does not retain a release or ambiguity evidence.

The product sources have two naming and schedule discrepancies. The overview still calls M0 the current milestone, and the overview, PRD, and architecture use the former CacheLane name. GitHub milestone M1, issue #298, and the current repository use FaultLane. This plan follows the behavior requirements from GRP-01 through GRP-05 and REL-03 through REL-04, while using the current product name and milestone state.

The PRD's fingerprint inputs include exception reason and assertion text. The current symbolication result does not retain either stable field from `minidump-processor`. This change adds them to a new result version without storing exception addresses or instruction text.

## Acceptance criteria

- Deterministic repeats of the same known crash join one issue across distinct crash GUIDs and releases.
- Known crashes with a different crash class, stable project stack, assertion template, or unresolved module identity remain separate.
- Every event that reaches a partial or complete processing result stores fingerprint algorithm and version. Events without enough stable evidence remain visibly ungrouped instead of sharing a broad fallback issue.
- Each grouped event stores a versioned issue fingerprint and variant fingerprint. Issue queries return first and last seen, exact event count, affected releases, variants, and a deterministic representative event.
- Release mapping stores exact, missing, and ambiguous outcomes. Ambiguous mappings retain the scoped candidate release IDs and are visible through the API.
- New-in-release, ongoing, resolved, and regressed states use release build timestamps. Missing or tied timestamps produce an unknown ordering result and never a guessed regression.
- Marking an issue resolved against one scoped release and then processing the same fingerprint in a provably later release reopens the same issue as regressed.
- Retries, stale leases, reprocessing, and concurrent workers cannot double-count an event, create duplicate issues, or overwrite a newer assignment.
- Issue list, issue detail, resolution, and reopen operations are tenant-scoped, bounded, versioned in OpenAPI, and return no-store responses.
- Grouping can be disabled without disabling crash processing or deleting grouping data.

## Risk and blast radius

Risk: R2.

This change adds a pure fingerprinting capability, extends the versioned processing contract, adds relational issue and release data, changes the crash publication transaction, and exposes new control API routes. Incorrect normalization can hide distinct defects through a false merge or create excessive noise through false splits. Incorrect release ordering can report a false regression. Incorrect transaction or scope predicates can corrupt counts or cross tenant boundaries.

The migration is additive. No hosted deployment, production data, destructive migration, new service, external dependency, or production credential is in scope.

## Fingerprint v1

Create a pure `faultlane-grouping` crate. It depends on the existing domain, processing, JSON, and SHA-256 facilities and has no database, object-store, web, or worker dependency. The architecture already identifies fingerprinting as a capability boundary, and keeping the versioned algorithm outside the server makes golden behavior testable without PostgreSQL or Docker.

The algorithm name is `stack` and its initial version is `1`. Hashes are lowercase SHA-256 over tagged, length-prefixed components. Length prefixes prevent concatenation ambiguity, and explicit tags make later versions independent of field order or JSON serialization.

The issue signature uses, in order:

1. normalized Unreal crash type;
2. normalized crash classification and stable exception reason when available;
3. a normalized assertion or ensure template when present;
4. up to eight stable resolved project frames from the faulting thread;
5. up to five selected engine frames only when no project frame is available;
6. normalized module name, embedded debug identity, and module-relative offset for unresolved frames;
7. a bounded error template for assertion, ensure, GPU, OOM, or stack-poor failures;
8. normalized platform only when the selected root evidence is system or platform specific.

Resolved frame identity uses normalized module and function names, including inline function names in call order. It excludes source roots, source line numbers, absolute instruction addresses, thread IDs, crash GUIDs, release IDs, timestamps, and machine context. This keeps a source relocation or new build address from splitting the same root stack.

Frame categories are deterministic:

- `engine` when a normalized source path is under `Engine/Source` or the module is a known Unreal runtime module;
- `system` for a bounded checked-in set of Windows runtime, driver, and graphics modules;
- `project` for other resolved game or plugin frames;
- `unknown` when the module or symbol evidence is insufficient.

The checked-in category tables are part of fingerprint version 1. Changing a category, normalization rule, component order, or selection limit requires a new fingerprint version and golden updates.

Error-template normalization collapses whitespace and replaces addresses, GUIDs, timestamps, and volatile numeric runs with typed placeholders. It is Unicode safe, linear in the bounded input, and capped before hashing. It never stores the source error text in issue rows.

The variant signature uses the issue components plus a bounded normalized faulting stack and classification evidence. Variants distinguish meaningful subpatterns inside one conservative issue without changing the stable issue URL.

When no stable frame, module identity, assertion, or specific classified error remains, the crate returns `insufficient`. The event still records `stack` version `1`, release mapping, and processing state, but no issue is created. This is safer than merging unrelated stack-poor crashes by crash class alone.

## Processing contract change

Symbolication schema version 2 adds only:

- stable exception reason;
- bounded assertion text when present.

It does not add the exception address, instruction bytes, process ID, timestamps, or other volatile process data. Processing version 2 emits the new symbolication schema. Previous version 1 results remain valid inputs for local reprocessing and history. The parser accepts supported historical attempts while requiring new current attempts to use the current version.

`crash_processing_results.processing_version` comes from the processing contract rather than a SQL literal. Existing immutable version 1 rows remain unchanged. Fingerprint v1 can consume either supported processing version and omits unavailable exception or assertion components for version 1 results.

## Release mapping and ordering

Resolve releases from the same structured fields used by symbol selection: project, build version, normalized platform, architecture, and case-insensitive configuration. Store all tenant-scoped candidates before selecting artifacts.

Mapping states are:

- `matched` for exactly one candidate;
- `missing` for no candidate;
- `ambiguous` for multiple candidates.

Only `matched` events contribute release rollups or regression state. Missing and ambiguous events still group by fingerprint and remain visible. Symbol selection uses the exact matched release only, so ambiguity is no longer silently presented as missing symbols.

Release chronology uses a non-null `build_timestamp`. Different releases with equal timestamps are unordered. Created time, UUID order, lexical version order, and event arrival order are not release chronology and must not be used as substitutes.

The first matched occurrence makes an issue new in that release. A later ordered occurrence makes it ongoing unless the issue was resolved. Resolution requires a scoped release with a build timestamp. An event is a regression only when its matched release timestamp is strictly greater than the resolution release timestamp. Same-release, earlier, missing, ambiguous, or tied-timestamp events cannot reopen an issue as regressed.

Late-arriving events recompute first and last release from ordered evidence. They cannot turn an older occurrence into a regression.

## Database changes

Use one additive migration.

Add to `crash_events`:

- nullable `issue_id` and `release_id` with composite tenant-scoped foreign keys;
- `release_mapping_state` and `grouping_state` with checked values;
- nullable fingerprint, variant fingerprint, and grouping quality;
- non-null fingerprint algorithm and version after a processing result is published;
- grouping timestamp.

Add `crash_event_release_candidates` keyed by event and release with organization and project in every key and foreign key. Exact and ambiguous mappings retain their candidate evidence; missing mappings have no candidate rows.

Add `issues` with organization, project, algorithm, version, fingerprint, safe title, status, regression state, first and last seen, event count, representative event, first and last ordered release, resolution release, resolution time, and update time. A unique key on project, algorithm, version, and fingerprint creates one stable issue per versioned signature.

Add `issue_variants` keyed by issue and variant fingerprint with first and last seen, event count, and representative event. Add `issue_releases` keyed by issue and release with first and last seen, event count, and representative event.

All tables use composite organization and project scope. Indexes cover project issue ordering, issue event lookup, issue release lookup, and unique fingerprint insertion. No row stores raw comments, logs, source paths, error messages, or binary data.

The prior application continues to run against the expanded schema. Existing processed events remain ungrouped until new work processes them; #299 owns automatic and bulk reprocessing.

## Transaction and concurrency behavior

Compute the fingerprint from the already validated bounded result before opening the publication transaction. Under the current random lease token, the transaction:

1. locks and rechecks the exact job lease;
2. inserts the immutable processing result;
3. resolves and records scoped release candidates;
4. upserts the unique issue and locks the selected issue row;
5. assigns the event once with algorithm, version, fingerprints, release state, and issue;
6. upserts the event's variant and release membership;
7. recomputes issue, variant, and release aggregates from assigned events;
8. evaluates resolution and regression using locked ordered release evidence;
9. updates the event's processing state and completes the job.

Recomputation from event assignments avoids fragile increment and decrement logic. Repeating publication for the same event is idempotent. Concurrent first occurrences converge through the issue unique key and row lock. Stale workers fail at the lease lock before any durable publication.

An event keeps its existing issue assignment for the same fingerprint algorithm and version. Moving events between versions, merging issues, splitting issues, and previewing movement remain part of the later re-fingerprinting work.

Representative selection prefers the event with the highest bounded grouping quality, then the earliest received timestamp, then UUID for a deterministic tie break. Quality counts stable resolved project frames before all other evidence. A retry cannot replace a better representative arbitrarily.

## Control API

Add bounded cursor-based routes:

- `GET /api/v1/projects/{project_id}/issues`;
- `GET /api/v1/projects/{project_id}/issues/{issue_id}`;
- `PUT /api/v1/projects/{project_id}/issues/{issue_id}/resolution`;
- `DELETE /api/v1/projects/{project_id}/issues/{issue_id}/resolution`.

List and detail responses include stable issue path, algorithm and version, status, regression state, counts, timestamps, representative event ID, release mapping summaries, and variants. Detail includes bounded release and variant rows with deterministic ordering. Affected installations is omitted until a privacy-reviewed installation identifier exists.

Resolution accepts one release ID. The release must belong to the same organization and project and have ordered build evidence. Reopen clears the active resolution anchor and sets the current state from retained occurrence evidence. Unauthorized and cross-tenant IDs remain indistinguishable from missing resources. Responses use `Cache-Control: no-store`.

The existing event state response gains issue path, fingerprint metadata, release mapping state, and candidate release IDs as additive optional fields.

## Security and data handling

| Risk | Control | Evidence |
|---|---|---|
| False merge hides distinct defects | Conservative stable inputs, class and assertion separation, unresolved debug identities, no broad fallback | Golden split fixtures and stack-poor `insufficient` cases |
| Volatile data causes false splits | Exclude addresses, GUIDs, timestamps, source roots, lines, release IDs, and machine data | Cross-release and volatility golden tests |
| Hash ambiguity or algorithm drift | Tagged length-prefixed SHA-256 input and checked algorithm version | Golden component and digest tests |
| Cross-tenant issue or release access | Composite keys, scoped queries, local authorization boundary | Two-organization database and API tests |
| Concurrent double counting | Unique issue key, locked publication, aggregate recomputation | Concurrent worker and retry tests |
| False regression | Strict non-null unique build timestamp ordering | Missing, tied, late, same, earlier, and later release tests |
| Sensitive text duplicated into issues | Hash normalized templates and store only bounded safe titles | Hostile message, path, control character, and log inspection tests |
| Stale worker publishes grouping | Existing random lease lock covers result and grouping atomically | Expired lease publication test |

## Implementation sequence

1. Add the pure grouping crate with version constants, bounded normalization, frame classification, component hashing, variant output, titles, and golden join and split tests.
2. Extend symbolication and processing contracts with stable exception and assertion fields while retaining version 1 history compatibility.
3. Add the issue, event assignment, release candidate, variant, and release rollup schema with previous-server compatibility checks.
4. Refactor release resolution into one scoped result used by both symbol selection and publication.
5. Add lease-fenced idempotent issue publication, aggregate recomputation, representative selection, and regression transitions.
6. Add tenant-scoped issue list, detail, resolve, and reopen routes plus additive event-state fields and OpenAPI coverage.
7. Add the grouping kill switch, structured fixed-field logs, operations notes, and rollback instructions.
8. Add PostgreSQL tests for retries, concurrency, reprocessing stability, release ambiguity, late arrival, resolution, regression, tenant scope, and stale leases.
9. Extend the isolated proof with repeated and distinct fixtures across two timestamped releases, API queries, resolution, regression, variants, and exact database evidence.
10. Run focused tests, migration compatibility, `scripts/check-fast`, `scripts/check`, and `scripts/smoke`, then perform a fresh correctness and security review before opening a draft pull request.

## Verification

Unit tests prove:

- identical root causes join despite different crash GUIDs, build addresses, timestamps, source roots, and line numbers;
- different crash types, project frames, assertion templates, and unresolved debug identities split;
- GPU and OOM cases do not collapse into one broad issue;
- stack-poor unrelated events remain ungrouped;
- algorithm, version, component order, normalization, titles, and digests are golden;
- version 1 processing results remain valid historical input after version 2 is emitted.

Database and API tests prove:

- exact, missing, and ambiguous release mappings;
- one issue under concurrent first occurrences;
- exact counts after retries and concurrent publication;
- variants and releases retain representative events and first and last seen;
- late and tied releases cannot create a false regression;
- resolution followed by a strictly later occurrence reopens the same issue as regressed;
- cross-tenant issue, event, candidate, release, resolution, and representative IDs are rejected;
- a stale lease cannot publish a result, fingerprint, candidate, or issue update;
- disabling grouping keeps processing results and event states working.

The behavior proof creates two releases with distinct build timestamps, uploads the checked-in synthetic PE and PDB fixtures, and submits:

- two equivalent crashes with different GUIDs in the first release;
- one materially different known crash in the first release;
- the equivalent crash again in the second release after resolving its issue against the first release.

The proof queries the API and database to show two issues, three events under the repeated issue, one stable repeated issue ID across releases, exact variant and release counts, a deterministic representative, and `regressed` after the later occurrence. It also exercises an ambiguous release fixture and verifies that no guessed release affects regression state.

Run the pre-change server against the expanded schema and verify readiness. Run `scripts/check` and `scripts/smoke` on the final head. Use dedicated local Compose resources for proof work and remove every created container, network, volume, image, log, and scratch directory afterward.

## Rollout and rollback

Add `FAULTLANE_GROUPING_ENABLED`. Keep it disabled until the migration and worker checks pass, then enable workers before exposing issue views. Disabling it leaves crash ingestion, isolated processing, event state, symbols, and stored grouping rows intact while stopping new issue assignment and regression transitions.

Rollback disables grouping and restores the prior application build. The additive tables, columns, immutable results, fingerprints, issue assignments, and rollups remain for a corrected build. Do not delete or reverse migrated data. A later contract migration may remove unused structures only after the rollback window closes.

## Out of scope

- Manual issue merge, split, ignore-frame, or preferred-fingerprint controls
- Background re-fingerprinting or movement previews
- Project-specific normalization rules
- Automatic reprocessing after symbol upload and bulk reprocessing from #299
- Dashboard pages and readable stack presentation from #300
- Alerts, usage enforcement, billing, authentication, retention, or production deployment
- Other Unreal versions, non-Windows platforms, and cross-platform fingerprint equivalence
