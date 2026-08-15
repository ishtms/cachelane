# Bounded dashboard reads and search

Issue: https://github.com/ishtms/faultlane/issues/363

Status: Waiting for #358 and #359

## Context

One overview request runs separate scans over the same event population for totals, days, releases, platform and architecture, crash type, symbolication, ingest health, processing states, and observed usage. Each statement has a two-second timeout. At the default ingest ceiling, one project can have about 5.18 million events in the 30-day window.

Issue search preserves arbitrary contains matching with leading and trailing wildcards over issue titles and event search documents. Neither column has a search index. The live schema inspection confirmed that `crash_event_search` has only its tenant and event primary key.

## Acceptance criteria

- Overview totals and distributions read bounded daily project rollups instead of repeating raw-event scans.
- Current-cycle usage reads authoritative usage counters.
- Late processing and reprocessing move rollup counts exactly once between old and new dimensions.
- A bounded reconciliation command compares and repairs one project and date range.
- Search uses an indexed PostgreSQL representation with documented token behavior for titles, functions, modules, messages, and comments.
- Every rollup and search query retains organization and project scope.
- Five million project events remain below the two-second statement timeout with bounded buffer reads under concurrent overview refreshes.
- One million search documents return common and no-match terms with an index-backed plan below the timeout.

## Risk and blast radius

Risk: R2.

The change adds rollup and search schema, changes overview read sources, and changes search from arbitrary substring matching to explicit token matching. Incorrect deltas can show wrong counts, and an incorrect search query can miss results or cross tenant boundaries. Raw events remain authoritative and no data is deleted.

## Current behavior and evidence

- The PRD calls for daily rollup tables and a p95 issue-list target below 500 ms.
- `load_overview` performs the repeated raw scans serially inside one repeatable-read transaction.
- `usage_cycle_counters` already owns accepted current-cycle event and byte totals.
- Publication already derives the release, platform, architecture, crash type, symbolication state, and processing state needed for rollup deltas.
- Existing search tests use meaningful tokens such as `second::Root()` and `second player`; they do not require arbitrary mid-token substring behavior.

## Decisions

- Add a generic project daily count table keyed by organization, project, UTC day, dimension, and normalized key. Supported dimensions are event total, release, platform and architecture, crash type, symbolication state, and processing state.
- Maintain new-event and processing deltas in the existing acceptance and publication transactions. Raw events remain the repair source.
- Use PostgreSQL `simple` full-text vectors with GIN indexes for issue titles and event search text. Search is case-insensitive token matching, punctuation separates tokens, and all supplied tokens must match. Punctuation-only input returns no matches.
- Keep raw overview queries behind a rollout switch until backfill and reconciliation agree.

## Implementation sequence

1. Add the daily rollup table, tenant constraints, dimension checks, and indexes. Add nullable full-text vector columns and GIN indexes without changing current reads.
2. Increment acceptance totals and initial states once. During publication or reprocessing, apply one decrement and increment for each changed dimension using the before and after event state.
3. Change overview queries to aggregate at most the requested day and dimension rows. Use usage-cycle counters for authoritative cycle values and targeted indexes for remaining health reads.
4. Populate full-text vectors on issue title changes and event search publication. Replace `ILIKE` predicates with scoped `@@` queries built through `plainto_tsquery('simple', $n)`.
5. Add `faultlane-server repair-project-rollups` with required project and date bounds. It rebuilds bounded days transactionally and can also backfill missing search vectors in bounded batches.
6. Backfill disposable scale fixtures, reconcile raw and rolled-up values, then enable bounded reads through `FAULTLANE_DASHBOARD_ROLLUPS_ENABLED`.
7. Add transition, late publication, reprocessing, drift repair, search semantics, pagination, timeout, concurrency, and tenant-isolation tests.
8. Run five-million-event overview and one-million-document search proofs with `EXPLAIN (ANALYZE, BUFFERS)`, then run `./scripts/check-fast`.

## Tests and operational verification

- Rollup tests cover acceptance rollback, unknown to known dimensions, release change, processing failure and recovery, and replay.
- Reconciliation tests introduce scoped drift and prove exact repair without changing another tenant or date range.
- Search tests cover function punctuation, mixed case, multiple terms, comments, modules, no-match, punctuation-only input, tenant isolation, and pagination cursors.
- Load proof records per-statement duration, buffers, pool wait, response time, and result equality with raw queries.

Monitor rollup lag, reconciliation drift, overview statement duration, timeout count, search duration, and search-vector backlog. Do not log search documents, comments, or query text.

## Compatibility, rollout, and rollback

Schema additions are backward compatible. Older applications ignore them. New writes dual-populate while reads remain on the old path. Enable rollup reads only after backfill and reconciliation pass for the staged projects.

Rollback disables `FAULTLANE_DASHBOARD_ROLLUPS_ENABLED` and restores raw reads. Keep rollup rows and vectors for inspection and repair. Token-search behavior must be documented in the API and UI before enabling it.

## Out of scope

- Elasticsearch, ClickHouse, or another datastore
- Arbitrary substring search
- New dashboard widgets or filters
- Partitioning and pruning policies for long-term history
