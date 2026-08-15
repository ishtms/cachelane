# Bounded crash publication

Issue: https://github.com/ishtms/faultlane/issues/359

Status: Locally verified on August 15, 2026

## Context

Every grouped publication currently deletes and rebuilds issue variant and release rows, then scans the same issue again for its aggregate. It does this for unchanged reprocessing too. Publication also awaits one SQL statement per context facet, release candidate, and missing-symbol waiter, with up to 4,096 waiters while the job, project, event, and issue locks are held.

On a disposable 100,000-event single-issue fixture, the three corrected-form aggregate scans took 374.419 ms, 115.883 ms, and 86.773 ms. They read the same 5,556 event buffers and spilled ordered aggregates to temporary storage. This cost repeats for every new event.

## Acceptance criteria

- A first durable grouping applies one issue, variant, and matched-release delta exactly once.
- Retries and unchanged reprocessing apply no rollup delta.
- A changed release assignment removes the old release delta, applies the new one, and keeps chronology and representatives exact.
- Representative selection remains deterministic by grouping quality, received time, and event ID.
- Full recomputation exists only behind a bounded operator command for repair.
- Context facets, release candidates, and symbol waiters use one set-based statement per collection.
- A 100,000-event hot issue publishes its next event without scanning prior issue events.
- The maximum valid 4,096 waiters, 32 facets, and release candidates persist exactly and remain idempotent well inside the lease duration.

## Risk and blast radius

Risk: R2.

The change affects grouping counts, representatives, release chronology, reprocessing, and publication transaction length. Incorrect deltas can corrupt issue summaries. The blast radius is the worker, grouping tables, a small additive index migration, the server command surface, and PostgreSQL tests. Raw artifacts and tenant authorization do not change.

## Current behavior and evidence

- `recompute_issue` locks the issue, rebuilds `issue_variants`, rebuilds `issue_releases`, and recomputes the issue aggregate.
- `apply_grouping` already distinguishes a first assignment from an event that is durably grouped, which provides the idempotency boundary.
- Reprocessing can change release mapping before the grouped-event early return.
- Uniqueness keys already support variant, release, waiter, and facet set operations.
- The existing issue-event index can support targeted representative lookup after a release delta, but it does not make full rebuilds constant cost.

## Implementation sequence

1. Carry the event's prior grouping, variant, release state, and representative inputs through the publication transaction.
2. On first grouping, atomically create or lock the issue and increment its aggregate once. Upsert the variant and matched-release rows with the same event delta.
3. On a release change, decrement or remove the old release row, increment the new row, and use a targeted ordered lookup only when a departing event was the representative.
4. Recompute issue release chronology from the bounded release-rollup rows, not crash events.
5. Add only the index needed for deterministic replacement lookup when a release representative moves.
6. Add `faultlane-server repair-issue` with required organization, project, and issue IDs. It performs one explicit transactional rebuild, reports fixed counts only, and does not run on ordinary publication.
7. Replace collection insert loops with typed array `UNNEST` statements while keeping existing cardinality, byte, tenant, and conflict bounds.
8. Add failure, concurrency, retry, release-change, representative, and maximum-payload tests, then run the focused scale proof and `./scripts/check-fast`.

## Tests and operational verification

- PostgreSQL tests cover two first events racing for one fingerprint, stale leases, replay, unchanged reprocessing, release reassignment, and representative replacement.
- Repair tests introduce controlled drift, repair one scoped issue, and prove unrelated tenants and issues do not change.
- Maximum collection tests assert exact rows and a fixed number of collection statements by construction.
- The 100,000-event proof records buffer reads and confirms the next publication touches only the event, issue, variant, and release rows needed for its delta.

## Data, security, compatibility, rollout, and rollback

The migration is additive and keeps existing rows readable by the previous worker. All delta and repair queries retain organization and project scope. Customer-controlled result arrays keep their current size and byte limits.

Roll out after #358 with grouping enabled against disposable PostgreSQL data. Reconcile fixture rollups before enabling concurrent same-project claims in #361. Rollback restores the full recomputation code, leaves the additive index, and runs the repair command for issues changed by the new implementation.

## Completed evidence

- First grouping now applies one issue, variant, and matched-release delta. Unchanged reprocessing changes no rollup, while release reassignment removes the old membership and applies the new one with exact bounds and representatives.
- Context facets, release candidates, and symbol waiters use one typed `UNNEST` statement per collection. A maximum fixture persisted 32 facets, 101 candidates, and 4,096 waiters exactly, including an idempotent retry, in 2.38 seconds for the complete focused test.
- `faultlane-server repair-issue` rebuilt a deliberately drifted tenant-scoped fixture and returned `{"events":1,"variants":1,"releases":0}` through the real binary.
- On a 100,000-event issue, the next publication completed in 134.929 ms and an unchanged retry completed in 43.827 ms. Concurrent publications and concurrent unchanged retries kept the count exact. The representative lookup used the additive index with four buffers and 0.069 ms execution time.
- All 26 PostgreSQL-backed server tests and `./scripts/check-fast` passed on the final issue tree.

## Out of scope

- Manual issue merge or split
- Re-fingerprinting events into another issue
- A new queue, service, or datastore
- Changing grouping or release semantics
