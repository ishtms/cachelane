# Bounded storage retention

Issue: https://github.com/ishtms/faultlane/issues/360

Status: Locally verified on August 16, 2026

## Context

Every crash publication currently computes project-wide raw and symbol sums before checking whether enforcement or sampling needs them. On 100,000 raw objects, the current storage subquery scanned every object and took 28.661 ms, while the event and policy lookup without the sums took 0.121 ms.

The retention scheduler runs once per minute and schedules at most 100 global deletions. One project can accept 120 events per minute, so the default ceiling falls behind by 20 objects per minute, or 28,800 per day. The selector has no global due-time index.

## Acceptance criteria

- Retained raw and symbol byte totals are maintained transactionally with acceptance, symbol availability, and confirmed deletion.
- A scoped reconciliation compares maintained totals with one-time full sums under concurrent writes.
- Default non-sampling publication does not scan project object populations.
- Every raw object has an indexed deletion deadline with documented policy-change behavior.
- Schedulers claim set-based bounded batches with `SKIP LOCKED`, drain to a time budget, and can run concurrently.
- More than 200,000 due objects across projects schedule within the retention target without duplicate jobs or counter drift.
- Migration and rollout follow expand, migrate, and contract without deleting production or customer data.

## Risk and blast radius

Risk: R3.

This changes sensitive raw-artifact lifecycle behavior, storage accounting, PostgreSQL schema, and scheduler concurrency. An error can delete an object early, retain it too long, or enforce the wrong storage policy. No production environment exists, but the implementation still requires plan approval, disposable staging evidence, a kill switch, and rollback before any deletion behavior is enabled.

## Current behavior and evidence

- `record_acceptance`, `record_symbol_stored`, and `record_raw_deleted` already provide transactional points for counter deltas.
- `usage_cycle_counters` owns cycle usage, but it is not an all-time retained-byte balance.
- `crash_event_objects` has a stored-object partial index by project and creation time, not a due-time index.
- The current scheduler joins each object to a mutable project policy, orders globally by event receipt time, and stops after one 100-row batch.
- Current policy edits do not restore an object once a deletion job has already been scheduled.

## Decisions

- Add a project-scoped storage counter table instead of summing usage-ledger history or object populations.
- Add nullable `raw_delete_after` during expansion. New accepted objects receive an immutable deadline from the accepted policy snapshot. Policy edits apply prospectively. This avoids an unbounded update and avoids silently shortening an existing object's deadline.
- Backfill legacy deadlines and counters with a bounded operator command before enabling the new scheduler. Leave the column nullable until a later contract step proves coverage.
- Add `FAULTLANE_RETENTION_V2_ENABLED` as the rollout and rollback switch. Disabled mode retains the existing scheduler behavior.

## Implementation sequence

1. Add the storage counter table, nullable deadline column, due-time partial index, and migration tests without changing current reads.
2. Update raw acceptance, first project reference to a symbol object, and confirmed raw deletion to apply idempotent counter deltas in their existing transactions.
3. Read event and policy first in retention classification. Return before storage lookup unless enabled sampling and retain-all policy require the maintained counters.
4. Add a bounded backfill and reconciliation command that locks one project, fills missing deadlines in batches, computes current stored totals, and reports drift without exposing object keys.
5. Implement a set-based due claim that starts from the partial deadline index, updates lifecycle state, and inserts idempotent deletion jobs in one transaction.
6. Drain batches until empty or a fixed time budget expires. Keep the interval and batch size bounded and permit multiple scheduler instances.
7. Add migration, counter, deadline, policy, concurrent scheduler, retry, and deletion-confirmation tests.
8. Stage with 200,000 disposable due objects, verify counts and plans, exercise the kill switch and rollback, then run `./scripts/check-fast`.

## Security and operational verification

- Deadlines never become earlier after acceptance through a policy edit in this version.
- Only a confirmed object-store deletion decrements retained raw bytes.
- Replayed acceptance, symbol availability, scheduling, and deletion do not double count.
- Logs contain project IDs, batch sizes, due age, duration, drift counts, and fixed failures only. They do not contain object keys, crash content, or credentials.
- Monitor due count, oldest due age, claim rate, completion rate, counter drift, and failed deletion jobs.

## Compatibility, rollout, and rollback

The previous application ignores the additive table and column. The new application dual-runs with the switch disabled while backfill and reconciliation complete. Enable the new scheduler only after no supported object has a missing deadline and counters match full sums.

Rollback disables `FAULTLANE_RETENTION_V2_ENABLED`, stops scheduler claims, restores the prior application, and keeps all additive state for inspection. Do not delete counter rows or deadlines. Reconcile before resuming either scheduler.

## Completed evidence

- Raw acceptance, unique symbol publication, and confirmed raw deletion maintain project byte totals in their existing transactions. Concurrent deletion, symbol publication, and reconciliation finished with exact full-sum totals and zero drift.
- A 1,000,000-object fixture used indexed event and raw-object lookups with no aggregate or population scan. The production publication query completed in 0.192 ms.
- Four concurrent schedulers claimed 200,002 due objects across two projects in 59.882 seconds at 3,339 objects per second. The due index was selected, jobs were unique, and reconciliation reported zero drift.
- The real `reconcile-storage` command ran against a fresh migrated database and returned zero missing deadlines and zero raw or symbol drift.
- The existing quota sampling regression, strict Clippy, and `./scripts/check-fast` passed on the final issue tree.

## Out of scope

- Customer-requested deletion and legal erasure workflows
- Symbol deletion, which is not implemented yet
- Retention changes for normalized metadata
- Production deployment or production credentials
- Removing legacy columns or code in the same milestone

## Approval

Ishtmeet Singh approved this plan on August 15, 2026, including immutable prospective deadlines, counter authority, scheduler concurrency, the rollout switch, staging proof, and rollback.
