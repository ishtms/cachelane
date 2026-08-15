# Fair crash backlog processing

Issue: https://github.com/ishtms/faultlane/issues/361

Status: Locally verified on August 16, 2026

## Context

Each worker claims and completes one job before polling again. The claim query also rejects every candidate from a project that already has one unexpired lease. A disposable proof with ten pending jobs showed worker one leasing a job and worker two receiving no candidate, leaving one leased and nine pending.

A crash storm is normally concentrated in one project. With a 150-second processor wall limit, the fixed project concurrency of one prevents horizontal scaling and can let accepted work outpace processing.

## Acceptance criteria

- Each worker runs a configured bounded number of jobs concurrently.
- PostgreSQL enforces a configured bounded number of active leases per project.
- Lease fencing, stale-publication rejection, target locks, retry state, cancellation, reconciliation, and processor isolation remain intact.
- Claim indexes match queue priority and availability order.
- Several workers reach the configured same-project concurrency on at least 10,000 hot-project jobs without duplicate publication.
- A second project advances within a bounded interval while the hot project remains backlogged.
- Measured sustained drain capacity exceeds configured ingest and retry rates.

## Risk and blast radius

Risk: R3.

This increases simultaneous untrusted processor containers and changes database connection, CPU, memory, scratch, and object-store demand. Incorrect bounds can exhaust the host or database, while incorrect concurrency can duplicate publication. Per-container security limits remain unchanged, but total host capacity and rollout defaults require approval and staging evidence.

## Current behavior and evidence

- `Worker::run_loop` awaits one `run_job` before another claim.
- `claim_job` locks the project and uses `NOT EXISTS` to enforce one active project lease.
- The pending index orders by availability before priority, while the query orders by priority before availability.
- Existing random lease tokens, heartbeat renewal, final publication locks, and processor ownership labels provide the required fencing primitives.
- Incremental issue rollups from #359 are required before same-project publication can scale usefully.

## Decisions

- Keep the modular worker and PostgreSQL queue. Do not add a broker or service.
- Add explicit worker and per-project concurrency settings with conservative defaults and hard upper bounds.
- Keep the project-row lock in claim selection so concurrent claimers enforce the per-project limit atomically.
- Keep all existing per-container CPU, memory, disk, process, network, and wall-time limits unchanged.

## Implementation sequence

1. Parse and validate bounded worker and per-project concurrency settings at startup. Size the database pool from the accepted worker bound plus claim and heartbeat headroom.
2. Replace the single awaited job with a bounded task set that continues claiming while capacity is available and drains cleanly on shutdown.
3. Change the project gate from zero active leases to an atomic count below the configured limit while retaining project-row serialization and `SKIP LOCKED` fairness.
4. Correct the pending claim index order and recheck expired-lease selection with representative backlog statistics.
5. Keep one heartbeat and cancellation path per job. Ensure shutdown stops new claims, cancels owned processors, and releases or expires each lease safely.
6. Add deterministic claim, lease, stale publish, shutdown, processor ownership, pool exhaustion, and two-project fairness tests.
7. Run a multi-worker synthetic processor proof with 10,000 hot-project jobs and a smaller second project. Record concurrency, throughput, queue age, database connections, CPU, memory, and scratch use.
8. Run `./scripts/prove-isolated-processing` and `./scripts/check-fast`.

## Security and operational verification

The processor still has no network, credentials, host sockets, or writable host filesystem beyond its owned scratch attempt. Staging must show that the configured worst case fits host CPU, memory, scratch, Docker, database pool, and object-store request budgets.

Logs and metrics include configured bounds, active global and project jobs, claim latency, queue age, lease loss, processor duration, and cancellation. They do not include artifact contents or customer identifiers beyond existing internal IDs.

## Compatibility, rollout, and rollback

Old workers and new workers can share the queue because lease fields and fencing remain compatible. Start with both bounds at one, then raise them only in disposable staging after #359 is verified. No hosted or production rollout is part of this issue.

Rollback sets both bounds to one or restores the prior worker. Existing jobs, attempts, leases, results, and objects remain. Wait for or expire active leases before reducing worker instances.

## Verification evidence

- Settings default to one, reject values outside one through eight, and size each worker pool to two connections per active job plus four. The focused settings test passed with a maximum pool size of 20.
- Three synthetic workers with six total slots drained 10,100 jobs in 110.123 seconds at 91 jobs per second. The second project claimed work in 202 milliseconds before any hot-project completion, hot-project concurrency reached and never exceeded four, and every job completed once at attempt one.
- The measured rate exceeds the disposable project ingest setting of 120 requests per minute plus the four-slot minimum-backoff retry ceiling.
- Focused claim, lease, stale-publication, concurrent-publication, retry, resource-quarantine, shutdown, and pool-pressure tests passed.
- `./scripts/prove-isolated-processing` passed with two real worker processes and same-project concurrency two. It also verified the processor boundary, resource limits, storage and database outage recovery, lease fencing, owned cleanup, publication, and runtime smoke behavior.
- The runtime configuration permits at most four processors using four CPUs, 8 GiB memory, and 256 MiB scratch. The disposable Docker host reported 24 CPUs and about 16 GiB memory.
- `./scripts/check-fast` passed on the final issue tree.
- No hosted or production rollout was performed. Rollback remains resetting both concurrency settings to one after active leases finish or expire.

## Out of scope

- Changing per-container security limits
- Adding a broker, service, or datastore
- Autoscaling or production infrastructure
- Reordering ordinary work ahead of higher-priority jobs

## Approval

Ishtmeet Singh approved this plan on August 15, 2026, including the concurrency defaults and hard bounds, pool sizing, host-capacity staging criteria, rollout sequence, and rollback.
