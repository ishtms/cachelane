# Isolated worker operations

Set `FAULTLANE_ISOLATED_PROCESSING_ENABLED=true` only after migrations are applied and `FAULTLANE_PROCESSOR_IMAGE` names a locally available processor image. The worker resolves the tag once and runs the resulting immutable image ID. Symbol upload also requires isolated processing to be enabled.

Local development builds the image and starts the worker through `./scripts/dev`. A direct startup sequence is:

```text
docker build -t faultlane-processor:dev -f deploy/processor/Dockerfile .
cargo run --package faultlane-server -- migrate
cargo run --package faultlane-server -- worker
```

Readiness requires PostgreSQL, private object storage, Docker, and a valid processor image. Do not give processor containers network access, host sockets, or credentials. Monitor pending and expired jobs, retry counts, quarantined events and artifacts, derived-cache failures, worker heartbeat age, processor duration, and owned scratch growth. Logs contain only internal IDs, states, durations, versions, and fixed error codes.

Each processor container is labeled with the deployment scope, job ID, and random lease token. Workers reconcile containers in their own deployment scope at startup and every 30 seconds. A container is removed only when its exact job and token no longer hold an unexpired lease. The matching attempt directory is removed only after its name is validated from those internal identifiers.

The scratch root and every attempt directory are private. A new root receives a FaultLane ownership marker before use, and startup refuses to change or reuse an existing directory without that exact marker. Unix permissions are `0700`. On Windows, startup removes inherited access and grants full control only to the current service identity and `SYSTEM`; startup fails if the ACL cannot be applied and verified. After an unclean shutdown, start a worker against the same database and scratch root to reconcile abandoned containers and directories.

Object-store failures return a job to bounded backoff without changing customer-visible results. A database outage can leave a job leased until its recorded lease expires because no durable transition is possible while PostgreSQL is unavailable. After recovery, the same or another worker claims the expired lease, and token checks reject publication by the old attempt.

Rollback sets `FAULTLANE_ISOLATED_PROCESSING_ENABLED=false`, which keeps the API available but disables symbol-upload routes in the current build, stops workers and their owned processor containers, and restores the previous application build. The migration is additive. Original objects, pending jobs, results, and derived caches remain available for a corrected worker. Do not remove queue rows or objects during rollback.

## Reprocessing rollout

Apply migrations and start the current API and worker with `FAULTLANE_REPROCESSING_ENABLED=false`. Confirm normal crash processing, artifact publication, and queue health before enabling the flag on both roles. New crash jobs retain priority 100. Reactivated crash jobs use priority 200, and the worker schedules at most one request page after every 20 ordinary jobs or when the queue is idle.

The flag prevents manual request creation and stops workers from selecting requests or reactivating event jobs. Progress reads remain available. Exact symbol waiters and automatic requests may still be recorded while disabled so an artifact arrival is not lost.

To roll back, disable reprocessing before restoring the prior application and worker. Leave the additive schema, request rows, generations, waiters, jobs, raw objects, and immutable results in place. A prior worker understands the reused `process_crash` job and ignores the new request tables. When the current worker returns, it reconciles unfinished request events whose canonical job was completed by an older worker.

## Issue rollup repair

Run a full issue rollup rebuild only when operator checks find drift:

```text
faultlane-server repair-issue --organization-id <organization-uuid> --project-id <project-uuid> --issue-id <issue-uuid>
```

The command requires `DATABASE_URL`, locks one tenant-scoped issue, rebuilds its issue, variant, and release counts in one transaction, and prints only the repaired event, variant, and release counts. It scans that issue's events, so do not run it as routine publication work. A failure rolls back the complete repair.
