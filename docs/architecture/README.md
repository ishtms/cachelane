# Architecture

FaultLane is a modular monolith. API, ingest, worker, scheduler, and migration roles share one Rust codebase. PostgreSQL stores tenant and product state, S3-compatible object storage holds large binary artifacts, and Next.js provides the dashboard.

## Durable boundaries

- Treat crash bundles, minidumps, logs, comments, and symbols as sensitive untrusted input.
- Parse and symbolize hostile artifacts across the isolated processor boundary.
- Scope every row, object, job, and cache access to its organization and project.
- Make ingest, publication, reprocessing, alerts, and cleanup idempotent and safe to retry.
- Use leased jobs with bounded work, stale-owner protection, and explicit failure states.
- Keep database changes backward compatible across a deployment window using expand, migrate, and contract.
- Keep large artifacts out of PostgreSQL and keep object keys opaque and tenant-scoped.
- Keep external integrations behind bounded adapters with fixed error handling and no sensitive payload logging.

Add another deployment boundary only after measurements show the modular monolith cannot meet an accepted requirement. Record lasting exceptions and tradeoffs under `docs/decisions`.
