# Indexable UUID database lookups

Issue: https://github.com/ishtms/faultlane/issues/358

Status: Locally verified

## Context

The database audit at `a5f62e92167b8a7d575519850208f0d607c01f9c` found UUID columns cast to text in production predicates across authentication, ingest, processing, reprocessing, grouping, usage, dashboards, and alerts. A source scan found 474 predicate casts before test modules in nine server files. PostgreSQL cannot use the normal UUID B-tree key for `uuid_column::text = $1`.

On PostgreSQL 17.6 with one million `projects` rows and parallelism disabled, `id::text = $1` used a sequential scan, removed 999,999 rows, read 12,345 buffers, and took 157.773 ms. `id = $1::uuid` used the existing unique index, read four buffers, and took 0.061 ms.

## Acceptance criteria

- Every production UUID predicate, join condition, cursor, update, and delete keeps the UUID column unmodified and casts the bound value.
- UUID lists use native comparisons without adding a UUID application dependency solely for binding.
- Externally supplied UUIDs are validated before database execution and retain the existing invalid-request or not-found response instead of becoming a database error.
- Text casts remain allowed in result projections and other output formatting.
- A repository check rejects new UUID column-side casts in production SQL predicates.
- Representative one-million-row plans use UUID indexes with constant buffer reads.
- Tenant scope and existing behavior remain unchanged in every affected module.

## Risk and blast radius

Risk: R2.

This is a cross-component query rewrite. A missed cast leaves a hot path unbounded. An incorrect bound cast can turn malformed public input into a 500 response. The blast radius is the Rust server and its PostgreSQL tests. There is no schema, object-storage, external-service, or production deployment change.

## Current behavior and evidence

- The migration indexes are native UUID B-trees, including primary keys and organization/project composite keys.
- `apps/server/src/crash_ingest.rs` already contains the correct pattern `project_id = $1::uuid`.
- Existing API modules have repeated local UUID-shape validators, while the shared project authorization path does not reject every malformed project ID before SQL.
- Some batch predicates use `uuid_column::text = ANY($1::text[])`; these need an indexable conversion of the values rather than the column.
- The disposable PostgreSQL proof confirmed the plan and buffer difference at one million rows.

## Implementation sequence

1. Consolidate the existing UUID-shape validation into one server helper and apply it at public project, issue, event, rule, integration, request, release, session, invitation, and member identifier boundaries.
2. Change single-value predicates to `uuid_column = $n::uuid`, preserving organization and project scope in the same statement.
3. Change text-array predicates to compare the UUID column against values cast from `unnest($n::text[])`. Validate every public list before binding it.
4. Update cursors and lock predicates to compare native UUIDs, including lease tokens and composite pagination keys.
5. Add a focused source check in `scripts/check-repository` that scans production SQL before test modules and rejects an identifier cast to text immediately before a comparison operator.
6. Add invalid-ID behavior tests for each public route family and PostgreSQL tests for representative scoped reads, writes, locks, deletes, and array predicates.
7. Run the million-row `EXPLAIN (ANALYZE, BUFFERS)` proof with parallelism disabled, then run `./scripts/check-fast`.

## Tests and operational verification

- Source-guard fixtures cover forbidden predicates and allowed projections.
- API tests cover malformed and well-formed IDs without cross-tenant disclosure.
- PostgreSQL tests cover equality, composite scope, cursor, `ANY`-style lists, update, delete, and `FOR UPDATE` paths.
- The scale proof records plan node, rows removed, buffers, planning time, and execution time for the old and corrected forms.

No new logs are required. Existing fixed API errors remain the observable failure behavior.

## Data, security, compatibility, rollout, and rollback

Stored data and schema do not change. Tenant filters remain in the same statements. Validation accepts the existing 36-character hexadecimal UUID shape, including upper-case input already accepted by current route helpers.

Land this before the other database audit work so later queries start from the indexable form. Rollback is a code revert. There is no data migration or destructive action.

## Verification

- The source guard reduced 501 production and 652 total server predicate casts to zero.
- All 23 PostgreSQL-backed server tests passed, including malformed public identifier responses and scoped reads, writes, locks, deletes, cursors, and UUID lists.
- On one million migrated project rows with parallelism disabled, the prior predicate used a sequential scan, touched 12,345 buffers, and took 204.816 ms. The native UUID predicate used the existing index, touched four buffers, and took 0.059 ms.
- `./scripts/check-fast` passed.

## Out of scope

- Adding UUID expression indexes
- Replacing SQLx or PostgreSQL
- General query formatting or unrelated refactoring
- Changing public identifier formats
