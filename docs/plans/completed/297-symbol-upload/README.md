# Missing symbol upload for a release

Issue: [#297](https://github.com/ishtms/cachelane/issues/297)

Status: Completed through PR #345 on August 14, 2026. No production deployment was performed.

## Outcome

When a build engineer runs `cachelane symbols upload <path> --project <slug> --release <version>`, CacheLane scans Windows PE and PDB artifacts locally, uploads only missing matching artifacts, resumes interrupted multipart work, and returns deterministic release coverage.

## Acceptance criteria

- Negotiate missing artifacts by SHA-256 plus validated embedded identity.
- Create or update release metadata for version, platform, architecture, configuration, revision, channel, and build timestamp.
- Resume completed multipart parts without storing duplicate objects.
- Store uploader, CI job, release, platform, scan-relative source path, timestamp, checksum, and CLI version as provenance.
- Deduplicate only within one organization without revealing cross-organization existence.
- Return stable coverage, mismatch corrections, and validation, authorization, retryable, and internal exit codes.
- Run the CLI twice against isolated PostgreSQL and MinIO. The second run must transfer zero bytes and return the same release and coverage.

## Risk and blast radius

Risk: R3.

The change adds scoped credentials, organization and project data, a PostgreSQL migration, direct object-store uploads, release metadata, and a public API contract. Failures could expose artifact existence across tenants, publish mismatched symbols, leak a credential or presigned URL, orphan multipart state, or block application rollback.

No production deployment, production credential, or production data is in scope. Hosted storage uses Cloudflare R2. Isolated local staging uses MinIO through the same S3-compatible protocol.

## Approved design

- Use private Cloudflare R2 buckets for hosted artifacts, MinIO locally and for self-hosting, and the S3-compatible API for both.
- Use the AWS SDK for Rust only for multipart control and presigning. Bind each part to its key, upload ID, number, byte length, `Content-MD5`, and a ten-minute expiry. Verify full SHA-256 and embedded identity before publication.
- Mint separate project-scoped artifact upload tokens through the loopback bootstrap control API. Store only a digest, return the raw token once, and support revocation. Issue #310 will replace bootstrap token management without widening token scope.
- Default the CLI platform to Windows, infer architecture, and accept explicit configuration and revision flags. Store only scan-relative paths.
- Deduplicate by validated identity and checksum inside one organization. Never expose cross-organization existence.
- Gate all new routes with `CACHELANE_SYMBOL_UPLOAD_ENABLED`.

### Architecture reconciliation

Decision 0003 requires untrusted artifact parsing to run with CPU, memory, disk, wall-time, filesystem, and network isolation. The approved #297 flow performs final PE and PDB identity verification after upload, while issue #311 owns the isolated processing worker. This change therefore refuses to enable symbol upload on a non-loopback API. Local and isolated staging verification use strict size, disk, and network bounds in the API process. Hosted activation remains blocked until #311 moves this verification step into the isolated worker. This preserves the accepted worker decision without delaying the local end-to-end upload contract needed by #311.

## Security analysis

| Threat | Control | Required evidence |
|---|---|---|
| Cross-organization artifact discovery | Scope every token, release, manifest, object, session, and query by organization and project | Two-organization API test |
| Upload token disclosure or privilege expansion | Separate credential prefix and middleware, digest-only storage, one-time response, revocation, no control-route fallback | Token storage, scope, and revocation tests |
| Presigned URL abuse | HTTPS except literal loopback, no redirects, short expiry, exact part binding, no API bearer token on object requests | CLI and signed-request tests |
| Corrupt or mismatched artifact publication | Part `Content-MD5`, provider ETag check, bounded full SHA-256 verification, existing PE or PDB scanner, transactional publication | Mismatch and malformed-object tests |
| In-process parser exposed before worker isolation | Require a literal loopback API while enabled, then move verification to #311 before hosted activation | Unsafe-host startup failure and local staging only |
| Resource exhaustion | Limits for artifact count, per-artifact and total bytes, part count, request text, network time, and private spool use | Boundary tests and complete repository check |
| Multipart replay or duplicate completion | Authoritative recorded parts, active-session uniqueness, explicit lifecycle states, idempotent completion | Resume, retry, and duplicate-completion tests |
| Database commit uncertainty | Keep the completed private object for reconciliation when publication state is uncertain | Failure recovery test and staging outage proof |
| Sensitive output | Fixed errors and stable JSON without tokens, credentials, object keys, absolute roots, or parser input | Output assertions and review |
| Rollback blocked by schema | Additive migration with feature-disabled compatibility | Previous application startup against expanded schema |

## Implementation sequence

1. Add additive tables for tokens, releases, objects, validated identities, release associations, multipart sessions, and recorded parts.
2. Add token creation and revocation through the existing bootstrap control boundary.
3. Add tenant-scoped negotiation, part signing and recording, completion verification, and coverage routes.
4. Add the CLI scan, hash, missing-only upload, resume, completion, and deterministic output path.
5. Update OpenAPI, storage decision, local configuration, README, proof script, and optional smoke coverage.
6. Run focused tests, `scripts/check-fast`, `scripts/check`, runtime smoke, isolated MinIO staging, outage recovery, and old-application compatibility.
7. Perform a fresh security review and merge only when all R3 gates pass.

## Staging evidence

Use an isolated Compose project with unique ports, database, MinIO bucket, network, and volumes. Apply migrations twice, start the API with artifact upload enabled, create a project and upload token, and run `scripts/prove-symbol-upload`. Verify the second command transfers zero bytes with unchanged release coverage. Interrupt storage and database access separately, verify safe retryable errors, restore each service, and verify completion or retry succeeds. Start the previous server revision against the expanded schema and verify readiness. Inspect the database and logs for digest-only tokens, organization-scoped provenance, and absence of raw tokens, presigned URLs, absolute roots, and object credentials.

### Completed staging evidence

The approved local staging gate passed on August 14, 2026:

- The isolated `cachelane297staging` Compose project used PostgreSQL 17.6 and MinIO `RELEASE.2025-09-07T16-13-09Z` on dedicated ports, database names, network, and volumes. No shared or production resource was used.
- Migrations succeeded twice against the clean final database.
- `scripts/prove-symbol-upload` uploaded the checked-in Windows PE and PDB fixtures. The first run transferred 648,192 bytes. The second run transferred zero bytes with the same release and coverage: two available, zero missing, zero mismatch, and ready.
- The final combined `scripts/smoke` run passed with durable ingest and symbol upload enabled against the same empty database. It stored one crash event, two artifacts totaling 648,192 bytes, two complete provenance rows, and two completed multipart sessions. Release metadata retained the staging channel and UTC build timestamp.
- Pausing MinIO produced retryable CLI exit code 4. Restoring MinIO allowed the same command to upload successfully. Starting the API while PostgreSQL was unavailable also produced exit code 4. Restoring PostgreSQL allowed the next command to complete with zero retransferred bytes and ready coverage.
- PostgreSQL contained one 32-byte upload-token digest, two complete provenance rows with relative paths, upload timestamps, CI job, and CLI version, and two completed sessions. No plaintext token column exists.
- Anonymous bucket access returned HTTP 403. The private verification spool was empty after completion. Captured service output contained only fixed startup records, with no raw token, presigned URL, object key, absolute source root, or object credential.
- The pre-change `8e080ab` server started and answered readiness against the final expanded schema.

The dedicated containers, networks, and volumes were removed after verification.

## Rollout and rollback

The migration is additive. New routes remain unavailable unless the feature flag is enabled. Rollout stops at local isolated staging for this issue.

Rollback disables artifact upload and restores the prior server and CLI artifacts. Keep completed objects, release associations, and additive tables intact. Abort or reconcile incomplete multipart sessions after rollback. Do not delete tenant data as part of rollback.

## Out of scope

- Hosted deployment or production configuration
- Normal hosted sessions, role-based token management, invitations, and audit history from #310
- Frontend release or symbol management
- Symbolication workers, issue grouping, notifications, billing, or usage enforcement
- Other platforms or Unreal versions

## Approved decisions

Ishtmeet Singh approved Cloudflare R2 for hosted artifacts, MinIO for local and self-hosted use, the separate scoped token, organization-only deduplication, the feature flag, and isolated local staging on August 14, 2026. Any material change to the provider, authorization scope, tenant boundary, staging gate, or rollback plan requires another approval.
