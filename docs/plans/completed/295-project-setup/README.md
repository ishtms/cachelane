# Project creation and write-only crash URLs

Issue: [#295](https://github.com/ishtms/cachelane/issues/295)

Status: Completed through PR #342 on August 13, 2026. No production deployment was performed.

## Outcome

When a bootstrap administrator uses the setup page, CacheLane creates an account, organization, and project, then shows one generated UE 5.8 `DataRouterUrl` whose key is recognized only by the ingest authorization boundary.

## Context

M0 is complete. The Rust server currently exposes health routes only, the Next.js app is a static landing page, the OpenAPI document contains health operations, and `migrations/` is empty. Docker Compose already provides PostgreSQL 17.6, but the workspace has no database client, migration runner, credential generator, or tenant repository.

Issue #295 is the dependency root for durable ingest, symbol upload, hosted authentication, and the rest of M1. It is R3 because it introduces tenant data, authorization, persistent credentials, database migrations, public API contracts, and a setup UI.

Two issue dependencies need an explicit interpretation before implementation:

- #295 assumes an authenticated actor, while full GitHub and email authentication belongs to #310 and #310 currently depends on #295.
- #295 asks its proof to submit to the ingest route, while durable crash acceptance belongs to #296. CacheLane must not return a successful ingest response before raw data and the processing job are durable.

The proposed resolution is a loopback-only bootstrap administrator adapter for local and staging proof. It creates the first user record and supplies an authenticated actor to the same Rust authorization boundary that #310 will later use. The generated ingest key can be resolved by the ingest authorization capability, but `POST /u/{key}` does not return success until #296 implements durable persistence.

## Acceptance criteria

- An explicitly enabled bootstrap administrator can create the first user, organization, Owner membership, and project through the versioned Rust API and the Next.js setup page.
- Creation returns the raw ingest key and complete UE 5.8 `DataRouterUrl` once. Database rows contain only a hash and a short non-secret display suffix.
- The setup page renders copyable `Config/DefaultGame.ini` and `Config/DefaultEngine.ini` snippets, including `IncludeCrashReporter=True`, `bSendLogFile=true`, and the configured ingest base URL.
- An Owner can create an overlapping replacement ingest key and revoke either key without deleting the project.
- Revoked, malformed, and unknown ingest keys do not resolve. Responses remain indistinguishable and never echo the supplied key.
- An ingest key is rejected by every control API route and cannot be used as bootstrap or user authorization.
- Every user, membership, project, and key query is scoped by organization and project. Cross-organization identifiers return the same not-found response as absent identifiers.
- Repeated setup requests do not create another bootstrap owner or reveal the original key.
- Existing health routes and M0 commands remain unchanged.
- `POST /u/{key}` does not acknowledge a crash in this issue. Successful durable submission remains acceptance criteria for #296.

## Risk and blast radius

Risk: R3.

The change affects authentication, authorization, tenant isolation, credential lifecycle, PostgreSQL schema, API contracts, and browser-visible setup data. A defect could expose a write key, let a key cross into the control plane, create cross-tenant access, or leave the database incompatible with a prior application revision.

The initial rollout remains local and staging-only. It does not configure a hosted provider, expose a public environment, access production credentials, or deploy production. Hosted authentication remains blocked on #310.

## Current behavior and evidence

- `cachelane-server api` and `cachelane-server ingest` use the same Axum router and expose only health routes.
- `cachelane-server migrate` logs a placeholder message and does not connect to PostgreSQL.
- `migrations/` contains no schema.
- `openapi/cachelane.yaml` defines only health operations.
- The web app has no forms, API client, authentication state, or behavior-test harness.
- Docker Compose and `.env.example` already define local PostgreSQL and service URLs.
- `ARCHITECTURE.md` makes PostgreSQL authoritative for users, organizations, memberships, projects, and credentials. It requires authorization in Rust and organization plus project scope on every row access.
- The threat model requires write-only project keys, hashing at rest, rotation, revocation, and tenant isolation.
- The workspace has no existing PostgreSQL, secure random generation, key hashing, UUID, or browser behavior-test dependency that can implement these requirements.

## Proposed design

### Authentication boundary

Add one Rust `AuthenticatedActor` boundary used by control handlers and application behavior. The first adapter accepts a high-entropy bootstrap administrator secret only when bootstrap auth is explicitly enabled and the API is bound to loopback. The secret comes from environment configuration, is never placed in a URL or response, and is compared through a fixed-size digest without logging either value.

The bootstrap setup operation is one-time. It creates the first user and Owner membership transactionally. Later requests resolve the configured bootstrap identity to that stored user. #310 adds hosted sessions, OAuth, email authentication, invitations, roles, and audit history without changing project authorization rules.

### Persistence

Add the smallest persistence capability needed by the server, backed by the existing PostgreSQL decision. Use additive forward migrations for:

- `users`;
- `organizations`;
- `organization_memberships` with an initial `owner` role;
- `projects` with an organization-scoped unique slug;
- `project_ingest_keys` with organization and project scope, hash, display suffix, creation time, and nullable revocation time.

Use database constraints and composite references where practical so a project key cannot reference a project from another organization. Application queries still include actor, organization, and project scope. PostgreSQL row-level security is deferred until the hosted connection and identity model exists, but it must be reconsidered before customer data is hosted.

The workspace currently lacks a PostgreSQL client and cryptographic credential primitives. The implementation may add only the focused crates required for Tokio-compatible PostgreSQL access and migrations, UUID values, operating-system randomness, URL-safe encoding, SHA-256 hashing of high-entropy keys, and constant-time bootstrap-secret comparison. Password hashing is not needed because this issue does not implement password authentication.

### Ingest keys

Generate at least 256 bits from the operating-system random source. Prefix the encoded value with a fixed CacheLane key marker so accidental misuse is recognizable. Hash the complete key before insertion and zero or drop the raw value after the one response is serialized. Never implement lookup by filename, user-supplied project ID, or a stored plaintext prefix.

Rotation creates a new active key so a developer can update packaged builds without downtime. Revocation is a separate idempotent operation. List and setup responses expose key IDs, creation and revocation state, and a short suffix, never a recoverable key.

### API and UI

Keep business and authorization rules in Rust. Add versioned control operations for one-time setup, project setup retrieval, key creation, and key revocation. Add a private ingest-key resolver used by the ingest role and behavior tests, but do not add a successful crash-ingest response in this issue.

Update the checked-in OpenAPI contract with stable request, response, and error schemas. Secrets must be marked write-only and appear only in creation responses.

Add a focused Next.js setup route that calls the Rust API, displays the one-time URL, and renders exact UE 5.8 configuration. It must not persist the raw key in browser storage, analytics, logs, URLs, or build output. A refresh shows key metadata and offers rotation instead of redisplaying the secret.

## Security analysis

| Threat | Required control | Evidence before review |
|---|---|---|
| Ingest key used as an administrative token | Separate credential types and middleware, with no shared fallback | Negative API tests for every control route |
| Plaintext key disclosure at rest | 256-bit random key, one-time response, SHA-256 digest storage | Database assertion and response snapshot |
| Secret disclosure through logs or errors | Fixed error codes, no request-token tracing, redacted credential types | Captured tracing and malformed-key tests |
| Cross-organization access | Actor, organization, and project predicates plus database constraints | Two-organization integration tests for read and mutation paths |
| Bootstrap adapter exposed remotely | Explicit enable flag, required secret, loopback binding check, disabled default | Startup failure tests for unsafe combinations |
| Replayed setup creates another owner | Transactional one-time guard and stable conflict error | Concurrent setup integration test |
| Key rotation causes downtime | Add new active key before explicit old-key revocation | Overlapping-key behavior test |
| Revoked key remains usable | Revocation checked during digest lookup in the same query | Resolver test before and after revocation |
| Browser retains the raw key | Render from the creation response only, no local storage, cache disable headers | Browser test plus storage and refresh assertions |
| Migration blocks rollback | Additive tables only, no destructive reverse migration | Old application health check against expanded schema |

## Implementation sequence

1. Record human approval of this plan, including the bootstrap adapter, ingest-proof boundary, and staging interpretation.
2. Update #295 acceptance criteria to match the approved boundary, move it to Ready, then claim it and move it to In Progress.
3. Add the constrained persistence and credential dependencies with license and Rust-version checks.
4. Add additive migrations, the migration command, and persistence integration tests.
5. Add credential types, one-time setup behavior, tenant-scoped project queries, key rotation, revocation, and the ingest-key resolver.
6. Add Axum authentication and control routes with stable errors, then update OpenAPI.
7. Add the setup page and browser behavior tests without browser-side secret persistence.
8. Run focused tests, the actual API and UI proof, `bash scripts/check-fast`, `bash scripts/check`, and `bash scripts/smoke` on the final head.
9. Collect staging-equivalent evidence, perform a fresh security review, and keep the pull request unmerged until every R3 gate passes.

## Verification and staging evidence

Unit and integration tests must cover validation, slug uniqueness, transaction rollback, digest-only storage, one-time display, concurrent setup, overlapping rotation, idempotent revocation, malformed and revoked keys, credential-type separation, and two-organization isolation.

API behavior tests must exercise the real Axum router with PostgreSQL. Browser tests must create the project through the actual setup page, inspect the generated snippets, confirm refresh does not reveal the key, rotate it, revoke it, and verify browser storage remains empty.

Because the repository has no hosted staging target, the proposed staging evidence is an isolated Docker Compose project with unique ports and volumes:

1. bootstrap a clean PostgreSQL instance;
2. apply migrations through `cachelane-server migrate`;
3. start the API and web roles on loopback with bootstrap auth explicitly enabled;
4. create a project through the setup page;
5. verify only the digest and suffix exist in PostgreSQL;
6. resolve both overlapping ingest keys through the ingest authorization boundary;
7. prove the ingest key cannot access control routes;
8. revoke one key and prove it no longer resolves;
9. run health, smoke, restart, and old-application compatibility checks;
10. destroy only the isolated test volumes after evidence is recorded.

Human approval must state whether this local isolated environment satisfies the R3 staging gate. If hosted staging is required, implementation remains blocked because no hosted deployment target exists.

### Completed staging evidence

The approved local staging gate passed on August 13, 2026:

- The isolated `cachelane295staging` Compose project used dedicated PostgreSQL, MinIO, network, volumes, and ports. No shared or production resource was used.
- `cachelane-server migrate` succeeded twice against a clean PostgreSQL 17.6 database.
- The PostgreSQL behavior test proved concurrent setup creates one complete tenant, only the SHA-256 key digest is stored, cross-organization lookup returns not found, and a fresh server state resolves the persisted active key.
- The API, ingest, and production web processes passed `scripts/smoke` on loopback.
- Installed Chrome completed project creation, one-time key display, configuration rendering, secret-free refresh, overlapping rotation, control-route denial, revocation, and active versus revoked ingest resolution.
- Local and session storage remained empty, and the service logs contained no raw ingest key.
- The pre-change `a928409` server built and answered readiness with the expanded database configuration, which confirms the additive schema does not block application rollback.
- The dedicated containers, network, and test volumes were removed after evidence was collected.

## Compatibility, rollout, and rollback

All schema changes are additive. The prior server binary must continue to start and answer health routes against the expanded schema. New project routes remain disabled unless bootstrap auth is explicitly configured. No production or public rollout is part of this issue.

Rollback disables the project routes and bootstrap adapter, then restores the previous application artifact. Expansion tables remain in place until a later approved contract change. Generated keys may be revoked, but no table or customer data is deleted during rollback.

## Out of scope

- Successful crash acknowledgement, raw object storage, jobs, rate limits, and processing state from #296
- GitHub OAuth, email authentication, normal hosted sessions, invitations, four-role authorization, and audit history from #310
- Symbol upload, releases, grouping, worker processing, alerts, usage, billing, and public deployment
- PostgreSQL row-level security activation before the hosted identity and connection model is selected
- Production credentials, production data, deployment configuration, or cloud-provider selection

## Approved decisions

Ishtmeet Singh approved all three decisions on August 13, 2026:

1. Use the loopback-only bootstrap administrator adapter until #310 adds hosted authentication.
2. Prove the ingest key at the authorization boundary without returning successful crash acceptance before #296.
3. Treat isolated local Docker Compose evidence as the staging gate for this non-deployed change.

Any change to these decisions requires another plan review before implementation continues.
