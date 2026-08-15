# Crash and project alerts

Issue: https://github.com/ishtms/faultlane/issues/301

Status: Awaiting human approval

## Context

M1 needs project alerts for first-seen and regressed issues, volume, missing symbols, processing failures, ingest silence, and quota pressure. Rules must support email, Discord, Slack, and signed webhooks, with environment filters, quiet hours, recovery notifications, bounded retries, and visible delivery state.

The tracked product code has no alert tables, routes, worker, or web surface. It already has the prerequisite state in PostgreSQL: versioned issue grouping and regression state, event processing state and missing-symbol diagnostics, environment-scoped ingest keys and events, authoritative usage counters and thresholds, hosted project authorization, and a leased job pattern.

The authoritative sources have two known discrepancies. `docs/product/overview.md`, `PRD.md`, and `ARCHITECTURE.md` still use the former product name, and the overview still calls M0 current. GitHub milestone 11, the tracked workflow, and the application use FaultLane and show M1 in progress. This plan follows ALT-01 through ALT-05, ALT-08, ALT-09, BIL-03, the current issue, and the current repository identity.

## Acceptance criteria

- An Owner or Admin can create, list, update, and disable project-scoped email, Discord, Slack, and generic webhook integrations without receiving stored credentials back from the API.
- An Owner or Admin can configure enabled rules by environment for first-seen issues, regressions, volume thresholds, missing symbols, processing failures, ingest silence, and quota thresholds.
- Rules support a bounded daily UTC quiet window. A transition that starts and recovers entirely during the quiet window is suppressed instead of sending stale trigger and recovery messages.
- A condition transition creates one durable logical notification. Replays, concurrent evaluators, and worker retries do not create another logical delivery for the same rule, scope, generation, and state.
- Clearing an active condition creates one recovery notification. First-seen and regression conditions recover when the issue is resolved, missing-symbol and processing conditions recover after successful processing, volume and ingest-silence conditions recover when their thresholds clear, and quota conditions recover after a cycle or policy change clears the threshold.
- Email, Discord, Slack, and signed webhook payloads contain bounded project and issue metadata, fixed condition state, and authorized FaultLane links. They never contain raw bundles, logs, comments, symbols, credentials, or provider response bodies.
- Generic webhooks include a stable delivery ID, timestamp, and HMAC-SHA256 signature. Retries preserve the delivery ID.
- Delivery uses bounded connect and request timeouts, bounded attempts with backoff for definite transient failures, terminal failure codes for permanent failures, and `delivery_unknown` for an ambiguous post-dispatch timeout.
- Customer-controlled HTTP destinations use HTTPS, reject credentials and fragments, reject redirects, resolve and pin only public addresses for each attempt, and cannot reach loopback, private, link-local, multicast, documentation, or other reserved networks.
- Discord and Slack URLs are restricted to their documented HTTPS webhook hosts and path shapes. Email recipients must be current organization members rather than arbitrary addresses.
- Discord, Slack, and generic webhook credentials are encrypted before PostgreSQL storage with authenticated encryption. The encryption key is required only when alerts are enabled, is loaded from a secret file or environment value, and is never stored or logged.
- Every query, condition, delivery, integration, rule, audit entry, and link is scoped to the same organization and project. Cross-project identifiers return not found.
- API responses expose stable rule, condition, and delivery states plus fixed failure codes. Logs contain internal IDs, adapter kind, attempts, duration, and fixed result codes only.
- The OpenAPI contract, web settings flow, focused behavior tests, adapter tests, and an end-to-end proof cover all rule kinds, all four adapters, recovery, quiet hours, concurrency, retry, redaction, authorization, and tenant isolation.
- `./scripts/check-fast` passes and the issue diff remains limited to alert behavior and its required plan, migration, API, worker, web, proof, and configuration changes.

## Risk and blast radius

Risk: R3.

This change stores outbound integration credentials, adds customer-controlled network destinations, extends authorization and public API surfaces, adds background delivery, and adds PostgreSQL schema. A defect could disclose a credential, enable server-side request forgery, send a cross-tenant link, duplicate notifications, or let an alert backlog affect crash processing.

The blast radius is the control API, web settings, worker and scheduler roles, PostgreSQL, outbound email and webhook traffic, and local or future hosted configuration. It does not change raw artifact storage, parser isolation, symbol contents, billing provider state, production infrastructure, or production deployment. No hosted environment currently exists.

## Current behavior and evidence

- GitHub has no direct dependency records for #301. Its stated prerequisites are present on `origin/main`: issue grouping and regression state, processing state, usage thresholds, and project authorization.
- Issue #301 is assigned to `ishtms`, belongs to M1, and is In Progress. #303 and #313 remain Backlog. There is no open pull request or milestone branch on the remote.
- `apps/server/src/project_setup.rs` composes the API routes and shared server state. There is no alert module or route.
- `apps/server/src/auth.rs` allows Owner and Admin roles to manage a project. The alert settings can reuse that existing permission instead of adding a new role model.
- `apps/server/src/worker.rs` uses PostgreSQL leases, idempotency keys, bounded retries, and fixed failure codes for crash and artifact jobs. Older workers claim every row in the existing `jobs` table and reject unknown job types, so alert delivery must use its own additive queue table to remain safe during rollback.
- `apps/server/src/usage.rs` owns authoritative 70, 90, 100, and courtesy-exhausted thresholds and the scheduler role. It does not emit alert transitions.
- Grouping publication already determines first-seen and regression state in one transaction. Processing publication and terminal job paths already determine missing-symbol and processing-failure state.
- The workspace already uses `reqwest`, `hmac`, `sha2`, `getrandom`, `ipnet`, `url`, PostgreSQL, and Tokio. Existing credentials are hashed because they never need to be recovered. Reversible integration credentials require a focused authenticated-encryption dependency because the current stack cannot decrypt them safely.
- The existing email sign-in adapter uses `FAULTLANE_EMAIL_DELIVERY_URL` and `FAULTLANE_EMAIL_DELIVERY_TOKEN`. Alert email delivery should reuse that provider configuration and transport behavior.
- The threat model names malicious webhook destinations, integration-secret disclosure, stored script payloads, and cross-tenant references as required controls. The PRD also requires alert fan-out to remain isolated from event processing.

## Data model

Add one backward-compatible migration with these project-scoped tables:

- `alert_integrations`: adapter kind, display name, optional member recipient, encrypted configuration, nonce and format version, enabled state, creator, and timestamps.
- `alert_rules`: integration, condition kind, environment, bounded threshold and window fields, optional daily UTC quiet window, enabled state, creator, and timestamps.
- `alert_condition_states`: rule, stable scope key, inactive or active state, generation, current source IDs, transition times, and last evaluation time.
- `alert_deliveries`: condition generation and state, bounded payload, pending or leased queue fields, attempt and backoff state, delivered, failed, dead, suppressed, or unknown result, fixed failure code, and timestamps.

Composite foreign keys carry organization and project through every relationship. Unique constraints on rule, scope key, generation, state, and integration prevent duplicate logical deliveries. Payloads store only bounded normalized notification data, never decrypted credentials or raw customer artifacts.

The dedicated delivery queue is intentional. It keeps outbound latency and retries separate from crash jobs, and older application versions ignore the additive tables during rollback.

## Implementation sequence

1. Add the migration, project-scoped constraints, indexes, queue leases, fixed state checks, and migration tests. Keep every new table additive.
2. Add a small alert module to load and validate configuration, encrypt and decrypt adapter credentials, validate outbound destinations, sign generic webhook payloads, and expose fixed error codes. Add one direct authenticated-encryption dependency because hashing cannot support outbound delivery.
3. Add Owner and Admin control API endpoints for integrations, rules, condition state, delivery history, and disablement. Update the checked-in OpenAPI contract. Secret values are accepted only on create or explicit rotation and are never returned.
4. Add a project alert settings page using the existing server-only API client and project navigation. Show configuration, environment, quiet window in UTC, enabled state, last transition, last delivery result, and fixed remediation text without exposing credentials.
5. Record bounded alert observations beside existing durable state changes for issue creation, regression, resolution, missing symbols, processing failure, successful recovery, and quota transitions. Observation inserts are local PostgreSQL work only and never perform network calls.
6. Extend the scheduler with bounded project-fair evaluation for volume, ingest silence, quiet-window release, and quota recovery. Evaluators lock one condition row and create a delivery only when the durable state changes.
7. Run a separate alert-delivery loop in the existing worker role with its own queue claim, concurrency bound, database lease, HTTP client, timeout, and kill switch. It must not claim or delay crash-processing jobs.
8. Implement email, Discord, Slack, and generic signed webhook adapters against local mock endpoints. Use JSON serialization or plain text templates, never provider-specific string concatenation with raw customer content.
9. Add focused unit, PostgreSQL, adapter, API, OpenAPI, and browser tests, then add one disposable end-to-end proof that configures all adapters and rules, drives trigger and recovery transitions, replays work, and checks one authorized logical delivery per transition.
10. Run the focused proof and `./scripts/check-fast`, review the issue diff, and record the exact commit and commands on #301 before moving it to Locally verified.

## Delivery semantics

FaultLane can guarantee one durable logical delivery record per condition transition. Generic webhook receivers also receive a stable idempotency key and can guarantee one side effect.

Email, Discord, and Slack do not expose one shared exactly-once protocol. Definite pre-dispatch connection failures and explicit retryable responses use bounded backoff. A timeout after dispatch is ambiguous, so it becomes `delivery_unknown` and is not retried automatically. The UI can perform an explicit replay using the same delivery ID. This avoids silently claiming exactly-once behavior that an external provider cannot guarantee.

Quiet hours delay active transitions. If the same condition recovers before the quiet window ends, both queued transitions become suppressed. If it remains active, the trigger is released after quiet hours and a later recovery is delivered normally.

## Security analysis

### Authorization and tenant isolation

- Reuse the existing project-management permission, currently limited to Owner and Admin, for integration and rule mutations.
- Allow authenticated project members to read only redacted rule and delivery state when needed by the project page. Do not expose encrypted columns through query models.
- Scope every mutation and delivery lookup by organization, project, and resource ID in one query. Build links from trusted configured base URLs plus scoped IDs.

### Credential storage

- Use a maintained Rust authenticated-encryption crate with a 256-bit key and a random nonce for each secret update.
- Bind organization ID, project ID, integration ID, adapter kind, and format version as additional authenticated data so ciphertext cannot be moved between rows or tenants.
- Accept the active key from `FAULTLANE_INTEGRATION_KEY_FILE` or `FAULTLANE_INTEGRATION_KEY`. Fail startup when alerts are enabled and the key is missing, malformed, or too short. Prefer the file path for Docker and hosted secret mounts.
- Store only ciphertext, nonce, and format version. Never log request bodies, decrypted URLs, signing secrets, authorization headers, or provider response bodies.
- A future hosted deployment must inject this key from its approved managed KMS or secret manager. Choosing a cloud KMS before a hosted platform decision is outside this issue.

### Outbound requests

- Permit HTTPS only. Disallow user information, fragments, noncanonical webhook paths, redirects, and oversized URLs.
- Resolve every customer hostname immediately before delivery. Reject the destination if any resolved address is non-public, then pin the approved address set for the TLS request so DNS rebinding cannot redirect the connection.
- Restrict Discord and Slack to their webhook hosts. Apply the same public-address checks to generic webhooks.
- Bound serialized payloads, response headers, response bodies read or discarded, redirects, connect time, total time, attempts, and concurrent deliveries.
- Sign generic webhooks over the exact timestamp, delivery ID, and body with HMAC-SHA256. Use constant-time signature verification in tests and document receiver replay checks.

### Customer content

- Use fixed event types and error codes. Include bounded project name, environment, issue title, counts, and authorized links only.
- Escape HTML email content and rely on JSON serialization for webhook adapters. Never include log text, user comments, command lines, raw stack contents, symbols, minidumps, provider errors, or integration secrets.

## Tests and operational verification

- Migration tests cover clean apply, current-data preservation, composite tenant constraints, state checks, uniqueness, and an older application ignoring the new tables.
- Crypto tests cover round trip, wrong key, tampering, nonce uniqueness, cross-tenant ciphertext movement, malformed key configuration, and redacted debug and API output.
- Destination tests cover allowed provider URLs, invalid paths, credentials, fragments, redirects, IPv4 and IPv6 reserved ranges, mixed public and private DNS answers, DNS rebinding, and oversized inputs.
- Rule tests cover every condition, environment filtering, volume boundaries, ingest silence, quota levels, daily UTC quiet windows including midnight wrap, recovery, enable and disable, and policy changes.
- Concurrency tests run evaluators and workers in parallel, expire leases, replay delivery rows, and prove one logical delivery per rule, scope, generation, and state.
- Adapter tests use local email, Discord, Slack, and generic receivers for success, signature verification, retryable status, permanent status, connection failure, timeout, redaction, disabled integration, and bounded payloads.
- Authorization tests cover Owner, Admin, Developer, Viewer, unauthenticated callers, cross-project IDs, removed email recipients, and secret rotation.
- Browser tests create and disable integrations and rules, reload redacted state, show delivery outcomes, and confirm secrets are absent from HTML and client responses.
- `./scripts/prove-alerts` uses disposable PostgreSQL and mock destinations to exercise the control API, scheduler, worker, and browser-facing state for all four adapters and representative trigger and recovery paths.
- Final issue verification runs the focused Rust and web tests, `./scripts/prove-alerts`, and `./scripts/check-fast` from a clean milestone worktree.

Structured logs record organization, project, rule, condition, and delivery IDs, adapter kind, attempt, duration, and fixed outcome only. Operators can disable all alert claims with `FAULTLANE_ALERTS_ENABLED=false` while keeping condition and delivery rows available for inspection.

## Compatibility, rollout, and staging

The migration is additive. Existing API, ingest, worker, scheduler, web, OpenAPI consumers, and stored rows continue to work while alerts are disabled. The alert worker uses its own table so a prior worker never claims an unknown job type.

Stage locally in the M1 worktree with a unique Compose project, ports, database, object bucket, processor scratch path, and synthetic test data. Start with alerts disabled, apply the migration, start the new API, worker, and scheduler, configure the encryption key and local mock providers, then enable alerts for one disposable project. Prove all transitions, delivery isolation, secret redaction, and rollback without production credentials or customer data.

No production or hosted deployment is part of this issue. A later hosted rollout requires an approved provider, managed key source, egress policy, email sender identity, domain configuration, rate limits, monitoring, and staging evidence.

## Rollback

Set `FAULTLANE_ALERTS_ENABLED=false` to stop new observations, evaluations, and delivery claims. Disable affected rules or integrations through the API when only one adapter is unhealthy. Leave the additive tables, encrypted credentials, condition generations, and delivery history in place for inspection.

Restore the prior application build after alert claims have stopped. The prior build ignores the additive alert tables and continues ingest, processing, usage, and dashboard behavior. Do not delete queued deliveries or decrypt credentials during rollback. A corrected build can resume pending rows using their original logical delivery IDs.

## Out of scope

- GitHub and Jira issue integrations
- SMS, push notifications, or arbitrary external email recipients
- User-defined templates or raw crash content in notifications
- IANA timezone and daylight-saving quiet-hour rules beyond explicit UTC windows
- A new broker, service, datastore, or hosted deployment
- Cloud provider, KMS, SMTP vendor, DNS, or egress infrastructure selection
- Rewriting earlier M1 commits or implementing #303 or #313
- Claiming remote exactly-once side effects from providers that do not support idempotency

## Approval

R3 implementation starts only after a human approves this plan, including the outbound network controls, encrypted-secret design, UTC quiet hours, and delivery semantics for ambiguous provider timeouts.
