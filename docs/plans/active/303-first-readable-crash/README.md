# Local first readable crash demo

Issue: https://github.com/ishtms/faultlane/issues/303

Status: Awaiting human approval

## Context

M1 needs one guided path from project creation to a readable UE 5.8 Windows crash. The application already creates projects and one-time ingest keys, renders Unreal configuration, durably accepts Crash Report Client requests, processes them in isolated workers, uploads PE and PDB artifacts through the CLI, reprocesses missing-symbol events, groups issues, and renders readable issue detail. Those capabilities are separate today.

Issue #303 previously combined the interactive product workflow with hosted proof. It is now limited to a complete local demonstration that Ishtmeet Singh can run and inspect before any provider or deployment decision. Issue #364 owns hosted deployment, private demo maintenance, and public read-only access after this local workflow is accepted.

`docs/product/overview.md`, `PRD.md`, and `ARCHITECTURE.md` still contain the former product and CLI names in places. GitHub and the application use FaultLane. This plan does not rewrite those unrelated sources.

## Acceptance criteria

- A newly created project continues into a guided UE 5.8 Windows onboarding page with exact `Config/DefaultGame.ini` and `Config/DefaultEngine.ini` snippets, the packaged Crash Reporter setting, and the generated `DataRouterUrl`.
- Ingest keys and artifact upload tokens remain one-time secrets. They are never persisted in browser storage, URLs, logs, source files, sample files, or PostgreSQL plaintext. Reloading offers safe rotation instead of redisplaying a secret.
- The page moves automatically through waiting, received, processing, missing symbols, and readable issue states. It shows fixed remediation for failed, quarantined, invalid, and unavailable work.
- State survives reload because it is derived from durable project, event, job, result, release, waiter, and issue rows.
- The onboarding read is bounded, tenant-scoped, and no-store. It returns only safe status, release metadata, exact missing identities, fixed diagnostics, and an authorized issue path.
- The page provides PowerShell-safe copy controls for the configuration check, `faultlane symbols scan`, token setup, and `faultlane symbols upload` using the observed project and release.
- `faultlane unreal check` detects missing source configuration, editor-only configuration, a disabled packaged Crash Reporter, a missing packaged CrashReportClient binary, an unsupported engine association, and an unpackaged editor executable without printing secrets.
- A tracked UE 5.8 sample project packages outside the worktree and crashes only with the exact `-FaultLaneCrash` flag.
- Supported repository commands start isolated local API, ingest, worker, scheduler, processor, web, PostgreSQL, and MinIO resources.
- The installed UE 5.8.1 build packages the sample for Win64. The sample submits before symbols, reaches missing symbols, receives matching PE and PDB artifacts, reprocesses automatically, and resolves a known frame to function, file, and line.
- Repeated instances group into one issue and a materially different sample crash remains separate.
- Browser, API, CLI, and runtime tests cover all states, reload, retry, authorization, tenant isolation, one-time secrets, configuration mistakes, explicit crash intent, missing symbols, reprocessing, grouping, and failure behavior.
- The proof finishes with the local services and synthetic project available for manual browser interaction, and documents exact stop and cleanup commands.
- Generated builds, reports, symbols, ingest keys, tokens, credentials, and private fixtures remain outside the repository.
- Focused tests and `./scripts/check-fast` pass. Complete milestone certification remains the later `./scripts/check` run on the final milestone head.

## Risk and blast radius

Risk: R3.

The change handles one-time credentials, exposes new authorized project state, renders commands containing tenant identifiers, processes local project and packaged-build paths, and deliberately crashes a packaged application. A defect could expose a credential, cross tenant boundaries, generate a shell-unsafe command, mislabel an editor crash as packaged, or crash without explicit intent.

The blast radius is the project setup API and web flow, one bounded onboarding projection, the existing artifact-token endpoint, the CLI, a tracked sample project, public setup instructions, and local proof scripts. It does not include public anonymous access, a cloud provider, DNS, TLS termination, billing, production deployment, a new service, a new datastore, an editor plugin, or other Unreal versions.

## Current behavior and evidence

- `POST /api/v1/setup` and ingest-key rotation return a raw key, generated `DataRouterUrl`, and exact UE 5.8 configuration once.
- The setup page displays the one-time key and snippets, then links to the general dashboard. It has no onboarding progress.
- The event API exposes durable event state only when the caller already knows an event ID.
- PostgreSQL already stores the project, event, job, result, release, missing-symbol waiter, issue assignment, and authorized issue path needed for an onboarding projection.
- The dashboard already renders exact missing identities and a PowerShell-safe symbol upload command.
- The control API already creates a project-scoped artifact token for Owner or Admin and returns it once. The web application has no surface for it.
- The CLI already scans and uploads bounded Windows artifacts. It has no Unreal source and packaged configuration check.
- No tracked `.uproject` or distributable Unreal sample exists.
- UE 5.8.1 is installed at `C:\Program Files\Epic Games\UE_5.8` with the required packaging tools.
- The repository can run local PostgreSQL, MinIO, application roles, and the isolated processor, but does not connect them into this user-visible proof.
- All earlier M1 workflow issues are locally verified. Issue #303 is the next Backlog item and no open pull request owns it.

## Proposed design

### Onboarding projection

Add `GET /api/v1/projects/{project_id}/onboarding` behind the existing project authorization boundary. Return the earliest readable event when one exists, otherwise the newest accepted event. Derive fixed states from existing durable rows and add no onboarding table or background service.

The response contains only safe release metadata, timestamps, bounded missing identities, fixed diagnostics, a server-generated remediation command, and an internal issue path. It never returns raw crash content, object keys, credentials, comments, logs, custom context, or stored result JSON.

### Web flow and credentials

Render onboarding around the one-time setup response. After reload, read durable state and key metadata without recovering the raw key. Poll the onboarding endpoint every three seconds only while the page is visible, with bounded backoff on availability failure.

Use the existing authorized artifact-token endpoint and PowerShell quoting rules. Show raw tokens only in the direct action result and never in URLs, logs, durable server props, or browser storage.

### Unreal configuration check

Add `faultlane unreal check <project-root> --package <packaged-build-root>`. Traverse and read bounded inputs without following symbolic links or adding a dependency. Emit deterministic fixed check IDs and relative paths without echoing the configured route or key.

### Sample and local runtime

Add a minimal C++ UE 5.8 project under `samples/unreal-5.8-crasher`. Its crash path is unreachable without the exact test flag. Package from a disposable copy outside the worktree, inject the local ingest URL only into that copy, and keep all generated Unreal output outside Git.

Extend supported local orchestration and proof scripts only as needed to start isolated resources, run the real sample flow, and leave the final environment available for manual inspection. Cleanup must resolve and validate only the dedicated local resources.

## Security analysis

- Reuse authenticated actor and project membership checks. Scope every query by organization and project in the same query.
- Limit credential rotation and artifact-token creation to the existing `ManageProject` permission.
- Keep digest-only secret storage and one-time display. Apply `Cache-Control: no-store` and `Pragma: no-cache` to onboarding and secret responses.
- Bound command inputs, path length, traversal depth, entry count, file count, and bytes read. Ignore links and return fixed errors without absolute paths or file contents.
- Require the exact sample-only crash flag. Normal startup must not crash.
- Continue processing crash bundles and symbols through the existing object storage and isolated processor boundaries.
- Use only synthetic local data and disposable credentials. No production credentials or customer data enter the proof.

## Implementation sequence

1. Record approval of this revised local-only plan. Requery #303, assign it to `ishtms`, and move it to In Progress.
2. Add onboarding response types and state derivation with tenant-scoped PostgreSQL tests.
3. Add the authorized no-store route and OpenAPI contract.
4. Add the setup-to-onboarding UI, polling, reload handling, remediation, token action, and copy controls.
5. Add the bounded Unreal configuration checker and CLI behavior tests.
6. Add the minimal sample project, disposable packaging script, explicit crash flag, and instructions.
7. Extend the browser and runtime proof across project creation, crash submission, missing symbols, upload, reprocessing, grouping, and readable issue navigation.
8. Package with installed UE 5.8.1 and run the complete isolated local flow.
9. Run focused verification and `./scripts/check-fast`, then inspect the diff, generated files, secrets, security boundaries, and cleanup behavior.
10. Leave the verified local demo running for Ishtmeet Singh to inspect. After acceptance, stop and clean only the dedicated resources.
11. Commit the issue-sized implementation, post proof on #303, check its acceptance criteria, and move it to Locally verified. Leave the issue open for the milestone pull request.

## Tests and operational verification

- Unit tests cover state mapping, fixed diagnostics, command quoting, configuration parsing, bounds, link handling, and secret redaction.
- PostgreSQL and API tests cover every durable state, retry selection, missing identities, reprocessing, readable issue selection, tenant isolation, role permissions, no-store headers, corrupt results, and query bounds.
- Browser tests cover creation, one-time key display, refresh, rotation, live transitions, token display, copy controls, retry, unavailable services, and the final issue link.
- The sample packages from a clean disposable copy, starts normally without the flag, and crashes only with the exact flag.
- Runtime proof submits before symbols, observes missing symbols, uploads matching PE and PDB files, observes automatic reprocessing, verifies grouping, and resolves a function, file, and line.
- `./scripts/check-fast` is the issue gate. No five-million-row benchmark is required because #303 does not change the dashboard scale contract.

## Compatibility, rollout, and rollback

The route and UI are additive. No schema migration is planned. Existing setup, dashboard, ingest, upload, processing, reprocessing, and issue APIs remain compatible. Gate onboarding with `FAULTLANE_ONBOARDING_ENABLED`, disabled by default outside the proof environment.

Rollback disables the flag, restores the prior API, web, and CLI builds, revokes disposable local credentials, and stops the dedicated resources. Delete only validated disposable package and service data. Do not delete accepted events or shared resources.

## Out of scope

- Public anonymous demo access
- Selecting or configuring a cloud provider
- DNS, public TLS, managed databases, or hosted object storage
- Production deployment or production credentials
- Full self-hosted backup, restore, upgrade, signed release, SBOM, or licensing work from #307
- Billing, an Unreal Editor plugin, other Unreal versions, or a new service, datastore, broker, or dependency
- A five-million-row benchmark

## Approval

R3 implementation starts only after Ishtmeet Singh approves this revised plan, including secret handling, polling, the bounded projection, the configuration checker, the explicit crash flag, isolated local staging, manual inspection handoff, cleanup, and rollback.
