# First readable crash onboarding

Issue: https://github.com/ishtms/faultlane/issues/303

Status: Awaiting human approval and a hosted staging target

## Context

M1 needs one guided path from project creation to a readable UE 5.8 Windows crash. The existing application already creates projects and one-time ingest keys, renders the required Unreal configuration, durably accepts Crash Report Client requests, processes them in isolated workers, uploads PE and PDB artifacts through the CLI, reprocesses missing-symbol events, groups issues, and renders readable issue detail. Those capabilities are separate today. There is no onboarding status API, live onboarding UI, packaged sample project, local configuration checker, or browser flow that connects them.

The authoritative sources have three known discrepancies. `docs/product/overview.md` still names CacheLane and calls M0 current, while the repository, GitHub, and application use FaultLane and show M1 in progress. `PRD.md` also retains the former product and CLI names. Most importantly, issue #303 requires proof against a hosted test project, while `ARCHITECTURE.md` defers the hosted platform decision and the repository states that no production deployment is configured. This plan keeps the hosted proof requirement. It does not silently substitute localhost for hosted staging.

## Acceptance criteria

- A newly created project continues directly into a guided UE 5.8 Windows onboarding page with exact `Config/DefaultGame.ini` and `Config/DefaultEngine.ini` snippets, the packaged Crash Reporter setting, and the generated `DataRouterUrl`.
- Ingest keys and artifact upload tokens remain one-time secrets. They are never persisted in browser storage, URLs, logs, analytics, source files, sample files, or PostgreSQL plaintext. Reloading offers safe rotation instead of redisplaying a secret.
- The page moves automatically through waiting, received, processing, missing symbols, and readable issue states. It also shows fixed retry or remediation states for failed, quarantined, invalid, and unavailable work.
- State survives reload because it is derived from durable project, event, job, result, release, waiter, and issue rows rather than client-only state.
- The onboarding state read is bounded, tenant-scoped, no-store, and returns only fixed status, safe release metadata, exact missing identities, fixed diagnostics, and an authorized issue path. It never returns raw crash content, object keys, credentials, comments, logs, or stored result JSON.
- The page provides PowerShell-safe copy controls for a bounded local configuration check, `faultlane symbols scan`, token setup, and `faultlane symbols upload`. The upload command uses the authorized project slug and the exact release, architecture, and configuration observed from the crash.
- A local CLI check detects missing source configuration, a URL placed only under an editor-generated config path, a disabled packaged Crash Reporter, a missing packaged CrashReportClient binary, an unsupported engine association, and an unpackaged editor executable. Output uses fixed codes and never echoes the ingest URL or key.
- A tracked distributable UE 5.8 sample project packages outside the repository worktree and crashes only when an explicit test flag is supplied. Generated builds, reports, symbols, ingest keys, and private fixtures are not committed.
- The installed UE 5.8.1 build packages the sample for Win64, the packaged sample submits through the configured `DataRouterUrl`, and its matching PE and PDB produce a function, source file, and line in the linked issue.
- Missing-symbol proof submits the packaged sample before its symbols are available, shows the exact corrective upload command, uploads the matching artifacts, and reaches the same readable issue through automatic reprocessing.
- Browser and API tests cover every state, reload, retry, authorization, tenant isolation, one-time secrets, configuration mistakes, copy controls, and failure behavior.
- One approved nonproduction hosted test project completes the same project creation, package, submit, upload, reprocess, and readable issue flow without database edits, production credentials, or private setup knowledge.
- Public setup instructions can be followed from the root README and the sample project's tracked README without direct assistance.
- Focused tests and `./scripts/check-fast` pass. Complete milestone certification remains a single later `./scripts/check` run on the final milestone head.

## Risk and blast radius

Risk: R3.

This change handles one-time project and upload credentials, exposes new authorized project state, renders commands containing tenant identifiers and optionally a one-time token, processes local project and packaged-build paths, deliberately crashes a packaged application, and requires a real nonproduction hosted proof. A defect could expose a write credential, cross tenant boundaries, generate a shell-unsafe command, mislabel an editor crash as packaged, crash without explicit intent, or claim a hosted path works when only localhost was tested.

The implementation blast radius is the project setup API and web flow, one bounded onboarding projection, the existing artifact-token endpoint, the CLI, a tracked sample project, OpenAPI, public README instructions, and local proof scripts. It does not include billing, production deployment, a new service, a new datastore, an editor plugin, other Unreal versions, or production customer data.

## Current behavior and evidence

- `POST /api/v1/setup` and ingest-key rotation return a raw key, generated `DataRouterUrl`, and exact UE 5.8 configuration once. `GET /api/v1/projects/{project_id}/setup` returns only key metadata, so a refresh cannot and must not recover the raw URL.
- The setup page displays the one-time key and snippets, then links directly to the general dashboard. Existing setup views show key metadata but no onboarding progress.
- `GET /api/v1/projects/{project_id}/events/{event_id}` exposes durable event state only when the caller already knows an event ID. A new developer cannot discover the first accepted event through onboarding.
- The database already stores the project, ingest-key scope, event and job state, current immutable result, release mapping, missing-symbol waiters, issue assignment, and authorized issue path needed for the onboarding projection.
- The dashboard already renders exact missing identities and a PowerShell-safe `faultlane symbols upload` command. The onboarding path can reuse that command construction instead of adding another quoting convention.
- The control API already creates a project-scoped artifact upload token for an Owner or Admin and returns it once. The web application has no surface for that operation.
- `faultlane symbols scan` and `faultlane symbols upload` already validate bounded Windows artifacts and use `FAULTLANE_TOKEN`. There is no command that checks Unreal source and packaged configuration.
- No tracked `.uproject`, packaged sample application, or distributable Unreal sample project exists.
- UE 5.8.1 is installed at `C:\Program Files\Epic Games\UE_5.8`, and `RunUAT.bat` plus `UnrealEditor-Cmd.exe` are available for local packaging evidence.
- The installed UE source confirms that Crash Report Client reads `DataRouterUrl` and `bSendLogFile` from the `[CrashReportClient]` engine configuration and has a separate unattended upload path.
- The repository contains only Docker Compose for local PostgreSQL and MinIO plus the application and processor images. It contains no hosted application deployment, public test URL, managed database configuration, or approved nonproduction credentials.
- Issue #303 is P0, belongs to M1, has no assignee, and is in Backlog. No open pull request owns it. Issue #313 moved to M2 because M2 explicitly includes billing.

## Proposed design

### Onboarding projection

Add `GET /api/v1/projects/{project_id}/onboarding`. Reuse the existing project authorization boundary. Project members may read safe status, while only Owner and Admin may rotate credentials or create an artifact upload token.

The query uses tenant-leading predicates and fixed limits. It returns the earliest readable event when one exists. Otherwise it returns the newest accepted event so a corrected retry can replace a failed first attempt. With no event it returns `waiting`. The fixed state mapping is:

- `waiting`: no event exists;
- `received`: an event is durably stored and its job has not started;
- `processing`: the event is parsed, symbolicating, leased, or otherwise in progress;
- `missing_symbols`: the event is awaiting exact PE or PDB identities;
- `readable_issue`: a readable current result is grouped into an issue;
- `failed` or `quarantined`: terminal work with a fixed safe reason;
- `unavailable`: the status read could not be completed.

The response includes safe release version, platform, architecture, build configuration, timestamps, exact bounded missing identities, a server-generated remediation command, and an internal issue path when available. It derives current truth and adds no onboarding state table or background task.

Likely configuration diagnostics use fixed evidence only. Before any event, a bounded wait based on project creation time points to the package and config checklist without claiming certainty. Once a result exists, module, platform, architecture, engine version, and build configuration evidence can identify an Unreal Editor executable, a non-Windows or non-x64 report, an unsupported engine version, or incomplete packaged metadata.

### Web flow and one-time credentials

Keep the existing project creation transaction and secret storage rules. After creation, render onboarding around the one-time response instead of sending the user to the general dashboard. A later reload reads durable status and key metadata. If the raw ingest key was not saved, the user creates a replacement and explicitly revokes the old key after updating the build.

A small client component polls the onboarding endpoint every three seconds while the page is visible. It stops on navigation, backs off on availability failures, and continues through missing symbols so automatic reprocessing can reach the readable issue. Use polling because the existing API and deployment have no event-stream boundary and the expected load is one bounded project read during setup.

Create artifact upload tokens through the existing authorized endpoint. Show the raw token only in the action result. Generate separate copy controls for the PowerShell environment assignment, scan command, and upload command. Dynamic values use the existing PowerShell single-quote escaping. No command is placed in a URL, log, server error, or persistent browser state.

### Unreal configuration check

Add `faultlane unreal check <project-root> --package <packaged-build-root>`. Use bounded filesystem traversal and bounded text reads with no new dependency. Do not follow symbolic links.

The command checks the `.uproject` engine association, source `Config/DefaultGame.ini`, source `Config/DefaultEngine.ini`, common `Saved/Config/WindowsEditor` misplacement, packaged Windows executable, and packaged CrashReportClient binary. It emits deterministic JSON with fixed check IDs and remediation text. It reports only relative paths and the presence or validity of a configured route, never the route value or key.

### Distributable sample project

Add a minimal C++ UE 5.8 project under `samples/unreal-5.8-crasher`. Its crash path is unreachable unless the packaged executable receives an exact `-FaultLaneCrash` flag. The known sample frame calls a fatal UE assertion after startup so matching sample symbols resolve to a stable function, file, and line.

A PowerShell packaging script accepts the ingest URL through an environment value, copies the sample to a disposable directory outside the worktree, writes configuration only in that copy, and runs the installed UE 5.8.1 automation tool. It never prints the URL. Package output, reports, PE, PDB, logs, and generated Unreal directories remain outside Git. The sample README documents packaging, validation, explicit crash invocation, symbols, cleanup, and the fact that the command intentionally terminates the sample.

## Security analysis

### Authorization and tenant isolation

- Reuse the current authenticated actor and project membership checks.
- Scope every event, job, result, waiter, release, issue, and token query by organization and project in the same query.
- Return not found for cross-project IDs and never accept an event, release, or issue ID from the browser as authority for the project projection.
- Limit credential rotation and upload-token creation to the existing `ManageProject` permission.

### Credentials and browser state

- Preserve digest-only storage and one-time display for ingest keys and upload tokens.
- Apply `Cache-Control: no-store` and `Pragma: no-cache` to every onboarding and secret response.
- Do not place secrets in query strings, redirect locations, server-rendered durable props, browser storage, logs, analytics, sample source, package scripts, or database columns.
- Treat a copied token command as an explicit user action. Clear the component state on navigation and prove reload cannot recover the token.

### Commands and local files

- Construct commands from validated project and release data with the existing PowerShell quoting rules.
- Bound path length, traversal depth, entry count, file count, and bytes read. Ignore symbolic links and return fixed errors without absolute paths or file contents.
- Parse only the configuration keys needed for the checks. Do not execute project scripts, load editor modules, or inspect arbitrary binary contents in the CLI check.

### Intentional crash and untrusted artifacts

- Require the exact sample-only flag before the crash path runs. Normal startup must remain safe.
- Keep the sample isolated from the application server and never copy generated UE artifacts into the repository.
- Continue sending crash reports and symbols through the existing bounded ingest, object storage, OCI processor, tenant selection, and upload paths.

## Implementation sequence

1. Record human approval of this plan and the hosted staging decision. Requery #303, assign it to `ishtms`, and move it to In Progress only after both gates are satisfied.
2. Add strict onboarding response types and state derivation with tenant-scoped PostgreSQL tests for waiting, every processing transition, retry replacement, missing symbols, readable issue selection, terminal failures, bounds, and cross-tenant denial.
3. Add the authorized no-store onboarding route and OpenAPI contract. Reuse the existing missing-symbol command builder and fixed result validation.
4. Add the setup-to-onboarding web flow, visible-page polling, reload and retry handling, state-specific remediation, one-time artifact token action, and safe copy controls.
5. Add `faultlane unreal check` with bounded source and package checks plus deterministic CLI behavior tests for correct, missing, editor-only, malformed, symlinked, oversized, and secret-bearing inputs.
6. Add the minimal tracked UE 5.8 sample project, disposable packaging script, explicit crash flag, and public README instructions.
7. Extend the browser proof to create a project, preserve one-time secret behavior, observe every state without manual refresh, create an upload token, copy commands, retry a failed event, upload missing symbols, and reach the linked readable issue.
8. Package the sample with installed UE 5.8.1 and run the complete isolated local flow against dedicated PostgreSQL, MinIO, API, ingest, worker, processor, web, ports, storage, and scratch resources.
9. Run focused Rust, CLI, API, OpenAPI, web, and Playwright tests plus `./scripts/check-fast`. Review the issue diff, secrets, sample outputs, compatibility, and rollback.
10. Run the same flow against the approved nonproduction hosted test project without database edits or private setup steps. Capture only safe IDs, states, timings, and the readable sample frame as evidence.
11. Commit the issue-sized implementation, post exact proof on #303, check completed criteria, and move it to Locally verified. Leave the issue open for the milestone pull request.

## Tests and operational verification

- Unit tests cover state mapping, fixed diagnostics, command quoting, configuration parsing, bounds, symlink handling, and secret redaction.
- PostgreSQL and API tests cover every durable event state, jobs before and during a lease, retry after failure, exact missing identities, automatic reprocessing, readable issue selection, two-tenant isolation, role permissions, no-store headers, corrupt current results, and query bounds.
- Browser tests cover creation, one-time key display, refresh, safe rotation, waiting, live transitions, missing-symbol command generation, one-time upload token display, copy controls, retry, unavailable services, and the final issue link.
- The sample test packages from a clean disposable copy with installed UE 5.8.1, confirms the worktree remains free of generated files and secrets, runs normally without the crash flag, and crashes only with the exact flag.
- Local end-to-end proof starts dedicated services, submits the packaged sample before symbols, observes missing symbols, uploads the matching PE and PDB, observes automatic reprocessing, and verifies a function, file, and line on the same issue.
- Hosted staging repeats the user-visible flow through public TLS endpoints using only approved nonproduction credentials and synthetic sample data. It verifies API, ingest, object storage, worker, processor, web, and browser behavior without production access.
- `./scripts/check-fast` is the issue gate. No 5 million row benchmark is required because #303 does not change the dashboard scale contract. `./scripts/check` runs once later on the exact final milestone head.

## Compatibility, rollout, and staging

The onboarding route and UI are additive. No schema migration is required. Existing setup, dashboard, ingest, upload, processing, reprocessing, and issue APIs remain compatible. Add `FAULTLANE_ONBOARDING_ENABLED`, disabled by default outside the proof environment, so rollout can expose onboarding without changing core ingest or dashboard behavior.

Local staging uses a unique Compose project, ports, database, bucket, object prefix, processor image, scratch root, and synthetic sample data. It proves product behavior and rollback but does not satisfy the issue's hosted acceptance criterion.

Hosted staging requires an approved nonproduction application target with TLS API, ingest, and web origins, PostgreSQL, private S3-compatible storage, the isolated processor runtime, secret injection, and no production customer data. The repository has no such target today. Selecting or creating it is an infrastructure decision outside this plan's implementation authority and must be approved before #303 can become Locally verified.

## Rollback

Set `FAULTLANE_ONBOARDING_ENABLED=false` to remove the onboarding status and token UI while leaving setup, ingest, processing, symbols, and the dashboard available. Restore the prior API, web, and CLI builds. Revoke only disposable test ingest and artifact tokens created for failed proof runs.

The sample project is inert unless separately packaged and launched with its exact crash flag. Delete only its disposable package directory and synthetic hosted test project after evidence is retained. Do not delete accepted events, objects, results, releases, issues, or shared infrastructure during rollback.

## Out of scope

- Production deployment or production credentials
- Selecting a cloud application host, database provider, DNS provider, or secret manager
- Hosted billing from #313
- An Unreal Editor plugin
- UE 5.4 through UE 5.7, other UE 5.8 patch claims, non-Windows platforms, or non-x64 Windows
- Shipping generated Unreal builds, private fixtures, PE files, PDB files, minidumps, logs, or raw reports in Git
- Storing or recovering plaintext ingest keys or upload tokens
- A WebSocket, event bus, new service, new datastore, or new dependency for onboarding
- Repeating the 5 million row dashboard benchmark

## Approval

R3 implementation starts only after Ishtmeet Singh approves this plan, including one-time secret handling, the polling model, the bounded onboarding projection, the local configuration checker, the explicit sample crash flag, local staging, and rollback.

Approval must also resolve the hosted proof gate by either providing or authorizing creation of a specific nonproduction hosted target. Replacing the hosted criterion with isolated local staging would weaken #303 and the M1 milestone and requires an explicit issue-scope change.
