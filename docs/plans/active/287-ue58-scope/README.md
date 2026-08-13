# Unreal Engine 5.8 development scope

Issue: [#287](https://github.com/ishtms/cachelane/issues/287)

## Context

CacheLane currently claims packaged Windows support for UE 5.4 and later, and M0 includes separate real-fixture work for UE 5.4 through UE 5.8. The available Windows environment has Unreal Engine 5.8.1 installed at `C:\Program Files\Epic Games\UE_5.8` with changelist 56057345 and Visual Studio Build Tools. UE 5.4 through UE 5.7 are not installed.

Active development should prove one complete Windows path with the installed engine before expanding compatibility. UE 5.4 through UE 5.7 will be validated in a dedicated pre-launch milestone after M2 and before general availability. Other UE 5.8 patch releases remain unverified until that compatibility pass.

The current public target is UE 5.8 Win64. The exact local validation baseline is UE 5.8.1. Version-tolerant parsing remains useful and must not be replaced by a hard engine-version rejection.

## Acceptance criteria

- Current product, repository, UI, test, and roadmap language names UE 5.8 Win64 as the only supported development target.
- Local validation and synthetic engine-version fixtures use the installed UE 5.8.1 build.
- M0 requires one real UE 5.8 report, matching PDB and PE artifacts, deterministic normalized JSON, and a readable stack.
- Issues #143 through #146 move from M0 to a dedicated pre-launch Unreal compatibility milestone after M2 and remain in Backlog.
- Issues #28, #147 through #150, #235, and #254 describe the UE 5.8 development baseline without claiming multi-version coverage.
- The M0 roadmap removes UE 5.4 through UE 5.7 from its exit path and links the deferred compatibility milestone.
- Earlier engine versions appear only in deferred compatibility work, historical evidence, or source notes.
- Version-tolerant parsing remains intact, with no new runtime rejection based only on the engine version.
- Repository checks and the web smoke check pass after implementation.

## Risk and blast radius

Risk is R2 because this changes the product compatibility claim, M0 exit path, public UI text, synthetic test metadata, and several GitHub roadmap items.

The change is reversible and does not alter authentication, authorization, billing, infrastructure, deployment, stored data, tenant boundaries, dependencies, APIs, parser limits, or untrusted-input controls. No customer or production state exists.

## Current behavior and evidence

- `AGENTS.md`, `README.md`, `PRD.md`, and `docs/product/overview.md` claim UE 5.4+ or UE 5.4 through UE 5.8 support.
- `apps/web/app/page.tsx` displays `Built for Unreal Engine 5.4+`.
- `crates/unreal/src/lib.rs` uses `5.4.4-123456` in its complete synthetic crash-context fixture and golden JSON.
- The active parser plan for #42 and the completed Windows CI plan for #282 still describe the earlier compatibility scope.
- Issues #143 through #147 separately request real fixtures for UE 5.4 through UE 5.8, all in M0 and Backlog.
- Issues #148, #235, and #254 require a multi-version protocol or fixture matrix during M0.
- Issue #150 is the only In Progress M0 application issue and already requires a real supported Windows report.
- The repository has no engine-version rejection in the parser, so narrowing the tested scope does not require a new code path.

`AGENTS.md`, `PRD.md`, `ARCHITECTURE.md`, and most product, architecture, security, and operations Markdown are intentionally local and ignored. Repository rules prohibit force-adding or staging them. They may be updated locally for workspace consistency but must not be staged. Tracked README files, product code, and tests remain normal reviewable changes.

## Implementation sequence

1. Update local authoritative scope sources, including `AGENTS.md`, `PRD.md`, and `docs/product/overview.md`, without staging ignored Markdown.
2. Update tracked `README.md`, the web landing-page compatibility claim, the Unreal synthetic fixture, golden assertions, and tracked plan wording that otherwise states the old scope.
3. Create a `Pre-launch Unreal compatibility` milestone for work after M2 and before general availability.
4. Move issues #143 through #146 to that milestone, keep them in Backlog, and mark their bodies as deferred compatibility work rather than active M0 dependencies.
5. Narrow issues #28, #147 through #150, #235, and #254 to the UE 5.8 baseline. Update #149 and other fixture wording when the audit finds an implied active multi-version requirement.
6. Update roadmap issue #6 so M0 depends on UE 5.8 evidence only and links the deferred milestone.
7. Add a short scope update to historical issue #282 and its completed plan without rewriting its verification record.
8. Audit repository files, open issues, closed issue scope notes, and project fields so earlier versions appear only as deferred or historical context.

## Tests and operational verification

- `cargo test -p cachelane-unreal`
- `./scripts/check-fast`
- `./scripts/check`
- `./scripts/smoke`
- Run a repository-wide text audit excluding dependency lockfiles, generated output, the ignored bootstrap snapshot, and historical or deferred compatibility text.
- Query affected GitHub issues through REST and their targeted Project V2 fields through GraphQL.
- Confirm #143 through #146 are open, Backlog, and assigned to the pre-launch milestone.
- Confirm #147 remains in M0 and identifies UE 5.8.1 as the local evidence baseline.
- Confirm M0 issue #6 no longer requires UE 5.4 through UE 5.7 fixtures.

## Data, security, and compatibility

No stored data, migration, API contract, tenant boundary, credential, or external processing system changes. Crash artifacts remain sensitive untrusted input and retain all existing parser and isolation requirements.

The scope statement distinguishes tested support from tolerant behavior. Inputs from other Unreal versions may still parse, but CacheLane will not claim compatibility until the late pre-launch matrix passes. This avoids adding speculative engine-version branches while keeping future compatibility work possible.

## Implementation evidence

- Tracked product language, the landing page, Unreal fixtures, CLI fixture expectations, and relevant plans now use the UE 5.8 development target and UE 5.8.1 validation baseline.
- Milestone 9 tracks UE 5.4 through UE 5.7 and additional UE 5.8 patch validation after M2. Issues #143 through #146 are open in that milestone and remain in Backlog.
- Issues #6, #28, #147 through #150, #235, #236, #254, and #282 now distinguish the current UE 5.8 baseline from deferred or historical compatibility work.
- `cargo test -p cachelane-unreal` passed with 23 tests.
- `cargo test -p cachelane-cli` passed with 9 tests.
- `./scripts/check-fast` passed.
- `./scripts/check` passed, including the release build and repository checks.
- `./scripts/smoke` passed while `./scripts/dev` ran with isolated local ports and its own Compose project.
- No service was deployed and no stored data, API, dependency, authorization, tenant, credential, or parser-limit change was made.

## Rollout and rollback

Roll out the repository and GitHub wording together so the public claim, current milestone, and issue queue agree. No service deployment is required.

Roll back by reverting the repository change, restoring the previous issue titles, bodies, labels, and M0 milestone assignments, and deleting the pre-launch milestone if it is empty. No data cleanup, credential rotation, migration, or external rollback is required.

## Out of scope

- Running UE 5.4 through UE 5.7 compatibility tests now
- Installing additional Unreal versions
- Rejecting crash reports by engine version
- Changing XML, minidump, PDB, PE, archive, or symbolication behavior
- Editing historical comments or commit messages
- Modifying the ignored `cachelane-windows-bootstrap-2026-08-13` snapshot
- Deployment or production changes

## Unresolved decisions

None. For this plan, pre-launch compatibility occurs after M2 and before general availability. If the release sequence changes, the deferred milestone can move without changing the UE 5.8 development baseline.
