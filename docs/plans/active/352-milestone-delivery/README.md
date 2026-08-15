# Milestone delivery workflow

Issue: https://github.com/ishtms/faultlane/issues/352

Status: Awaiting human approval

## Context

FaultLane is being built by one developer before production launch. The current workflow creates a branch, worktree, pull request, remote CI cycle, review, squash merge, and cleanup for each issue. Recent pull requests take about 18 to 22 minutes in remote checks, and the same checks run again after each merge to `main`. This makes local iteration wait on GitHub without consistently producing small review units.

GitHub must remain authoritative for milestones, issues, dependencies, ownership, and Project status. Product issues should still have acceptance criteria and issue-sized commits. The delivery unit should change from one issue per pull request to one milestone per pull request.

The current local verification cannot support that cadence yet. `scripts/check-fast` runs every workspace test, PostgreSQL tests return early when `FAULTLANE_TEST_DATABASE_URL` is absent, `scripts/check` can change `apps/web/next-env.d.ts`, and the complete gate omits the tracked browser, smoke, behavior-proof, and fuzz surfaces. `scripts/doctor` only detects occupied ports when `lsof` is installed.

The prior plan for this issue proposed adding more required pull request checks. Pull request #353 was closed without merge. This plan replaces that approach.

## Acceptance criteria

- `docs/workflow/README.md` is the tracked workflow contract for milestone delivery.
- The local `next-task` skill fetches the current GitHub milestone, issues, dependencies, and Project state, then implements one unblocked issue in the milestone worktree.
- Completing an issue produces focused behavior proof, a locally verified issue-sized commit, an issue comment with the commit SHA and evidence, and the `Locally verified` Project status. It does not open a pull request, run remote CI, close the issue, merge, or delete the worktree.
- A local `finish-milestone` skill verifies every included issue and acceptance criterion, runs the complete local certification, performs a fresh review, and opens one pull request with a closing statement for every included issue.
- Remote CI runs on the final milestone pull request head. A human performs final review and uses a rebase merge so issue-sized commits remain in history.
- The local `ship` skill is limited to an explicitly requested urgent hotfix, security emergency, or other single-issue exception that cannot safely wait for the milestone.
- GitHub Project 4 includes a `Locally verified` status between `In Progress` and `In review`.
- `scripts/check-fast` is a useful issue-level local gate and does not duplicate the complete milestone certification.
- `scripts/check` exercises PostgreSQL-backed tests without silent skipping, includes the required browser, smoke, proof, and fuzz validation, and leaves a previously clean worktree clean.
- `scripts/doctor` detects occupied ports on the supported Windows path without depending on `lsof`.
- Repository settings enable rebase merge, and the main ruleset allows rebase for milestone pull requests while retaining pull request enforcement, linear history, resolved review threads, strict required checks, and protection against deletion and force pushes.
- Stale active plans and incorrect Project state are reconciled without deleting or overwriting either dirty delivery worktree.
- The current M1 transition starts from current `main`. Its final milestone pull request closes only the remaining issues #301, #303, and #313 and does not rewrite the ten already merged issues.

## Risk and blast radius

Risk: R3.

The change affects repository verification, GitHub Project state, merge configuration, and the local delivery procedure. A broken gate could allow a milestone pull request to reach review with missing evidence. An incorrect ruleset update could block merges or allow the wrong merge method. The blast radius is limited to repository development and delivery. It does not change product APIs, stored customer data, tenant boundaries, production infrastructure, production credentials, or deployments.

## Current behavior and evidence

- The repository remote is `https://github.com/ishtms/faultlane.git`, while the local `next-task` preflight expects `ishtms/cachelane` and fails before selection.
- The root worktree is on `main` at `f6ab596` and is clean apart from the existing untracked `FaultLane_Pricing.docx`.
- There are 14 existing secondary worktrees. `feature/delivery-guards` and `feature/m1-delivery-proof` contain uncommitted work and must not be changed or removed by this plan.
- GitHub Project 4 currently has Backlog, Ready, In Progress, In review, and Done statuses. It has no `Locally verified` status.
- M1 has three open issues: #301 is In Progress, while #303 and #313 are Backlog.
- Repository settings allow only squash merges. The active main ruleset allows only squash and requires `check`, `dependency audit`, and `dependency review`.
- Pull request #353 is closed and its plan was not merged to `main`.
- The local `AGENTS.md`, `.agents/`, `PRD.md`, `ARCHITECTURE.md`, and most Markdown files are ignored. `docs/workflow/README.md` can be tracked under the existing `README.md` exception without changing `.gitignore` or force-adding files.
- Five plans remain active after their linked pull requests were merged.

## Implementation sequence

1. Add the tracked workflow contract with the milestone and issue state machine, proof requirements, exception policy, review boundary, and rollback rules.
2. Update local `AGENTS.md` only as needed to point at the tracked contract while preserving its safety, testing, writing, identity, and GitHub rules. Do not stage it.
3. Rewrite the local `next-task` skill as the issue-level milestone loop, fix its FaultLane preflight, and validate it.
4. Add the local `finish-milestone` skill for final certification, review, pull request creation, CI follow-up, and human merge handoff. Validate it.
5. Narrow the local `ship` skill to explicit single-issue exceptions and remove lifecycle overlap between the three delivery skills.
6. Split focused issue verification from milestone certification. Make PostgreSQL test execution explicit, make the full command clean-tree stable, and include the required runtime, browser, behavior-proof, and fuzz surfaces through repository scripts.
7. Replace the `lsof`-only port check with a cross-platform probe that works from Git Bash on Windows.
8. Run focused script tests, then run the complete local certification from a clean worktree with Docker services available. Record the exact head and prove the tree remains clean.
9. Open a draft workflow pull request as staging evidence. Confirm Linux, Windows, browser/runtime, dependency audit, and dependency review behavior on the exact verified head without making new checks required.
10. Add `Locally verified` to Project 4 and exercise the full status transition on the workflow issue.
11. Enable repository rebase merge and update the main ruleset to allow rebase while preserving every existing protection and required check.
12. Requery the repository settings and Project fields, perform a fresh review, and leave the workflow pull request for human rebase merge.
13. After merge, archive this plan, reconcile the already merged active plans without touching the dirty worktrees, and start the remaining M1 work from current `main` in one milestone worktree.

## Tests and operational verification

- Validate the three local delivery skills with the skill validator and deterministic dry runs against the live M1 issue state.
- Run targeted tests for the PostgreSQL wrapper, clean-tree guard, browser/runtime orchestration, fuzz compilation, and Windows port probe.
- Run `./scripts/doctor` on Windows with one configured port free and then occupied.
- Run `./scripts/check-fast` and record its duration and covered surfaces.
- Run `./scripts/check` with no preconfigured test database URL and prove that PostgreSQL-backed tests execute.
- Run the browser and smoke paths against isolated local services.
- Compare `git status --short` before and after the complete check and require no new diff.
- Use a draft pull request to verify the same checked-in commands on Ubuntu and Windows before changing the live ruleset.
- Requery Project fields and repository rules after mutation and compare all preserved settings with the captured baseline.
- Perform a fresh review from a separate session or human reviewer before merge. The implementing session must not represent its own review as independent.

## Data, security, and compatibility

No product data model, migration, API, or tenant boundary changes. Local test services use disposable test credentials and data. Repository automation must keep read-only contents permission and must not receive production credentials, customer data, private crash bundles, symbols, or Unreal fixtures.

The supported development path remains Windows with Git Bash, Docker Desktop, and UE 5.8.1. Linux CI is secondary confirmation. The local certification must work on Windows before the live merge rules change.

Reducing per-issue remote CI increases the time between remote checks. The mitigations are issue-sized commits, mandatory local proof, an explicit `Locally verified` state, complete milestone certification, one final remote CI run on the exact reviewed head, and human merge.

## Rollout and staging

Roll out the workflow in two stages. First, land and exercise the tracked contract, local skills, and verification scripts on a draft pull request while the existing rules remain active. Second, after the exact head passes local and remote staging evidence, add the Project status and enable rebase in repository settings. Do not weaken existing required checks during the transition.

Use the new workflow for the remaining M1 issues only after the workflow pull request is merged. Existing merged M1 history remains unchanged.

## Rollback

- Revert the workflow pull request to restore the prior checked-in scripts and contract.
- Restore the prior local skill and `AGENTS.md` files from their recorded pre-change copies.
- Move any issue in `Locally verified` back to its prior status before removing that option.
- Restore repository merge settings to squash-only and restore the captured ruleset document if rebase causes a problem.
- Keep pull request enforcement, linear history, required checks, review-thread resolution, deletion protection, and force-push protection active throughout rollback.
- Preserve issue comments, commits, plans, and verification evidence so no completed work is lost.

## Out of scope

- Product feature implementation for #301, #303, or #313
- Rewriting or rebasing the ten M1 issues already merged
- Deployment or production changes
- Production credentials, customer data, or private Unreal fixtures
- Modifying `.gitignore`
- Staging or committing `AGENTS.md`, `.agents/`, `.codex/`, or ignored Markdown files
- Deleting or rewriting either dirty delivery worktree
- Making Windows or browser checks newly required before staging evidence exists

## Approval

Human approval is required before implementation because the plan changes live repository merge rules and the delivery gate.
