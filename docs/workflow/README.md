# Development workflow

This is the delivery contract for the solo, pre-production phase of FaultLane. GitHub owns planning and status. Local work owns iteration. A milestone pull request is the normal review and CI unit.

`AGENTS.md` safety rules still apply. Local skills are adapters for this contract and must not weaken it.

## Delivery model

```text
GitHub milestone and issues
        -> one milestone branch and worktree
        -> issue-sized commits and local proof
        -> one milestone pull request closing every included issue
        -> remote CI on the final head
        -> fresh review and human rebase merge
```

Do not open a pull request, wait for remote CI, close an issue, or merge after each normal milestone issue.

Use a separate pull request only for an urgent hotfix, a security emergency, the workflow itself, or work that cannot safely wait for the milestone. State the exception on its issue.

## GitHub authority

Fetch live state before milestone kickoff, before claiming an issue, before opening the milestone pull request, and after merge. Use `gh`, GitHub REST, or GitHub GraphQL.

GitHub is authoritative for:

- milestones, included issues, dependencies, and priority;
- issue acceptance criteria, risk, ownership, and proof comments;
- Project status;
- pull requests, checks, reviews, and merge state.

Do not substitute a local task list for stale or missing GitHub state. Reconcile the GitHub state first.

The normal Project state machine is:

```text
Backlog -> Ready -> In Progress -> Locally verified -> In review -> Done
```

`Locally verified` means the issue has an issue-sized commit, behavior proof, and the required local issue gate. It does not mean the issue is closed or merged.

## Milestone kickoff

1. Fetch `origin` and query the current milestone, its open issues, direct dependencies, Project items, open pull requests, branches, and worktrees.
2. Confirm the GitHub account is `ishtms`, the Git author is `Ishtmeet Singh`, and the remote is `ishtms/faultlane`.
3. Create or update one milestone plan for shared R2 and R3 decisions. Obtain human approval before any R3 implementation.
4. Create one branch and isolated worktree from current `origin/main`, normally `milestone/<milestone-name>`.
5. Configure unique ports, Compose project name, storage, and test data for that worktree when services are needed.
6. Order issues by dependency and priority. Move only the next unblocked issue to Ready.

Keep one active milestone implementation worktree. Do not create a worktree per issue.

## Issue loop

For each issue:

1. Requery the issue, milestone, dependencies, acceptance criteria, risk, assignment, and Project status.
2. Confirm it is unblocked and belongs in the current milestone. Assign it to `ishtms` and move it to In Progress.
3. Implement the smallest coherent behavior in the milestone worktree. Keep supporting maintenance inside the issue only when that behavior requires it.
4. Add behavior tests at the lowest useful boundary and exercise the real command, API, UI, or runtime entrypoint.
5. Run focused tests while iterating, then run `./scripts/check-fast` for the issue head.
6. Review the issue diff for acceptance criteria, unrelated changes, secrets, generated files, compatibility, security, operations, and rollback.
7. Create one or more small logical commits for the issue with short, lowercase, natural messages.
8. Post the final local commit SHA, exact commands, proof, residual risk, and rollback on the issue.
9. Check completed acceptance-criteria boxes and move the issue to Locally verified.
10. Leave the issue open. Do not open a pull request, trigger remote CI, merge, or remove the milestone worktree.
11. Requery GitHub and select the next unblocked Ready issue.

Pushing the milestone branch for backup is optional. A backup push must not open a pull request or replace the issue proof comment.

## Verification layers

Focused verification is selected from the changed behavior. It may be a Rust test target, web test, API request, CLI command, browser scenario, proof script, or runtime exercise. Record the exact command and result.

`./scripts/check-fast` is the issue-level repository gate. It should catch formatting, lint, type, compile, and ordinary unit-test failures without performing the complete service and release certification.

`./scripts/check` is the milestone certification command and the command CI calls. It must:

- run all repository checks and release builds;
- exercise PostgreSQL-backed tests without silent skips;
- compile tracked fuzz targets and run the bounded configured fuzz proof;
- run required local services, smoke checks, browser behavior, and milestone proof;
- use disposable test data and no production credentials;
- leave a previously clean worktree clean.

Do not claim local certification when a required service, database, browser, fixture, or tool was skipped. Fix the environment or report the blocker.

## Finish a milestone

1. Requery the milestone and confirm every included issue is Locally verified, assigned, open, and supported by checked acceptance criteria plus a proof comment.
2. Review the commit sequence and diff from the milestone base. Keep issue boundaries understandable and remove unrelated work.
3. Start from a clean tree and run `./scripts/doctor`, `./scripts/check`, and any milestone-specific UE 5.8.1 proof required by the plan.
4. Confirm the complete check leaves the tree clean. Record the verified head SHA and all evidence.
5. Obtain a fresh review from a separate session or a human. The implementing session must not call its own review independent.
6. Fix findings and rerun every invalidated check. If the base changes, rebase and recertify the exact final head.
7. Push the milestone branch and open one draft pull request with a short natural title, proof, risk, security and operational effects, rollback, and one `Closes #<issue>` line for every included issue.
8. Move every included issue to In review.
9. Run remote CI on the exact reviewed head. Do not merge a different head or bypass a required check.
10. Mark the pull request ready only after local certification, remote checks, and review evidence agree.
11. Stop for human review and human rebase merge. Do not squash a milestone pull request.

## After merge

1. Verify every closing issue is closed and Done, every acceptance criterion is checked, and the milestone shows the expected completion state.
2. Verify the pull request used rebase merge and the issue-sized commits remain understandable in `main` history.
3. Archive completed plans and record final outcomes.
4. Delete only the merged milestone branch and disposable worktree after confirming they contain no unique or uncommitted work.
5. Reconcile any failed closure, stale Project state, or missing proof immediately.

## Current M1 transition

Do not rewrite the ten M1 issues already merged. The remaining milestone branch started from current `main`. After the database audit scope change, the final M1 pull request should close #301, #303, #313, and #358 through #363 unless GitHub milestone scope changes again.
