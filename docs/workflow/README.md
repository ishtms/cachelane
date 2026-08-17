# Development workflow

FaultLane uses a small delivery loop for the solo, pre-production phase.

```text
request
  -> issue when useful
  -> one branch
  -> implementation and focused tests
  -> ./scripts/check-fast
  -> one pull request
  -> required check
  -> merge and automatic issue closure
```

`AGENTS.md` safety, identity, testing, and scope rules still apply.

## Issues and plans

Use an issue when the outcome needs acceptance criteria, coordination, or history. Small maintenance work may start from the request and use the pull request as its record.

Keep the issue about the observable outcome. Put implementation evidence in the pull request. Do not add a proof comment or a repository plan file.

- R0 and R1 changes proceed with clear acceptance criteria.
- R2 changes need a concise issue plan only when uncertainty or cross-component risk justifies it.
- R3 changes need a human-approved issue plan, security analysis, staging strategy, and rollback.
- R4 operations require explicit human execution.

## Branch and worktree

Fetch current GitHub state and branch from `origin/main`. Use the main checkout when it is available. Create one task worktree only when the main checkout contains unrelated work that cannot be moved safely.

Never delete a branch or worktree until its change is merged and it contains no unique commits or uncommitted files.

## Implementation and local verification

Implement one coherent feature or fix per pull request. Add behavior or regression tests at the lowest useful boundary and exercise the real command, API, UI, or runtime entrypoint.

Run focused checks while iterating, then run `./scripts/check-fast`. Run additional local proofs when the changed boundary requires them. Use `./scripts/check` before a sensitive release or when the issue plan requires complete certification.

Review the final diff for scope, secrets, generated files, compatibility, tenant isolation, untrusted input, failure handling, operations, and rollback.

## Pull request and CI

Open one pull request with the issue, result, verification, risk, and rollback when relevant. Add `Closes #<number>` for every issue the pull request completes.

The only required status is `check`. It runs formatting, linting, type checking, Rust unit tests, PostgreSQL integration tests, repository checks, and browser or processor proofs when the changed paths require them.

The Windows job is advisory and covers Windows compilation plus focused behavior. Dependency review runs only when dependency manifests or lockfiles change.

Complete release builds, bounded fuzzing, full browser certification, and dependency audits run on a schedule or when a sensitive change requires them.

Obtain a fresh review for R3 changes and unusually large changes. Smaller changes may merge after the required check passes and all review threads are resolved.

## After merge

Confirm closing issues closed automatically. Remove the merged task branch and optional worktree only after checking for unique or uncommitted work. No manual Project transition or proof comment is required.
