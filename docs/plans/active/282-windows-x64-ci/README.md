# Windows x64 CI lane

Issue: https://github.com/ishtms/cachelane/issues/282

## Context

CacheLane is developed on an Apple silicon Mac, while M0 targets packaged UE 5.4 through UE 5.8 Win64 reports, PDB and PE identity, and Windows minidump symbolication. The current CI workflow has one Ubuntu job that runs `./scripts/check`. The repository has no registered self-hosted runners.

The first change should add an ephemeral GitHub-hosted x64 Windows lane. This gives every Windows-sensitive Rust and CLI change a native Windows build and test result without adding a persistent machine, credentials, private fixtures, or Unreal Engine to public CI.

This lane does not replace the separate real UE fixture and end-to-end work in issues #143 through #150, #235 through #237, and #254 through #260.

## Acceptance criteria

- A separate `windows check` job runs on `windows-2025` for pull requests, pushes to `main`, and manual workflow dispatches.
- The job installs the pinned Node and Rust toolchains already used by CI.
- The job runs `./scripts/check` from Bash.
- The workflow records `x86_64-pc-windows-msvc` as the Rust host and executes the built Windows tests and binaries.
- The job has read-only repository permission and receives no secrets or private fixtures.
- The existing Linux `check` job and required check context remain unchanged during the first rollout.
- A Windows failure is visible as its own check with useful command output.
- Making the Windows check required remains a separate repository-rules decision after stable evidence exists.

## Risk and blast radius

Risk: R2.

The change adds another operating system to CI and can expose Windows-only failures or increase workflow duration. Its blast radius is limited to repository validation. It does not change product behavior, APIs, stored data, tenant boundaries, dependencies, deployment, production credentials, or customer data.

Making the new check required would be a separate R3 repository-rules change. Registering a persistent self-hosted Unreal runner would also be separate R3 work.

## Current behavior and evidence

- `.github/workflows/ci.yml` has one `ubuntu-latest` job named `check`.
- The job uses read-only repository permission and calls the canonical `./scripts/check` command.
- The active `main` ruleset requires `check`, `dependency audit`, and `dependency review`.
- GitHub reports no registered self-hosted runners for the repository.
- GitHub provides an ephemeral `windows-2025` x64 runner for public repositories.
- The current development Mac is an M1 Max and has no `prlctl` or `utmctl` command installed.
- Recent Linux CI runs on `main` are passing.

## Implementation sequence

1. Keep the existing Linux job name and contents unchanged.
2. Add a separate job named `windows check` using `windows-2025`.
3. Reuse the pinned checkout and Node setup actions.
4. Enable Corepack and install dependencies from the lockfile.
5. Install Rust 1.97.1 with Clippy and rustfmt.
6. Select Bash explicitly for shell steps.
7. Print and assert the Rust host is `x86_64-pc-windows-msvc`.
8. Run `./scripts/check` without adding a second Windows-only test command.
9. Fix only incompatibilities required for the canonical check to pass on Windows.

## Tests and operational verification

- Run `./scripts/check-repository` to parse the workflow and repository files.
- Run `./scripts/check` locally.
- Manually dispatch CI for the implementation branch.
- Confirm the Linux `check` and `windows check` jobs pass.
- Confirm the Windows log reports the expected Rust host.
- Confirm Rust tests execute as Windows binaries.
- Confirm the workflow has read-only permissions and no secret references.
- Confirm the active ruleset and existing required check contexts are unchanged.

## Data, security, and compatibility

The job processes only public repository content on a fresh GitHub-hosted VM. It must not download private real fixtures or receive repository, cloud, Unreal, or production credentials.

The job validates Windows x64 compilation and behavior. It does not prove UE CrashReportClient protocol compatibility, native crash behavior, PDB and PE matching against real builds, or end-to-end symbolication. Those require the private fixture corpus and an authoritative x64 Windows UE environment.

A permanent self-hosted runner must not be registered to the public repository. If real UE automation is added later, use a private validation boundary, explicit trusted dispatch, a resettable machine image, and no production access.

## Rollout

Land the Windows job as an additional non-required check. Use it immediately for M0 Windows-sensitive changes and collect runtime and failure evidence from representative pull requests. Propose a separate ruleset change only after the job is stable and useful.

## Rollback

Remove the `windows check` job. The existing Linux check, security workflows, and branch rules remain unchanged.

## Out of scope

- Installing Unreal Engine on GitHub-hosted runners
- Registering a self-hosted runner to the public repository
- Collecting, sanitizing, or publishing real crash fixtures
- Installing Parallels or UTM
- Creating a private fixture repository
- Changing required status checks
- Adding a new task runner or dependency

## Unresolved decisions

None for the non-required hosted Windows lane.

The authoritative UE x64 execution machine, private fixture storage, reset strategy, and approval boundary remain decisions for the R3 fixture and end-to-end plan.
