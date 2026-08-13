# CacheLane

CacheLane is an Unreal-native crash analytics and symbolication platform. It receives Unreal Engine crash reports, stores their original artifacts, matches exact debug information, produces readable stacks, and groups repeated failures into issues.

The current target is packaged Unreal Engine 5.8 games on Windows, validated against the installed UE 5.8.1 build. Basic desktop reporting uses Unreal's built-in Crash Report Client, so a runtime SDK is not required. Earlier engine versions will be tested during the late pre-launch compatibility pass.

## Current status

The repository includes the first-project setup flow, Windows crash-processing feasibility work, local PostgreSQL and MinIO services, and deterministic verification. Local bootstrap setup creates an owner, organization, project, and write-only ingest key. Durable crash ingestion remains unavailable until its storage boundary is implemented.

No production deployment is configured.

## Repository layout

```text
apps/server       Rust API, ingest, worker, scheduler, and migration roles
apps/cli          Rust command line application
apps/web          Next.js dashboard
crates/domain     Shared product state and domain types
deploy            Local and self-hosting deployment assets
migrations        PostgreSQL migrations
openapi           Versioned HTTP contract
scripts           Stable development and verification commands
```

## Local setup

Requirements:

- Rust 1.97.1 through rustup
- Node.js 24.13.1
- pnpm 10.21.0 through Corepack
- Docker with Docker Compose

```bash
./scripts/setup
./scripts/doctor
./scripts/dev
```

The web app runs at `http://127.0.0.1:3000`, the API at `http://127.0.0.1:8080`, and the ingest boundary at `http://127.0.0.1:8081` by default. Open `http://127.0.0.1:3000/setup` to create the first project. Bootstrap setup is loopback-only and uses the development secret in `.env`. Edit that file to isolate ports and the Compose project name for another worktree.

Run the command-line application locally with:

```bash
cargo run -p cachelane-cli -- --help
```

## Verification

```bash
./scripts/check-fast
./scripts/check
./scripts/smoke
```

`./scripts/check` is the canonical pre-PR command and is also used by CI. `./scripts/smoke` expects the local application or a target environment to be running.

## License

The server license is not finalized. The proposed model is AGPL-3.0 for the server and web application, with Apache-2.0 for the CLI and Unreal plugin, subject to legal and design-partner review. Until a license is added, normal copyright restrictions apply.
