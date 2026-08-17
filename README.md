# FaultLane

FaultLane is an Unreal-native crash analytics and symbolication platform. It receives Unreal Engine crash reports, stores their original artifacts, matches exact debug information, produces readable stacks, and groups repeated failures into issues.

The current target is packaged Unreal Engine 5.8 games on Windows, validated against the installed UE 5.8.1 build. Basic desktop reporting uses Unreal's built-in Crash Report Client, so a runtime SDK is not required.

The product promise is a readable, symbolicated test crash within ten minutes of account creation, excluding Unreal packaging time.

## Current status

The repository includes project setup, durable Windows crash ingest, isolated processing, Windows symbol upload, grouping, issue views, missing-symbol recovery, alerts, usage enforcement, and an interactive first-crash flow. Local bootstrap setup creates an owner, organization, project, and write-only environment key. A bounded UE 5.8 crash request is stored in the private local bucket before FaultLane acknowledges it and queues processing.

No production deployment is configured.

The current goal is to prove the ten-minute readable crash flow with a real design partner. Self-hosting, wider Unreal compatibility, other platforms, and studio controls stay in a short future roadmap until that workflow is validated.

FaultLane does not currently include generic observability, gameplay analytics, session replay, console support, automated fixes, Kubernetes, Kafka, Redis, Elasticsearch, ClickHouse, or a service per subsystem.

## Architecture

FaultLane is a modular Rust monolith backed by PostgreSQL and S3-compatible object storage, with a Next.js dashboard. API, ingest, worker, scheduler, and migration roles share one codebase. Crash bundles, dumps, logs, comments, and symbols are sensitive untrusted input and cross an isolated processor boundary.

PostgreSQL owns tenant and product state. Object storage owns large binary artifacts. Every row and object access stays tenant-scoped, jobs are idempotent and leased, and database changes remain backward compatible across a deployment window. Durable decisions live under `docs/decisions`, while security and operational boundaries stay close to the affected code.

The current product scope is in [`docs/product/README.md`](docs/product/README.md). Durable system boundaries are in [`docs/architecture/README.md`](docs/architecture/README.md).

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

The web app runs at `http://127.0.0.1:3000`, the API at `http://127.0.0.1:8080`, and the ingest boundary at `http://127.0.0.1:8081` by default. Open `http://127.0.0.1:3000/setup` to create the first project. Bootstrap setup is loopback-only and uses the development secret in `.env`. MinIO initialization creates the private development bucket. Edit `.env` to isolate ports and the Compose project name for another worktree.

Run the command-line application locally with:

```bash
cargo run -p faultlane-cli -- --help
```

## First readable Unreal crash

Start the full local stack with `./scripts/dev`, then open `http://127.0.0.1:3000/setup`. The setup page creates the first project and shows the write key once. It also shows the exact generated `DataRouterUrl`, both required Unreal configuration snippets, and live progress from crash receipt through symbolication.

The tracked UE 5.8 sample is under `samples/unreal-5.8-crasher`. It exits normally unless the packaged game receives the exact `-FaultLaneCrash` flag. Package a disposable copy outside the repository from Git Bash:

```bash
export FAULTLANE_SAMPLE_DATA_ROUTER_URL='http://127.0.0.1:8081/u/<write-key>'
export FAULTLANE_SAMPLE_OUTPUT='/c/Users/<you>/AppData/Local/Temp/faultlane-first-crash'
./scripts/package-unreal-sample
```

The packaging command uses the installed `C:\Program Files\Epic Games\UE_5.8` build by default, writes the injected private configuration and all generated artifacts only to `FAULTLANE_SAMPLE_OUTPUT`, and runs the same bounded configuration check shown in the web guide. Its final JSON reports the disposable project, package, and symbol roots. Set `UNREAL_ENGINE_ROOT` only when UE 5.8 is installed elsewhere.

The check can also be run directly:

```bash
cargo run --package faultlane-cli -- unreal check '<project-root>' --package '<packaged-build-root>'
```

Run `package/Windows/FaultLaneCrasher/Binaries/Win64/FaultLaneCrasher-Win64-Shipping.exe` once without the flag to confirm it stays running, then run it with `-unattended -nullrhi -FaultLaneCrash`. The setup page moves through waiting, received, processing, and matching-symbol states. Use the reported `symbols` directory as `<symbol-root>`, copy the scan command, create a one-time artifact upload token, and copy the generated token and upload commands. The upload command includes the detected project, release, architecture, and configuration. Matching PE and PDB uploads trigger reprocessing automatically. The final state links to the readable grouped issue. Add `-FaultLaneCrashSecondary` only alongside the primary flag to produce the separate secondary sample crash.

Keep `./scripts/dev` running while inspecting the issue. Press Ctrl+C in that terminal to stop the application roles. To stop local PostgreSQL and MinIO while keeping their data, run:

```bash
docker compose --project-name "${FAULTLANE_COMPOSE_PROJECT:-faultlane}" --env-file .env -f deploy/docker-compose/compose.yml stop postgres minio
```

To remove the disposable packaged project, delete the exact `FAULTLANE_SAMPLE_OUTPUT` directory you selected. To also remove this worktree's local database and object-store volumes, run the following only after checking the Compose project name:

```bash
docker compose --project-name "${FAULTLANE_COMPOSE_PROJECT:-faultlane}" --env-file .env -f deploy/docker-compose/compose.yml down --volumes --remove-orphans
```

After creating a project-scoped artifact upload token through the control API, upload a Windows release with:

```bash
export FAULTLANE_API_URL=http://127.0.0.1:8080
export FAULTLANE_TOKEN=<one-time-artifact-upload-token>
cargo run -p faultlane-cli -- symbols upload <artifact-path> --project <project-slug> --release <version> --configuration shipping --channel playtest --build-timestamp <RFC3339-time>
```

Hosted deployments will use a private Cloudflare R2 bucket with `OBJECT_STORE_ENDPOINT`, `OBJECT_STORE_BUCKET`, `OBJECT_STORE_REGION=auto`, `OBJECT_STORE_ACCESS_KEY`, and `OBJECT_STORE_SECRET_KEY`. Local and self-hosted deployments use MinIO through the same S3-compatible API. Final PE and PDB verification runs inside the isolated processor boundary.

## Verification

```bash
./scripts/check-fast
./scripts/check-pr
./scripts/check
./scripts/smoke
```

`./scripts/check-fast` is the normal local gate. `./scripts/check-pr` is the required pull request gate and needs PostgreSQL. Set `FAULTLANE_BASE_SHA` to the base commit when running it locally so changed-path proofs are selected. `./scripts/check` adds release builds, bounded fuzzing, and full browser certification for nightly, release, and sensitive-change use. `./scripts/smoke` expects the local application or a target environment to be running.
Set `FAULTLANE_SMOKE_DURABLE=true` for an empty isolated target to include one real crash upload, duplicate retry, and state read.
Set `FAULTLANE_SMOKE_SYMBOL_UPLOAD=true` for an empty isolated target to upload the checked-in Windows artifacts twice and verify that the second run transfers zero bytes.

## License

The server license is not finalized. The proposed model is AGPL-3.0 for the server and web application, with Apache-2.0 for the CLI and Unreal plugin, subject to legal and design-partner review. Until a license is added, normal copyright restrictions apply.
