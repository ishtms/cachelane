# Processor boundary

Crash bundles and Windows artifacts are untrusted. The connected worker downloads tenant-scoped objects into a private attempt directory, then passes that directory to one short-lived processor container. The processor never receives database, object-store, API, or host credentials.

The worker resolves the configured image to an immutable image ID at startup and fails if the image is missing, malformed, or declares environment variables other than `PATH`. Each attempt uses fixed internal arguments and paths with:

- no network;
- a read-only root filesystem and read-only input mount;
- a non-root user, dropped capabilities, `no-new-privileges`, and the default seccomp profile;
- one CPU, 2 GiB memory and swap, 64 processes, 256 open files, 120 CPU seconds, 150 wall seconds, 64 MiB scratch, and 16 MiB output;
- bounded stderr that is discarded and never copied into event state or logs.

The processor Docker build context allows only workspace manifests and Rust source under `apps/cli`, `apps/server`, and `crates`. Local environment files, documents, artifacts, logs, build outputs, and unrelated workspace content are never sent to the builder.

Every durable publication locks and rechecks the organization, project, job, worker, random lease token, and unexpired lease. Losing a lease prevents artifact, cache, or crash-result publication. Parser and identity failures use fixed safe codes. A resource failure retries once in a fresh container, while storage, database, and runtime failures use bounded retries.

Containers carry only internal deployment-scope, job, and lease-token ownership labels. Startup and periodic reconciliation remove an owned container only after PostgreSQL confirms that its exact lease is absent or expired. Attempt-directory cleanup accepts only names derived from valid UUID job and lease identifiers. Startup refuses to change permissions on or reuse an existing scratch root without its exact FaultLane ownership marker. The private scratch hierarchy uses `0700` permissions on Unix. Windows startup removes inherited access and verifies that only the current service identity and `SYSTEM` retain full control.

Raising a compiled limit, adding processor network access, passing customer-controlled arguments, or exposing credentials to the processor requires a new security review.
