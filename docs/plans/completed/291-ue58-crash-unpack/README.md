# Bounded UE 5.8 crash request unpacking

Issue: [#291](https://github.com/ishtms/cachelane/issues/291)

## Outcome

Add `cachelane crash unpack <request>` so a developer can inspect a UE 5.8 Crash Report Client request and receive deterministic JSON containing the envelope metadata and accepted files. Invalid or unsafe requests return a nonzero exit code with a safe error category.

## Context

The CLI can parse a standalone crash context XML file and scan Windows debug artifacts, but it cannot read the request body sent by Crash Report Client. M0 needs the real report envelope decoded before parsing and symbolication can be composed behind one command.

The installed UE 5.8.1 source at `Engine/Source/Runtime/CrashReportCore/Private/CrashUpload.cpp` is the transport authority for this change. `FCrashUploadToDataRouter` sends an `application/octet-stream` POST with `AppID`, `AppVersion`, `AppEnvironment`, `UploadType`, and `UserID` query parameters. The body is a zlib stream. Its expanded payload starts with `CR1`, fixed ANSI directory and archive names, expanded size, and file count. Each file record contains a sequential index, fixed ANSI leaf name, byte count, and bytes.

## Acceptance criteria

- The command decodes the zlib-compressed `CR1` format produced by the installed UE 5.8.1 Crash Report Client.
- The decoder reads expanded data sequentially and does not retain the complete expanded request in memory.
- Default limits bound compressed bytes, expanded bytes, expansion ratio, file count, file bytes, crash context bytes, and XML nodes.
- Traversal, absolute paths, invalid or padded names, duplicate critical files, malformed compression, incorrect sizes or counts, trailing data, invalid crash context UTF-8, unsafe XML, and malformed XML return typed safe errors.
- Unknown safe files remain visible in the manifest without interpreting or printing their contents.
- Identical input produces byte-for-byte identical JSON and rejected requests produce no stdout and a nonzero exit code.
- A private sanitized request captured from the installed UE 5.8.1 build passes the same command without entering Git.

## Risk and blast radius

Risk: R2.

This adds a decompression dependency and executable parsing path at a sensitive untrusted-input boundary. The change is local to the Unreal library and CLI. It creates no network listener, database, stored state, tenant boundary, credential, deployment, or production action.

## Current behavior and evidence

- `cachelane crash parse` accepts only a standalone XML file.
- `crates/unreal` already rejects DTDs, malformed XML, unexpected roots, and excessive XML nodes with safe errors.
- The architecture places Unreal request parsing in a capability crate below application entrypoints.
- The threat model requires streaming reads plus compressed, expanded, ratio, count, per-file, traversal, duplicate-file, XML, and parser limits.
- The installed UE 5.8.1 `CrashUpload.cpp` writes the `CR1` header and file records through `FMemoryWriter`, compresses the result with zlib, and sends the compressed bytes as the POST body.

## Implementation sequence

1. Add the constrained zlib dependency to the workspace and Unreal crate.
2. Add versioned manifest, file-kind, limits, and typed error types to the Unreal capability.
3. Decode the `CR1` header and file records through bounded streaming readers.
4. Validate names, indexes, sizes, counts, critical-file uniqueness, crash context UTF-8, and XML safety while discarding file contents after inspection.
5. Add the `crash unpack` CLI entrypoint with deterministic JSON and safe errors.
6. Add parser and CLI behavior tests for valid input and adversarial boundaries, plus a fuzz target for compressed request bytes.
7. Run a synthetic command proof, the private UE 5.8.1 request proof, focused checks, and the complete repository check.

## Verification

- `cargo test -p cachelane-unreal`
- `cargo test -p cachelane-cli`
- `cargo check --manifest-path fuzz/Cargo.toml --bin crash_request`
- `cargo run -p cachelane-cli -- crash unpack <synthetic-ue58-request>` twice with byte-for-byte comparison
- Adversarial CLI tests cover compressed and expanded limits, ratio, file count, per-file size, traversal, absolute paths, duplicates, malformed compression, truncation, unsafe XML, malformed XML, and trailing data.
- `cachelane crash unpack <private-ue58-request>` validates the installed UE 5.8.1 capture locally without committing it.
- `./scripts/check-fast`
- `./scripts/check`

No service smoke test is needed because the feature is a local CLI command.

## Data, security, and compatibility

Request bodies, file contents, source paths, and parser payloads are never included in errors. The manifest exposes only the archive metadata, leaf filenames, file sizes, and classifications requested by the developer. The decoder retains at most one bounded crash context plus small read buffers. Other file bytes are discarded after counting.

The initial defaults accept up to 64 MiB compressed, 256 MiB expanded, 128 files, 128 MiB per file, a 200:1 expansion ratio, a 4 MiB crash context, and 100,000 XML nodes. These limits are explicit caller data so a future ingest boundary can configure stricter values without changing the format parser.

The decoder targets the installed UE 5.8.1 `CR1` format. Unknown safe files are preserved in the manifest. Unsupported envelope versions fail closed instead of falling back to the older incomplete header format mentioned in the engine source.

## Rollout and rollback

Ship the command as an additive local feature. Roll back by reverting the pull request. No stored data, migration, external resource, or cleanup is involved.

## Out of scope

- HTTP ingestion, query-parameter validation, persistence, or asynchronous jobs
- Writing extracted files to disk
- Semantic normalization beyond validating the crash context XML
- Minidump parsing and symbolication
- Optional attachment uploads sent as a later Crash Report Client request
- Committing private request data or matching build artifacts

## Unresolved decisions

None. The private request proof may lower limits if observed UE 5.8.1 files are materially smaller, but it must not raise them without new evidence and review.

## Validation evidence

The private proof used a Blueprint-only packaged Development build created by installed UE 5.8.1 changelist 56057345 with Crash Report Client included. `debug crash` produced a request captured on localhost.

- Method: `POST`
- Content type: `application/octet-stream`
- Query keys: `AppEnvironment`, `AppID`, `AppVersion`, `UploadType`, and `UserID`
- Compression: zlib
- Envelope: `CR1`
- Compressed request: 134,839 bytes
- Expanded archive: 708,878 bytes
- Files: `CacheLaneProof.log` at 62,907 bytes, `CrashContext.runtime-xml` at 25,254 bytes, `CrashReportClient.ini` at 342 bytes, and `UEMinidump.dmp` at 618,748 bytes

The command returned exit code 0 twice for the captured body and emitted byte-for-byte identical version 1 manifests containing one log, one crash context, one unknown file, and one minidump. The request and matching packaged artifacts remain in a dedicated private directory outside Git.

## Result

Bounded UE 5.8 crash request decoding shipped in [#338](https://github.com/ishtms/cachelane/pull/338). The synthetic adversarial suite and private installed-engine proof passed, and the request decoder fuzz target compiles with the repository checks.
