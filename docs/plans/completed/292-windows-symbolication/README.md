# Local Windows minidump symbolication

Issue: [#292](https://github.com/ishtms/cachelane/issues/292)

## Outcome

Add `cachelane crash symbolicate <dump> --symbols <path>` so a developer receives deterministic JSON with the faulting thread first, readable Windows frames where matching PE and PDB artifacts are available, partial raw frames otherwise, exact artifact diagnostics, trust, inline frames, and processor versions.

## Context

The merged artifact scanner discovers PE and PDB files and matches companions by embedded debug identity and architecture. The CLI does not parse minidumps, unwind stacks, or resolve source locations. M0 requires that executable path before local reprocessing and full report processing can be composed.

The current rust-minidump crates provide a Windows x64 stackwalker and a local debug-info provider. The provider uses PE unwind data through framehop and PDB function, source, and inline data through wholesym. It accepts a module list that can be rewritten to selected local paths while retaining each minidump module's base address and identity. This lets CacheLane select artifacts through its scanner first and prevents the provider from trusting filenames or original paths embedded in the dump.

## Acceptance criteria

- The command accepts one bounded Windows x64 minidump and one bounded local artifact tree.
- Minidump modules select PE files by embedded code ID, debug ID, and architecture, then select PDB companions through the scanner's embedded identity match.
- The provider can read only selected regular files under the requested artifact root. Original code and PDB paths embedded in the minidump are never opened.
- Output places the faulting thread first and orders remaining threads by thread ID.
- Every frame preserves the raw instruction address, module, module-relative address, trust, symbol status, function, source file, source line, and inline frames where available.
- Output records symbolicator and minidump processor versions plus exact expected code and debug IDs for missing or mismatched modules.
- Identical input produces byte-for-byte identical JSON.
- Malformed, oversized, unsupported, timed-out, missing, and mismatched inputs return bounded safe errors or partial results without echoing artifact contents or original private paths.
- A private UE 5.8.1 packaged crash resolves a known faulting stack through the same command while the fixture remains outside Git.

## Risk and blast radius

Risk: R2.

This adds parser, unwind, symbol lookup, memory-map, and async runtime dependencies at a sensitive untrusted-binary boundary. It extends the symbols crate and CLI only. It adds no API, database, stored state, tenant boundary, network access, service, deployment, credential, or production action.

The blast radius includes workspace build time, dependency audit surface, local file reads, and Windows-specific processing behavior. Linux CI must still compile and run all platform-independent tests. The native Windows lane and local UE 5.8.1 proof own readable-stack evidence.

## Current behavior and evidence

- `cachelane symbols scan` returns deterministic PE and PDB identity records and does not follow symbolic links.
- `cachelane crash parse` parses standalone crash context XML, but no command accepts a minidump.
- The private packaged UE 5.8.1 proof contains a 618,748-byte `UEMinidump.dmp`, a matching 331,716,024-byte `UnrealGame.exe`, and a 293,163,008-byte `UnrealGame.pdb`.
- rust-minidump 0.27 exposes faulting-thread selection, all-thread walking, frame trust, raw addresses, source locations, and inline frames.
- minidump-unwind 0.27 with `debuginfo` loads Windows x64 unwind data from PE files and symbols from PDB files without network access.
- Existing workspace facilities do not parse minidumps or PDB line and inline records. Implementing those formats or Windows unwinding locally would duplicate the selected maintained libraries.

## Implementation sequence

1. Pin the compatible 0.27 rust-minidump crates with network features disabled and enable the existing Tokio runtime for local async processing.
2. Add bounded artifact-tree scanning for entry count, directory depth, file count, individual artifact size, and total artifact size without following links. Read only the PDB stream directory and 64-byte DBI identity header so large Unreal PDB streams do not require large scanner allocations.
3. Parse the minidump after a byte limit and reject unsupported operating systems and architectures.
4. Match every module to scanner records by code ID, debug ID, and architecture. Record exact missing or mismatch diagnostics.
5. Clone the minidump module list and replace embedded file paths with selected paths under the symbol root or guaranteed missing paths under that root.
6. Run the debug-info provider and processor behind a wall-time boundary, then map only required values into CacheLane's versioned deterministic schema.
7. Add unit and CLI behavior tests for readable, partial, mismatch, malformed, oversized, deterministic, and safe-error behavior. Add a minidump fuzz target.
8. Run the real command against the private UE 5.8.1 crash and matching packaged artifacts.
9. Run focused checks, `./scripts/check-fast`, and one `./scripts/check` for the final pull request head.

## Verification

- Symbols tests cover exact module selection, same-name mismatches, missing PE, missing PDB, artifact-tree limits, deterministic ordering, and selected paths staying under the symbol root.
- CLI tests exercise the real executable and compare repeated JSON byte for byte.
- Windows behavior tests use a small synthetic PE, PDB, and minidump produced from checked-in fixture source. A synthetic 36,716,544-byte DBI stream proves the scanner reads only its identity header while retaining the existing 16 MiB metadata-read cap.
- `cargo check --manifest-path fuzz/Cargo.toml --bin minidump`
- `cargo run -p cachelane-cli -- crash symbolicate <synthetic-minidump> --symbols <synthetic-artifacts>`
- `cargo run -p cachelane-cli -- crash symbolicate <private-ue58-minidump> --symbols <private-package>`
- `./scripts/check-fast`
- `./scripts/check`

No service smoke test is required because this is a local CLI feature.

## Data, security, and compatibility

The default limits are 64 MiB per minidump, 4,096 artifact-tree entries, 64 directory levels, 512 artifacts, 1 GiB per artifact, 4 GiB total artifacts, 512 threads, 4,096 modules, 512 frames per thread, and 120 seconds wall time. PE metadata reads retain the existing 16 MiB cap, with debug-directory and CodeView reads limited further to 64 KiB each. PDB scanner metadata reads also retain the 16 MiB cap, and DBI identity uses only the 64-byte header even when the stream is much larger. These limits accept the observed UE 5.8.1 proof while bounding directly controlled input and output sizes. A later isolated worker still owns operating-system CPU and resident-memory enforcement.

The scanner does not follow symbolic links. Only regular files returned by the scanner are handed to the processor. Paths embedded in minidumps are used as display metadata only and are reduced to leaf module names in CacheLane output. Errors contain fixed categories and never parser payloads, artifact contents, or requested private paths.

The command supports Windows x64 minidumps for the installed UE 5.8.1 development path. Unsupported operating systems and CPU architectures fail closed. The output schema and processor versions make later compatible extensions explicit.

## Rollout and rollback

Ship the command as an additive local feature. Roll back by reverting the pull request. No state, migration, external resource, or cleanup is involved.

## Out of scope

- Hosted worker sandboxing or production resource isolation
- Symbol upload, storage, caches, or network symbol servers
- Linux, macOS, mobile, or 32-bit Windows symbolication
- Crash request extraction or normalized crash-context composition
- Reprocessing state, grouping, persistence, or APIs
- Committing private Unreal reports or packaged artifacts

## Unresolved decisions

None. M0 validates Windows x64 only. Broader platform behavior remains in its roadmap milestones.

## Result

Local Windows minidump symbolication shipped in [#339](https://github.com/ishtms/cachelane/pull/339). Synthetic end-to-end tests prove exact artifact selection, readable source and inline frames, partial stacks, safe failures, and byte-stable output. The private UE 5.8.1 proof resolves readable functions from matching packaged artifacts.
