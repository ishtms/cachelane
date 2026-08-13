# Windows artifact identity scanning

Issue: [#290](https://github.com/ishtms/cachelane/issues/290)

## Outcome

Add `cachelane symbols scan <path>` so a developer can recursively inspect Windows PE and PDB artifacts and receive deterministic JSON containing relative path, artifact type, architecture, embedded debug identity, PE code identity, size, match state, and safe per-file errors.

## Context

The CLI currently parses Unreal crash context XML only. The workspace has no Windows artifact parser or symbol ownership boundary. The PRD requires content-based PE and PDB matching before upload and symbolication. `ARCHITECTURE.md` permits a new crate when it creates a real ownership, dependency, security, or test boundary. Parsing sensitive untrusted debug artifacts creates that boundary.

The authoritative source order also refers to relevant files under `docs/security/` and `docs/operations/`, but those directories are absent. This plan therefore applies the untrusted-artifact controls stated directly in the PRD and architecture. It does not create unrelated documentation.

## Decision

Create a focused `cachelane-symbols` library used by the CLI. Use `object` 0.40 with only PE reading and standard library support, plus `pdb` 0.8 for PDB information and DBI architecture. Keep discovery and matching in the library so later upload and symbolication features can reuse the same identities without invoking the CLI.

- Read PE metadata through `object` and PDB metadata through `pdb`.
- Format a debug identity as uppercase PDB GUID bytes followed by the hexadecimal age. This is the common Windows debug identifier form and is shared by both artifact types.
- Format the PE code identity from its timestamp and image size, not its filename or file length.
- Match a PDB when its GUID matches, its PDB age is at least the PE CodeView age, and known architectures do not conflict. This follows the PDB format contract for incremental updates.
- Discover only regular `.exe`, `.dll`, and `.pdb` files, case-insensitively. Do not follow symbolic links.
- Sort by normalized relative path and serialize a stable result schema.
- Return typed safe categories for unreadable, malformed, unsupported, or missing-identity artifacts. Do not include bytes or parser payloads in errors.

## Risk and blast radius

Risk: R2.

The change adds two parser dependencies, one reusable crate, a CLI command, and a JSON contract. It reads local untrusted files but creates no database, network, tenant, credential, deployment, or production state. The command is additive and reversible.

## Implementation sequence

1. Add the symbol crate and constrained parser dependencies.
2. Implement deterministic discovery without following links.
3. Extract PE type, architecture, CodeView identity, code identity, and image size.
4. Extract PDB identity and architecture.
5. Match compatible artifacts and expose stable result types.
6. Add the `symbols scan` CLI entrypoint and JSON output.
7. Add synthetic PE and PDB behavior fixtures built in tests, plus malformed and ordering cases.
8. Run the product proof, fast checks, and the complete repository check.

## Verification

- Unit tests cover identity formatting, match rules, stable ordering, extensions, symbolic links, malformed inputs, and safe error categories.
- CLI behavior tests run the real executable against a synthetic artifact tree and compare byte-for-byte JSON across repeated scans.
- `cargo run -p cachelane-cli -- symbols scan <synthetic-windows-artifact-dir>` proves the entrypoint.
- `./scripts/check-fast` and `./scripts/check` must pass on the final commit.

## Security and compatibility

Artifact bytes and source parser errors are never serialized. Paths are relative to the requested root and normalized only for stable output. Symbolic links are ignored so recursion cannot escape the requested tree. PE reads are on demand and PDB reads are bounded by the selected stream parser, while hosted CPU, memory, disk, time, and filesystem isolation remains the responsibility of the later worker feature.

The output schema starts at version 1. Future formats add new artifact variants or versioned fields without changing Windows identity meaning. The implementation targets the installed Rust toolchain and UE 5.8 Windows artifacts. Real Unreal artifact quality is proven later by the private M0 end-to-end issue.

## Rollout and rollback

Ship the command as an additive local capability. Later upload and symbolication code may consume the library only after its behavior tests pass. Roll back by reverting the feature pull request. No stored state or migration requires repair.

## Out of scope

- Artifact upload, storage, tenant deduplication, or release manifests
- Minidump stack walking or symbolication
- Hosted worker sandbox implementation
- Non-Windows artifact formats
- Derived symbol or unwind cache generation
- Private Unreal fixture material

## Result

Windows PE and PDB identity scanning shipped in [#337](https://github.com/ishtms/cachelane/pull/337). The command matches artifacts by embedded identities, emits deterministic JSON, rejects unsafe artifact trees, and passes the synthetic CLI behavior tests and repository checks.
