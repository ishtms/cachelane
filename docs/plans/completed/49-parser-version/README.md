# Versioned crash context records

Issue: [#49](https://github.com/ishtms/faultlane/issues/49)

## Outcome

Every extracted crash context record carries a stable parser version and can be serialized as deterministic normalized JSON for later reprocessing.

This advances the M0 exit criterion by making parser output versioned and reproducible before the real report and readable stack proof in issue #150.

## Scope

Included:

- Add one public crash context parser version constant.
- Store that version on every `CrashContextData` value created by extraction.
- Make extracted crash context records, properties, and thread data serializable.
- Prove deterministic full-record JSON with synthetic tests.

Excluded:

- Issue #150, which requires a real Windows report, matching artifacts, and a readable stack.
- Symbol scanning, artifact matching, minidump processing, ingestion, persistence, and reprocessing jobs.
- Command-line or HTTP behavior.
- Database schemas, migrations, and stored production data.

## Dependency order and delivery

The parser adapter and extraction work from issues #42, #43, #44, #45, #47, and #48 are complete. This feature has no unresolved dependency.

One pull request stage will update `crates/unreal/Cargo.toml`, `crates/unreal/src/lib.rs`, and `Cargo.lock` only if dependency metadata changes it. No API schema, migration, service, or external resource changes are expected.

## Acceptance criteria

- `CrashContextData` includes a parser version set by extraction from one public version constant.
- Extracted records, properties, and thread data serialize with stable field names and ordering.
- JSON preserves source and normalized values, repeated ordered data, and namespaced unknown fields.
- Identical XML and extraction options produce byte-identical JSON.
- Command-line data remains excluded by default and only appears when explicitly enabled.
- Synthetic tests cover the version, deterministic full-record JSON, unknown fields, and command-line policy.
- No HTTP API, database, authorization, deployment, or user-facing behavior changes.

## Risk and gates

Risk is R2 because this adds an additive serialization contract at the Unreal and shared-domain boundary. The existing workspace `serde` dependency is sufficient. There is no authentication, authorization, tenant, infrastructure, deployment, or production-data change, so no R3 approval or staging gate applies.

Extracted text remains sensitive untrusted input. Serialization must not log it or enable command-line extraction by default.

## Verification

- `cargo test -p faultlane-unreal`
- `./scripts/check-fast`
- `./scripts/check`

No runtime smoke check is required because no application entry point changes.

## Rollout and rollback

Rollout is the normal library merge after checks and independent review. This plan moves to completed in the same reviewed pull request so merged `main` does not retain a finished stage under active plans.

Roll back by reverting the parser-version field, serialization derives, dependency change, and tests. No data migration or operational cleanup is required.

## Final state

The pull request references issue #49 without closing it. Issue #49 remains In Progress until the future event persistence and reprocessing path stores and reads the parser version. The M0 roadmap keeps #49 incomplete. Issues #53 and #150 remain Backlog because they are separate symbol and end-to-end outcomes.

## Result

- Every extracted `CrashContextData` record carries parser version `1` from one public constant.
- Complete records, properties, threads, normalized values, and unknown fields serialize deterministically.
- Command-line data is absent by default and only serializes with explicit extraction permission.
- `cargo test -p faultlane-unreal`, `./scripts/check-fast`, and `./scripts/check` passed locally.
- Pull request CI, dependency review, and dependency audit passed.
- Independent review found one issue-closing scope error. The plan and pull request now keep persistence and reprocessing work open in issue #49.

## Unresolved decisions

None.
