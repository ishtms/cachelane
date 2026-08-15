# Alert database correctness

Issue: https://github.com/ishtms/faultlane/issues/362

Status: Locally verified on August 16, 2026

## Context

The alert claim predicate requires `attempt < max_attempt` before it considers an expired lease. A disposable proof started a delivery at attempt two of three, claimed attempt three, expired its lease, and confirmed the next claim returned no row while the delivery remained expired and leased.

Rule evaluation always selects the same oldest 1,000 enabled rules. Issue observations also stop at 1,000, but recovery compares that truncated result with every stored active scope. This can starve later rules, miss later issue triggers, and recover an active issue that only fell outside the page.

## Acceptance criteria

- Every expired lease is reconciled, including a final-attempt lease.
- An exhausted expired lease reaches `dead` with one fixed failure code, or follows an explicitly documented final retry, and never remains leased.
- Enabled rules rotate through bounded pages without selecting the same first page forever.
- Issue triggers process all pages before recovery uses a complete active set.
- 1,001 enabled rules all advance within a bounded number of ticks.
- 1,001 active matching issues produce no missed trigger or false recovery.
- The complete #301 alert proof is refreshed on the corrected head.

## Risk and blast radius

Risk: R2 within the approved #301 R3 design.

The change affects alert queue terminal state, scheduler progress, and recovery correctness. It does not change secret storage, outbound destination validation, payload contents, authorization, or provider retry semantics. The schema change is additive.

## Current behavior and evidence

- `claim_delivery` filters attempts before pending and expired-lease branches, which produced the measured stuck row.
- `evaluate_rules_once` orders enabled rules by unchanged `updated_at` and ID with `LIMIT 1000` and no cursor.
- `evaluate_rule` builds a set from at most 1,000 issue observations, then marks every stored active scope absent from that set as recovered.
- Alert transitions and delivery uniqueness are already idempotent under concurrent evaluators.

## Implementation sequence

1. Change delivery claim reconciliation so one locked candidate can either become a new lease or atomically become `dead` with `lease_expired_final` when its attempts are exhausted.
2. Keep the lease-token completion check and existing definite, ambiguous, and permanent delivery outcomes unchanged.
3. Add `last_evaluated_at` to alert rules and an index that selects the least recently evaluated enabled rules. Mark a rule only after its evaluation finishes.
4. Keyset-page issue observations for one rule to exhaustion. Apply triggers page by page, but run recovery only after the final page. A crash before the final page leaves active conditions active and safely replays on the next evaluation.
5. Preserve the complete-set recovery predicate and environment and tenant scope in SQL.
6. Add expired-final-lease, concurrent reclaimer, 1,001-rule, 1,001-issue, interrupted page, replay, disablement, and tenant-isolation tests.
7. Run `./scripts/prove-alerts`, `./scripts/check-fast`, and refresh #301 evidence.

## Tests and operational verification

- Queue tests assert no expired leased row can remain unclaimable.
- Scheduler tests record the maximum age since each enabled rule was evaluated.
- Issue tests move a still-active issue across page boundaries and assert no recovery until its condition clears.
- Existing outbound adapter, signature, secret, SSRF, authorization, quiet-hour, and ambiguous-timeout tests remain unchanged and pass.

Monitor oldest rule evaluation age, evaluation duration, issue pages, terminal expired leases, dead deliveries, and fixed failure codes. Logs keep the existing redaction rules.

## Compatibility, rollout, and rollback

The new rule timestamp and index are additive. Older schedulers ignore them. New schedulers can evaluate existing rules with null timestamps first. Stage with alerts enabled only against disposable providers and data.

Rollback disables alerts and restores the previous application while retaining rule timestamps and delivery states. Before resuming the old worker, reconcile any expired final leases manually or with the corrected build so they are not stranded again.

## Verification evidence

- A final-attempt delivery was claimed at attempt three, expired, and reconciled once to `dead` with `lease_expired_final` by two concurrent reclaimers. A separate nonfinal expired lease was reclaimed and delivered by exactly one worker.
- A fixture with 1,001 enabled rules and one disabled rule evaluated 1,000 rules on the first tick and every enabled rule within two ticks. The disabled rule remained unevaluated. The final proof completed both ticks in 14.877 seconds.
- A fixture with 1,001 matching issues stopped after its first page without running recovery, then replayed and completed two keyset pages in 26.606 seconds. Every matching scope stayed active, a moved still-active issue did not recover, only the resolved issue recovered, and another tenant remained untouched.
- `./scripts/prove-alerts` passed all five non-database alert tests and four PostgreSQL alert tests in 52.2 seconds. It refreshed the seven original condition, deduplication, recovery, retry, API, redaction, adapter, and tenant-scope checks from #301.
- `./scripts/check-fast` passed on the final issue tree.
- No hosted or production rollout was performed. Rollback remains disabling alerts, retaining all state, and reconciling expired final leases with the corrected build before an older worker resumes.

## Out of scope

- New alert kinds or providers
- Changing exactly-once claims for external providers
- Secret rotation or network policy changes
- Replacing the alert queue
