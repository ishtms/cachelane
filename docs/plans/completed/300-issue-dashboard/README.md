# Issue dashboard and readable crash detail

Issue: [#300](https://github.com/ishtms/faultlane/issues/300)

Status: Completed through PR #351 on August 14, 2026. No production deployment was performed.

## Outcome

When an authorized developer opens a project, FaultLane shows a bounded health overview and a searchable, stably paginated issue list. Opening an issue shows its representative crash, readable faulting and all-thread stacks, event history, release and platform facets, processing attempts, exact missing-symbol identities, and a safe copyable upload command.

The current loopback bootstrap owner can inspect sensitive derived context, download the retained raw bundle or bounded log attachment, and request idempotent event reprocessing. Hosted sessions and the four production roles remain owned by #310 and will replace the bootstrap adapter without changing the tenant-scoped dashboard queries.

## Context

Issues #311, #298, and #299 now provide isolated processing results, stable issue assignments, release evidence, immutable processing history, exact missing-symbol waiters, and bounded reprocessing requests. The control API already has basic issue list and aggregate detail routes, but it does not return a project overview, event timeline, readable event detail, processing attempts, raw downloads, or corrective commands. Its issue cursor points at a mutable database row instead of carrying the ordering tuple.

The Next.js app has only the landing and local setup routes. It has no project shell, issue list, issue detail, loading boundary, route error boundary, pagination, reprocess action, copy control, attachment proxy, or dashboard browser test.

The product sources have three known discrepancies. The overview still calls M0 current, and the overview, PRD, and architecture retain the former product name. GitHub milestone M1 and the repository use FaultLane. The #300 issue asks for a usage view, while #302 owns authoritative billing-cycle metering, plan limits, retention, and quota enforcement. This change therefore shows explicitly labeled observed event and retained-byte totals from current durable rows. It does not call them billable usage or make admission decisions. #302 will replace that snapshot with the authoritative usage ledger and plan state.

Project data rules and configurable redaction belong to #312. Until then, comments, log tails, GameData, system fields, and raw downloads are available only through the current owner-only control boundary, never through public ingest credentials. The API returns only explicit bounded fields and never returns `unknown_fields`, command lines, raw result JSON, object keys, processor stderr, symbol files, or storage credentials.

## Acceptance criteria

- An authorized project read returns a repeatable-read overview with a fixed 30-day UTC window, daily event buckets, new and regressed issues, top active issues, release and platform distributions, crash types, symbolication success, missing-symbol counts, ingest recency, processing-state and queue health, and an explicitly non-billing observed usage snapshot.
- The issue list supports bounded filters for status, regression state, release, crash type, platform, architecture, engine version, symbolication state, first and last seen, plus bounded free-text matching across title, function, module, error message, and user comment.
- Issue and event list pages use strict opaque keyset cursors containing the complete ordering tuple and filter identity. Invalid, oversized, cross-filter, and cross-project cursors fail safely. No offset pagination or mutable row lookup is used.
- Loading, empty, error, and populated project and issue states are accessible, responsive, and distinguish API unavailability from a missing resource without exposing authorization details.
- Issue detail returns title, status, regression state, counts, first and last seen, releases, platforms, variants, release mapping, representative event, and stable internal paths from one repeatable-read snapshot.
- The event timeline is separately paginated and returns bounded facets for release, platform, architecture, environment, crash type, and processing state. Every event is proven to belong to the requested issue and project.
- Event detail projects only validated current-result fields: crash classification, processing state, bounded user comment, bounded log tail, bounded GameData and system context, release evidence, faulting and all-thread stacks, missing identities, and immutable result and request history.
- Every displayed stack frame includes its raw instruction, module and relative address when present, symbol status, function, source file and line, inline frames, trust, and partial or truncated state. The faulting thread is unambiguous.
- Missing-symbol diagnostics use exact tenant-scoped waiter evidence and show required PE or PDB kind, module, architecture, debug ID, code ID when required, release, and a PowerShell-safe copyable `faultlane symbols upload` command with no stored absolute path.
- The current owner can request event reprocessing through the existing bounded API with a deterministic idempotency key tied to the event and current result. The UI shows accepted progress without creating duplicate manual requests on retry.
- The current owner can download the bounded derived log as UTF-8 text and stream the retained raw bundle through a scoped API and server-side web proxy. Responses disclose no object key, bucket, credential, symbol file, or reusable storage URL and use safe filenames, no-store, no-sniff, and no-referrer headers.
- Missing, orphaned, oversized, or storage-unavailable raw objects return fixed errors before or during streaming without widening access. Raw download can be disabled independently of issue reads.
- All API queries carry organization and project scope. Issue, event, release, result, request, and object IDs from another tenant are indistinguishable from missing resources.
- Stored HTML, script, control characters, long Unicode, path-like text, and shell metacharacters render only as inert text. Customer strings never enter HTML, CSS, links, response headers, commands, or logs without contextual escaping and bounds.
- OpenAPI, canonical runtime smoke, API behavior tests, and real-browser behavior tests cover the new contracts and the complete seeded readable and missing-symbol flows.

## Risk and blast radius

Risk: R3.

This change exposes sensitive crash-derived content and retained raw artifacts through new API and browser surfaces, adds cross-component queries and object streaming, and adds an operator-triggered reprocessing action. A defect could cross tenant boundaries, disclose a minidump or comment, turn stored text into script or shell execution, expose object-store credentials, produce misleading health data, create unstable pagination, or overload PostgreSQL with an unbounded search.

The schema change is additive and includes tenant-leading indexes plus a small current-result read projection. No hosted deployment, production credential, production data, billing decision, destructive migration, dependency, service, external search engine, or direct browser-to-database access is in scope.

## Selected API design

Keep the Rust control API as the authorization and data boundary. Extend the existing issue capability instead of adding a service, analytics store, or frontend database client.

Add these bounded routes:

```text
GET  /api/v1/projects/{project_id}/overview
GET  /api/v1/projects/{project_id}/issues
GET  /api/v1/projects/{project_id}/issues/{issue_id}
GET  /api/v1/projects/{project_id}/issues/{issue_id}/events
GET  /api/v1/projects/{project_id}/issues/{issue_id}/events/{event_id}
GET  /api/v1/projects/{project_id}/issues/{issue_id}/events/{event_id}/log
GET  /api/v1/projects/{project_id}/issues/{issue_id}/events/{event_id}/raw
```

The existing issue list and detail paths remain compatible. Additive fields use explicit response types rather than passing stored JSON through to clients. Event reprocessing continues to use the #299 route with an event scope.

All JSON responses use `Cache-Control: no-store` and `Pragma: no-cache`. The raw and log responses additionally use `X-Content-Type-Options: nosniff`, `Content-Security-Policy: sandbox`, `Referrer-Policy: no-referrer`, and an internal-ID-only attachment filename. The raw endpoint streams the exact database-selected object through the API and never redirects to a signed provider URL.

`FAULTLANE_DASHBOARD_ENABLED` gates the new overview, expanded detail, search, event, log, and raw routes. `FAULTLANE_RAW_ARTIFACT_DOWNLOAD_ENABLED` is a narrower off switch for raw bytes. Basic #298 issue reads and all ingest, processing, grouping, reprocessing, setup, and symbol routes continue when either flag is off.

## Query and pagination design

The overview uses one read-only repeatable-read transaction. Its window is the current UTC day plus the previous 29 UTC days. The API emits every day, including zero-count days, so the browser does not infer missing buckets. Top lists and distributions have fixed limits and an `other` count where needed.

Observed usage is derived only from durable rows:

- accepted events whose `received_at` falls in the current UTC calendar month;
- bytes from retained `crash_event_objects` referenced by those events;
- bytes from available organization-scoped customer artifact objects associated with the project;
- project count for the bootstrap owner's organization.

The response calls this `observed_usage`, includes `authoritative: false`, and returns no quota, charge, overage, or retention promise. #302 owns those semantics.

Issue ordering is `last_seen_at DESC, id DESC`. Event ordering is `received_at DESC, id DESC`. The opaque cursor is a versioned URL-safe base64 payload containing the ordering timestamp, UUID, project ID, route kind, and SHA-256 of normalized filters. Decoding is bounded before allocation. A cursor cannot be reused with a different project, endpoint, or filter set.

Filters match any current event assigned to the issue, not only its representative. Search examines only these explicit current-result fields: issue title, crash error message, user comment, symbolicated function, and module. Search text is limited, normalized as Unicode text, escaped as a literal `ILIKE` pattern, and never interpreted as SQL, regular expression, or JSONPath. The per-event search document is limited to 65,536 Unicode scalar values, enforced by both the worker and database. Search reads use a two-second PostgreSQL statement timeout. GameData search waits for #312 because only owner-allowlisted keys may become indexed search fields.

No Elasticsearch, ClickHouse, Redis, client-side filtering, new dependency, or unbounded JSON serialization is introduced. Measured worst-case JSON search exceeded the two-second budget, so the additive `crash_event_search` projection stores only the approved search document, bounded user comment, dashboard dimensions, and symbolication state. The worker updates it in the existing lease-fenced current-result publication transaction. It does not index raw unknown fields, command lines, full logs, or unredacted GameData.

## Event projection and bounds

The API validates the stored processing contract before projecting it. A corrupt or unsupported result produces a fixed `result_unavailable` state and does not serialize partial arbitrary JSON.

Response bounds are independent of the larger processor limits:

- 100 issue rows per page;
- 100 event rows per page;
- 100 variants and 100 releases per issue;
- 128 threads and 256 frames per thread;
- 64 inline frames per physical frame;
- 100 GameData entries and 100 system entries;
- 4 KiB per displayed property value;
- 8 KiB user comment;
- 64 KiB log tail;
- 50 immutable result attempts and 50 reprocessing request events;
- 100 missing-symbol identities.

Every bounded collection or string reports truncation. String truncation occurs on valid Unicode scalar boundaries. Event detail omits crash context thread register text, raw call-stack strings, unknown XML fields, and command lines because the normalized stack already owns presentation and those fields add disclosure without meeting #300.

Missing-symbol rows merge current-result `crash_symbol_waiters` with missing or mismatched artifacts from the event's exact release manifest. The union is tenant-scoped, deduplicated by exact identity, and bounded before projection. The corrective command is assembled from the validated project slug and release fields. Each PowerShell argument is single-quoted with embedded single quotes doubled, and the build path remains the literal placeholder `<build-directory>`.

Processing history joins immutable result rows and bounded reprocessing request-event rows under the same scope. It returns result ID, versions, checksum, creation time, current marker, request ID, request source, state, and fixed failure code. It never returns old raw result bodies.

## Web design

Add server-rendered routes:

```text
/projects/{project_id}
/projects/{project_id}/issues/{issue_id}
```

Use the existing server-only API client and bootstrap secret. Browser code never receives the secret. Add typed API responses, explicit error mapping, Next.js loading and error boundaries, an empty-state action back to setup, keyset pagination links that preserve filters, and small client components only for copying the remediation command and confirming reprocessing.

The project page shows compact health cards, a semantic events-over-time table with a progressively enhanced CSS chart, distributions, health state, filters, and issue rows. The issue page shows summary, representative event, stack, missing symbols, context, processing history, facets, and timeline. Avoid a new UI framework, chart library, query library, or state dependency.

Next Route Handlers proxy log and raw downloads. They call the Rust API with server-held authorization and forward only an allowlisted set of status and content headers. They never forward request cookies, arbitrary headers, provider locations, or response text on failure.

All customer-controlled text is rendered through normal React text nodes. There is no `dangerouslySetInnerHTML`, dynamic CSS, customer-derived class name, or customer-derived URL. Stack and log text use wrapping and horizontal overflow without executing links.

## Security analysis

| Threat | Control | Required evidence |
|---|---|---|
| Cross-tenant issue or event read | Actor, organization, project, issue, event, result, release, request, and object predicates on every query | Two-organization API and browser tests for each identifier type |
| Raw dump or log disclosure | Owner-only control boundary, separate raw flag, exact scoped object join, server-side proxy | Unauthorized, ingest-key, cross-project, disabled, missing-object, and storage-outage tests |
| Object-store credential or key disclosure | Stream through the API, fixed filenames, no provider redirect or object metadata | Header, body, URL, and captured-log inspection |
| Stored XSS | Explicit typed projection, React text nodes, no raw HTML, no dynamic CSS or customer URLs | Script, SVG, event-handler, bidi, and control-character browser fixtures |
| Shell injection in remediation command | PowerShell literal quoting for every dynamic argument and fixed executable and flags | Quotes, dollar expressions, semicolons, newlines, and Unicode command fixtures |
| Sensitive overexposure | Omit unknown fields, command line, registers, raw parser JSON, and symbol paths; bound every returned value | Hostile fixture response snapshots and log inspection |
| Search denial of service | Short literal query, scoped candidate joins, keyset pagination, fixed statement budget, measured indexes | Query-plan evidence and seeded worst-case timeout behavior |
| Pagination skips or crosses filters | Full ordering tuple and project and filter identity in bounded opaque cursor | Concurrent insert, tie, deletion, invalid cursor, and filter-reuse tests |
| Misleading usage or health | Fixed UTC window, explicit denominators, zero buckets, `authoritative: false`, no inferred crash-free rate | Boundary-time, empty, partial, failed, and missing-result tests |
| Reprocess button duplicates work | Deterministic idempotency key and existing generation-based canonical job | Double click, retry, refresh, and in-flight request tests |
| Corrupt stored result reaches browser | Revalidate the versioned processing contract and map failure to a fixed state | Malformed, oversized, unsupported-version, and extra-field tests |

## Database and compatibility

The additive migration adds project, issue, received-time, processing-state, current-result, and release indexes. It also creates the measured event search projection, keeps it tenant-scoped, links it to one immutable result, backfills current results, and populates it atomically with current-result publication.

Do not change or rewrite an applied migration. The prior #299 API, ingest, and worker must start and process normal events against the expanded schema. The prior web build remains compatible with unchanged setup APIs.

No result, raw object, issue, or event row is mutated by a read. Reprocessing remains the only dashboard mutation and uses the existing #299 request tables and worker path.

## Implementation sequence

1. Update #300 with this refined scope, approval, compatibility boundary, and rollback. Move it to Ready, then assign it and move it to In Progress when implementation starts.
2. Add strict shared dashboard response and cursor types, Unicode-safe bounds, processing-result projection, PowerShell quoting, and focused unit tests.
3. Add measured additive indexes or the minimal event read projection only where query-plan evidence requires it. Prove old-application compatibility.
4. Extend issue list pagination and filters while preserving the existing response path and no-store behavior.
5. Add the repeatable-read project overview, issue detail expansion, event timeline, facets, event detail, missing-symbol diagnostics, and processing history.
6. Add scoped log and raw streaming with independent feature flags, fixed response headers, object-store failure handling, and no symbol-object path.
7. Add the Next.js project and issue routes, typed server-only client, filters, pagination, loading, empty and error boundaries, copy control, reprocessing action, and download proxies.
8. Add PostgreSQL and API tests for bounds, pagination, filters, tenant isolation, corrupt stored data, health math, usage labeling, reprocessing idempotency, and raw access.
9. Add Playwright coverage using seeded readable and missing-symbol issues, hostile stored strings, empty and error projects, pagination, copied command, reprocessing, log download, and raw download.
10. Extend runtime proof with project overview, issue search, readable stack, missing-symbol command, raw authorization, and browser navigation while retaining all #299 isolation and recovery checks.
11. Run focused tests, query-plan checks, previous-application compatibility, `scripts/check-fast`, `scripts/check`, and `scripts/smoke` on the final head.
12. Perform a fresh security, correctness, accessibility, and responsive-layout review. Fix every finding, rerun invalidated gates, push a draft pull request, confirm Linux and Windows CI, mark it ready for human review, and stop without merging.

## Verification and staging

Unit tests prove cursor validation, filter normalization, Unicode bounds, result projection, stack ordering, truncation metadata, shell quoting, overview arithmetic, and safe filenames.

PostgreSQL and API tests prove:

- empty, one-row, tied-time, and multi-page issue and event lists;
- all filters and literal free-text matching without wildcard or control-character interpretation;
- overview daily zero buckets, new and regressed counts, top lists, distributions, symbolication denominator, missing symbols, ingest recency, queue state, and observed totals;
- one repeatable issue read while concurrent events publish;
- representative event, faulting and all-thread stacks, inline frames, partial states, facets, bounded context, result history, and reprocessing history;
- exact missing PE and PDB identities and command quoting;
- two-organization isolation for every path and nested identifier;
- owner success plus unauthenticated and ingest-key denial;
- fixed behavior for corrupt results, missing objects, storage outage, disabled flags, and reprocessing API failure;
- raw responses contain the exact retained bytes with fixed safe headers and no object key, provider URL, or credential.

The browser proof starts a clean dedicated PostgreSQL, MinIO, API, ingest, worker, and production Next.js environment. It seeds one readable repeated issue, one missing-symbol issue, one empty project, and a second tenant. In installed Chrome it opens the project, observes loading then populated health, filters and paginates issues, opens the readable issue, inspects the faulting and all-thread stack, selects timeline events, downloads the log and raw bundle, and starts reprocessing. It then opens the missing-symbol issue and copies the exact safely quoted command.

The hostile fixture contains HTML, script-like text, quotes, shell metacharacters, Unicode, bidi controls, and path text in every displayed field. The proof verifies it remains inert text, no script runs, no unexpected network request occurs, storage stays empty, and no control credential appears in HTML or browser storage. Separate navigation proves the empty and fixed error states.

Run the pre-change #299 server and worker against the expanded schema and prove normal ingest, processing, grouping, and reprocessing. Run canonical `scripts/check-fast`, `scripts/check`, and `scripts/smoke`. Inspect captured logs for only internal IDs, counts, versions, states, durations, and fixed codes. Remove every dedicated container, image, network, volume, log, and scratch directory afterward.

## Rollout and rollback

Apply the additive migration, start the current API with `FAULTLANE_DASHBOARD_ENABLED=false`, verify database, object-store, and existing API health, then enable dashboard reads. Keep `FAULTLANE_RAW_ARTIFACT_DOWNLOAD_ENABLED=false` until scoped download tests and access policy are confirmed, then enable it independently.

Rollback disables raw downloads and dashboard reads first, restores the prior web and API builds, and leaves additive indexes or projection rows intact. Ingest, worker processing, grouping, reprocessing, symbols, raw objects, and issue assignments remain available. Do not delete customer data, reverse migrations, or revoke unrelated credentials during rollback.

## Out of scope

- GitHub OAuth, email sign-in, sessions, invitations, four-role authorization, and audit history from #310
- Configurable redaction, allowlisted GameData indexing, data-rule versions, and rule-triggered reprocessing from #312
- Authoritative usage ledgers, plan limits, quota sampling, retention, and billing from #302 and #313
- Issue assignment, priority, notes, external ticket links, manual merge, or split
- Alerts and integrations from #301
- Generic arbitrary JSON queries, saved searches, analytics infrastructure, session denominators, or crash-free rates
- Symbol-file download, external symbol servers, source hosting, or source-code rendering
- Hosted deployment, production credentials, production data, or other Unreal and operating-system versions

## Approval

Ishtmeet Singh authorized R3 plan approval and implementation through the active instruction to finish M1 and the explicit grant of approval permissions. That approval covers the existing bootstrap-owner boundary until #310, bounded sensitive projections, scoped raw and log downloads, deterministic reprocessing, additive query support, isolated local staging, feature flags, and rollback path above.

No unresolved decision blocks implementation.
