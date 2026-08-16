# Public crash demo

Issue: https://github.com/ishtms/faultlane/issues/364

Status: Blocked on #303, local measurements, provider decision, and human approval

## Context

FaultLane needs public evidence for the Epic MegaGrant without launching a general hosted service. After #303 proves the complete UE 5.8 Windows workflow locally, this issue deploys that same verified workflow for maintainers and exposes a separate anonymous read-only view backed only by synthetic data.

This is not FaultLane Cloud, a customer beta, or the complete self-hosted release from #307. It is one nonproduction demonstration instance operated by the project owner. The public surface must be safe to browse without giving reviewers credentials or write access.

## Acceptance criteria

- Deploy the same verified API, ingest, worker, scheduler, processor, web, PostgreSQL, and S3-compatible workflow used by #303 through public TLS endpoints.
- Keep one private authenticated operator path for project creation, crash submission, symbol upload, reprocessing, and deterministic demo refresh.
- Expose one explicitly configured public demo project without requiring reviewer credentials.
- Allow anonymous navigation only through safe issue list, issue detail, release, grouping, and symbolication views needed for the demo.
- Deny every anonymous mutation at the Rust service boundary, including ingest, uploads, tokens, projects, memberships, alerts, issue state, deletion, export, and reprocessing.
- Return no raw dump, symbol, log, comment, custom context, object key, credential, private identifier, or cross-project data through the demo API.
- Use only synthetic UE 5.8 data demonstrating received, missing-symbol, reprocessed, readable, grouped, and distinct-crash outcomes.
- Clearly label the instance and its data as synthetic and read-only.
- Apply bounded public reads, rate controls, safe cache behavior, dependency health checks, fixed failure responses, and a tested public-access kill switch.
- Prove deterministic seed, reset, restart, and teardown without direct database edits, production credentials, or customer data.
- Record provider selection, architecture, resource limits, measured utilization, estimated idle cost, immutable artifact identifiers, deployment evidence, and rollback target before exposing the URL.
- Focused tests, staging proof, and `./scripts/check-fast` pass. Complete milestone certification remains the later `./scripts/check` run.

## Risk and blast radius

Risk: R3.

This issue changes anonymous authorization, public network exposure, deployment, DNS, TLS, secrets, and persistent infrastructure. A defect could expose sensitive crash or symbol data, enable mutation, cross project boundaries, incur unbounded cost, lose demo state, or present misleading evidence.

The blast radius is one isolated nonproduction demo environment, dedicated synthetic project data, dedicated credentials, public demo routes and pages, deployment configuration, DNS, monitoring, and teardown. It does not include production customers, customer onboarding, billing, paid plans, general account creation, production support, high availability, or the full #307 self-hosted release.

## Current behavior and evidence

- General control API routes require authenticated session or scoped credentials.
- Public ingest accepts a write-only project key and must not be exposed through the anonymous demo identity.
- Dashboard reads are already tenant-scoped and bounded, but there is no anonymous public project boundary.
- Raw crash artifacts and symbols are private by architecture and must stay unavailable.
- The isolated processor requires a Docker-capable runtime with no network and strict resource limits.
- The repository has local PostgreSQL and MinIO composition but no approved hosted target, deployment workflow, public URL, managed database, or production credentials.
- #303 owns the interactive local workflow and runtime measurements. #307 owns the later complete self-hosted release, backup, restore, upgrades, signed artifacts, SBOM, and licensing work.

## Proposed design

### Access model

Add dedicated anonymous demo reads under `/api/v1/demo` and a `/demo` web entrypoint. Configure exactly one demo organization and project on the server. Do not grant an anonymous identity access to the general control API.

Reuse internal safe issue projections where possible, but return smaller demo DTOs that omit raw and private fields. Keep general routes authenticated and all mutations unchanged. A disabled or invalid demo configuration fails closed with a fixed unavailable response.

The public web view calls only the dedicated demo reads. It contains no token, session, upload, state mutation, export, deletion, or raw-artifact control. Server tests must prove direct requests to every mutation family remain denied.

### Synthetic data

Use an idempotent operator proof that exercises public APIs with dedicated credentials. Create separate synthetic releases or crashes so the final dataset retains both missing-symbol and readable examples after reprocessing. Include repeated equivalent crashes and one materially distinct crash. Do not seed through SQL or copy private fixtures into the environment.

### Deployment candidate and provider decision

The default candidate is one small Linux VM running the same containerized roles, PostgreSQL, and MinIO on encrypted persistent volumes, with Cloudflare providing DNS, TLS proxying, basic edge protection, and traffic visibility. This matches the self-hosted architecture, supports the Docker processor boundary, and minimizes idle managed-service cost for a no-user demo.

Do not select a VM provider or size until #303 records peak and idle CPU, memory, disk, object growth, and processor duration. At that point compare current providers on total monthly cost, region, Docker support, persistent disk, backup options, network limits, recovery, and exit path. Record the selected provider and rejected alternatives in an architecture decision before creating resources.

Managed PostgreSQL or object storage requires measured reliability or capacity need. It is not the default for the demo because it adds cost and operational boundaries. The application must retain its S3-compatible abstraction so a later move remains possible.

### Operations

Build immutable application and processor artifacts from the verified milestone commit. Inject dedicated secrets outside source control. Restrict administrative access, expose only required TLS origins, set disk and container limits, monitor health and queue age, and cap public traffic.

Provide a kill switch that removes anonymous demo access without stopping private ingest and processing. Provide an exact teardown inventory so only the dedicated DNS, VM, volumes, credentials, and synthetic project are removed.

## Security analysis

- Resolve the demo organization and project from trusted configuration, never from an anonymous tenant identifier.
- Use dedicated read handlers and safe DTOs. Do not bypass or weaken general authorization.
- Apply organization and project predicates to every demo query and fixed row limits to every collection.
- Deny raw artifact, symbol, log, comment, custom-context, export, and internal object access.
- Escape every displayed value and preserve the restrictive content security policy.
- Keep operator sessions and credentials separate from anonymous traffic. Store secrets only through the selected provider's protected injection mechanism.
- Keep PostgreSQL, object storage, the Docker socket, processor scratch, and administrative endpoints off the public network.
- Preserve isolated processor limits and immutable image resolution.
- Use synthetic data only. Do not upload production, customer, or third-party crash artifacts or symbols.
- Add edge and origin bounds so bypassing Cloudflare does not expose an unrestricted origin.
- Log fixed route, status, duration, and internal correlation data without request secrets or crash content.

## Implementation sequence

1. Complete and accept #303. Capture local resource measurements and the exact verified commit.
2. Requery #364, current infrastructure prices, provider capabilities, and deployment constraints. Record the provider decision, estimated idle cost, staging strategy, and teardown inventory.
3. Obtain human approval of this plan and the provider decision before creating external resources or changing DNS.
4. Add dedicated demo read types, tenant-fixed queries, routes, feature flag, and denial tests.
5. Add the read-only web entrypoint and clear synthetic-data labeling.
6. Add the idempotent API-driven synthetic data refresh and prove it locally against the #303 environment.
7. Add the smallest deployment packaging needed for the selected nonproduction target without implementing the full #307 release scope.
8. Build immutable artifacts from the verified milestone head and deploy to isolated staging with dedicated credentials and data.
9. Run private operator proof, refresh the synthetic dataset, and verify the public experience in a clean browser.
10. Test direct mutation denial, tenant isolation, origin isolation, rate controls, restart, kill switch, rollback, and teardown.
11. Run focused verification and `./scripts/check-fast`, inspect the diff and deployment evidence, then leave the URL available for human review.
12. After approval, record safe evidence on #364 and move it to Locally verified. Leave the issue open for the milestone pull request.

## Tests and operational verification

- Unit tests cover trusted configuration, fixed project resolution, DTO redaction, and failure responses.
- PostgreSQL and API tests cover bounded reads, cross-tenant denial, missing or invalid configuration, and all excluded sensitive fields.
- Route tests attempt every anonymous mutation family and require denial without side effects.
- Browser tests use a clean context with no cookies or credentials and navigate the complete public demo.
- Seed tests run twice and prove stable bounded data without duplicates or SQL access.
- Staging proof runs the packaged sample through the private operator path, uploads symbols, observes reprocessing, and confirms the public view.
- Operations tests cover process restart, dependency failure, public kill switch, origin restriction, credential rotation, and exact teardown targets.
- Capture idle and proof-run CPU, memory, disk, object size, processor duration, request volume, and estimated monthly cost.

## Data, compatibility, rollout, and rollback

Use a dedicated organization, project, database, object prefix or bucket, credentials, and synthetic artifacts. No migration should be required solely for public access. If durable public-project configuration is later justified, it must use an additive migration and preserve older application compatibility.

Roll out with anonymous access disabled. Deploy private services, run health checks and operator proof, refresh synthetic data, then enable the public demo flag and route DNS. Roll back by disabling the flag first, removing public DNS routing, restoring the previous immutable application artifact, and preserving the isolated data until the failure is understood.

Teardown removes only the resolved resources listed in the approved inventory. Revoke dedicated credentials and delete synthetic data only after evidence is retained. Do not run broad or wildcard deletion commands.

## Out of scope

- General hosted signup, customer accounts, subscriptions, billing, quotas, or support
- Production deployment, customer data, or production credentials
- High availability, multi-region service, autoscaling, or Kubernetes
- Full #307 backup, restore, upgrade, signed release, SBOM, provenance, or licensing scope
- Managed infrastructure without measured need
- Other Unreal versions or platforms
- A public upload, live mutation sandbox, or downloadable raw crash and symbol artifacts

## Unresolved decisions

- VM provider, region, size, persistent disk, and backup approach after #303 measurements
- Domain and subdomain after provider selection
- Exact public retention window after the MegaGrant review period

## Approval

The issue split and local-first order were approved by Ishtmeet Singh on August 16, 2026. External resource creation, DNS changes, public exposure, and the final provider decision require a second explicit approval after #303 measurements and the provider comparison are available.
