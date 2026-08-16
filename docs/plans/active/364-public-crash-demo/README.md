# Public crash demo

Issue: https://github.com/ishtms/faultlane/issues/364

Status: In progress. Local implementation and certification are complete; external deployment is blocked on dedicated provider and Cloudflare credentials.

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
- The verified local roles used about 0.67 GB at idle: application processes used 530,550,784 bytes, PostgreSQL used 52.95 MiB, and MinIO used 85.21 MiB.
- The local PostgreSQL data used 67,992 KiB, MinIO used 880 KiB, and the processor image used 34,562,756 bytes. Processor isolation remains one CPU, 2 GiB memory, 64 MiB scratch, and 150 seconds wall time.
- The #303 workflow is present at milestone commit `32cebb0`.
- The local public demo proof passed on August 17, 2026, including deterministic refresh, read-only SQL enforcement, mutation denial, tenant isolation, browser confinement, restart, credential rotation, kill switch, and database failure behavior.
- `./scripts/check-fast` and the complete `./scripts/check` passed on August 17, 2026. The complete check took 1,108.9 seconds and included all configured PostgreSQL integration tests, release builds, repository checks, fuzz smoke tests, and browser proof.
- The locally built `faultlane-demo-web:review` image ID is `sha256:47d1919aab97df68aa36a82e22f2a9e7e5ed9ea1fcd0ec7e56ae7b35eaa2ab1f`, and the `faultlane-demo-server:review` image ID is `sha256:1b0b60a18424949b300d423d70e0f73e60bb340992eac532a805bdffc4762d4a`. Published registry digests still need to be recorded after external credentials are available.

## Proposed design

### Access model

Add dedicated anonymous demo reads under `/api/v1/demo` and a `/demo` web entrypoint. Configure exactly one demo organization and project on the server. Do not grant an anonymous identity access to the general control API.

Reuse internal safe issue projections where possible, but return smaller demo DTOs that omit raw and private fields. Keep general routes authenticated and all mutations unchanged. A disabled or invalid demo configuration fails closed with a fixed unavailable response.

The public web view calls only the dedicated demo reads. It contains no token, session, upload, state mutation, export, deletion, or raw-artifact control. Server tests must prove direct requests to every mutation family remain denied.

### Synthetic data

Use an idempotent operator proof that exercises public APIs with dedicated credentials. Create separate synthetic releases or crashes so the final dataset retains both missing-symbol and readable examples after reprocessing. Include repeated equivalent crashes and one materially distinct crash. Do not seed through SQL or copy private fixtures into the environment.

### Deployment target and provider decision

Use one Hetzner CX33-class VM in Germany with four shared vCPUs, 8 GB RAM, and 80 GB local storage. The [listed price after June 15, 2026](https://docs.hetzner.com/general/infrastructure-and-availability/price-adjustment/) is EUR 8.49 per month before IPv4 and VAT. This leaves room for the measured 0.67 GB idle footprint and the existing 2 GiB processor boundary without adding managed services. Take one provider snapshot before an application upgrade and retain the prior immutable image digests as the application rollback target.

DigitalOcean was rejected because its [current 4 GB, two vCPU Droplet](https://www.digitalocean.com/pricing/droplets) is USD 24 per month. AWS Lightsail was rejected because its [4 GB, two vCPU Linux bundle](https://aws.amazon.com/lightsail/pricing/) is USD 40 per month. Both offer less memory at a higher idle price for this isolated demo. Managed PostgreSQL and object storage remain out of scope because local PostgreSQL and MinIO use little storage and the demo has no reliability or capacity evidence requiring another service boundary.

Use a remotely managed Cloudflare Tunnel for the public hostname. Route only the web container through the outbound tunnel, keep the API and ingest operator ports bound to VM loopback, and block inbound VM traffic. Cloudflare documents [Tunnel firewall behavior](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/configure-tunnels/tunnel-with-firewall/) as an outbound-only connector on TCP or UDP port 7844. The protected tunnel token stays in the deployment environment, and the deployed image uses `--no-autoupdate` with an immutable image digest. Configure the public hostname to `http://web:3000`, add the required final catch-all route in the managed tunnel, and apply public edge rate controls. The origin remains unreachable by public IP.

The selected public hostname is still pending the Cloudflare account and zone available to the operator. No provider, Cloudflare, DNS, or production credentials were present in the local or GitHub Actions environment on August 16, 2026, so no external resources have been created.

### Operations

Build immutable application and processor artifacts from the verified milestone commit. Inject dedicated secrets outside source control. Restrict administrative access, expose only required TLS origins, set disk and container limits, monitor health and queue age, and cap public traffic.

Provide a kill switch that removes anonymous demo access without stopping private ingest and processing. Provide an exact teardown inventory so only the dedicated DNS, VM, volumes, credentials, and synthetic project are removed.

The deployment package uses one exact Compose project, two exact named data volumes, a dedicated processor scratch directory, loopback-only operator ports, fixed container limits, and immutable image references. `scripts/demo-up` validates digests, initializes dependencies, applies migrations, and checks health. `scripts/demo-down` preserves data by default and requires the exact project confirmation before deleting the two verified volumes. The protected application environment controls the public demo flag, fixed organization and project, rate limit, and dedicated application credentials. The separate protected control environment holds the tunnel token and immutable deployment inputs. PostgreSQL, MinIO, web, and Cloudflare Tunnel receive only their required environment values.

The external teardown inventory is the public hostname route and DNS record, one remotely managed tunnel and token, one CX33 VM, its firewall and optional pre-upgrade snapshot, the two named Docker volumes, the processor scratch directory, the dedicated organization and project credentials, and no other account resources. Disable the public flag and remove the hostname route first, revoke the tunnel and application credentials, retain evidence, then delete the verified VM resources.

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

- Domain and subdomain after the Cloudflare account and zone are available
- Exact public retention window after the MegaGrant review period

## Approval

The issue split and local-first order were approved by Ishtmeet Singh on August 16, 2026. On August 16, 2026, Ishtmeet Singh also approved the Hetzner and Cloudflare decision, dedicated resource creation, DNS and TLS changes, public exposure, the kill switch, staging, rollback, and exact teardown. The approval is recorded on issue #364. External work can begin once the dedicated provider and Cloudflare credentials are available.
