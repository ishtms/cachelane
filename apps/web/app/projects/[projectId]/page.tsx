import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";

import {
  FaultlaneApiError,
  type ProjectAlerts,
  type ExistingSetup,
  type IssueList,
  type ProjectDataRules,
  type ProjectOverview,
  type ProjectUsage,
  faultlaneApi,
} from "../../../lib/faultlane";
import { DataRulesForm } from "./data-rules-form";
import { AlertsForm } from "./alerts-form";
import { UsageForm } from "./usage-form";

export const metadata: Metadata = {
  title: "Project overview | FaultLane",
};

type SearchValues = Record<string, string | string[] | undefined>;

const filterNames = [
  "cursor",
  "status",
  "regression_state",
  "release_id",
  "crash_type",
  "platform",
  "architecture",
  "engine_version",
  "symbolication_state",
  "context_key",
  "context_value",
  "first_seen_from",
  "first_seen_to",
  "last_seen_from",
  "last_seen_to",
  "query",
] as const;

function single(value: string | string[] | undefined): string {
  return typeof value === "string" ? value : "";
}

function issueQuery(values: SearchValues): URLSearchParams {
  const query = new URLSearchParams();
  for (const name of filterNames) {
    const value = single(values[name]);
    if (value) {
      query.set(name, value);
    }
  }
  return query;
}

function formatNumber(value: number): string {
  return new Intl.NumberFormat("en-US").format(value);
}

function formatBytes(value: number): string {
  if (value < 1000) return `${value} B`;
  if (value < 1_000_000) return `${(value / 1000).toFixed(1)} KB`;
  if (value < 1_000_000_000) return `${(value / 1_000_000).toFixed(1)} MB`;
  return `${(value / 1_000_000_000).toFixed(2)} GB`;
}

function formatDate(value: string | null): string {
  if (!value) return "Not yet";
  return new Intl.DateTimeFormat("en-US", {
    dateStyle: "medium",
    timeStyle: "short",
    timeZone: "UTC",
  }).format(new Date(value));
}

function DistributionList({
  title,
  rows,
  truncated,
  otherCount,
}: {
  title: string;
  rows: ProjectOverview["releases"];
  truncated: boolean;
  otherCount: number;
}) {
  return (
    <section className="dashboard-panel distribution-panel">
      <div className="panel-heading">
        <h2>{title}</h2>
        {truncated ? <span>Top 20</span> : null}
      </div>
      {rows.length === 0 ? (
        <p className="empty-copy">No events in this window.</p>
      ) : (
        <dl className="distribution-list">
          {rows.map((row) => (
            <div key={row.key}>
              <dt>
                {row.label}
                {row.truncated ? "..." : ""}
              </dt>
              <dd>{formatNumber(row.count)}</dd>
            </div>
          ))}
          {otherCount > 0 ? (
            <div>
              <dt>Other</dt>
              <dd>{formatNumber(otherCount)}</dd>
            </div>
          ) : null}
        </dl>
      )}
    </section>
  );
}

function Unavailable({ code }: { code: string }) {
  return (
    <main className="dashboard-main">
      <DashboardNav phase="Project unavailable" />
      <section className="state-panel" role="alert">
        <p className="setup-kicker">Could not load project</p>
        <h1>The dashboard is unavailable.</h1>
        <p>
          {code === "bootstrap_unavailable"
            ? "Local bootstrap access is not configured for the web server."
            : "FaultLane could not reach the control API. Check the local services and try again."}
        </p>
        <Link className="button primary" href=".">
          Try again
        </Link>
      </section>
    </main>
  );
}

function DashboardNav({ phase }: { phase: string }) {
  return (
    <nav className="nav">
      <Link className="brand" href="/" aria-label="FaultLane home">
        <span className="brand-mark" aria-hidden="true">
          F
        </span>
        FaultLane
      </Link>
      <div className="nav-actions">
        <Link href="/account">Account</Link>
        <span className="phase">{phase}</span>
      </div>
    </nav>
  );
}

export default async function ProjectPage({
  params,
  searchParams,
}: {
  params: Promise<{ projectId: string }>;
  searchParams: Promise<SearchValues>;
}) {
  const { projectId } = await params;
  const values = await searchParams;
  const filters = issueQuery(values);
  const apiFilters = new URLSearchParams(filters);
  apiFilters.delete("cursor");
  const cursor = single(values.cursor);
  if (cursor) apiFilters.set("cursor", cursor);

  let overview: ProjectOverview;
  let issues: IssueList;
  let setup: ExistingSetup;
  let dataRules: ProjectDataRules;
  let usage: ProjectUsage;
  let alerts: ProjectAlerts | null;
  try {
    [overview, issues, setup, dataRules, usage, alerts] = await Promise.all([
      faultlaneApi<ProjectOverview>(
        `/api/v1/projects/${encodeURIComponent(projectId)}/overview`,
      ),
      faultlaneApi<IssueList>(
        `/api/v1/projects/${encodeURIComponent(projectId)}/issues${apiFilters.size ? `?${apiFilters}` : ""}`,
      ),
      faultlaneApi<ExistingSetup>(
        `/api/v1/projects/${encodeURIComponent(projectId)}/setup`,
      ),
      faultlaneApi<ProjectDataRules>(
        `/api/v1/projects/${encodeURIComponent(projectId)}/data-rules`,
      ),
      faultlaneApi<ProjectUsage>(
        `/api/v1/projects/${encodeURIComponent(projectId)}/usage`,
      ),
      faultlaneApi<ProjectAlerts>(
        `/api/v1/projects/${encodeURIComponent(projectId)}/alerts`,
      ).catch((error: unknown) => {
        if (error instanceof FaultlaneApiError && error.status === 404)
          return null;
        throw error;
      }),
    ]);
  } catch (error) {
    if (
      error instanceof FaultlaneApiError &&
      (error.status === 404 || error.code === "not_found")
    ) {
      notFound();
    }
    return (
      <Unavailable
        code={
          error instanceof FaultlaneApiError ? error.code : "request_failed"
        }
      />
    );
  }

  const filterValue = (name: (typeof filterNames)[number]) =>
    single(values[name]);
  const nextQuery = new URLSearchParams(filters);
  if (issues.next_cursor) nextQuery.set("cursor", issues.next_cursor);
  const maxDailyEvents = Math.max(
    1,
    ...overview.events_over_time.map((bucket) => bucket.count),
  );

  return (
    <main className="dashboard-main">
      <DashboardNav phase={setup.setup.organization.name} />

      <header className="dashboard-header">
        <div>
          <p className="setup-kicker">Project overview</p>
          <h1>{setup.setup.project.name}</h1>
          <p>
            Last event {formatDate(overview.ingest.last_received_at)}. Metrics
            use a fixed 30-day UTC window.
          </p>
        </div>
        <Link
          className="button secondary"
          href={`/setup?project=${encodeURIComponent(projectId)}`}
        >
          Project setup
        </Link>
      </header>

      <section className="metric-grid" aria-label="Project health summary">
        <article>
          <span>Events</span>
          <strong>{formatNumber(overview.totals.events)}</strong>
          <small>Last 30 days</small>
        </article>
        <article>
          <span>Active issues</span>
          <strong>{formatNumber(overview.totals.issues)}</strong>
          <small>{formatNumber(overview.totals.new_issues)} new</small>
        </article>
        <article>
          <span>Readable stacks</span>
          <strong>
            {overview.symbolication.success_percent === null
              ? "No data"
              : `${overview.symbolication.success_percent.toFixed(2)}%`}
          </strong>
          <small>
            {formatNumber(overview.symbolication.denominator)} classified
          </small>
        </article>
        <article>
          <span>Missing symbols</span>
          <strong>{formatNumber(overview.missing_symbol_count)}</strong>
          <small>Exact artifact identities</small>
        </article>
      </section>

      <section
        className="dashboard-panel issue-panel"
        aria-labelledby="issues-title"
      >
        <div className="panel-heading">
          <div>
            <p className="setup-kicker">Triage</p>
            <h2 id="issues-title">Issues</h2>
          </div>
          <span>{formatNumber(issues.items.length)} on this page</span>
        </div>

        <form className="filter-form" method="get">
          <label className="filter-search">
            Search title, stack, module, error, or comment
            <input
              name="query"
              defaultValue={filterValue("query")}
              maxLength={120}
              placeholder="Arena::Tick or access violation"
            />
          </label>
          <label>
            Status
            <select name="status" defaultValue={filterValue("status")}>
              <option value="">Any</option>
              <option value="open">Open</option>
              <option value="resolved">Resolved</option>
            </select>
          </label>
          <label>
            Regression
            <select
              name="regression_state"
              defaultValue={filterValue("regression_state")}
            >
              <option value="">Any</option>
              {["new", "ongoing", "regressed", "resolved", "unknown"].map(
                (state) => (
                  <option value={state} key={state}>
                    {state}
                  </option>
                ),
              )}
            </select>
          </label>
          <label>
            Symbolication
            <select
              name="symbolication_state"
              defaultValue={filterValue("symbolication_state")}
            >
              <option value="">Any</option>
              {["readable", "partial", "missing", "failed", "processing"].map(
                (state) => (
                  <option value={state} key={state}>
                    {state}
                  </option>
                ),
              )}
            </select>
          </label>
          <details className="advanced-filters">
            <summary>More filters</summary>
            <div>
              {[
                ["release_id", "Release ID"],
                ["crash_type", "Crash type"],
                ["platform", "Platform"],
                ["architecture", "Architecture"],
                ["engine_version", "Engine version"],
                ["context_key", "GameData key"],
                ["context_value", "GameData value"],
                ["first_seen_from", "First seen from (RFC 3339)"],
                ["first_seen_to", "First seen to (RFC 3339)"],
                ["last_seen_from", "Last seen from (RFC 3339)"],
                ["last_seen_to", "Last seen to (RFC 3339)"],
              ].map(([name, label]) => (
                <label key={name}>
                  {label}
                  <input
                    name={name}
                    defaultValue={filterValue(
                      name as (typeof filterNames)[number],
                    )}
                  />
                </label>
              ))}
            </div>
          </details>
          <div className="filter-actions">
            <button className="button primary" type="submit">
              Apply filters
            </button>
            <Link className="button secondary" href={`/projects/${projectId}`}>
              Clear
            </Link>
          </div>
        </form>

        {issues.items.length === 0 ? (
          <div className="empty-state">
            <h3>No matching issues</h3>
            <p>
              Accepted crashes appear here after processing and grouping. Clear
              the filters or check the project setup.
            </p>
            <Link
              className="button secondary"
              href={`/setup?project=${encodeURIComponent(projectId)}`}
            >
              Open project setup
            </Link>
          </div>
        ) : (
          <div className="table-scroll">
            <table className="data-table issue-table">
              <thead>
                <tr>
                  <th>Issue</th>
                  <th>Status</th>
                  <th>Events</th>
                  <th>Releases</th>
                  <th>Last seen</th>
                </tr>
              </thead>
              <tbody>
                {issues.items.map((issue) => (
                  <tr key={issue.issue_id}>
                    <td>
                      <Link
                        className="issue-link"
                        href={`/projects/${encodeURIComponent(projectId)}/issues/${encodeURIComponent(issue.issue_id)}`}
                      >
                        {issue.title}
                      </Link>
                      <code>{issue.issue_id}</code>
                    </td>
                    <td>
                      <span
                        className={`status status-${issue.regression_state}`}
                      >
                        {issue.regression_state}
                      </span>
                    </td>
                    <td>{formatNumber(issue.event_count)}</td>
                    <td>{formatNumber(issue.affected_release_count)}</td>
                    <td>{formatDate(issue.last_seen_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {issues.next_cursor ? (
          <div className="pagination">
            <Link
              className="button secondary"
              href={`/projects/${encodeURIComponent(projectId)}?${nextQuery}`}
            >
              Next page
            </Link>
          </div>
        ) : null}
      </section>

      <section className="dashboard-grid">
        <section className="dashboard-panel timeline-panel">
          <div className="panel-heading">
            <h2>Events over time</h2>
            <span>UTC</span>
          </div>
          <div className="table-scroll compact-scroll">
            <table className="data-table event-chart">
              <thead>
                <tr>
                  <th>Day</th>
                  <th>Events</th>
                  <th className="visual-column">Volume</th>
                </tr>
              </thead>
              <tbody>
                {overview.events_over_time.map((bucket) => (
                  <tr key={bucket.day}>
                    <td>{bucket.day}</td>
                    <td>{formatNumber(bucket.count)}</td>
                    <td className="visual-column">
                      <meter
                        min={0}
                        max={maxDailyEvents}
                        value={bucket.count}
                        aria-label={`${bucket.count} events on ${bucket.day}`}
                      />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>

        <section className="dashboard-panel health-panel">
          <div className="panel-heading">
            <h2>Processing health</h2>
          </div>
          <dl className="health-list">
            <div>
              <dt>Pending jobs</dt>
              <dd>{formatNumber(overview.processing.pending_jobs)}</dd>
            </div>
            <div>
              <dt>Leased jobs</dt>
              <dd>{formatNumber(overview.processing.leased_jobs)}</dd>
            </div>
            <div>
              <dt>Failed jobs</dt>
              <dd>{formatNumber(overview.processing.failed_jobs)}</dd>
            </div>
            <div>
              <dt>Dead jobs</dt>
              <dd>{formatNumber(overview.processing.dead_jobs)}</dd>
            </div>
            <div>
              <dt>Oldest pending</dt>
              <dd>{formatDate(overview.processing.oldest_pending_at)}</dd>
            </div>
          </dl>
        </section>
      </section>

      <section className="distribution-grid">
        <DistributionList
          title="Releases"
          rows={overview.releases}
          truncated={overview.releases_truncated}
          otherCount={overview.releases_other_count}
        />
        <DistributionList
          title="Platforms"
          rows={overview.platforms}
          truncated={overview.platforms_truncated}
          otherCount={overview.platforms_other_count}
        />
        <DistributionList
          title="Crash types"
          rows={overview.crash_types}
          truncated={overview.crash_types_truncated}
          otherCount={overview.crash_types_other_count}
        />
      </section>

      <section className="dashboard-panel data-rules-panel">
        <div className="panel-heading">
          <div>
            <p className="setup-kicker">Privacy and search</p>
            <h2>Project data rules</h2>
          </div>
          <span>Version {dataRules.version}</span>
        </div>
        <p className="fine-print">
          Matching text is replaced in derived crash context and logs. Only
          listed GameData keys are indexed for search and facets. Retained raw
          artifacts are unchanged and keep separate access controls.
        </p>
        <DataRulesForm projectId={projectId} rules={dataRules} />
      </section>

      <section className="dashboard-panel alerts-panel">
        <div className="panel-heading">
          <div>
            <p className="setup-kicker">Project notifications</p>
            <h2>Crash and project alerts</h2>
          </div>
          <span>{alerts ? `${alerts.rules.length} rules` : "Disabled"}</span>
        </div>
        <p className="fine-print">
          Send first-seen, regression, volume, symbol, processing, ingest, and
          quota alerts to email, Discord, Slack, or a signed webhook.
        </p>
        {alerts ? (
          <AlertsForm projectId={projectId} alerts={alerts} />
        ) : (
          <p className="empty-copy">
            Alerts are not enabled for this deployment.
          </p>
        )}
      </section>

      <section className="dashboard-panel usage-panel">
        <div className="panel-heading">
          <div>
            <p className="setup-kicker">Authoritative billing cycle</p>
            <h2>Usage and quota policy</h2>
          </div>
          <span>
            {usage.cycle_start} to {usage.cycle_end}
          </span>
        </div>
        <dl className="usage-grid">
          <div>
            <dt>Accepted events</dt>
            <dd>
              {formatNumber(usage.accepted_events)} /{" "}
              {formatNumber(usage.event_limit)}
            </dd>
          </div>
          <div>
            <dt>Policy state</dt>
            <dd>{usage.policy_state}</dd>
          </div>
          <div>
            <dt>Quota enforcement</dt>
            <dd>{usage.enforcement_enabled ? "active" : "paused"}</dd>
          </div>
          <div>
            <dt>Retained raw storage</dt>
            <dd>{formatBytes(usage.retained_raw_bytes)}</dd>
          </div>
          <div>
            <dt>Symbol storage</dt>
            <dd>{formatBytes(usage.symbol_storage_bytes)}</dd>
          </div>
          <div>
            <dt>Total artifact storage</dt>
            <dd>
              {formatBytes(usage.artifact_storage_bytes)} /{" "}
              {formatBytes(usage.artifact_storage_limit_bytes)}
            </dd>
          </div>
          <div>
            <dt>Organization projects</dt>
            <dd>
              {formatNumber(usage.organization_projects)} /{" "}
              {formatNumber(usage.project_limit)}
            </dd>
          </div>
          <div>
            <dt>Accepted raw data</dt>
            <dd>{formatBytes(usage.accepted_raw_bytes)}</dd>
          </div>
          <div>
            <dt>Accepted symbol data</dt>
            <dd>{formatBytes(usage.accepted_symbol_bytes)}</dd>
          </div>
          <div>
            <dt>Raw data deleted</dt>
            <dd>{formatBytes(usage.deleted_raw_bytes)}</dd>
          </div>
          <div>
            <dt>Sampled repeated events</dt>
            <dd>{formatNumber(usage.sampled_raw_events)}</dd>
          </div>
          <div>
            <dt>Estimated represented events</dt>
            <dd>
              {formatNumber(usage.estimated_represented_events)} estimated
            </dd>
          </div>
          <div>
            <dt>Normalized retention</dt>
            <dd>
              {usage.normalized_retention_days} /{" "}
              {usage.normalized_retention_limit_days} days
            </dd>
          </div>
          <div>
            <dt>Raw retention</dt>
            <dd>
              {usage.raw_retention_days} / {usage.raw_retention_limit_days} days
            </dd>
          </div>
          <div>
            <dt>Retain all raw</dt>
            <dd>{usage.retain_all_raw ? "enabled" : "disabled"}</dd>
          </div>
        </dl>
        <p className="fine-print">
          {usage.threshold
            ? `Usage has reached the ${usage.threshold.replace("courtesy_exhausted", "courtesy buffer exhaustion")} threshold. `
            : "No usage threshold is active. "}
          Paid overages are{" "}
          {usage.paid_overages_enabled
            ? `limited to ${formatNumber(usage.spend_cap_cents ?? 0)} cents for this policy.`
            : "disabled."}
          {usage.estimates_present
            ? " Sampling totals are estimates and are labeled above."
            : " All current totals are exact."}
        </p>
        <UsageForm projectId={projectId} usage={usage} />
      </section>
    </main>
  );
}
