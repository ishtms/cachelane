import type { Metadata } from "next";
import Link from "next/link";

import {
  FaultlaneApiError,
  type PublicDemoInfo,
  type PublicDemoIssueList,
  faultlanePublicApi,
  publicDemoRequestHeaders,
} from "../../lib/faultlane";

export const metadata: Metadata = {
  title: "Public crash demo | FaultLane",
  description: "Read-only synthetic Unreal Engine 5.8 crash data",
};

function formatDate(value: string | null): string {
  if (!value) return "Not yet";
  return new Intl.DateTimeFormat("en-US", {
    dateStyle: "medium",
    timeStyle: "short",
    timeZone: "UTC",
  }).format(new Date(value));
}

function DemoNav() {
  return (
    <nav className="nav">
      <Link className="brand" href="/" aria-label="FaultLane home">
        <span className="brand-mark" aria-hidden="true">
          F
        </span>
        FaultLane
      </Link>
      <span className="phase">Read-only demo</span>
    </nav>
  );
}

export default async function DemoPage() {
  let info: PublicDemoInfo;
  let issues: PublicDemoIssueList;
  try {
    const headers = await publicDemoRequestHeaders();
    [info, issues] = await Promise.all([
      faultlanePublicApi<PublicDemoInfo>("/api/v1/demo", { headers }),
      faultlanePublicApi<PublicDemoIssueList>("/api/v1/demo/issues", {
        headers,
      }),
    ]);
  } catch (error) {
    const code =
      error instanceof FaultlaneApiError ? error.code : "request_failed";
    return (
      <main className="dashboard-main">
        <DemoNav />
        <section className="state-panel" role="alert">
          <p className="setup-kicker">Public demo unavailable</p>
          <h1>The demo is currently disabled.</h1>
          <p>
            FaultLane returned {code}. No private project access was attempted.
          </p>
        </section>
      </main>
    );
  }

  return (
    <main className="dashboard-main">
      <DemoNav />
      <header className="dashboard-header">
        <div>
          <div className="demo-labels" aria-label="Demo safeguards">
            <span className="status status-readable">
              Synthetic UE 5.8 data
            </span>
            <span className="status">Read-only</span>
          </div>
          <h1>{info.title}</h1>
          <p>
            Browse grouped crashes and symbolicated stacks. This isolated
            project contains synthetic data and exposes no uploads, raw
            artifacts, logs, comments, credentials, or mutation controls.
          </p>
        </div>
      </header>

      <section className="metric-grid" aria-label="Demo summary">
        <article>
          <span>Issues</span>
          <strong>{info.issue_count}</strong>
          <small>Bounded public list</small>
        </article>
        <article>
          <span>Engine</span>
          <strong>5.8</strong>
          <small>{info.engine}</small>
        </article>
        <article>
          <span>Access</span>
          <strong>Read</strong>
          <small>Anonymous views only</small>
        </article>
        <article>
          <span>Last crash</span>
          <strong className="demo-date">{formatDate(info.last_seen_at)}</strong>
          <small>UTC</small>
        </article>
      </section>

      <section className="dashboard-panel issue-panel">
        <div className="panel-heading">
          <h2>Grouped crash issues</h2>
          <span>{issues.truncated ? "Newest 50" : "Synthetic project"}</span>
        </div>
        {issues.items.length === 0 ? (
          <div className="empty-state">
            <h3>No demo issues are available.</h3>
            <p>The private operator can refresh the synthetic dataset.</p>
          </div>
        ) : (
          <div className="table-scroll">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Issue</th>
                  <th>State</th>
                  <th>Symbols</th>
                  <th>Events</th>
                  <th>Last seen</th>
                </tr>
              </thead>
              <tbody>
                {issues.items.map((issue) => (
                  <tr key={issue.key}>
                    <td>
                      <Link className="issue-link" href={issue.path}>
                        {issue.title}
                      </Link>
                      <code>{issue.fingerprint}</code>
                    </td>
                    <td>
                      <span
                        className={`status status-${issue.regression_state}`}
                      >
                        {issue.regression_state}
                      </span>
                    </td>
                    <td>
                      <span
                        className={`status status-${issue.symbolication_state}`}
                      >
                        {issue.symbolication_state}
                      </span>
                      {issue.reprocessed ? (
                        <span className="status status-completed demo-outcome">
                          reprocessed
                        </span>
                      ) : null}
                    </td>
                    <td>{issue.event_count}</td>
                    <td>{formatDate(issue.last_seen_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </main>
  );
}
