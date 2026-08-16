import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";

import {
  FaultlaneApiError,
  type PublicDemoIssueDetail,
  faultlanePublicApi,
  publicDemoRequestHeaders,
} from "../../../../lib/faultlane";

export const metadata: Metadata = {
  title: "Demo issue | FaultLane",
};

function formatDate(value: string): string {
  return new Intl.DateTimeFormat("en-US", {
    dateStyle: "medium",
    timeStyle: "short",
    timeZone: "UTC",
  }).format(new Date(value));
}

export default async function DemoIssuePage({
  params,
}: {
  params: Promise<{ issueKey: string }>;
}) {
  const { issueKey } = await params;
  let issue: PublicDemoIssueDetail;
  try {
    const headers = await publicDemoRequestHeaders();
    issue = await faultlanePublicApi<PublicDemoIssueDetail>(
      `/api/v1/demo/issues/${encodeURIComponent(issueKey)}`,
      { headers },
    );
  } catch (error) {
    if (error instanceof FaultlaneApiError && error.status === 404) notFound();
    const code =
      error instanceof FaultlaneApiError ? error.code : "request_failed";
    return (
      <main className="dashboard-main">
        <nav className="nav">
          <Link className="brand" href="/demo">
            FaultLane demo
          </Link>
          <span className="phase">Read-only demo</span>
        </nav>
        <section className="state-panel" role="alert">
          <p className="setup-kicker">Demo issue unavailable</p>
          <h1>The issue could not be loaded.</h1>
          <p>FaultLane returned {code}.</p>
        </section>
      </main>
    );
  }

  return (
    <main className="dashboard-main">
      <nav className="nav">
        <Link className="brand" href="/demo" aria-label="FaultLane public demo">
          <span className="brand-mark" aria-hidden="true">
            F
          </span>
          FaultLane demo
        </Link>
        <span className="phase">Synthetic and read-only</span>
      </nav>

      <header className="issue-header">
        <div>
          <p className="breadcrumb">
            <Link href="/demo">Demo issues</Link> /{" "}
            {issue.crash_type ?? "crash"}
          </p>
          <div className="demo-labels">
            <span className="status status-readable">
              Synthetic UE 5.8 data
            </span>
            <span className="status">Read-only</span>
          </div>
          <h1>{issue.title}</h1>
        </div>
      </header>

      <section className="metric-grid" aria-label="Issue summary">
        <article>
          <span>Events</span>
          <strong>{issue.event_count}</strong>
          <small>Equivalent crashes</small>
        </article>
        <article>
          <span>Releases</span>
          <strong>{issue.affected_release_count}</strong>
          <small>Affected synthetic builds</small>
        </article>
        <article>
          <span>Symbolication</span>
          <strong className="demo-date">{issue.symbolication_state}</strong>
          <small>Current representative</small>
        </article>
        <article>
          <span>Last seen</span>
          <strong className="demo-date">
            {formatDate(issue.last_seen_at)}
          </strong>
          <small>UTC</small>
        </article>
      </section>

      <section className="dashboard-panel issue-panel">
        <div className="panel-heading">
          <h2>Symbolicated stack</h2>
          <span>
            {issue.threads_truncated ? "Bounded result" : "Safe projection"}
          </span>
        </div>
        {issue.threads.length === 0 ? (
          <p className="empty-copy">
            No readable stack is available for this issue.
          </p>
        ) : (
          issue.threads.map((thread) => (
            <article className="demo-thread" key={thread.thread_id}>
              <div className="thread-heading">
                <h3>Thread {thread.thread_id}</h3>
                {thread.faulting ? (
                  <span className="status status-failed">Faulting thread</span>
                ) : null}
              </div>
              <div className="table-scroll">
                <table className="data-table stack-table">
                  <thead>
                    <tr>
                      <th>Module</th>
                      <th>Function</th>
                      <th>Source</th>
                    </tr>
                  </thead>
                  <tbody>
                    {thread.frames.map((frame, index) => (
                      <tr key={`${thread.thread_id}-${index}`}>
                        <td>{frame.module ?? "Unknown"}</td>
                        <td>
                          {frame.function ?? "Unresolved"}
                          {frame.inlines.map((inline, inlineIndex) => (
                            <small className="inline-frame" key={inlineIndex}>
                              inlined {inline.function}
                            </small>
                          ))}
                        </td>
                        <td>
                          {frame.source_file
                            ? `${frame.source_file}${frame.source_line ? `:${frame.source_line}` : ""}`
                            : "Not available"}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </article>
          ))
        )}
      </section>

      <div className="dashboard-grid">
        <section className="dashboard-panel">
          <div className="panel-heading">
            <h2>Releases</h2>
            <span>
              {issue.releases_truncated ? "Newest 32" : "Synthetic builds"}
            </span>
          </div>
          {issue.releases.length === 0 ? (
            <p className="empty-copy">No matched release is available.</p>
          ) : (
            <div className="table-scroll">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Version</th>
                    <th>Target</th>
                    <th>Events</th>
                  </tr>
                </thead>
                <tbody>
                  {issue.releases.map((release) => (
                    <tr key={`${release.version}-${release.architecture}`}>
                      <td>{release.version}</td>
                      <td>
                        {release.platform} / {release.architecture} /{" "}
                        {release.configuration}
                      </td>
                      <td>{release.event_count}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>

        <section className="dashboard-panel">
          <div className="panel-heading">
            <h2>Missing symbols</h2>
            <span>
              {issue.missing_symbols_truncated ? "First 32" : "Diagnostic only"}
            </span>
          </div>
          {issue.missing_symbols.length === 0 ? (
            <p className="empty-copy">No missing symbol artifacts.</p>
          ) : (
            <div className="table-scroll">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Module</th>
                    <th>Artifact</th>
                    <th>Architecture</th>
                  </tr>
                </thead>
                <tbody>
                  {issue.missing_symbols.map((symbol) => (
                    <tr key={`${symbol.module}-${symbol.required_artifact}`}>
                      <td>{symbol.module}</td>
                      <td>{symbol.required_artifact.toUpperCase()}</td>
                      <td>{symbol.architecture}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      </div>
    </main>
  );
}
