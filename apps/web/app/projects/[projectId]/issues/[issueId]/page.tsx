import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";

import {
  type Distribution,
  type EventDetail,
  type EventList,
  FaultlaneApiError,
  type IssueDetail,
  faultlaneApi,
} from "../../../../../lib/faultlane";
import { CopyButton } from "./copy-button";
import { ReprocessButton } from "./reprocess-button";

export const metadata: Metadata = {
  title: "Issue detail | FaultLane",
};

function single(value: string | string[] | undefined): string {
  return typeof value === "string" ? value : "";
}

function formatDate(value: string | null): string {
  if (!value) return "Not yet";
  return new Intl.DateTimeFormat("en-US", {
    dateStyle: "medium",
    timeStyle: "short",
    timeZone: "UTC",
  }).format(new Date(value));
}

function formatNumber(value: number): string {
  return new Intl.NumberFormat("en-US").format(value);
}

function statusLabel(value: string): string {
  return value.replaceAll("_", " ");
}

function FacetList({
  title,
  rows,
  otherCount,
}: {
  title: string;
  rows: Distribution[];
  otherCount: number;
}) {
  return (
    <section className="facet-group">
      <h3>{title}</h3>
      {rows.length ? (
        <ul>
          {rows.map((row) => (
            <li key={row.key}>
              <span>
                {row.label}
                {row.truncated ? "..." : ""}
              </span>
              <strong>{formatNumber(row.count)}</strong>
            </li>
          ))}
          {otherCount > 0 ? (
            <li>
              <span>Other</span>
              <strong>{formatNumber(otherCount)}</strong>
            </li>
          ) : null}
        </ul>
      ) : (
        <p className="empty-copy">No values</p>
      )}
    </section>
  );
}

function ContextTable({
  title,
  values,
  truncated,
}: {
  title: string;
  values: EventDetail["game_data"];
  truncated: boolean;
}) {
  return (
    <section className="dashboard-panel context-panel">
      <div className="panel-heading">
        <h2>{title}</h2>
        {truncated ? <span>First 100</span> : null}
      </div>
      {values.length ? (
        <div className="table-scroll">
          <table className="data-table property-table">
            <tbody>
              {values.map((property, index) => (
                <tr key={`${property.name}-${index}`}>
                  <th>
                    {property.name}
                    {property.name_truncated ? "..." : ""}
                  </th>
                  <td>
                    {property.value}
                    {property.value_truncated ? "…" : ""}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <p className="empty-copy">No approved values were recorded.</p>
      )}
    </section>
  );
}

function IssueUnavailable({ code }: { code: string }) {
  return (
    <main className="dashboard-main">
      <section className="state-panel" role="alert">
        <p className="setup-kicker">Issue unavailable</p>
        <h1>The issue could not be loaded.</h1>
        <p>
          {code === "service_unavailable"
            ? "FaultLane could not reach the control API."
            : "The control API returned an unexpected response."}
        </p>
        <Link className="button primary" href=".">
          Try again
        </Link>
      </section>
    </main>
  );
}

export default async function IssuePage({
  params,
  searchParams,
}: {
  params: Promise<{ projectId: string; issueId: string }>;
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const { projectId, issueId } = await params;
  const search = await searchParams;
  const cursor = single(search.cursor);
  const base = `/api/v1/projects/${encodeURIComponent(projectId)}/issues/${encodeURIComponent(issueId)}`;

  let issue: IssueDetail;
  let events: EventList;
  try {
    [issue, events] = await Promise.all([
      faultlaneApi<IssueDetail>(base),
      faultlaneApi<EventList>(
        `${base}/events${cursor ? `?cursor=${encodeURIComponent(cursor)}` : ""}`,
      ),
    ]);
  } catch (error) {
    if (
      error instanceof FaultlaneApiError &&
      (error.status === 404 || error.code === "not_found")
    ) {
      notFound();
    }
    return (
      <IssueUnavailable
        code={
          error instanceof FaultlaneApiError ? error.code : "request_failed"
        }
      />
    );
  }

  const selectedEventId = single(search.event) || issue.representative_event_id;
  let selected: EventDetail | null = null;
  let resultUnavailable = false;
  try {
    selected = await faultlaneApi<EventDetail>(
      `${base}/events/${encodeURIComponent(selectedEventId)}`,
    );
  } catch (error) {
    if (
      error instanceof FaultlaneApiError &&
      (error.status === 404 || error.code === "not_found")
    ) {
      notFound();
    }
    if (
      error instanceof FaultlaneApiError &&
      (error.status === 409 || error.code === "result_unavailable")
    ) {
      resultUnavailable = true;
    } else {
      return (
        <IssueUnavailable
          code={
            error instanceof FaultlaneApiError ? error.code : "request_failed"
          }
        />
      );
    }
  }

  const eventQuery = new URLSearchParams();
  if (cursor) eventQuery.set("cursor", cursor);
  const nextQuery = new URLSearchParams();
  if (events.next_cursor) nextQuery.set("cursor", events.next_cursor);
  const threads = selected
    ? [...selected.threads].sort(
        (left, right) => Number(right.faulting) - Number(left.faulting),
      )
    : [];

  return (
    <main className="dashboard-main">
      <nav className="nav">
        <Link className="brand" href="/" aria-label="FaultLane home">
          <span className="brand-mark" aria-hidden="true">
            F
          </span>
          FaultLane
        </Link>
        <Link className="phase phase-link" href={`/projects/${projectId}`}>
          Project overview
        </Link>
      </nav>

      <header className="issue-header">
        <div className="breadcrumb">
          <Link href={`/projects/${projectId}`}>Project</Link>
          <span>/</span>
          <span>Issue</span>
        </div>
        <div className="issue-title-row">
          <div>
            <p className="setup-kicker">
              {issue.fingerprint_algorithm} fingerprint
            </p>
            <h1>{issue.title}</h1>
          </div>
          <span className={`status status-${issue.regression_state}`}>
            {statusLabel(issue.regression_state)}
          </span>
        </div>
        <dl className="issue-summary-grid">
          <div>
            <dt>Occurrences</dt>
            <dd>{formatNumber(issue.event_count)}</dd>
          </div>
          <div>
            <dt>First seen</dt>
            <dd>{formatDate(issue.first_seen_at)}</dd>
          </div>
          <div>
            <dt>Last seen</dt>
            <dd>{formatDate(issue.last_seen_at)}</dd>
          </div>
          <div>
            <dt>Affected releases</dt>
            <dd>{formatNumber(issue.affected_release_count)}</dd>
          </div>
        </dl>
      </header>

      <section className="dashboard-grid issue-workspace">
        <section className="dashboard-panel event-list-panel">
          <div className="panel-heading">
            <div>
              <p className="setup-kicker">Timeline</p>
              <h2>Crash events</h2>
            </div>
            <span>{events.items.length} on this page</span>
          </div>
          <div className="event-list">
            {events.items.map((event) => {
              const query = new URLSearchParams(eventQuery);
              query.set("event", event.event_id);
              return (
                <Link
                  className={
                    event.event_id === selectedEventId
                      ? "event-row event-row-selected"
                      : "event-row"
                  }
                  href={`/projects/${encodeURIComponent(projectId)}/issues/${encodeURIComponent(issueId)}?${query}`}
                  key={event.event_id}
                >
                  <span>
                    <strong>
                      {event.release_version ?? "Unmapped release"}
                      {event.metadata_truncated ? "..." : ""}
                    </strong>
                    <small>{formatDate(event.received_at)}</small>
                  </span>
                  <span
                    className={`status status-${event.symbolication_state}`}
                  >
                    {event.symbolication_state}
                  </span>
                  <code>{event.event_id}</code>
                </Link>
              );
            })}
          </div>
          {events.next_cursor ? (
            <div className="pagination">
              <Link
                className="button secondary"
                href={`/projects/${encodeURIComponent(projectId)}/issues/${encodeURIComponent(issueId)}?${nextQuery}`}
              >
                Older events
              </Link>
            </div>
          ) : null}
        </section>

        <aside className="dashboard-panel facet-panel">
          <div className="panel-heading">
            <h2>Event facets</h2>
          </div>
          <FacetList
            title="Releases"
            rows={events.facets.releases}
            otherCount={events.facets.releases_other_count}
          />
          <FacetList
            title="Platforms"
            rows={events.facets.platforms}
            otherCount={events.facets.platforms_other_count}
          />
          <FacetList
            title="Architectures"
            rows={events.facets.architectures}
            otherCount={events.facets.architectures_other_count}
          />
          <FacetList
            title="Environments"
            rows={events.facets.environments}
            otherCount={events.facets.environments_other_count}
          />
          <FacetList
            title="Crash types"
            rows={events.facets.crash_types}
            otherCount={events.facets.crash_types_other_count}
          />
          <FacetList
            title="Processing"
            rows={events.facets.processing_states}
            otherCount={events.facets.processing_states_other_count}
          />
        </aside>
      </section>

      {resultUnavailable || !selected ? (
        <section className="state-panel result-error" role="alert">
          <p className="setup-kicker">Stored result unavailable</p>
          <h2>This event cannot be displayed safely.</h2>
          <p>
            Its current processing result is missing, corrupt, unsupported, or
            does not match the crash event identity.
          </p>
        </section>
      ) : (
        <>
          <section className="dashboard-panel event-summary-panel">
            <div className="panel-heading event-actions-heading">
              <div>
                <p className="setup-kicker">Selected event</p>
                <h2>{selected.event.event_id}</h2>
              </div>
              <div className="event-actions">
                <ReprocessButton
                  projectId={projectId}
                  issueId={issueId}
                  eventId={selected.event.event_id}
                  currentResultId={selected.event.current_result_id}
                />
                {selected.log ? (
                  <a
                    className="button secondary"
                    href={`/api/projects/${encodeURIComponent(projectId)}/issues/${encodeURIComponent(issueId)}/events/${encodeURIComponent(selected.event.event_id)}/log`}
                  >
                    Download log
                  </a>
                ) : null}
                {selected.raw_available ? (
                  <a
                    className="button secondary"
                    href={`/api/projects/${encodeURIComponent(projectId)}/issues/${encodeURIComponent(issueId)}/events/${encodeURIComponent(selected.event.event_id)}/raw`}
                  >
                    Download raw bundle
                  </a>
                ) : null}
              </div>
            </div>
            <dl className="event-metadata">
              <div>
                <dt>Received</dt>
                <dd>{formatDate(selected.event.received_at)}</dd>
              </div>
              <div>
                <dt>State</dt>
                <dd>{statusLabel(selected.event.processing_state)}</dd>
              </div>
              <div>
                <dt>Release</dt>
                <dd>{selected.event.release_version ?? "Unmapped"}</dd>
              </div>
              <div>
                <dt>Platform</dt>
                <dd>
                  {[selected.event.platform, selected.event.architecture]
                    .filter(Boolean)
                    .join(" / ") || "Unknown"}
                </dd>
              </div>
              <div>
                <dt>Engine</dt>
                <dd>{selected.event.engine_version ?? "Unknown"}</dd>
              </div>
              <div>
                <dt>Crash GUID</dt>
                <dd>
                  {selected.crash_guid ?? "Unavailable"}
                  {selected.crash_guid_truncated ? "..." : ""}
                </dd>
              </div>
              <div>
                <dt>Build version</dt>
                <dd>
                  {selected.build_version ?? "Unavailable"}
                  {selected.build_version_truncated ? "..." : ""}
                </dd>
              </div>
              <div>
                <dt>Build configuration</dt>
                <dd>
                  {selected.build_configuration ?? "Unavailable"}
                  {selected.build_configuration_truncated ? "..." : ""}
                </dd>
              </div>
              <div>
                <dt>Release mapping</dt>
                <dd>{statusLabel(selected.release_mapping.state)}</dd>
              </div>
            </dl>
            {selected.event.metadata_truncated ? (
              <p className="fine-print">Some event metadata was truncated.</p>
            ) : null}
            {selected.release_mapping.candidate_release_ids.length ? (
              <details className="release-evidence">
                <summary>
                  {selected.release_mapping.candidate_release_ids.length}{" "}
                  release{" "}
                  {selected.release_mapping.candidate_release_ids.length === 1
                    ? "candidate"
                    : "candidates"}
                  {selected.release_mapping.candidate_release_ids_truncated
                    ? ", first 100 shown"
                    : ""}
                </summary>
                <ul>
                  {selected.release_mapping.candidate_release_ids.map(
                    (releaseId) => (
                      <li key={releaseId}>
                        <code>{releaseId}</code>
                      </li>
                    ),
                  )}
                </ul>
              </details>
            ) : null}
            {selected.classification ? (
              <section className="classification-panel">
                <h3>Crash classification</h3>
                <p>
                  <strong>{selected.classification.crash_type}</strong>,{" "}
                  {selected.classification.confidence} confidence
                  {selected.classification.truncated ? " (truncated)" : ""}
                </p>
                {selected.classification.evidence.length ? (
                  <ul>
                    {selected.classification.evidence.map((evidence, index) => (
                      <li key={`${evidence}-${index}`}>{evidence}</li>
                    ))}
                  </ul>
                ) : null}
                {selected.classification.signals.length ? (
                  <dl>
                    {selected.classification.signals.map((signal, index) => (
                      <div key={`${signal.kind}-${index}`}>
                        <dt>
                          {signal.kind}
                          {signal.truncated ? "..." : ""}
                        </dt>
                        <dd>
                          {signal.confidence}
                          {signal.evidence.length
                            ? `: ${signal.evidence.join(", ")}`
                            : ""}
                        </dd>
                      </div>
                    ))}
                  </dl>
                ) : null}
              </section>
            ) : null}
            {selected.error_message ? (
              <div className="crash-message">
                <h3>Error message</h3>
                <p>
                  {selected.error_message}
                  {selected.error_message_truncated ? "..." : ""}
                </p>
              </div>
            ) : null}
            {selected.user_comment ? (
              <div className="crash-message">
                <h3>User comment</h3>
                <p>
                  {selected.user_comment}
                  {selected.user_comment_truncated ? "..." : ""}
                </p>
              </div>
            ) : null}
          </section>

          {selected.missing_symbols.length ? (
            <section className="dashboard-panel missing-panel">
              <div className="panel-heading">
                <div>
                  <p className="setup-kicker">Action required</p>
                  <h2>Missing symbols</h2>
                </div>
                <span>
                  {selected.missing_symbols.length} identities
                  {selected.missing_symbols_truncated ? ", first 100" : ""}
                </span>
              </div>
              <div className="table-scroll">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Artifact</th>
                      <th>Module</th>
                      <th>Architecture</th>
                      <th>Debug ID</th>
                      <th>Code ID</th>
                      <th>Release</th>
                    </tr>
                  </thead>
                  <tbody>
                    {selected.missing_symbols.map((symbol) => (
                      <tr
                        key={`${symbol.required_artifact}-${symbol.module}-${symbol.debug_id}-${symbol.code_id ?? ""}`}
                      >
                        <td>{symbol.required_artifact.toUpperCase()}</td>
                        <td>
                          {symbol.module}
                          {symbol.truncated ? "..." : ""}
                        </td>
                        <td>{symbol.architecture}</td>
                        <td>
                          <code>{symbol.debug_id}</code>
                        </td>
                        <td>
                          <code>{symbol.code_id ?? "Not required"}</code>
                        </td>
                        <td>{symbol.release_version}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              {selected.remediation_command ? (
                <div className="command-row">
                  <code>{selected.remediation_command}</code>
                  <CopyButton value={selected.remediation_command} />
                </div>
              ) : null}
            </section>
          ) : null}

          <section className="dashboard-panel stack-panel">
            <div className="panel-heading">
              <div>
                <p className="setup-kicker">Readable stack</p>
                <h2>Threads</h2>
              </div>
              {selected.threads_truncated ? (
                <span>First 128 threads</span>
              ) : null}
            </div>
            {threads.length ? (
              <div className="thread-list">
                {threads.map((thread) => (
                  <section
                    className={
                      thread.faulting ? "thread faulting-thread" : "thread"
                    }
                    key={thread.thread_id}
                  >
                    <div className="thread-heading">
                      <h3>
                        {thread.name ?? `Thread ${thread.thread_id}`}
                        {thread.name_truncated ? "..." : ""}
                        {thread.faulting ? " (faulting)" : ""}
                      </h3>
                      <span>
                        {statusLabel(thread.unwind_status)}
                        {thread.unwind_status_truncated ? "..." : ""}
                      </span>
                    </div>
                    <div className="table-scroll">
                      <table className="data-table stack-table">
                        <thead>
                          <tr>
                            <th>#</th>
                            <th>Function</th>
                            <th>Module and address</th>
                            <th>Source</th>
                            <th>Status</th>
                            <th>Trust</th>
                          </tr>
                        </thead>
                        <tbody>
                          {thread.frames.map((frame, index) => (
                            <tr key={`${frame.instruction}-${index}`}>
                              <td>{index}</td>
                              <td>
                                <code>{frame.function ?? "Unresolved"}</code>
                                <small className="frame-instruction">
                                  {frame.instruction}
                                  {frame.truncated ? " (truncated)" : ""}
                                </small>
                                {frame.inlines.map((inline, inlineIndex) => (
                                  <small
                                    className="inline-frame"
                                    key={`${inline.function}-${inlineIndex}`}
                                  >
                                    inlined: {inline.function}
                                    {inline.source_file
                                      ? ` at ${inline.source_file}:${inline.source_line ?? "?"}`
                                      : ""}
                                    {inline.truncated ? " (truncated)" : ""}
                                  </small>
                                ))}
                                {frame.inlines_truncated ? (
                                  <small className="inline-frame">
                                    Additional inline frames were truncated.
                                  </small>
                                ) : null}
                              </td>
                              <td>
                                {frame.module ?? "Unknown module"}
                                <small>
                                  {frame.module_relative ?? frame.instruction}
                                </small>
                              </td>
                              <td>
                                {frame.source_file
                                  ? `${frame.source_file}:${frame.source_line ?? "?"}`
                                  : "Unavailable"}
                              </td>
                              <td>{statusLabel(frame.symbol_status)}</td>
                              <td>{frame.trust}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                    {thread.frames_truncated ? (
                      <p className="fine-print">
                        Additional frames were truncated.
                      </p>
                    ) : null}
                  </section>
                ))}
              </div>
            ) : (
              <p className="empty-copy">No normalized stack was produced.</p>
            )}
          </section>

          {selected.log ? (
            <section className="dashboard-panel log-panel">
              <div className="panel-heading">
                <h2>{selected.log.name}</h2>
                <span>
                  {selected.log.truncated
                    ? "Tail truncated"
                    : "Complete retained tail"}
                </span>
              </div>
              <pre>{selected.log.text}</pre>
            </section>
          ) : null}

          <section className="context-grid">
            <ContextTable
              title="Game data"
              values={selected.game_data}
              truncated={selected.game_data_truncated}
            />
            <ContextTable
              title="System context"
              values={selected.system_context}
              truncated={selected.system_context_truncated}
            />
          </section>

          <section className="dashboard-grid history-grid">
            <section className="dashboard-panel history-panel">
              <div className="panel-heading">
                <h2>Processing results</h2>
                {selected.processing_history.results_truncated ? (
                  <span>Latest 50</span>
                ) : null}
              </div>
              <div className="history-list">
                {selected.processing_history.results.map((result) => (
                  <article key={result.result_id}>
                    <span
                      className={
                        result.current ? "status status-readable" : "status"
                      }
                    >
                      {result.current ? "current" : "historical"}
                    </span>
                    <strong>
                      Schema {result.schema_version}, processor{" "}
                      {result.processing_version}
                    </strong>
                    <small>{formatDate(result.created_at)}</small>
                    <code>{result.checksum}</code>
                  </article>
                ))}
              </div>
            </section>
            <section className="dashboard-panel history-panel">
              <div className="panel-heading">
                <h2>Reprocessing requests</h2>
                {selected.processing_history.requests_truncated ? (
                  <span>Latest 50</span>
                ) : null}
              </div>
              {selected.processing_history.requests.length ? (
                <div className="history-list">
                  {selected.processing_history.requests.map((request) => (
                    <article key={request.request_id}>
                      <span className={`status status-${request.state}`}>
                        {request.state}
                      </span>
                      <strong>{request.source}</strong>
                      <small>{formatDate(request.created_at)}</small>
                      {request.failure_code ? (
                        <code>{request.failure_code}</code>
                      ) : null}
                    </article>
                  ))}
                </div>
              ) : (
                <p className="empty-copy">No reprocessing requests yet.</p>
              )}
            </section>
          </section>
        </>
      )}

      <section className="dashboard-panel issue-evidence-panel">
        <div className="panel-heading">
          <h2>Issue evidence</h2>
        </div>
        <dl className="event-metadata">
          <div>
            <dt>Release mapping</dt>
            <dd>
              {issue.release_mapping.matched} matched,{" "}
              {issue.release_mapping.missing} missing,{" "}
              {issue.release_mapping.ambiguous} ambiguous
            </dd>
          </div>
          <div>
            <dt>Variants</dt>
            <dd>{formatNumber(issue.variants.length)}</dd>
          </div>
          <div>
            <dt>Fingerprint version</dt>
            <dd>{issue.fingerprint_version}</dd>
          </div>
          <div>
            <dt>Issue ID</dt>
            <dd>{issue.issue_id}</dd>
          </div>
        </dl>
      </section>
    </main>
  );
}
