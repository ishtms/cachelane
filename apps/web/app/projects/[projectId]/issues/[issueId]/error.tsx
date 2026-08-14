"use client";

export default function IssueError({ reset }: { reset: () => void }) {
  return (
    <main className="dashboard-main">
      <section className="state-panel" role="alert">
        <p className="setup-kicker">Issue error</p>
        <h1>The issue could not be rendered.</h1>
        <p>The control API returned an unexpected response. Try again.</p>
        <button className="button primary" type="button" onClick={reset}>
          Try again
        </button>
      </section>
    </main>
  );
}
