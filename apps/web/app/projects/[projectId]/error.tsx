"use client";

export default function ProjectError({ reset }: { reset: () => void }) {
  return (
    <main className="dashboard-main">
      <section className="state-panel" role="alert">
        <p className="setup-kicker">Project error</p>
        <h1>The project could not be rendered.</h1>
        <p>
          The control API returned an unexpected response. Try the request
          again.
        </p>
        <button className="button primary" type="button" onClick={reset}>
          Try again
        </button>
      </section>
    </main>
  );
}
