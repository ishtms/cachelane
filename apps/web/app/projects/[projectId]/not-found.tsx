import Link from "next/link";

export default function ProjectNotFound() {
  return (
    <main className="dashboard-main">
      <section className="state-panel">
        <p className="setup-kicker">Project unavailable</p>
        <h1>This project could not be found.</h1>
        <p>
          The project may not exist, may be outside this owner, or dashboard
          reads may be disabled.
        </p>
        <Link className="button secondary" href="/setup">
          Back to setup
        </Link>
      </section>
    </main>
  );
}
