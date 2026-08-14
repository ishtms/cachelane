import Link from "next/link";

export default function IssueNotFound() {
  return (
    <main className="dashboard-main">
      <section className="state-panel">
        <p className="setup-kicker">Issue unavailable</p>
        <h1>This issue or event could not be found.</h1>
        <p>It may not belong to the requested project or owner.</p>
        <Link className="button secondary" href="/setup">
          Back to setup
        </Link>
      </section>
    </main>
  );
}
