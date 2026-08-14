export default function IssueLoading() {
  return (
    <main className="dashboard-main" aria-busy="true">
      <div className="loading-nav" />
      <div className="loading-panel loading-issue-header" />
      <section className="dashboard-grid">
        <div className="loading-panel" />
        <div className="loading-panel" />
      </section>
      <p className="sr-only">Loading issue detail</p>
    </main>
  );
}
