export default function ProjectLoading() {
  return (
    <main className="dashboard-main" aria-busy="true">
      <div className="loading-nav" />
      <section className="dashboard-header loading-block">
        <span />
        <span />
      </section>
      <section className="metric-grid">
        {[0, 1, 2, 3].map((item) => (
          <div className="loading-card" key={item} />
        ))}
      </section>
      <div className="loading-panel" />
      <p className="sr-only">Loading project dashboard</p>
    </main>
  );
}
