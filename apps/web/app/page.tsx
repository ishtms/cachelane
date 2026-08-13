const steps = [
  {
    number: "01",
    title: "Point Unreal at FaultLane",
    text: "Use Unreal Engine's built-in Crash Report Client with a project write key.",
  },
  {
    number: "02",
    title: "Upload matching symbols",
    text: "Attach PDB and PE artifacts to the exact release from local builds or CI.",
  },
  {
    number: "03",
    title: "Triage readable issues",
    text: "Group repeated failures and inspect project frames, builds, and Unreal context.",
  },
];

export default function Home() {
  return (
    <main>
      <nav className="nav">
        <a className="brand" href="#top" aria-label="FaultLane home">
          <span className="brand-mark" aria-hidden="true">
            F
          </span>
          FaultLane
        </a>
        <span className="phase">Foundation</span>
      </nav>

      <section className="hero" id="top">
        <div className="eyebrow">
          <span className="pulse" /> Built for Unreal Engine 5.8
        </div>
        <h1>
          Crash reports,
          <br />
          <span>made readable.</span>
        </h1>
        <p className="lede">
          FaultLane turns Unreal crash artifacts and matching debug symbols into
          grouped issues with useful stacks and clear diagnostics.
        </p>
        <div className="actions">
          <a className="primary" href="/setup">
            Set up a project
          </a>
          <a className="primary" href="https://github.com/ishtms/faultlane">
            View repository
          </a>
          <a className="secondary" href="#workflow">
            See the workflow
          </a>
        </div>
      </section>

      <section
        className="workflow"
        id="workflow"
        aria-labelledby="workflow-title"
      >
        <div className="section-heading">
          <p>Windows first</p>
          <h2 id="workflow-title">One focused path from crash to cause</h2>
        </div>
        <div className="step-grid">
          {steps.map((step) => (
            <article className="step" key={step.number}>
              <span>{step.number}</span>
              <h3>{step.title}</h3>
              <p>{step.text}</p>
            </article>
          ))}
        </div>
      </section>

      <footer>
        <span>FaultLane</span>
        <span>Project foundation in progress</span>
      </footer>
    </main>
  );
}
