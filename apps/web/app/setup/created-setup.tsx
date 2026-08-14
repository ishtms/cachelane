import type { CreatedSetup } from "../../lib/faultlane";

export function CreatedSetupResult({ created }: { created: CreatedSetup }) {
  return (
    <section className="setup-result" aria-labelledby="key-title">
      <p className="setup-kicker">Project created</p>
      <h2 id="key-title">Save this key now</h2>
      <p className="setup-copy">
        This write key is shown once. FaultLane stores only its hash and cannot
        show it again.
      </p>
      <code className="secret-value" data-testid="ingest-key">
        {created.ingest_key.value}
      </code>

      <h3>{created.configuration.default_game_ini_path}</h3>
      <pre>{created.configuration.default_game_ini}</pre>
      <h3>{created.configuration.default_engine_ini_path}</h3>
      <pre>{created.configuration.default_engine_ini}</pre>

      <div className="setup-panel-actions setup-link">
        <a
          className="button primary"
          href={`/projects/${encodeURIComponent(created.setup.project.id)}`}
        >
          Open project dashboard
        </a>
        <a
          className="button secondary"
          href={`/setup?project=${encodeURIComponent(created.setup.project.id)}`}
        >
          Manage project setup
        </a>
      </div>
    </section>
  );
}
