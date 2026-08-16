import type { Metadata } from "next";
import Link from "next/link";

import {
  type ExistingSetup,
  type ProjectOnboarding,
  setupApi,
  setupErrorMessage,
} from "../../lib/faultlane";
import { RevokeKey, RotateKey } from "./key-actions";
import { SetupForm } from "./setup-form";
import { OnboardingGuide } from "./onboarding-guide";

export const metadata: Metadata = {
  title: "Project setup | FaultLane",
};

async function ExistingProject({
  projectId,
  onboardingEnabled,
}: {
  projectId: string;
  onboardingEnabled: boolean;
}) {
  let existing: ExistingSetup;
  let onboarding: ProjectOnboarding | null = null;
  try {
    existing = await setupApi<ExistingSetup>(
      `/api/v1/projects/${encodeURIComponent(projectId)}/setup`,
    );
    if (onboardingEnabled) {
      onboarding = await setupApi<ProjectOnboarding>(
        `/api/v1/projects/${encodeURIComponent(projectId)}/onboarding`,
      );
    }
  } catch (error) {
    return <p className="form-error">{setupErrorMessage(error)}</p>;
  }

  const { setup } = existing;
  return (
    <section className="project-panel" aria-labelledby="project-title">
      <p className="setup-kicker">{setup.organization.name}</p>
      <h2 id="project-title">{setup.project.name}</h2>
      <p className="setup-copy">
        Write keys can submit crashes but cannot read or administer this
        project. Revoked keys stop resolving immediately.
      </p>
      <div className="key-list">
        {setup.ingest_keys.map((key) => (
          <div className="key-row" key={key.id}>
            <div>
              <code>clpk_...{key.display_suffix}</code>
              <span>{key.revoked_at ? "Revoked" : "Active"}</span>
            </div>
            {key.revoked_at ? null : (
              <RevokeKey projectId={setup.project.id} keyId={key.id} />
            )}
          </div>
        ))}
      </div>
      <div className="setup-panel-actions">
        <Link
          className="button primary"
          href={`/projects/${encodeURIComponent(setup.project.id)}`}
        >
          Open project dashboard
        </Link>
        <RotateKey
          projectId={setup.project.id}
          onboardingEnabled={onboardingEnabled}
        />
      </div>
      {onboarding ? (
        <OnboardingGuide projectId={setup.project.id} initial={onboarding} />
      ) : null}
    </section>
  );
}

export default async function SetupPage({
  searchParams,
}: {
  searchParams: Promise<{ project?: string }>;
}) {
  const { project } = await searchParams;
  const onboardingEnabled =
    process.env.FAULTLANE_ONBOARDING_ENABLED?.toLowerCase() === "true";

  return (
    <main>
      <nav className="nav">
        <Link className="brand" href="/" aria-label="FaultLane home">
          <span className="brand-mark" aria-hidden="true">
            F
          </span>
          FaultLane
        </Link>
        <span className="phase">Local bootstrap</span>
      </nav>

      <section className="setup-shell">
        <div className="setup-intro">
          <p className="setup-kicker">Unreal Engine 5.8</p>
          <h1>Set up your first project.</h1>
          <p className="lede">
            Create the initial owner, organization, project, and write-only
            crash ingest key.
          </p>
        </div>
        {project ? (
          <ExistingProject
            projectId={project}
            onboardingEnabled={onboardingEnabled}
          />
        ) : (
          <SetupForm onboardingEnabled={onboardingEnabled} />
        )}
      </section>
    </main>
  );
}
