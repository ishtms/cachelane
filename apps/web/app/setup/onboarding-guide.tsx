"use client";

import Link from "next/link";
import { useActionState, useEffect, useState } from "react";

import type { ProjectOnboarding } from "../../lib/faultlane";
import { createArtifactUploadToken, type SetupActionState } from "./actions";

const initialAction: SetupActionState = {};
const stateCopy: Record<ProjectOnboarding["state"], string> = {
  waiting: "Waiting for a packaged crash",
  received: "Crash received",
  processing: "Processing crash",
  missing_symbols: "Matching symbols required",
  readable_issue: "Readable issue ready",
  failed: "Processing failed",
  quarantined: "Crash quarantined",
};

function powershellLiteral(value: string) {
  return `'${value.replaceAll("'", "''")}'`;
}

function CopyCommand({ value, label }: { value: string; label: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="onboarding-command">
      <code>{value}</code>
      <button
        className="key-revoke"
        type="button"
        onClick={async () => {
          await navigator.clipboard.writeText(value);
          setCopied(true);
        }}
      >
        {copied ? "Copied" : `Copy ${label}`}
      </button>
    </div>
  );
}

export function OnboardingGuide({
  projectId,
  initial,
}: {
  projectId: string;
  initial: ProjectOnboarding;
}) {
  const [onboarding, setOnboarding] = useState(initial);
  const [pollError, setPollError] = useState(false);
  const tokenAction = createArtifactUploadToken.bind(null, projectId);
  const [tokenState, tokenFormAction, tokenPending] = useActionState(
    tokenAction,
    initialAction,
  );

  useEffect(() => {
    if (onboarding.state === "readable_issue") return;
    let cancelled = false;
    let timeout: ReturnType<typeof setTimeout> | undefined;
    let delay = 3000;
    const poll = async () => {
      if (document.visibilityState !== "visible") {
        timeout = setTimeout(poll, delay);
        return;
      }
      try {
        const response = await fetch(
          `/api/projects/${encodeURIComponent(projectId)}/onboarding`,
          { cache: "no-store" },
        );
        if (!response.ok) throw new Error("poll failed");
        const next = (await response.json()) as ProjectOnboarding;
        if (cancelled) return;
        setOnboarding(next);
        setPollError(false);
        delay = 3000;
        if (next.state === "readable_issue") return;
      } catch {
        if (cancelled) return;
        setPollError(true);
        delay = Math.min(delay * 2, 30000);
      }
      timeout = setTimeout(poll, delay);
    };
    timeout = setTimeout(poll, delay);
    return () => {
      cancelled = true;
      if (timeout) clearTimeout(timeout);
    };
  }, [onboarding.state, projectId]);

  return (
    <section className="onboarding-guide" aria-labelledby="onboarding-title">
      <p className="setup-kicker">First readable crash</p>
      <h3 id="onboarding-title" aria-live="polite">
        {stateCopy[onboarding.state]}
      </h3>
      <p className="setup-copy">
        Package the game, verify its source configuration, then run it with
        <code> -FaultLaneCrash</code>. This page updates automatically.
      </p>
      <CopyCommand value={onboarding.commands.check} label="config check" />
      <CopyCommand value={onboarding.commands.scan} label="symbol scan" />

      {onboarding.release ? (
        <p className="setup-copy">
          Release <code>{onboarding.release.version}</code>
          {onboarding.release.architecture
            ? `, ${onboarding.release.architecture}`
            : ""}
          {onboarding.release.configuration
            ? `, ${onboarding.release.configuration}`
            : ""}
        </p>
      ) : null}

      {onboarding.missing_symbols.length ? (
        <ul className="missing-symbols">
          {onboarding.missing_symbols.map((symbol) => (
            <li
              key={`${symbol.module}-${symbol.required_artifact}-${symbol.debug_id}`}
            >
              <code>{symbol.module}</code> needs {symbol.required_artifact}
            </li>
          ))}
        </ul>
      ) : null}

      {onboarding.commands.upload ? (
        <>
          <CopyCommand
            value={onboarding.commands.token_environment}
            label="token command"
          />
          <CopyCommand
            value={onboarding.commands.upload}
            label="symbol upload"
          />
          <form action={tokenFormAction}>
            <button className="secondary button" disabled={tokenPending}>
              {tokenPending ? "Creating..." : "Create one-time upload token"}
            </button>
          </form>
        </>
      ) : null}

      {tokenState.artifactToken ? (
        <div className="one-time-token">
          <strong>Save this upload token now</strong>
          <code data-testid="artifact-upload-token">
            {tokenState.artifactToken.token}
          </code>
          <CopyCommand
            value={`$env:FAULTLANE_TOKEN = ${powershellLiteral(tokenState.artifactToken.token)}`}
            label="upload token"
          />
        </div>
      ) : null}
      {tokenState.error ? (
        <p className="form-error">{tokenState.error}</p>
      ) : null}
      {onboarding.diagnostic ? (
        <p className="form-error">{onboarding.diagnostic.message}</p>
      ) : null}
      {pollError ? (
        <p className="form-error" aria-live="polite">
          Status update failed. Retrying automatically.
        </p>
      ) : null}
      {onboarding.issue_path ? (
        <Link className="button primary" href={onboarding.issue_path}>
          Open readable issue
        </Link>
      ) : null}
    </section>
  );
}
