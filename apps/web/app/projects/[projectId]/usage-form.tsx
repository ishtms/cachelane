"use client";

import { useActionState, useState } from "react";

import type { ProjectUsage } from "../../../lib/faultlane";
import { type UsageState, saveUsageSettings } from "./usage-actions";

const initialState: UsageState = {};

export function UsageForm({
  projectId,
  usage,
}: {
  projectId: string;
  usage: ProjectUsage;
}) {
  const action = saveUsageSettings.bind(null, projectId);
  const [state, formAction, pending] = useActionState(action, initialState);
  const current = state.usage ?? usage;
  const [paidOverages, setPaidOverages] = useState(
    current.paid_overages_enabled,
  );

  if (!current.can_edit) {
    return (
      <p className="fine-print">
        Only an organization owner can change retention, retain-all, or paid
        overage settings.
      </p>
    );
  }

  return (
    <form
      className="usage-settings-form"
      action={formAction}
      onSubmit={(event) => {
        if (
          paidOverages &&
          !window.confirm(
            "Save this spend cap and allow paid overages up to that amount?",
          )
        ) {
          event.preventDefault();
        }
      }}
    >
      <label>
        Normalized retention days
        <input
          name="normalized_retention_days"
          type="number"
          min={1}
          max={current.normalized_retention_limit_days}
          defaultValue={current.normalized_retention_days}
          required
        />
      </label>
      <label>
        Raw retention days
        <input
          name="raw_retention_days"
          type="number"
          min={1}
          max={current.raw_retention_limit_days}
          defaultValue={current.raw_retention_days}
          required
        />
      </label>
      <label className="checkbox-row">
        <input
          name="retain_all_raw"
          type="checkbox"
          defaultChecked={current.retain_all_raw}
        />
        Retain all raw crashes while storage permits
      </label>
      <label className="checkbox-row">
        <input
          name="paid_overages_enabled"
          type="checkbox"
          checked={paidOverages}
          onChange={(event) => setPaidOverages(event.target.checked)}
        />
        Allow paid event overages
      </label>
      <label>
        Monthly spend cap in cents
        <input
          name="spend_cap_cents"
          type="number"
          min={1500}
          max={10_000_000}
          defaultValue={current.spend_cap_cents ?? ""}
          disabled={!paidOverages}
          required={paidOverages}
        />
      </label>
      <div className="filter-actions">
        <button className="button primary" type="submit" disabled={pending}>
          {pending ? "Saving..." : "Save usage settings"}
        </button>
        <span
          className={state.error ? "form-error" : "action-status"}
          aria-live="polite"
        >
          {state.error
            ? state.error
            : state.usage
              ? `Policy version ${state.usage.policy_version} saved.`
              : `Current policy version ${current.policy_version}.`}
        </span>
      </div>
    </form>
  );
}
