"use client";

import { useActionState } from "react";

import type { ProjectDataRules } from "../../../lib/faultlane";
import { type DataRulesState, saveDataRules } from "./data-rules-actions";

const initialState: DataRulesState = {};

export function DataRulesForm({
  projectId,
  rules,
}: {
  projectId: string;
  rules: ProjectDataRules;
}) {
  const action = saveDataRules.bind(null, projectId);
  const [state, formAction, pending] = useActionState(action, initialState);
  const current = state.rules ?? rules;

  if (!current.can_edit) {
    return (
      <p className="fine-print">
        Data rules version {current.version}. Only an organization owner can
        view or change redaction patterns.
      </p>
    );
  }

  return (
    <form
      className="data-rules-form"
      action={formAction}
      onSubmit={(event) => {
        if (
          !window.confirm("Save these rules and reprocess existing events?")
        ) {
          event.preventDefault();
        }
      }}
    >
      <label>
        Literal redaction patterns, one per line
        <textarea
          name="redaction_patterns"
          rows={6}
          defaultValue={current.redaction_patterns.join("\n")}
          maxLength={8192}
          autoComplete="off"
          spellCheck={false}
        />
      </label>
      <label>
        Indexed GameData keys, one per line
        <textarea
          name="indexed_game_data_keys"
          rows={6}
          defaultValue={current.indexed_game_data_keys.join("\n")}
          maxLength={4096}
          autoComplete="off"
          spellCheck={false}
        />
      </label>
      <div className="filter-actions">
        <button className="button primary" type="submit" disabled={pending}>
          {pending ? "Saving..." : "Save data rules"}
        </button>
        <span
          className={state.error ? "form-error" : "action-status"}
          aria-live="polite"
        >
          {state.error
            ? state.error
            : state.rules
              ? state.rules.reprocessing_request_id
                ? `Version ${state.rules.version} saved. Existing events are queued for reprocessing.`
                : `Version ${state.rules.version} was already current.`
              : `Current version ${current.version}.`}
        </span>
      </div>
    </form>
  );
}
