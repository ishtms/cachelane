"use client";

import { useActionState } from "react";

import { type ReprocessState, requestEventReprocessing } from "./actions";

const initialState: ReprocessState = {};

export function ReprocessButton({
  projectId,
  issueId,
  eventId,
  currentResultId,
}: {
  projectId: string;
  issueId: string;
  eventId: string;
  currentResultId: string | null;
}) {
  const action = requestEventReprocessing.bind(
    null,
    projectId,
    issueId,
    eventId,
    currentResultId ?? "missing",
  );
  const [state, formAction, pending] = useActionState(action, initialState);

  return (
    <form
      className="reprocess-form"
      action={formAction}
      onSubmit={(event) => {
        if (
          !window.confirm("Reprocess this event using the current pipeline?")
        ) {
          event.preventDefault();
        }
      }}
    >
      <button
        className="button secondary"
        type="submit"
        disabled={pending || !currentResultId}
      >
        {pending ? "Requesting..." : "Reprocess event"}
      </button>
      <span
        className={state.error ? "form-error" : "action-status"}
        aria-live="polite"
      >
        {state.error
          ? state.error
          : state.request
            ? `Request ${state.request.state}, ${state.request.selected_count} event selected.`
            : ""}
      </span>
    </form>
  );
}
