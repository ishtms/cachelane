"use client";

import { useActionState } from "react";

import { createSetup, type SetupActionState } from "./actions";
import { CreatedSetupResult } from "./created-setup";

const initialState: SetupActionState = {};

export function SetupForm() {
  const [state, formAction, pending] = useActionState(
    createSetup,
    initialState,
  );

  if (state.created) {
    return <CreatedSetupResult created={state.created} />;
  }

  return (
    <form className="setup-form" action={formAction}>
      <label>
        Owner email
        <input name="owner_email" type="email" required autoComplete="email" />
      </label>
      <label>
        Organization name
        <input name="organization_name" required maxLength={80} />
      </label>
      <label>
        Organization slug
        <input
          name="organization_slug"
          required
          maxLength={63}
          pattern="[a-z0-9]+(?:-[a-z0-9]+)*"
        />
      </label>
      <label>
        Project name
        <input name="project_name" required maxLength={80} />
      </label>
      <label>
        Project slug
        <input
          name="project_slug"
          required
          maxLength={63}
          pattern="[a-z0-9]+(?:-[a-z0-9]+)*"
        />
      </label>
      {state.error ? <p className="form-error">{state.error}</p> : null}
      <button className="primary" type="submit" disabled={pending}>
        {pending ? "Creating..." : "Create project"}
      </button>
    </form>
  );
}
