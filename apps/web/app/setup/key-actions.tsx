"use client";

import { useActionState, useEffect } from "react";
import { useRouter } from "next/navigation";

import {
  revokeIngestKey,
  rotateIngestKey,
  type SetupActionState,
} from "./actions";
import { CreatedSetupResult } from "./created-setup";

const initialState: SetupActionState = {};

export function RotateKey({
  projectId,
  onboardingEnabled,
}: {
  projectId: string;
  onboardingEnabled: boolean;
}) {
  const action = rotateIngestKey.bind(null, projectId);
  const [state, formAction, pending] = useActionState(action, initialState);

  if (state.created) {
    return (
      <CreatedSetupResult
        created={state.created}
        onboardingEnabled={onboardingEnabled}
      />
    );
  }

  return (
    <form action={formAction}>
      {state.error ? <p className="form-error">{state.error}</p> : null}
      <button className="secondary button" type="submit" disabled={pending}>
        {pending ? "Creating..." : "Create another key"}
      </button>
    </form>
  );
}

export function RevokeKey({
  projectId,
  keyId,
}: {
  projectId: string;
  keyId: string;
}) {
  const router = useRouter();
  const action = revokeIngestKey.bind(null, projectId, keyId);
  const [state, formAction, pending] = useActionState(action, initialState);

  useEffect(() => {
    if (state.revoked) {
      router.refresh();
    }
  }, [router, state.revoked]);

  return (
    <form action={formAction}>
      {state.error ? <span className="form-error">{state.error}</span> : null}
      <button className="key-revoke" type="submit" disabled={pending}>
        {pending ? "Revoking..." : "Revoke"}
      </button>
    </form>
  );
}
