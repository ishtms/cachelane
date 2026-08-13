"use server";

import { revalidatePath } from "next/cache";

import {
  type CreatedSetup,
  setupApi,
  setupErrorMessage,
} from "../../lib/cachelane";

export type SetupActionState = {
  error?: string;
  created?: CreatedSetup;
  revoked?: boolean;
};

export async function createSetup(
  _previous: SetupActionState,
  formData: FormData,
): Promise<SetupActionState> {
  try {
    const created = await setupApi<CreatedSetup>("/api/v1/setup", {
      method: "POST",
      body: JSON.stringify({
        owner_email: String(formData.get("owner_email") ?? ""),
        organization_name: String(formData.get("organization_name") ?? ""),
        organization_slug: String(formData.get("organization_slug") ?? ""),
        project_name: String(formData.get("project_name") ?? ""),
        project_slug: String(formData.get("project_slug") ?? ""),
      }),
    });
    return { created };
  } catch (error) {
    return { error: setupErrorMessage(error) };
  }
}

export async function rotateIngestKey(
  projectId: string,
  _previous: SetupActionState,
): Promise<SetupActionState> {
  void _previous;
  try {
    const created = await setupApi<CreatedSetup>(
      `/api/v1/projects/${encodeURIComponent(projectId)}/ingest-keys`,
      { method: "POST" },
    );
    revalidatePath("/setup");
    return { created };
  } catch (error) {
    return { error: setupErrorMessage(error) };
  }
}

export async function revokeIngestKey(
  projectId: string,
  keyId: string,
  _previous: SetupActionState,
): Promise<SetupActionState> {
  void _previous;
  try {
    await setupApi(
      `/api/v1/projects/${encodeURIComponent(projectId)}/ingest-keys/${encodeURIComponent(keyId)}`,
      { method: "DELETE" },
    );
    revalidatePath("/setup");
    return { revoked: true };
  } catch (error) {
    return { error: setupErrorMessage(error) };
  }
}
