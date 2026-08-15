"use server";

import { revalidatePath } from "next/cache";

import {
  FaultlaneApiError,
  type AlertIntegration,
  type AlertRule,
  faultlaneApi,
} from "../../../lib/faultlane";

export type AlertActionState = {
  error?: string;
  message?: string;
  signingSecret?: string;
};

export async function createAlertIntegration(
  projectId: string,
  _previous: AlertActionState,
  formData: FormData,
): Promise<AlertActionState> {
  void _previous;
  const kind = text(formData, "kind");
  const name = text(formData, "name");
  const url = text(formData, "url");
  if (!kind || !name || (kind !== "email" && !url)) {
    return { error: "Enter a name and destination URL." };
  }
  try {
    const integration = await faultlaneApi<AlertIntegration>(
      `/api/v1/projects/${encodeURIComponent(projectId)}/alert-integrations`,
      {
        method: "POST",
        body: JSON.stringify({
          kind,
          name,
          url: kind === "email" ? null : url,
        }),
      },
    );
    revalidatePath(`/projects/${encodeURIComponent(projectId)}`);
    return {
      message: `${integration.name} created.`,
      signingSecret: integration.signing_secret,
    };
  } catch (error) {
    return alertError(error, "Integration could not be created.");
  }
}

export async function createAlertRule(
  projectId: string,
  _previous: AlertActionState,
  formData: FormData,
): Promise<AlertActionState> {
  void _previous;
  const condition = text(formData, "condition_kind");
  const threshold = optionalInteger(formData, "threshold");
  const windowSeconds = optionalInteger(formData, "window_seconds");
  const quietStart = optionalInteger(formData, "quiet_start_minute");
  const quietEnd = optionalInteger(formData, "quiet_end_minute");
  try {
    const rule = await faultlaneApi<AlertRule>(
      `/api/v1/projects/${encodeURIComponent(projectId)}/alert-rules`,
      {
        method: "POST",
        body: JSON.stringify({
          integration_id: text(formData, "integration_id"),
          condition_kind: condition,
          environment: text(formData, "environment"),
          threshold,
          window_seconds: windowSeconds,
          quiet_start_minute: quietStart,
          quiet_end_minute: quietEnd,
        }),
      },
    );
    revalidatePath(`/projects/${encodeURIComponent(projectId)}`);
    return {
      message: `${rule.condition_kind.replaceAll("_", " ")} rule created.`,
    };
  } catch (error) {
    return alertError(
      error,
      "Rule could not be created. Check its condition settings.",
    );
  }
}

export async function setAlertIntegrationEnabled(
  projectId: string,
  integrationId: string,
  enabled: boolean,
): Promise<void> {
  await faultlaneApi(
    `/api/v1/projects/${encodeURIComponent(projectId)}/alert-integrations/${encodeURIComponent(integrationId)}`,
    { method: "PATCH", body: JSON.stringify({ enabled }) },
  );
  revalidatePath(`/projects/${encodeURIComponent(projectId)}`);
}

export async function setAlertRuleEnabled(
  projectId: string,
  ruleId: string,
  enabled: boolean,
): Promise<void> {
  await faultlaneApi(
    `/api/v1/projects/${encodeURIComponent(projectId)}/alert-rules/${encodeURIComponent(ruleId)}`,
    { method: "PATCH", body: JSON.stringify({ enabled }) },
  );
  revalidatePath(`/projects/${encodeURIComponent(projectId)}`);
}

function text(formData: FormData, name: string): string {
  const value = formData.get(name);
  return typeof value === "string" ? value.trim() : "";
}

function optionalInteger(formData: FormData, name: string): number | null {
  const value = text(formData, name);
  if (!value) return null;
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) ? parsed : null;
}

function alertError(error: unknown, fallback: string): AlertActionState {
  if (error instanceof FaultlaneApiError) {
    if (error.status === 403)
      return { error: "Only an owner or admin can change alerts." };
    if (error.status === 400) return { error: fallback };
    if (error.status === 409)
      return { error: "That alert configuration already exists." };
  }
  return { error: fallback };
}
