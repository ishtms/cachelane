"use server";

import { revalidatePath } from "next/cache";

import {
  FaultlaneApiError,
  type ProjectUsage,
  faultlaneApi,
} from "../../../lib/faultlane";

export type UsageState = {
  error?: string;
  usage?: ProjectUsage;
};

export async function saveUsageSettings(
  projectId: string,
  _previous: UsageState,
  formData: FormData,
): Promise<UsageState> {
  void _previous;
  const paidOverages = formData.get("paid_overages_enabled") === "on";
  const spendCap = paidOverages
    ? integer(formData.get("spend_cap_cents"))
    : null;
  const normalizedRetention = integer(
    formData.get("normalized_retention_days"),
  );
  const rawRetention = integer(formData.get("raw_retention_days"));
  if (
    (paidOverages && spendCap === null) ||
    normalizedRetention === null ||
    rawRetention === null
  ) {
    return { error: "Enter valid whole-number limits." };
  }

  try {
    const usage = await faultlaneApi<ProjectUsage>(
      `/api/v1/projects/${encodeURIComponent(projectId)}/usage`,
      {
        method: "PUT",
        body: JSON.stringify({
          spend_cap_cents: spendCap,
          retain_all_raw: formData.get("retain_all_raw") === "on",
          normalized_retention_days: normalizedRetention,
          raw_retention_days: rawRetention,
        }),
      },
    );
    revalidatePath(`/projects/${encodeURIComponent(projectId)}`);
    return { usage };
  } catch (error) {
    if (error instanceof FaultlaneApiError) {
      if (error.status === 403)
        return { error: "Only an owner can change usage settings." };
      if (error.status === 400)
        return { error: "Check the spend cap and retention limits." };
    }
    return { error: "Usage settings could not be saved. Try again." };
  }
}

function integer(value: FormDataEntryValue | null): number | null {
  if (typeof value !== "string" || !/^\d+$/u.test(value)) return null;
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) && parsed > 0 ? parsed : null;
}
