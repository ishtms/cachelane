"use server";

import { revalidatePath } from "next/cache";

import {
  FaultlaneApiError,
  type ProjectDataRules,
  faultlaneApi,
} from "../../../lib/faultlane";

export type DataRulesState = {
  error?: string;
  rules?: ProjectDataRules;
};

export async function saveDataRules(
  projectId: string,
  _previous: DataRulesState,
  formData: FormData,
): Promise<DataRulesState> {
  void _previous;
  const redactionPatterns = lines(formData.get("redaction_patterns"));
  const indexedKeys = lines(formData.get("indexed_game_data_keys"));
  try {
    const rules = await faultlaneApi<ProjectDataRules>(
      `/api/v1/projects/${encodeURIComponent(projectId)}/data-rules`,
      {
        method: "PUT",
        body: JSON.stringify({
          redaction_patterns: redactionPatterns,
          indexed_game_data_keys: indexedKeys,
        }),
      },
    );
    revalidatePath(`/projects/${encodeURIComponent(projectId)}`);
    return { rules };
  } catch (error) {
    if (error instanceof FaultlaneApiError) {
      if (error.status === 403)
        return { error: "Only an owner can change data rules." };
      if (error.status === 400)
        return { error: "Check the pattern and key limits." };
    }
    return { error: "Data rules could not be saved. Try again." };
  }
}

function lines(value: FormDataEntryValue | null): string[] {
  if (typeof value !== "string") return [];
  return value
    .split(/\r?\n/u)
    .map((line) => line.trim())
    .filter(Boolean);
}
