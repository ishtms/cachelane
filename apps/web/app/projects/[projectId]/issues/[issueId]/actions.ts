"use server";

import { revalidatePath } from "next/cache";

import {
  type ReprocessingRequest,
  faultlaneApi,
} from "../../../../../lib/faultlane";

export type ReprocessState = {
  error?: string;
  request?: ReprocessingRequest;
};

export async function requestEventReprocessing(
  projectId: string,
  issueId: string,
  eventId: string,
  currentResultId: string,
  _previous: ReprocessState,
  _formData: FormData,
): Promise<ReprocessState> {
  void _previous;
  void _formData;
  if (currentResultId === "missing") {
    return { error: "This event has no processing result yet." };
  }
  try {
    const request = await faultlaneApi<ReprocessingRequest>(
      `/api/v1/projects/${encodeURIComponent(projectId)}/reprocessing`,
      {
        method: "POST",
        headers: {
          "idempotency-key": `dashboard-${eventId}-${currentResultId}`,
        },
        body: JSON.stringify({
          scope: { kind: "event", event_id: eventId },
          limit: 1,
        }),
      },
    );
    revalidatePath(
      `/projects/${encodeURIComponent(projectId)}/issues/${encodeURIComponent(issueId)}`,
    );
    return { request };
  } catch {
    return {
      error:
        "Reprocessing could not be started. Check worker health and try again.",
    };
  }
}
