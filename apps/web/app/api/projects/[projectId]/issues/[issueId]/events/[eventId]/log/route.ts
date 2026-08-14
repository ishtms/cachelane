import { proxyDownload } from "../../../../../../../../../lib/download";

export async function GET(
  _request: Request,
  context: {
    params: Promise<{ projectId: string; issueId: string; eventId: string }>;
  },
) {
  const { projectId, issueId, eventId } = await context.params;
  return proxyDownload({
    apiPath: `/api/v1/projects/${encodeURIComponent(projectId)}/issues/${encodeURIComponent(issueId)}/events/${encodeURIComponent(eventId)}/log`,
    eventId,
    kind: "log",
  });
}
