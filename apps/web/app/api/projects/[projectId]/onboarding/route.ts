import { faultlaneFetch } from "../../../../../lib/faultlane";

export async function GET(
  _request: Request,
  context: { params: Promise<{ projectId: string }> },
) {
  const { projectId } = await context.params;
  const response = await faultlaneFetch(
    `/api/v1/projects/${encodeURIComponent(projectId)}/onboarding`,
  );
  const body = await response.text();
  return new Response(body, {
    status: response.status,
    headers: {
      "cache-control": "no-store",
      "content-type":
        response.headers.get("content-type") ?? "application/json",
      pragma: "no-cache",
    },
  });
}
