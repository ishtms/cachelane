import "server-only";

import { faultlaneFetch } from "./faultlane";

const uuidPattern =
  /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i;

function unavailable(status = 503): Response {
  return new Response("Download unavailable.\n", {
    status,
    headers: {
      "cache-control": "no-store",
      pragma: "no-cache",
      "content-type": "text/plain; charset=utf-8",
      "x-content-type-options": "nosniff",
      "content-security-policy": "sandbox",
      "referrer-policy": "no-referrer",
    },
  });
}

export async function proxyDownload({
  apiPath,
  eventId,
  kind,
}: {
  apiPath: string;
  eventId: string;
  kind: "log" | "raw";
}): Promise<Response> {
  if (!uuidPattern.test(eventId)) return unavailable(404);

  let upstream: Response;
  try {
    upstream = await faultlaneFetch(apiPath);
  } catch {
    return unavailable();
  }
  if (!upstream.ok || !upstream.body) {
    return unavailable(
      [404, 409, 503].includes(upstream.status) ? upstream.status : 502,
    );
  }

  const headers = new Headers({
    "cache-control": "no-store",
    pragma: "no-cache",
    "content-type":
      kind === "log" ? "text/plain; charset=utf-8" : "application/octet-stream",
    "content-disposition": `attachment; filename="faultlane-event-${eventId}-${kind}.${kind === "log" ? "txt" : "bundle"}"`,
    "x-content-type-options": "nosniff",
    "content-security-policy": "sandbox",
    "referrer-policy": "no-referrer",
  });
  if (kind === "raw") {
    const length = upstream.headers.get("content-length");
    if (length && /^\d{1,8}$/.test(length))
      headers.set("content-length", length);
    const digest = upstream.headers.get("digest");
    if (digest && /^sha-256=[A-Za-z0-9+/]{43}=$/.test(digest)) {
      headers.set("digest", digest);
    }
  }
  return new Response(upstream.body, { status: 200, headers });
}
