import { NextResponse } from "next/server";

import { faultlanePublicApi } from "../../../../lib/faultlane";

const OAUTH_STATE_COOKIE = "faultlane_oauth_state";

export async function GET() {
  const result = await faultlanePublicApi<{ authorization_url: string }>(
    "/api/v1/auth/github/start",
    { method: "POST" },
  );
  const authorizationUrl = new URL(result.authorization_url);
  const state = authorizationUrl.searchParams.get("state");
  if (!state) throw new Error("GitHub sign-in did not return a state token");

  const response = NextResponse.redirect(authorizationUrl);
  response.cookies.set(OAUTH_STATE_COOKIE, state, {
    httpOnly: true,
    sameSite: "lax",
    secure: (process.env.PUBLIC_BASE_URL ?? "").startsWith("https://"),
    path: "/auth/github/callback",
    maxAge: 600,
  });
  return response;
}
