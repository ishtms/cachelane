import { NextRequest, NextResponse } from "next/server";

import {
  SESSION_COOKIE,
  SessionCreated,
  faultlanePublicApi,
} from "../../../../lib/faultlane";

const OAUTH_STATE_COOKIE = "faultlane_oauth_state";

export async function GET(request: NextRequest) {
  const code = request.nextUrl.searchParams.get("code");
  const state = request.nextUrl.searchParams.get("state");
  const expectedState = request.cookies.get(OAUTH_STATE_COOKIE)?.value;
  const webBaseUrl = process.env.PUBLIC_BASE_URL ?? request.url;
  if (!code || !state || !expectedState || state !== expectedState)
    return NextResponse.redirect(new URL("/sign-in", webBaseUrl));

  const session = await faultlanePublicApi<SessionCreated>(
    "/api/v1/auth/github/callback",
    {
      method: "POST",
      body: JSON.stringify({ code, state }),
    },
  );
  const response = NextResponse.redirect(new URL("/account", webBaseUrl));
  response.cookies.set(
    SESSION_COOKIE,
    session.token,
    sessionCookie(session.session.expires_at),
  );
  response.cookies.set(OAUTH_STATE_COOKIE, "", {
    httpOnly: true,
    sameSite: "lax",
    secure: (process.env.PUBLIC_BASE_URL ?? "").startsWith("https://"),
    path: "/auth/github/callback",
    expires: new Date(0),
  });
  return response;
}

function sessionCookie(expiresAt: string) {
  return {
    httpOnly: true,
    sameSite: "lax" as const,
    secure: (process.env.PUBLIC_BASE_URL ?? "").startsWith("https://"),
    path: "/",
    expires: new Date(expiresAt),
  };
}
