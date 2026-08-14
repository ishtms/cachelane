import { NextRequest, NextResponse } from "next/server";

import {
  SESSION_COOKIE,
  SessionCreated,
  faultlanePublicApi,
} from "../../../lib/faultlane";

export async function GET(request: NextRequest) {
  const token = request.nextUrl.searchParams.get("token");
  const webBaseUrl = process.env.PUBLIC_BASE_URL ?? request.url;
  if (!token) return NextResponse.redirect(new URL("/sign-in", webBaseUrl));

  const session = await faultlanePublicApi<SessionCreated>(
    "/api/v1/invitations/accept",
    {
      method: "POST",
      body: JSON.stringify({ token }),
    },
  );
  const response = NextResponse.redirect(new URL("/account", webBaseUrl));
  response.cookies.set(SESSION_COOKIE, session.token, {
    httpOnly: true,
    sameSite: "lax",
    secure: (process.env.PUBLIC_BASE_URL ?? "").startsWith("https://"),
    path: "/",
    expires: new Date(session.session.expires_at),
  });
  return response;
}
