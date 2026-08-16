import { NextRequest, NextResponse } from "next/server";

export function proxy(request: NextRequest) {
  if (process.env.FAULTLANE_PUBLIC_DEMO_WEB_ONLY !== "true") {
    return NextResponse.next();
  }

  const { pathname } = request.nextUrl;
  if (
    pathname === "/demo" ||
    pathname.startsWith("/demo/") ||
    pathname === "/favicon.ico"
  ) {
    return NextResponse.next();
  }
  if (pathname === "/") {
    return NextResponse.redirect(new URL("/demo", request.url));
  }
  return new NextResponse("Not found", {
    status: 404,
    headers: { "cache-control": "no-store" },
  });
}

export const config = {
  matcher: ["/((?!_next/static).*)"],
};
