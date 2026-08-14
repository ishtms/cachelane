"use server";

import { redirect } from "next/navigation";

import { faultlanePublicApi } from "../../lib/faultlane";

export async function startEmailSignIn(formData: FormData) {
  const email = String(formData.get("email") ?? "");
  await faultlanePublicApi<void>("/api/v1/auth/email/start", {
    method: "POST",
    body: JSON.stringify({ email }),
  });
  redirect("/sign-in?sent=1");
}
