"use server";

import { cookies } from "next/headers";
import { redirect } from "next/navigation";

import { SESSION_COOKIE, Role, faultlaneApi } from "../../lib/faultlane";

const roles: Role[] = ["owner", "admin", "developer", "viewer"];

export async function inviteMember(formData: FormData) {
  const organizationId = String(formData.get("organization_id") ?? "");
  const email = String(formData.get("email") ?? "");
  const role = String(formData.get("role") ?? "");
  if (!roles.includes(role as Role)) throw new Error("invalid role");
  await faultlaneApi(
    `/api/v1/organizations/${encodeURIComponent(organizationId)}/invitations`,
    {
      method: "POST",
      body: JSON.stringify({ email, role }),
    },
  );
  redirect("/account");
}

export async function changeMemberRole(formData: FormData) {
  const organizationId = String(formData.get("organization_id") ?? "");
  const userId = String(formData.get("user_id") ?? "");
  const role = String(formData.get("role") ?? "");
  if (!roles.includes(role as Role)) throw new Error("invalid role");
  await faultlaneApi(
    `/api/v1/organizations/${encodeURIComponent(organizationId)}/members/${encodeURIComponent(userId)}`,
    { method: "PATCH", body: JSON.stringify({ role }) },
  );
  redirect("/account");
}

export async function removeMember(formData: FormData) {
  const organizationId = String(formData.get("organization_id") ?? "");
  const userId = String(formData.get("user_id") ?? "");
  await faultlaneApi(
    `/api/v1/organizations/${encodeURIComponent(organizationId)}/members/${encodeURIComponent(userId)}`,
    { method: "DELETE" },
  );
  redirect("/account");
}

export async function revokeInvitation(formData: FormData) {
  const organizationId = String(formData.get("organization_id") ?? "");
  const invitationId = String(formData.get("invitation_id") ?? "");
  await faultlaneApi(
    `/api/v1/organizations/${encodeURIComponent(organizationId)}/invitations/${encodeURIComponent(invitationId)}`,
    { method: "DELETE" },
  );
  redirect("/account");
}

export async function revokeSession(formData: FormData) {
  const sessionId = String(formData.get("session_id") ?? "");
  const current = formData.get("current") === "true";
  await faultlaneApi(`/api/v1/auth/sessions/${encodeURIComponent(sessionId)}`, {
    method: "DELETE",
  });
  if (current) {
    (await cookies()).delete(SESSION_COOKIE);
    redirect("/sign-in");
  }
  redirect("/account");
}
