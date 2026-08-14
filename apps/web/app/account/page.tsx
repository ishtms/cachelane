import Link from "next/link";
import { redirect } from "next/navigation";

import {
  AuditList,
  FaultlaneApiError,
  MemberList,
  SessionList,
  SessionResponse,
  faultlaneApi,
} from "../../lib/faultlane";
import {
  changeMemberRole,
  inviteMember,
  removeMember,
  revokeInvitation,
  revokeSession,
} from "./actions";

export default async function AccountPage() {
  let session: SessionResponse;
  try {
    session = await faultlaneApi<SessionResponse>("/api/v1/auth/session");
  } catch (error) {
    if (
      error instanceof FaultlaneApiError &&
      [401, 404].includes(error.status ?? 0)
    ) {
      redirect("/sign-in");
    }
    throw error;
  }

  const membership = session.memberships[0];
  const sessions = await faultlaneApi<SessionList>("/api/v1/auth/sessions");
  const canManage = membership && ["owner", "admin"].includes(membership.role);
  const assignableRoles =
    membership?.role === "admin"
      ? [
          { value: "developer", label: "Developer" },
          { value: "viewer", label: "Viewer" },
        ]
      : [
          { value: "owner", label: "Owner" },
          { value: "admin", label: "Admin" },
          { value: "developer", label: "Developer" },
          { value: "viewer", label: "Viewer" },
        ];
  const team = membership
    ? await faultlaneApi<MemberList>(
        `/api/v1/organizations/${encodeURIComponent(membership.organization_id)}/members`,
      )
    : null;
  const audit = canManage
    ? await faultlaneApi<AuditList>(
        `/api/v1/organizations/${encodeURIComponent(membership.organization_id)}/audit`,
      )
    : null;

  return (
    <main>
      <nav className="nav">
        <Link className="brand" href="/" aria-label="FaultLane home">
          <span className="brand-mark" aria-hidden="true">
            F
          </span>
          FaultLane
        </Link>
        <span className="phase">
          {membership?.organization_name ?? "Account"}
        </span>
      </nav>

      <section className="setup-shell">
        <div className="setup-intro">
          <p className="eyebrow">Signed in</p>
          <h1>{session.user.email}</h1>
          <p className="lede">
            {membership
              ? `${membership.organization_name} · ${membership.role}`
              : "Accept an invitation to join an organization."}
          </p>
        </div>

        <div className="project-panel account-card">
          {team ? (
            <section>
              <div className="section-heading">
                <p>Team</p>
                <h2>Organization members</h2>
              </div>
              <div className="table-scroll">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Email</th>
                      <th>Role</th>
                      {canManage ? <th>Actions</th> : null}
                    </tr>
                  </thead>
                  <tbody>
                    {team.members.map((member) => (
                      <tr key={member.user_id}>
                        <td>{member.email}</td>
                        <td>{member.role}</td>
                        {canManage ? (
                          <td className="account-actions">
                            {membership.role === "owner" ||
                            !["owner", "admin"].includes(member.role) ? (
                              <>
                                <form action={changeMemberRole}>
                                  <input
                                    type="hidden"
                                    name="organization_id"
                                    value={membership.organization_id}
                                  />
                                  <input
                                    type="hidden"
                                    name="user_id"
                                    value={member.user_id}
                                  />
                                  <select
                                    name="role"
                                    defaultValue={member.role}
                                    aria-label={`Role for ${member.email}`}
                                  >
                                    {assignableRoles.map((role) => (
                                      <option
                                        value={role.value}
                                        key={role.value}
                                      >
                                        {role.label}
                                      </option>
                                    ))}
                                  </select>
                                  <button type="submit">Update</button>
                                </form>
                                <form action={removeMember}>
                                  <input
                                    type="hidden"
                                    name="organization_id"
                                    value={membership.organization_id}
                                  />
                                  <input
                                    type="hidden"
                                    name="user_id"
                                    value={member.user_id}
                                  />
                                  <button type="submit">Remove</button>
                                </form>
                              </>
                            ) : (
                              <span>Restricted</span>
                            )}
                          </td>
                        ) : null}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>
          ) : null}

          {canManage ? (
            <section>
              <div className="section-heading">
                <p>Invite</p>
                <h2>Add a teammate</h2>
              </div>
              <form className="setup-form account-invite" action={inviteMember}>
                <input
                  type="hidden"
                  name="organization_id"
                  value={membership.organization_id}
                />
                <label>
                  Email address
                  <input name="email" type="email" required maxLength={254} />
                </label>
                <label>
                  Role
                  <select name="role" defaultValue="developer">
                    {assignableRoles.map((role) => (
                      <option value={role.value} key={role.value}>
                        {role.label}
                      </option>
                    ))}
                  </select>
                </label>
                <button className="primary" type="submit">
                  Send invitation
                </button>
              </form>
              {team?.invitations.map((invitation) => (
                <form
                  className="account-row"
                  action={revokeInvitation}
                  key={invitation.id}
                >
                  <input
                    type="hidden"
                    name="organization_id"
                    value={membership.organization_id}
                  />
                  <input
                    type="hidden"
                    name="invitation_id"
                    value={invitation.id}
                  />
                  <span>
                    {invitation.email} · {invitation.role}
                  </span>
                  <button type="submit">Revoke</button>
                </form>
              ))}
            </section>
          ) : null}

          <section>
            <div className="section-heading">
              <p>Security</p>
              <h2>Active sessions</h2>
            </div>
            {sessions.sessions.map((item) => (
              <form
                className="account-row"
                action={revokeSession}
                key={item.id}
              >
                <input type="hidden" name="session_id" value={item.id} />
                <input
                  type="hidden"
                  name="current"
                  value={String(item.current)}
                />
                <span>
                  {item.current
                    ? "Current session"
                    : `Last used ${formatTime(item.last_seen_at)}`}
                </span>
                <button type="submit">
                  {item.current ? "Sign out" : "Revoke"}
                </button>
              </form>
            ))}
          </section>

          {audit ? (
            <section>
              <div className="section-heading">
                <p>Audit</p>
                <h2>Sensitive activity</h2>
              </div>
              <div className="table-scroll">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Time</th>
                      <th>Action</th>
                      <th>Result</th>
                    </tr>
                  </thead>
                  <tbody>
                    {audit.items.map((item) => (
                      <tr key={item.id}>
                        <td>{formatTime(item.occurred_at)}</td>
                        <td>{item.action}</td>
                        <td>{item.result}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>
          ) : null}
        </div>
      </section>
    </main>
  );
}

function formatTime(value: string) {
  return new Intl.DateTimeFormat("en", {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(new Date(value));
}
