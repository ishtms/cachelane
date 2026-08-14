import Link from "next/link";

import { AuthProviders, faultlanePublicApi } from "../../lib/faultlane";
import { startEmailSignIn } from "./actions";

export default async function SignInPage({
  searchParams,
}: {
  searchParams: Promise<{ sent?: string }>;
}) {
  const sent = (await searchParams).sent === "1";
  const providers = await faultlanePublicApi<AuthProviders>(
    "/api/v1/auth/providers",
  );
  return (
    <main>
      <nav className="nav">
        <Link className="brand" href="/" aria-label="FaultLane home">
          <span className="brand-mark" aria-hidden="true">
            F
          </span>
          FaultLane
        </Link>
        <span className="phase">Hosted account</span>
      </nav>

      <section className="setup-shell">
        <div className="setup-intro">
          <p className="eyebrow">Sign in</p>
          <h1>Open your crash workspace.</h1>
          <p className="lede">
            Sign in with one of the configured account providers.
          </p>
        </div>

        <div className="account-card">
          {sent ? (
            <section className="state-panel" role="status">
              <h2>Check your email</h2>
              <p>
                The sign-in link expires in 15 minutes and can be used once.
              </p>
            </section>
          ) : null}

          {providers.github ? (
            <a className="button primary" href="/auth/github/start">
              Continue with GitHub
            </a>
          ) : null}

          {providers.email ? (
            <form className="setup-form" action={startEmailSignIn}>
              <label>
                Email address
                <input name="email" type="email" required maxLength={254} />
              </label>
              <button className="primary" type="submit">
                Email me a sign-in link
              </button>
            </form>
          ) : null}

          {!providers.github && !providers.email ? (
            <p>Hosted sign-in has not been configured.</p>
          ) : null}
        </div>
      </section>
    </main>
  );
}
