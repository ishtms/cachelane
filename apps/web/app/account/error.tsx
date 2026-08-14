"use client";

import Link from "next/link";

export default function AccountError() {
  return (
    <main className="setup-shell">
      <section className="state-panel" role="alert">
        <h1>The account page is unavailable.</h1>
        <p>Try again or sign in with a fresh session.</p>
        <Link className="button" href="/account">
          Try again
        </Link>
        <Link className="button" href="/sign-in">
          Sign in
        </Link>
      </section>
    </main>
  );
}
