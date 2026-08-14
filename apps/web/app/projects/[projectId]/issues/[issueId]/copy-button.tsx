"use client";

import { useState } from "react";

export function CopyButton({ value }: { value: string }) {
  const [status, setStatus] = useState("Copy command");

  async function copy() {
    try {
      await navigator.clipboard.writeText(value);
      setStatus("Copied");
    } catch {
      setStatus("Copy failed");
    }
  }

  return (
    <button className="button secondary" type="button" onClick={copy}>
      <span aria-live="polite">{status}</span>
    </button>
  );
}
