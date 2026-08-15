import { readFile } from "node:fs/promises";

import { expect, test } from "@playwright/test";

function required(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

test("triages readable and missing-symbol crashes without leaking sensitive access", async ({
  page,
}) => {
  const projectId = required("FAULTLANE_PROOF_PROJECT_ID");
  const readableIssueId = required("FAULTLANE_PROOF_READABLE_ISSUE_ID");
  const missingIssueId = required("FAULTLANE_PROOF_MISSING_ISSUE_ID");
  const emptyProjectId = required("FAULTLANE_PROOF_EMPTY_PROJECT_ID");
  const outsideProjectId = required("FAULTLANE_PROOF_OUTSIDE_PROJECT_ID");
  const secret = required("FAULTLANE_BOOTSTRAP_SECRET");
  const baseOrigin = new URL(
    process.env.FAULTLANE_WEB_URL ?? "http://127.0.0.1:3000",
  ).origin;
  const unexpectedRequests: string[] = [];
  page.on("request", (request) => {
    const url = request.url();
    if (url.startsWith("http") && new URL(url).origin !== baseOrigin) {
      unexpectedRequests.push(url);
    }
  });
  await page.context().grantPermissions(["clipboard-read", "clipboard-write"], {
    origin: baseOrigin,
  });

  await page.goto(`/projects/${projectId}`);
  await expect(
    page.getByRole("heading", { name: "Windows Game", exact: true }),
  ).toBeVisible();
  await expect(page.getByText("Authoritative billing cycle")).toBeVisible();
  await expect(page.getByRole("link", { name: "Next page" })).toBeVisible();
  await page.getByRole("link", { name: "Next page" }).click();
  await expect(page).toHaveURL(/cursor=/);
  await expect(page.locator(".issue-table tbody tr").first()).toBeVisible();

  await page.goto(`/projects/${projectId}`);
  await page
    .getByLabel("Search title, stack, module, error, or comment")
    .fill("Browser seed 10000");
  await page.getByRole("button", { name: "Apply filters" }).click();
  await expect(
    page.getByRole("link", { name: "Browser seed 10000" }),
  ).toBeVisible();
  await expect(page.locator(".issue-table tbody tr")).toHaveCount(1);

  await page.goto(`/projects/${projectId}/issues/${readableIssueId}`);
  await expect(page.locator(".faulting-thread")).toBeVisible();
  await expect(page.locator(".stack-table tbody tr").first()).toContainText(
    "0x",
  );
  await expect(
    page.getByRole("heading", { name: "Crash classification" }),
  ).toBeVisible();
  await expect(
    page.getByText("</textarea><script>globalThis.pwned=true</script>"),
  ).toBeVisible();
  await expect(page.locator(".log-panel pre")).toContainText("<script>");
  await expect(page.locator(".event-row")).toHaveCount(3);

  const logDownloadPromise = page.waitForEvent("download");
  await page.getByRole("link", { name: "Download log" }).click();
  const logDownload = await logDownloadPromise;
  expect(logDownload.suggestedFilename()).toMatch(
    /^faultlane-event-[a-f0-9-]+-log\.txt$/,
  );
  const logPath = await logDownload.path();
  expect(logPath).not.toBeNull();
  expect(await readFile(logPath ?? "", "utf8")).toContain("<script>");

  const rawDownloadPromise = page.waitForEvent("download");
  await page.getByRole("link", { name: "Download raw bundle" }).click();
  const rawDownload = await rawDownloadPromise;
  expect(rawDownload.suggestedFilename()).toMatch(
    /^faultlane-event-[a-f0-9-]+-raw\.bundle$/,
  );
  const rawPath = await rawDownload.path();
  expect(rawPath).not.toBeNull();
  expect((await readFile(rawPath ?? "")).byteLength).toBeGreaterThan(100);

  page.once("dialog", (dialog) => dialog.accept());
  await page.getByRole("button", { name: "Reprocess event" }).click();
  await expect(page.locator(".action-status")).toContainText("Request");

  const secondEvent = page.locator(".event-row").nth(1);
  const secondEventId = (
    await secondEvent.locator("code").textContent()
  )?.trim();
  expect(secondEventId).toMatch(/^[a-f0-9-]{36}$/);
  await secondEvent.click();
  await expect(page).toHaveURL(new RegExp(`event=${secondEventId}$`));
  await expect(page.locator(".faulting-thread")).toBeVisible();

  await page.goto(`/projects/${projectId}/issues/${missingIssueId}`);
  await expect(
    page.getByRole("heading", { name: "Missing symbols" }),
  ).toBeVisible();
  const missingSymbols = page.locator(".missing-panel");
  await expect(
    missingSymbols.getByRole("cell", { name: "PDB", exact: true }),
  ).toBeVisible();
  const command = await page.locator(".command-row > code").textContent();
  expect(command).toContain("faultlane symbols upload '<build-directory>'");
  expect(command).toContain("--release '6.0.0'");
  await page.getByRole("button", { name: "Copy command" }).click();
  await expect(page.getByRole("button", { name: "Copied" })).toBeVisible();
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(
    command,
  );

  expect(
    await page.evaluate(() => Reflect.get(globalThis, "pwned")),
  ).toBeUndefined();
  expect(await page.evaluate(() => localStorage.length)).toBe(0);
  expect(await page.evaluate(() => sessionStorage.length)).toBe(0);
  expect(await page.locator('a[href^="javascript:"]').count()).toBe(0);
  expect(await page.content()).not.toContain(secret);

  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto(`/projects/${projectId}/issues/${readableIssueId}`);
  await expect(page.locator(".faulting-thread")).toBeVisible();
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= window.innerWidth,
    ),
  ).toBe(true);

  await page.goto(`/projects/${emptyProjectId}`);
  await expect(
    page.getByRole("heading", { name: "No matching issues" }),
  ).toBeVisible();
  await expect(
    page.getByText("No events in this window.").first(),
  ).toBeVisible();
  await expect(
    page.getByRole("heading", { name: "Project data rules" }),
  ).toBeVisible();
  await expect(
    page.getByRole("heading", { name: "Crash and project alerts" }),
  ).toBeVisible();
  await expect(
    page.getByText("Alerts are not enabled for this deployment."),
  ).toBeVisible();
  await page
    .getByLabel("Literal redaction patterns, one per line")
    .fill("browser-proof-secret");
  await page.getByLabel("Indexed GameData keys, one per line").fill("MapName");
  page.once("dialog", (dialog) => dialog.accept());
  await page.getByRole("button", { name: "Save data rules" }).click();
  await expect(page.locator(".data-rules-form .action-status")).toContainText(
    "Existing events are queued for reprocessing.",
  );
  await page.getByLabel("Raw retention days").fill("6");
  await page.getByRole("button", { name: "Save usage settings" }).click();
  await expect(
    page.locator(".usage-settings-form .action-status"),
  ).toContainText("Policy version 2 saved.");

  await page.goto(`/projects/${outsideProjectId}`);
  await expect(
    page.getByRole("heading", { name: "This project could not be found." }),
  ).toBeVisible();
  expect(unexpectedRequests).toEqual([]);
});
