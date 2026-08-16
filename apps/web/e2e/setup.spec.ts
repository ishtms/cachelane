import { expect, test } from "@playwright/test";

test("creates a project and manages one-time ingest keys", async ({ page }) => {
  const apiUrl = process.env.FAULTLANE_API_URL ?? "http://127.0.0.1:8080";
  const ingestUrl = process.env.FAULTLANE_INGEST_URL ?? "http://127.0.0.1:8081";
  let onboardingPoll = 0;
  let readable = false;
  await page.route("**/api/projects/*/onboarding", async (route) => {
    onboardingPoll += 1;
    const state = readable
      ? "readable_issue"
      : onboardingPoll === 1
        ? "received"
        : onboardingPoll === 2
          ? "processing"
          : "missing_symbols";
    await route.fulfill({
      contentType: "application/json",
      headers: { "cache-control": "no-store" },
      body: JSON.stringify({
        state,
        event: {
          id: "11111111-1111-4111-8111-111111111111",
          received_at: "2026-08-16T00:00:00Z",
          processing_state: state === "readable_issue" ? "processed" : state,
        },
        release: {
          id: "22222222-2222-4222-8222-222222222222",
          version: "1.0.0",
          platform: "windows",
          architecture: "x86_64",
          configuration: "shipping",
        },
        missing_symbols:
          state === "missing_symbols"
            ? [
                {
                  required_artifact: "pdb",
                  module: "Game.exe",
                  architecture: "x86_64",
                  debug_id: "ABC1",
                  code_id: "DEF1",
                },
              ]
            : [],
        missing_symbols_truncated: false,
        commands: {
          check:
            "faultlane unreal check '<project-root>' --package '<packaged-build-root>'",
          scan: "faultlane symbols scan '<symbol-root>'",
          token_environment: "$env:FAULTLANE_TOKEN = '<one-time-upload-token>'",
          upload:
            "faultlane symbols upload '<symbol-root>' --project 'ue58-game' --release '1.0.0' --architecture 'x86_64' --configuration 'shipping'",
        },
        issue_path:
          state === "readable_issue"
            ? "/projects/33333333-3333-4333-8333-333333333333/issues/44444444-4444-4444-8444-444444444444"
            : null,
        diagnostic:
          state === "missing_symbols"
            ? {
                code: "matching_symbols_missing",
                message:
                  "Upload the matching PE and PDB files for this release.",
                retryable: true,
              }
            : null,
      }),
    });
  });

  await page.goto("/setup");
  await page.getByLabel("Owner email").fill("owner@example.com");
  await page.getByLabel("Organization name").fill("Example Studio");
  await page.getByLabel("Organization slug").fill("example-studio");
  await page.getByLabel("Project name").fill("UE 5.8 Game");
  await page.getByLabel("Project slug").fill("ue58-game");
  await page.getByRole("button", { name: "Create project" }).click();

  await expect(
    page.getByRole("heading", { name: "Save this key now" }),
  ).toBeVisible();
  const firstKey = await page.getByTestId("ingest-key").textContent();
  expect(firstKey).toMatch(/^clpk_[a-f0-9]{64}$/);
  expect(await page.evaluate(() => localStorage.length)).toBe(0);
  expect(await page.evaluate(() => sessionStorage.length)).toBe(0);
  await expect(
    page.getByText("IncludeCrashReporter=True", { exact: false }),
  ).toBeVisible();
  await expect(
    page.getByText("DataRouterUrl=", { exact: false }),
  ).toBeVisible();
  await expect(page.getByTestId("data-router-url")).toContainText(
    `${ingestUrl}/u/${firstKey}`,
  );
  await expect(
    page.getByRole("heading", { name: "Waiting for a packaged crash" }),
  ).toBeVisible();
  await expect(
    page.getByRole("heading", { name: "Crash received" }),
  ).toBeVisible({ timeout: 10_000 });
  await expect(
    page.getByRole("heading", { name: "Processing crash" }),
  ).toBeVisible({ timeout: 10_000 });
  await expect(
    page.getByRole("heading", { name: "Matching symbols required" }),
  ).toBeVisible({ timeout: 10_000 });
  await expect(
    page.getByText("Game.exe needs pdb", { exact: false }),
  ).toBeVisible();
  await page.getByRole("button", { name: "Copy symbol upload" }).click();
  await expect(page.getByRole("button", { name: "Copied" })).toBeVisible();
  await page
    .getByRole("button", { name: "Create one-time upload token" })
    .click();
  const artifactToken = await page
    .getByTestId("artifact-upload-token")
    .textContent();
  expect(artifactToken).toMatch(/^clsu_[a-f0-9]{64}$/);
  await page.getByRole("button", { name: "Copy upload token" }).click();
  await expect(
    page.locator(".one-time-token").getByRole("button", { name: "Copied" }),
  ).toBeVisible();
  readable = true;
  await expect(
    page.getByRole("link", { name: "Open readable issue" }),
  ).toBeVisible({ timeout: 10_000 });

  await page.getByRole("link", { name: "Manage project setup" }).click();
  await expect(
    page.getByRole("heading", { name: "UE 5.8 Game" }),
  ).toBeVisible();
  await expect(page.locator("body")).not.toContainText(
    firstKey ?? "missing-key",
  );
  expect(await page.evaluate(() => localStorage.length)).toBe(0);
  expect(await page.evaluate(() => sessionStorage.length)).toBe(0);

  await page.getByRole("button", { name: "Create another key" }).click();
  const secondKey = await page.getByTestId("ingest-key").textContent();
  expect(secondKey).toMatch(/^clpk_[a-f0-9]{64}$/);
  expect(secondKey).not.toBe(firstKey);

  for (const key of [firstKey, secondKey]) {
    const response = await page.request.post(`${ingestUrl}/u/${key}`);
    expect(response.status()).toBe(400);
  }

  const projectId = new URL(page.url()).searchParams.get("project");
  const controlResponse = await page.request.get(
    `${apiUrl}/api/v1/projects/${projectId}/setup`,
    { headers: { authorization: `Bootstrap ${secondKey}` } },
  );
  expect(controlResponse.status()).toBe(401);

  await page.getByRole("link", { name: "Manage project setup" }).click();
  const rows = page.locator(".key-row");
  await expect(rows).toHaveCount(2);
  await rows.first().getByRole("button", { name: "Revoke" }).click();
  await expect(
    rows.first().getByText("Revoked", { exact: true }),
  ).toBeVisible();

  const revokedResponse = await page.request.post(`${ingestUrl}/u/${firstKey}`);
  expect(revokedResponse.status()).toBe(404);
  const activeResponse = await page.request.post(`${ingestUrl}/u/${secondKey}`);
  expect(activeResponse.status()).toBe(400);

  await page.goto(`/projects/${projectId}`);
  await expect(
    page.getByRole("heading", { name: "Crash and project alerts" }),
  ).toBeVisible();
  await page.getByLabel("Name").fill("Browser proof email");
  await page.getByRole("button", { name: "Add destination" }).click();
  await expect(page.getByText("Browser proof email created.")).toBeVisible();
  await page
    .getByLabel("Destination")
    .selectOption({ label: "Browser proof email" });
  await page.getByRole("button", { name: "Add rule" }).click();
  await expect(page.getByText("first seen rule created.")).toBeVisible();
  const alertRows = page.locator(".alerts-settings table tbody tr");
  await expect(alertRows).toHaveCount(2);
  await alertRows.first().getByRole("button", { name: "Disable" }).click();
  await expect(
    alertRows.first().getByRole("button", { name: "Enable" }),
  ).toBeVisible();
});
