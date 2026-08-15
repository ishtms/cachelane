import { expect, test } from "@playwright/test";

test("creates a project and manages one-time ingest keys", async ({ page }) => {
  const apiUrl = process.env.FAULTLANE_API_URL ?? "http://127.0.0.1:8080";
  const ingestUrl = process.env.FAULTLANE_INGEST_URL ?? "http://127.0.0.1:8081";

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
});
