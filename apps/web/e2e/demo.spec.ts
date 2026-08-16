import { expect, test } from "@playwright/test";

test("browses only the synthetic read-only crash demo", async ({ page }) => {
  const unexpectedRequests: string[] = [];
  const baseOrigin = new URL(
    process.env.FAULTLANE_WEB_URL ?? "http://127.0.0.1:3000",
  ).origin;
  page.on("request", (request) => {
    const url = request.url();
    if (url.startsWith("http") && new URL(url).origin !== baseOrigin) {
      unexpectedRequests.push(url);
    }
  });

  await page.goto("/demo");
  await expect(
    page.getByRole("heading", { name: "FaultLane UE 5.8 crash demo" }),
  ).toBeVisible();
  await expect(page.getByText("Synthetic UE 5.8 data")).toBeVisible();
  await expect(page.getByText("Read-only", { exact: true })).toBeVisible();
  await expect(
    page.getByRole("heading", { name: "Grouped crash issues" }),
  ).toBeVisible();
  await expect(page.locator("tbody .issue-link").first()).toBeVisible();
  await page.locator("tbody .issue-link").first().click();

  await expect(page).toHaveURL(/\/demo\/issues\/1-[a-f0-9]{64}$/);
  await expect(
    page.getByRole("heading", { name: "Symbolicated stack" }),
  ).toBeVisible();
  await expect(page.locator(".stack-table tbody tr").first()).toBeVisible();
  await expect(page.getByRole("heading", { name: "Releases" })).toBeVisible();
  await expect(
    page.getByRole("heading", { name: "Missing symbols" }),
  ).toBeVisible();

  const content = await page.content();
  for (const excluded of [
    "private-object-key",
    "raw.bundle",
    "UEMinidump.dmp",
    "Project.log",
    "clpk_",
    "clsu_",
    "C:\\",
  ]) {
    expect(content).not.toContain(excluded);
  }
  expect(await page.locator("form").count()).toBe(0);
  expect(await page.getByRole("button").count()).toBe(0);
  expect(
    await page.locator('a[download], a[href*="/raw"], a[href*="/log"]').count(),
  ).toBe(0);
  expect(await page.evaluate(() => localStorage.length)).toBe(0);
  expect(await page.evaluate(() => sessionStorage.length)).toBe(0);
  expect(unexpectedRequests).toEqual([]);

  const blockedSetup = await page.request.get("/setup");
  expect(blockedSetup.status()).toBe(404);
  const blockedMutation = await page.request.post("/setup", {
    data: {
      owner_email: "public@example.invalid",
      organization_name: "Public",
      organization_slug: "public",
      project_name: "Public",
      project_slug: "public",
    },
  });
  expect(blockedMutation.status()).toBe(404);
  const blockedIngest = await page.request.post("/u/not-a-project-key", {
    data: "synthetic",
  });
  expect(blockedIngest.status()).toBe(404);

  await page.setViewportSize({ width: 390, height: 844 });
  await page.reload();
  const layout = await page.evaluate(() => ({
    documentWidth: document.documentElement.scrollWidth,
    elements: Array.from(
      document.querySelectorAll<HTMLElement>(
        ".dashboard-main, .nav, .issue-header, .metric-grid, .dashboard-panel, .demo-thread, .table-scroll, .stack-table, .dashboard-grid",
      ),
    ).map((element) => ({
      className: element.className,
      clientWidth: element.clientWidth,
      overflowX: getComputedStyle(element).overflowX,
      rect: element.getBoundingClientRect().toJSON(),
      scrollWidth: element.scrollWidth,
    })),
    viewportWidth: window.innerWidth,
  }));
  expect(
    layout.documentWidth,
    JSON.stringify(layout, null, 2),
  ).toBeLessThanOrEqual(layout.viewportWidth);
});
