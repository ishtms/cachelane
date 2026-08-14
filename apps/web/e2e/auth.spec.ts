import { createServer, type Server } from "node:http";

import { expect, test } from "@playwright/test";

const deliveryPort = Number(process.env.FAULTLANE_TEST_EMAIL_PORT ?? "39010");
const deliveries: string[] = [];
let deliveryServer: Server;

test.beforeAll(async () => {
  deliveryServer = createServer((request, response) => {
    if (
      request.method !== "POST" ||
      request.url !== "/deliver" ||
      request.headers.authorization !== "Bearer browser-email-secret"
    ) {
      response.writeHead(404).end();
      return;
    }
    const chunks: Buffer[] = [];
    request.on("data", (chunk: Buffer) => chunks.push(chunk));
    request.on("end", () => {
      const body = JSON.parse(Buffer.concat(chunks).toString("utf8")) as {
        sign_in_url?: string;
      };
      if (!body.sign_in_url) {
        response.writeHead(400).end();
        return;
      }
      deliveries.push(body.sign_in_url);
      response.writeHead(202).end();
    });
  });
  await new Promise<void>((resolve, reject) => {
    deliveryServer.once("error", reject);
    deliveryServer.listen(deliveryPort, "127.0.0.1", resolve);
  });
});

test.afterAll(async () => {
  await new Promise<void>((resolve, reject) => {
    deliveryServer.close((error) => (error ? reject(error) : resolve()));
  });
});

test("signs in, invites a viewer, changes the role, and revokes access", async ({
  browser,
  page,
}) => {
  await page.goto("/setup");
  await page.getByLabel("Owner email").fill("owner@example.com");
  await page.getByLabel("Organization name").fill("Example Studio");
  await page.getByLabel("Organization slug").fill("example-studio");
  await page.getByLabel("Project name").fill("Windows Game");
  await page.getByLabel("Project slug").fill("windows-game");
  await page.getByRole("button", { name: "Create project" }).click();
  await expect(
    page.getByRole("heading", { name: "Save this key now" }),
  ).toBeVisible();

  await page.goto("/sign-in");
  const ownerDelivery = deliveries.length;
  await page.getByLabel("Email address").fill("owner@example.com");
  await page.getByRole("button", { name: "Email me a sign-in link" }).click();
  await expect(
    page.getByRole("heading", { name: "Check your email" }),
  ).toBeVisible();
  await expect.poll(() => deliveries.length).toBe(ownerDelivery + 1);
  await page.goto(deliveries[ownerDelivery]);
  await expect
    .poll(async () =>
      (await page.context().cookies()).some(
        (cookie) => cookie.name === "faultlane_session",
      ),
    )
    .toBe(true);
  await expect(page).toHaveURL(/\/account$/);
  await expect(
    page.getByRole("heading", { name: "owner@example.com" }),
  ).toBeVisible();
  await expect(page.getByText("Example Studio · owner")).toBeVisible();

  const invitationDelivery = deliveries.length;
  const invitationForm = page.locator("form.account-invite");
  await invitationForm.getByLabel("Email address").fill("viewer@example.com");
  await invitationForm.locator('select[name="role"]').selectOption("viewer");
  await invitationForm.getByRole("button", { name: "Send invitation" }).click();
  await expect.poll(() => deliveries.length).toBe(invitationDelivery + 1);

  const invitedContext = await browser.newContext({
    baseURL: process.env.FAULTLANE_WEB_URL ?? "http://127.0.0.1:3000",
  });
  const invitedPage = await invitedContext.newPage();
  await invitedPage.goto(deliveries[invitationDelivery]);
  await expect(
    invitedPage.getByRole("heading", { name: "viewer@example.com" }),
  ).toBeVisible();
  await expect(invitedPage.getByText("Example Studio · viewer")).toBeVisible();
  await expect(
    invitedPage.getByRole("heading", { name: "Add a teammate" }),
  ).toHaveCount(0);

  await page.reload();
  const viewerRow = page
    .getByRole("row")
    .filter({ hasText: "viewer@example.com" });
  await viewerRow
    .getByLabel("Role for viewer@example.com")
    .selectOption("developer");
  const roleResponse = page.waitForResponse(
    (response) =>
      response.request().method() === "POST" &&
      new URL(response.url()).pathname === "/account",
  );
  await viewerRow.getByRole("button", { name: "Update" }).click();
  expect((await roleResponse).ok()).toBe(true);
  await page.reload();
  await expect(viewerRow.getByLabel("Role for viewer@example.com")).toHaveValue(
    "developer",
  );

  await invitedPage.reload();
  await expect(
    invitedPage.getByText("Example Studio · developer"),
  ).toBeVisible();

  const removalResponse = page.waitForResponse(
    (response) =>
      response.request().method() === "POST" &&
      new URL(response.url()).pathname === "/account",
  );
  await page
    .getByRole("row")
    .filter({ hasText: "viewer@example.com" })
    .getByRole("button", { name: "Remove" })
    .click();
  expect((await removalResponse).ok()).toBe(true);
  await page.reload();
  await expect(page.getByText("viewer@example.com")).toHaveCount(0);
  await invitedPage.reload();
  await expect(invitedPage).toHaveURL(/\/account/);
  await expect(
    invitedPage.getByText("Accept an invitation to join an organization."),
  ).toBeVisible();

  await invitedContext.close();
});
