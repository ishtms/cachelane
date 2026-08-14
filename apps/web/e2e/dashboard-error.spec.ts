import { expect, test } from "@playwright/test";

test("distinguishes an unavailable API from a missing project", async ({
  page,
}) => {
  const projectId = process.env.FAULTLANE_PROOF_PROJECT_ID;
  if (!projectId) throw new Error("FAULTLANE_PROOF_PROJECT_ID is required");

  await page.goto(`/projects/${projectId}`);
  const alert = page.locator("section[role='alert']");
  await expect(alert).toBeVisible();
  await expect(
    alert.getByRole("heading", { name: "The dashboard is unavailable." }),
  ).toBeVisible();
  await expect(alert).toContainText("could not reach the control API");
  await expect(alert.getByRole("link", { name: "Try again" })).toHaveAttribute(
    "href",
    ".",
  );
});
