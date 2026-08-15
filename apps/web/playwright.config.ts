import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./e2e",
  outputDir:
    process.env.FAULTLANE_PLAYWRIGHT_OUTPUT_DIR ??
    "../../target/playwright-results",
  timeout: 30_000,
  use: {
    baseURL: process.env.FAULTLANE_WEB_URL ?? "http://127.0.0.1:3000",
    channel: "chrome",
  },
});
