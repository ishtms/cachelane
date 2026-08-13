import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./e2e",
  outputDir: "../../target/playwright-results",
  timeout: 30_000,
  use: {
    baseURL: process.env.CACHELANE_WEB_URL ?? "http://127.0.0.1:3000",
    channel: "chrome",
  },
});
