import { defineConfig, devices } from "@playwright/test";

const webHost = process.env.X_LOCAL_IP || "127.0.0.1";
const webPort = 4174;
const webUrl = `http://${webHost}:${webPort}`;

export default defineConfig({
  testDir: "tests/e2e",
  outputDir: "test-results",
  reporter: [["list"]],
  use: {
    baseURL: webUrl,
    trace: "retain-on-failure"
  },
  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] }
    }
  ],
  webServer: {
    command: "node tests/e2e/serve.mjs",
    url: webUrl,
    reuseExistingServer: !process.env.CI,
    stdout: "pipe",
    stderr: "pipe"
  }
});
