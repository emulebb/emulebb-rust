import { expect, test } from "@playwright/test";

import { installMockApi, type RecordedApiRequest } from "../fixtures/mockApi";

test.beforeEach(async ({ page }) => {
  await page.addInitScript(() => window.localStorage.clear());
});

test("loads mocked dashboard data and navigates primary views", async ({ page }) => {
  const requests: RecordedApiRequest[] = [];
  await page.route("**/api/v1/**", installMockApi(requests));

  await page.goto("/");

  await expect(page.getByRole("heading", { name: "eMuleBB WebUI" })).toBeVisible();
  await expect(page.getByText("0.1.0-beta.1")).toBeVisible();
  await expect(page.getByText("Sample Transfer.bin")).toBeVisible();
  await expect(page.locator("strong").filter({ hasText: /^Connected$/ })).toBeVisible();

  await page.getByRole("button", { name: "Transfers" }).click();
  await expect(page.getByRole("heading", { name: "Transfers" })).toBeVisible();
  await expect(page.locator("tr", { hasText: "Sample Transfer.bin" }).locator("select")).toHaveValue("1");
  await expect(page.getByText("Sample Peer")).toBeVisible();

  await page.getByRole("button", { name: "Sharing" }).click();
  await expect(page.getByRole("heading", { name: "Shared Folders" })).toBeVisible();
  await expect(page.getByRole("cell", { name: "C:\\Sample\\Shared", exact: true })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Reload Progress" })).toBeVisible();
  await expect(page.getByRole("paragraph").filter({ hasText: "C:\\Sample\\Shared\\Hashing Now.bin" })).toBeVisible();
  await expect(page.getByRole("cell", { name: "C:\\Sample\\Shared\\Queued Next.bin", exact: true })).toBeVisible();

  expect(requests.some((request) => request.path === "snapshot")).toBe(true);
});

test("persists the API key and sends it on later API requests", async ({ page }) => {
  const requests: RecordedApiRequest[] = [];
  await page.route("**/api/v1/**", installMockApi(requests));

  await page.goto("/");
  await expect(page.getByText("Sample Transfer.bin")).toBeVisible();

  await page.getByPlaceholder("X-API-Key").fill("sample-key");
  await page.getByRole("button", { name: "Save" }).click();
  await expect(page.getByText("API key saved")).toBeVisible();
  await page.getByTitle("Refresh").click();

  await expect
    .poll(() => requests.some((request) => request.headers["x-api-key"] === "sample-key"))
    .toBe(true);

  await page.getByTitle("Clear API key").click();
  await expect(page.getByText("API key cleared")).toBeVisible();
});

test("submits a synthetic transfer operation", async ({ page }) => {
  const requests: RecordedApiRequest[] = [];
  await page.route("**/api/v1/**", installMockApi(requests));

  await page.goto("/");
  await page.getByRole("button", { name: "Transfers" }).click();
  await expect(page.getByRole("heading", { name: "Transfers" })).toBeVisible();

  await page.getByTitle("Pause").click();
  await expect(page.getByText("Transfer paused")).toBeVisible();

  expect(
    requests.some(
      (request) =>
        request.method === "POST" &&
        request.path === "transfers/00112233445566778899AABBCCDDEEFF/operations/pause"
    )
  ).toBe(true);
});

test("settings use dirty state and advanced surface metadata", async ({ page }) => {
  const requests: RecordedApiRequest[] = [];
  await page.route("**/api/v1/**", installMockApi(requests));

  await page.goto("/");
  await page.getByRole("button", { name: "Settings" }).click();
  const settingsPanel = page.locator("section.panel").filter({ has: page.getByRole("heading", { name: "Settings" }) });

  await expect(settingsPanel.getByRole("heading", { name: "Storage" })).toBeVisible();
  await expect(settingsPanel.getByRole("heading", { name: "Transfers" })).toBeVisible();
  await expect(settingsPanel.getByRole("heading", { name: "Network" })).toBeVisible();
  await expect(settingsPanel.getByRole("heading", { name: "VPN Guard" })).toBeVisible();

  await expect(settingsPanel.getByText("Max connections")).toHaveCount(0);
  await expect(settingsPanel.getByText("Server connect timeout seconds")).toHaveCount(0);
  await settingsPanel.getByLabel(/Advanced/).check();
  await expect(settingsPanel.getByLabel("Max connections")).toBeVisible();
  await expect(settingsPanel.getByLabel("Server connect timeout seconds")).toBeVisible();

  const save = settingsPanel.getByRole("button", { name: "Save" });
  const revert = settingsPanel.getByRole("button", { name: "Revert" });
  await expect(save).toBeDisabled();
  await expect(revert).toBeDisabled();

  await settingsPanel.getByLabel("eD2K listen port").fill("70000");
  await expect(settingsPanel.getByText("eD2K listen port must be between 1 and 65535.")).toBeVisible();
  await expect(save).toBeDisabled();
  await settingsPanel.getByLabel("eD2K listen port").fill("4662");
  await expect(settingsPanel.getByText("eD2K listen port must be between 1 and 65535.")).toHaveCount(0);

  await settingsPanel.getByLabel("Incoming directory").fill("C:\\Changed\\Incoming");
  await expect(save).toBeEnabled();
  await expect(revert).toBeEnabled();

  await revert.click();
  await expect(settingsPanel.getByLabel("Incoming directory")).toHaveValue("C:\\Sample\\Incoming");
  await expect(save).toBeDisabled();

  await settingsPanel.getByLabel("Incoming directory").fill("C:\\Changed\\Incoming");
  await save.click();
  await expect(page.getByText("Settings saved; restart daemon for bind, port, NAT, VPN, and filter changes")).toBeVisible();
  expect(requests.some((request) => request.method === "PATCH" && request.path === "app/settings")).toBe(true);

  await settingsPanel.getByRole("button", { name: "Open Diagnostics" }).click();
  await expect(page.getByRole("heading", { name: "Diagnostics" })).toBeVisible();
});
