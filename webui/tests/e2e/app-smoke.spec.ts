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
