import { expect, test, type Page } from "@playwright/test";

import { installMockApi, mockSnapshotFixture, type RecordedApiRequest } from "../fixtures/mockApi";
import { pathForRoute, type Tab } from "../../src/routes";

const views: Tab[] = ["overview", "transfers", "search", "sharing", "shared-files", "uploads", "network", "servers", "kad", "categories", "friends", "settings", "diagnostics", "logs"];
const headings: Record<Tab, string> = { overview: "Startup & Indexing", transfers: "Transfers", search: "Search", sharing: "Shared Folders",
  "shared-files": "Shared Files", uploads: "Upload Queue Inspector", network: "Network Health", servers: "Servers", kad: "Kad",
  categories: "Categories", friends: "Friends", settings: "Settings", diagnostics: "Diagnostics", logs: "Logs" };
const nightlyVersion = "0.1.0-beta.2.nightly.20261114.g00112233";

async function noPageOverflow(page: Page) {
  await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1)).toBe(true);
}

test.beforeEach(async ({ page }) => {
  await page.addInitScript(() => sessionStorage.setItem("emulebb.webui.apiKey", "sample-key"));
});

for (const width of [320, 390, 768, 1280]) {
  test(`all fourteen views keep page overflow local at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 844 });
    const requests: RecordedApiRequest[] = [];
    const mock = installMockApi(requests);
    await page.route("**/api/v1/**", async (route) => {
      const path = new URL(route.request().url()).pathname;
      if (path === "/api/v1/app") {
        await route.fulfill({ json: { data: { name: "eMuleBB", version: nightlyVersion, channel: "nightly", capabilities: {} } } });
      } else if (path === "/api/v1/snapshot") {
        const state = mockSnapshotFixture();
        state.app.version = nightlyVersion;
        state.transfers[0].displayName = "Sample-" + "long-filename-segment-".repeat(18) + ".bin";
        await route.fulfill({ json: { data: state } });
      } else await mock(route);
    });
    for (const view of views) {
      await page.goto(pathForRoute({ tab: view }));
      await expect(page.getByRole("heading", { name: headings[view], exact: true })).toBeVisible();
      await expect(page.getByRole("button", { name: "Download: 2.0 KiB/s", exact: true })).toBeVisible();
      await noPageOverflow(page);
      if (width < 640) {
        await expect(page.getByRole("button", { name: "Menu", exact: true })).toHaveAttribute("aria-expanded", "false");
        await expect(page.getByRole("navigation", { name: "Primary views" })).toBeHidden();
      } else {
        await expect(page.getByRole("navigation", { name: "Primary views" })).toBeVisible();
        await expect(page.getByRole("button", { name: "Menu", exact: true })).toBeHidden();
      }
    }
  });
}

test("mobile menu closes for every link, current view, Escape, history, shortcuts and breakpoint changes", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.route("**/api/v1/**", installMockApi([]));
  await page.goto("/");
  const menu = page.getByRole("button", { name: "Menu", exact: true });
  const navigation = page.getByRole("navigation", { name: "Primary views" });
  for (const index of Array.from({ length: 14 }, (_, value) => value)) {
    await menu.click();
    await expect(navigation.getByRole("link")).toHaveCount(14);
    const link = navigation.getByRole("link").nth(index);
    const label = await link.innerText();
    await link.click();
    await expect(menu).toHaveAttribute("aria-expanded", "false");
    await expect(page.locator(".mobile-menu-bar strong")).toHaveText(label.trim());
  }
  await menu.click();
  await navigation.getByRole("link", { name: "Logs", exact: true }).click();
  await expect(menu).toHaveAttribute("aria-expanded", "false");
  await menu.click();
  await page.getByRole("combobox", { name: "Appearance" }).focus();
  await page.keyboard.press("Escape");
  await expect(menu).toBeFocused();
  await expect(navigation).toBeHidden();
  await menu.click();
  await page.goBack();
  await expect(menu).toHaveAttribute("aria-expanded", "false");
  await menu.click();
  await page.getByRole("button", { name: "Server: HighID", exact: true }).click();
  await expect(menu).toHaveAttribute("aria-expanded", "false");
  await menu.click();
  await page.setViewportSize({ width: 768, height: 844 });
  await expect(navigation).toBeVisible();
  await page.setViewportSize({ width: 390, height: 844 });
  await expect(navigation).toBeHidden();
  await expect(menu).toHaveAttribute("aria-expanded", "false");
});

test("appearance works while locked, follows System and persists explicit overrides", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.emulateMedia({ colorScheme: "dark" });
  await page.addInitScript(() => sessionStorage.clear());
  await page.route("**/api/v1/**", installMockApi([]));
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Connect to the local daemon" })).toBeVisible();
  const appearance = page.getByRole("combobox", { name: "Appearance" });
  await expect(appearance).toHaveValue("system");
  await expect(page.locator("html")).toHaveAttribute("data-bs-theme", "dark");
  await page.emulateMedia({ colorScheme: "light" });
  await expect(page.locator("html")).toHaveAttribute("data-bs-theme", "light");
  await appearance.selectOption("dark");
  await page.emulateMedia({ colorScheme: "light" });
  await expect(page.locator("html")).toHaveAttribute("data-bs-theme", "dark");
  await page.reload();
  await expect(appearance).toHaveValue("dark");
  await expect(page.locator("html")).toHaveAttribute("data-bs-theme", "dark");
  await appearance.selectOption("light");
  await page.emulateMedia({ colorScheme: "dark" });
  await expect(page.locator("html")).toHaveAttribute("data-bs-theme", "light");
  await page.getByLabel("API key", { exact: true }).fill("sample-key");
  await page.getByRole("button", { name: "Connect", exact: true }).click();
  await expect(page.getByRole("button", { name: "Menu", exact: true })).toBeVisible();
  await expect(appearance).toHaveValue("light");
  await noPageOverflow(page);
});

test("invalid appearance and unavailable storage retain usable session choices", async ({ page }) => {
  await page.route("**/api/v1/**", installMockApi([]));
  await page.addInitScript(() => localStorage.setItem("emulebb.webui.theme", "invalid"));
  await page.emulateMedia({ colorScheme: "dark" });
  await page.goto("/");
  await expect(page.getByRole("combobox", { name: "Appearance" })).toHaveValue("system");
  await expect(page.locator("html")).toHaveAttribute("data-bs-theme", "dark");
  await page.addInitScript(() => Object.defineProperty(window, "localStorage", { get() { throw new Error("Synthetic storage denial"); } }));
  await page.reload();
  await page.getByRole("combobox", { name: "Appearance" }).selectOption("light");
  await expect(page.locator("html")).toHaveAttribute("data-bs-theme", "light");
  await page.emulateMedia({ colorScheme: "dark" });
  await expect(page.locator("html")).toHaveAttribute("data-bs-theme", "light");
});

test("mobile forms, row actions and direct diagnostic buttons preserve request mappings", async ({ page }) => {
  await page.setViewportSize({ width: 320, height: 844 });
  const requests: RecordedApiRequest[] = [];
  await page.route("**/api/v1/**", installMockApi(requests));
  await page.goto("/transfers");
  const table = page.locator(".table-wrap").first();
  await expect(table).toHaveAttribute("tabindex", "0");
  await expect(page.getByText("Swipe horizontally for more columns").first()).toBeVisible();
  await table.focus();
  await page.keyboard.press("ArrowRight");
  await expect.poll(() => table.evaluate((element) => element.scrollLeft)).toBeGreaterThan(0);
  await page.getByTitle("Pause", { exact: true }).click();
  expect(requests.some((request) => request.method === "POST" && request.path.endsWith("/operations/pause"))).toBe(true);
  await page.goto(pathForRoute({ tab: "search" }));
  await page.getByPlaceholder("Search query", { exact: true }).fill("Sample phone query");
  await page.getByRole("button", { name: "Start", exact: true }).click();
  await expect.poll(() => requests.some((request) => request.method === "POST" && request.path === "searches")).toBe(true);
  await page.goto("/settings");
  await page.getByLabel("Incoming directory", { exact: true }).fill("/storage/emulated/0/Download/Sample/Incoming");
  await page.getByRole("button", { name: "Save", exact: true }).click();
  await expect.poll(() => requests.some((request) => request.method === "PATCH" && request.path === "app/settings")).toBe(true);
  await noPageOverflow(page);
  await page.goto("/diagnostics");
  const download = page.waitForEvent("download");
  await page.getByRole("button", { name: "Capture private bundle" }).click();
  expect((await download).suggestedFilename()).toContain("diagnostic-bundle");
  await page.getByRole("button", { name: "Crash test" }).click();
  await page.getByRole("button", { name: "Shutdown", exact: true }).click();
  await expect.poll(() => requests.some((request) => request.method === "POST" && request.path === "app/shutdown")).toBe(true);
  expect(requests.find((request) => request.path === "diagnostics/bundles")?.body).toBe(JSON.stringify({ confirmCapture: true, maxBytes: 16_777_216 }));
  expect(requests.find((request) => request.path === "diagnostics/crash-tests")?.body).toBe(JSON.stringify({ confirmCrash: true }));
});

test("mobile Safari smoke: menu, forms, table scrolling and both appearances", async ({ page }, testInfo) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.route("**/api/v1/**", installMockApi([]));
  await page.route("**/api/v1/app", (route) => route.fulfill({ json: { data: { name: "eMuleBB", version: nightlyVersion, channel: "nightly" } } }));
  await page.goto("/transfers");
  for (const theme of ["light", "dark"]) {
    await page.getByRole("combobox", { name: "Appearance" }).selectOption(theme);
    await expect(page.locator("html")).toHaveAttribute("data-bs-theme", theme);
    await page.getByRole("button", { name: "Menu", exact: true }).click();
    await page.getByRole("navigation", { name: "Primary views" }).getByRole("link", { name: "Sharing", exact: true }).click();
    await page.getByRole("textbox", { name: "Server folder path" }).fill("/storage/emulated/0/Download/Sample/Shared");
    await noPageOverflow(page);
    await expect(page.locator("input").first()).toHaveCSS("font-size", "16px");
    await page.locator(".table-wrap").first().evaluate((element) => { element.scrollLeft = element.scrollWidth; });
    await page.screenshot({ path: testInfo.outputPath(`phone-${theme}.png`), fullPage: true });
    await page.getByRole("button", { name: "Menu", exact: true }).click();
    await page.getByRole("navigation", { name: "Primary views" }).getByRole("link", { name: "Transfers", exact: true }).click();
  }
});

for (const width of [320, 390]) {
  test(`mobile Safari smoke: readable sharing paths and reference screenshots at ${width}px`, async ({ page }, testInfo) => {
    await page.setViewportSize({ width, height: 844 });
    await page.route("**/api/v1/**", installMockApi([]));
    await page.route("**/api/v1/app", (route) => route.fulfill({ json: {
      data: { name: "eMuleBB", version: nightlyVersion, channel: "nightly" }
    } }));
    for (const theme of ["light", "dark"]) {
      await page.goto("/");
      await page.getByRole("combobox", { name: "Appearance" }).selectOption(theme);
      await expect(page.getByRole("button", { name: "Download: 2.0 KiB/s", exact: true })).toBeVisible();
      await noPageOverflow(page);
      await page.screenshot({ path: testInfo.outputPath(`phone-${width}-overview-${theme}.png`), fullPage: true });

      await page.goto("/sharing");
      await expect(page.locator("html")).toHaveAttribute("data-bs-theme", theme);
      const table = page.locator(".root-table");
      const path = table.locator("tbody tr").first().locator("td").first();
      const scroll = page.getByRole("region", { name: "Shared folders", exact: true });
      await expect(path).toHaveText("C:\\Sample\\Shared");
      await expect.poll(() => path.evaluate((element) => element.getBoundingClientRect().width)).toBeGreaterThanOrEqual(160);
      await expect.poll(() => scroll.evaluate((element) => element.scrollWidth > element.clientWidth)).toBe(true);
      await expect(scroll.locator("..").getByText("Swipe horizontally for more columns")).toBeVisible();
      await noPageOverflow(page);
      await page.screenshot({ path: testInfo.outputPath(`phone-${width}-sharing-${theme}.png`), fullPage: true });

      await scroll.focus();
      await page.keyboard.press("ArrowRight");
      await expect.poll(() => scroll.evaluate((element) => element.scrollLeft)).toBeGreaterThan(0);
      const action = table.getByTitle("Remove", { exact: true }).first();
      await action.focus();
      await expect(action).toBeFocused();
      await expect.poll(() => action.evaluate((element) => {
        const button = element.getBoundingClientRect();
        const container = element.closest(".table-wrap")!.getBoundingClientRect();
        return button.left >= container.left - 1 && button.right <= container.right + 1;
      })).toBe(true);
      await noPageOverflow(page);
    }
  });
}
