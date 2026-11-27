import { expect, test, type Page } from "@playwright/test";
import type { DownloadSummary, SearchItem, SearchResult } from "../../src/api";
import { installMockApi, mockDownloadFixture, type RecordedApiRequest } from "../fixtures/mockApi";

const meta = { apiVersion: "2.0.0", nextCursor: null, hasMore: false };
const hash = "00112233445566778899aabbccddeeff";

async function expectNoOverflow(page: Page) {
  await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1)).toBe(true);
}

for (const width of [320, 390]) {
  test(`phone workflow opens Downloads, confirms handoff and controls jobs at ${width}px`, async ({ page }, testInfo) => {
    await page.setViewportSize({ width, height: 640 });
    await page.clock.install();
    const link = `ed2k://|file|Sample.bin|42|${hash}|/`;
    const requests: RecordedApiRequest[] = [];
    const mock = installMockApi(requests);
    let job: DownloadSummary = { ...mockDownloadFixture()[0], name: "Sample-" + "long-name-".repeat(24) + ".bin" };
    let detailsReads = 0;
    const controls: string[] = [];
    await page.route("**/api/v1/**", async (route) => {
      const url = new URL(route.request().url());
      const path = url.pathname.slice("/api/v1/".length);
      if (route.request().method() === "GET" && path === "downloads") {
        return route.fulfill({ json: { data: [job], meta: { ...meta, nextCursor: url.searchParams.has("cursor") ? null : "next-jobs", hasMore: !url.searchParams.has("cursor") } } });
      }
      if (path === "downloads/1") {
        detailsReads++;
        if (detailsReads === 2) return route.fulfill({ status: 503, json: { error: { message: "Details temporarily unavailable" } } });
        return route.fulfill({ json: { data: { ...job, payloadVerified: false, delivery: null, failure: null } } });
      }
      if (path === "downloads/stop" || path === "downloads/start") {
        controls.push(path);
        job = path === "downloads/stop" ? { ...job, intent: "stopped", state: "stopped", waitingReason: null }
          : { ...job, intent: "started", state: "downloading", waitingReason: null };
        return route.fulfill({ json: { data: [{ id: job.id, status: "accepted" }] } });
      }
      return mock(route);
    });
    await page.goto("/");
    await expect(page).toHaveURL("/mobile");
    const suffix = `?from=phone#ed2k=${encodeURIComponent(link)}`;
    await page.goto(`/downloads${suffix}`);
    await expect(page).toHaveURL(`/mobile${suffix}`);
    await expect(page.getByRole("heading", { name: "Connect to the local daemon" })).toBeVisible();
    await expect(page.getByRole("navigation", { name: "Mobile views" })).toHaveCount(0);
    await page.getByLabel("API key", { exact: true }).fill("sample-key");
    await page.getByRole("button", { name: "Connect", exact: true }).click();
    const input = page.getByRole("textbox", { name: "eD2K links" });
    await expect(input).toHaveValue(link);
    expect(requests.some((request) => request.method === "POST" && request.path === "downloads")).toBe(false);
    await page.getByRole("button", { name: "Queue links" }).click();
    await expect.poll(() => requests.find((request) => request.method === "POST" && request.path === "downloads")?.body).toContain(link);
    await expect(page).toHaveURL("/mobile?from=phone");
    await expect(input).toHaveCount(0);
    await expectNoOverflow(page);
    await page.screenshot({ path: testInfo.outputPath("phone-downloads.png") });
    await page.getByRole("button", { name: "Stop", exact: true }).click();
    await page.getByRole("button", { name: "Start", exact: true }).click();
    await expect(page.getByRole("button", { name: "Stop", exact: true })).toBeVisible();
    expect(controls).toEqual(["downloads/stop", "downloads/start"]);
    await page.getByRole("button", { name: job.name, exact: true }).click();
    const details = page.getByRole("dialog", { name: "Download details" });
    await expect(details.getByText(job.name, { exact: true })).toBeVisible();
    await page.clock.fastForward(10_000);
    await expect(details.locator(".update-warning")).toContainText("Details temporarily unavailable");
    await expect(details.getByText(job.name, { exact: true })).toBeVisible();
    await details.getByRole("button", { name: "Close" }).click();
    await expect(details).toHaveCount(0);
    await page.getByRole("button", { name: "Next page" }).click();
    await expect(page.getByRole("button", { name: "First page" })).toBeEnabled();
  });

  test(`phone workflow searches, queues results, and switches layouts at ${width}px`, async ({ page }, testInfo) => {
    await page.setViewportSize({ width, height: 600 });
    await page.addInitScript(() => sessionStorage.setItem("emulebb.webui.apiKey", "sample-key"));
    await page.clock.install();
    const mock = installMockApi([]);
    const entries: SearchItem[] = [{ id: "7", query: "Existing search", status: "completed", resultCount: 12 }];
    const results: SearchResult[] = Array.from({ length: 12 }, (_, index) => ({
      id: String(index + 1), hash: index.toString(16).padStart(32, "0"), displayName: `Sample result ${index + 1}`, sizeBytes: 1024, sources: 6
    }));
    let searchBody: unknown;
    let resultReads = 0;
    let holdResult = () => {};
    let finishQueue: (() => void) | undefined;
    await page.route("**/api/v1/**", async (route) => {
      const url = new URL(route.request().url());
      const path = url.pathname.slice("/api/v1/".length);
      if (path === "searches") {
        if (route.request().method() === "POST") {
          searchBody = route.request().postDataJSON();
          const created: SearchItem = { id: "8", query: "Phone search", status: "running", resultCount: 12 };
          if (!entries.some((entry) => entry.id === created.id)) entries.unshift(created);
          return route.fulfill({ json: { data: created } });
        }
        return route.fulfill({ json: { data: entries, meta } });
      }
      if (/^searches\/[78]$/.test(path)) return route.fulfill({ json: { data: entries.find((item) => item.id === path.at(-1)) } });
      if (/^searches\/[78]\/results$/.test(path)) {
        if (path === "searches/7/results" && ++resultReads === 2) {
          await new Promise<void>((resolve) => { holdResult = resolve; });
          return route.fulfill({ status: 503, json: { error: { message: "Results temporarily unavailable" } } });
        }
        return route.fulfill({ json: { data: url.searchParams.has("cursor") ? results.slice(0, 1) : results,
          meta: { ...meta, nextCursor: url.searchParams.has("cursor") ? null : "next-results" } } });
      }
      if (path === "searches/7/results/8/download") {
        await new Promise<void>((resolve) => { finishQueue = resolve; });
        return route.fulfill({ status: 201, json: { data: { ...mockDownloadFixture()[0], hash: results[7].hash } } });
      }
      return mock(route);
    });
    await page.goto("/searches/7?source=phone");
    await expect(page).toHaveURL("/mobile/searches/7?source=phone");
    const nav = page.getByRole("navigation", { name: "Mobile views" });
    await expect(nav.getByRole("link", { name: "Search" })).toHaveAttribute("aria-current", "page");
    const card = page.getByRole("article").filter({ hasText: "Sample result 8" });
    await card.scrollIntoViewIfNeeded();
    const scroll = await page.evaluate(() => window.scrollY);
    await page.clock.fastForward(10_000);
    await expect.poll(() => resultReads).toBe(2);
    await expect(card).toBeVisible();
    holdResult();
    await expect(page.locator(".update-warning").filter({ hasText: "Results temporarily unavailable" })).toBeVisible();
    expect(await page.evaluate(() => window.scrollY)).toBe(scroll);
    await card.getByRole("button", { name: "Download", exact: true }).click();
    await expect(card.getByRole("button", { name: "Queuing…" })).toBeDisabled();
    await expect.poll(() => Boolean(finishQueue)).toBe(true);
    finishQueue?.();
    await expect(card.getByText("Queued", { exact: true })).toBeVisible();
    await page.screenshot({ path: testInfo.outputPath("phone-search.png") });
    await nav.getByRole("link", { name: "Downloads" }).click();
    await expect(page).toHaveURL("/mobile");
    await page.goBack();
    await expect(card.getByText("Queued", { exact: true })).toBeVisible();
    await page.getByRole("button", { name: "Next page" }).click();
    await expect(page.getByRole("button", { name: "First page" })).toBeEnabled();
    await page.getByText("Search options", { exact: true }).click();
    await page.getByRole("combobox", { name: "Method", exact: true }).selectOption("kad");
    await page.getByRole("combobox", { name: "File type", exact: true }).selectOption("audio");
    await page.getByRole("searchbox", { name: "Search query" }).fill("Phone search");
    await page.getByRole("button", { name: "Search", exact: true }).click();
    await expect(page).toHaveURL("/mobile/searches/8");
    expect(searchBody).toEqual({ query: "Phone search", method: "kad", type: "audio" });
    await expectNoOverflow(page);
    await nav.getByRole("link", { name: "More" }).click();
    await page.getByRole("combobox", { name: "Appearance", exact: true }).selectOption("dark");
    await expect(page.locator("html")).toHaveAttribute("data-bs-theme", "dark");
    await expect(page.getByRole("link", { name: "Settings" })).toHaveAttribute("href", "/settings");
    await page.getByRole("link", { name: "Desktop view" }).click();
    await expect(page).toHaveURL("/searches/8");
    await expect(page.locator("table.search-results-table")).toBeVisible();
    await page.reload();
    await expect(page).toHaveURL("/searches/8");
    await expect(page.locator("table.search-results-table")).toBeVisible();
    await page.goto("/mobile/more");
    await expect(page.getByRole("combobox", { name: "Appearance", exact: true })).toHaveValue("dark");
    await page.getByRole("button", { name: "Log out" }).click();
    await expect(page.getByRole("heading", { name: "Connect to the local daemon" })).toBeVisible();
    expect(await page.evaluate(() => sessionStorage.getItem("emulebb.webui.apiKey"))).toBeNull();
  });
}
