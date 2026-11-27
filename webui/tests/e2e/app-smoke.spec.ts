import { expect, test } from "@playwright/test";

import { installMockApi, mockDownloadFixture, mockSnapshotFixture, type RecordedApiRequest } from "../fixtures/mockApi";

const longSharedRoot =
  "F:\\Sample\\Shared\\Deep Library Root With Long Name\\Album Archive Segment With A Very Long Folder Name\\Leaf Collection";

test.beforeEach(async ({ page }) => {
  await page.addInitScript(() => {
    window.localStorage.setItem("emulebb.webui.apiKey", "legacy-persistent-key");
    window.sessionStorage.clear();
    window.sessionStorage.setItem("emulebb.webui.apiKey", "sample-key");
  });
});

for (const [width, theme] of [[1280, "light"], [1280, "dark"], [1440, "light"], [1440, "dark"]] as const) {
  test(`desktop workflow tables fit at ${width}px in ${theme} appearance`, async ({ page }, testInfo) => {
    await page.setViewportSize({ width, height: 900 });
    await page.addInitScript((appearance) => localStorage.setItem("emulebb.webui.theme", appearance), theme);
    const mock = installMockApi([]);
    const longName = `Sample-${"long-filename-segment-".repeat(18)}.bin`;
    const jobs = mockDownloadFixture();
    const search = { id: "1", query: "Sample", status: "completed", resultCount: 1 };
    await page.route("**/api/v1/**", (route) => {
      const url = new URL(route.request().url());
      const meta = { apiVersion: "2.0.0", nextCursor: null, hasMore: false };
      switch (url.pathname) {
        case "/api/v1/downloads":
          return route.fulfill({ json: { data: [...jobs, { ...jobs[0], id: "2", name: longName, progress: null }], meta } });
        case "/api/v1/searches":
          return route.fulfill({ json: { data: [search], meta } });
        case "/api/v1/searches/1":
          return route.fulfill({ json: { data: search } });
        case "/api/v1/searches/1/results":
          return route.fulfill({ json: { data: [{ id: "11", hash: jobs[0].hash, displayName: longName, sizeBytes: null }], meta } });
        default:
          return mock(route);
      }
    });
    await page.goto("/downloads");
    await expect(page.locator("html")).toHaveAttribute("data-bs-theme", theme);
    const transfers = page.getByRole("table", { name: "Downloads", exact: true });
    await expect(transfers.getByRole("progressbar")).toBeVisible();
    await expect(transfers.getByText("25.0%")).toBeVisible();
    await expect(transfers.getByRole("row").filter({ hasText: longName }).getByText("Unknown progress", { exact: true })).toBeAttached();
    await expect.poll(() => transfers.locator("tbody tr").first().locator(".row-actions button").evaluateAll((buttons) =>
      new Set(buttons.map((button) => button.getBoundingClientRect().top)).size)).toBe(1);
    await expect.poll(() => transfers.locator("..").evaluate((element) => element.scrollWidth <= element.clientWidth + 1)).toBe(true);
    await page.screenshot({ path: testInfo.outputPath("desktop-transfers.png") });
    await page.getByRole("link", { name: "Search", exact: true }).click();
    const results = page.getByRole("table", { name: "Search results", exact: true });
    await expect(results.getByText(longName)).toBeVisible();
    await expect(results.getByRole("button", { name: "Download", exact: true })).toBeVisible();
    await expect.poll(() => results.locator("..").evaluate((element) => element.scrollWidth <= element.clientWidth + 1)).toBe(true);
    await page.screenshot({ path: testInfo.outputPath("desktop-search.png") });
  });
}

test("Search marks acknowledged downloads across results and clears the label after removal", async ({ page }) => {
  const job = mockDownloadFixture()[0];
  const search = { id: "1", query: "Sample", status: "completed", resultCount: 2 };
  const mock = installMockApi([]);
  let posts = 0;
  let finishDownload = () => {};
  await page.route("**/api/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname.slice("/api/v1/".length);
    const method = route.request().method();
    const pageMeta = { apiVersion: "2.0.0", nextCursor: null, hasMore: false };
    if (path === "searches") return route.fulfill({ json: { data: [search], meta: pageMeta } });
    if (path === "searches/1") return route.fulfill({ json: { data: search } });
    if (path === "searches/1/results") return route.fulfill({ json: {
      data: [
        { id: "11", hash: job.hash, displayName: "Sample result", sizeBytes: job.sizeBytes },
        { id: "12", hash: job.hash.toUpperCase(), displayName: "Other sample result", sizeBytes: job.sizeBytes }
      ],
      meta: pageMeta
    } });
    if (method === "POST" && path === "searches/1/results/11/download") {
      posts++;
      if (posts === 1) return route.fulfill({ status: 503, json: { error: { message: "Temporary download failure" } } });
      if (posts === 2) return route.fulfill({ status: 409, json: {
        error: { code: "LOCAL_CONTENT_CHOICE_REQUIRED", message: "Choose whether to download again" }
      } });
      await new Promise<void>((resolve) => { finishDownload = resolve; });
      return route.fulfill({ status: 201, json: { data: job } });
    }
    if (path === "downloads/remove") return route.fulfill({ json: { data: [{ id: job.id, status: "accepted" }] } });
    return mock(route);
  });
  await page.goto("/searches/1");
  const results = page.getByRole("table", { name: "Search results", exact: true });
  const row = results.getByRole("row").filter({ has: page.getByText("Sample result", { exact: true }) });
  const download = row.getByRole("button", { name: "Download", exact: true });
  await download.click();
  await expect(page.getByText("Temporary download failure")).toBeVisible();
  await expect(download).toBeEnabled();
  page.once("dialog", (dialog) => dialog.dismiss());
  await download.click();
  await expect.poll(() => posts).toBe(2);
  await expect(download).toBeEnabled();
  await download.click();
  await expect.poll(() => posts).toBe(3);
  const pending = results.getByRole("button", { name: "Queuing…" });
  await expect(pending).toHaveCount(2);
  for (const button of await pending.all()) {
    await expect(button).toBeDisabled();
    await button.dispatchEvent("click");
  }
  await expect(results.getByText("Queued", { exact: true })).toHaveCount(0);
  expect(posts).toBe(3);
  finishDownload();
  await expect(results.getByText("Queued", { exact: true })).toHaveCount(2);

  await page.getByRole("link", { name: "Downloads", exact: true }).click();
  await page.getByRole("link", { name: "Search", exact: true }).click();
  await expect(results.getByText("Queued", { exact: true })).toHaveCount(2);
  await page.getByRole("link", { name: "Downloads", exact: true }).click();
  page.once("dialog", (dialog) => dialog.accept());
  await page.getByRole("button", { name: "Remove from list", exact: true }).click();
  await expect(page.getByText("Download removed", { exact: true })).toBeVisible();
  await page.getByRole("link", { name: "Search", exact: true }).click();
  await expect(results.getByRole("button", { name: "Download", exact: true })).toHaveCount(2);
});

test("Search refresh keeps results visible and reads once per cadence despite event bursts", async ({ page }) => {
  const search = { id: "1", query: "Sample", status: "running", resultCount: 2 };
  const results = [
    { id: "11", hash: "11".repeat(16), displayName: "First sample", sizeBytes: 1 },
    { id: "12", hash: "22".repeat(16), displayName: "Second sample", sizeBytes: 2 }
  ];
  const mock = installMockApi([]);
  let resultReads = 0;
  let failRead = () => {};
  let finishRead = () => {};
  await page.route("**/api/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname.slice("/api/v1/".length);
    if (path === "capabilities") return route.fulfill({ json: { data: { capabilities: ["downloads.sse"] } } });
    if (path === "events") {
      return route.fulfill({ contentType: "text/event-stream", body: [1, 2, 3].map((id) =>
        `id: ${id}\ndata: {"type":"updated"}\n\n`).join("") });
    }
    if (path === "searches") return route.fulfill({ json: { data: [search], meta: { nextCursor: null } } });
    if (path === "searches/1") return route.fulfill({ json: { data: search } });
    if (path === "searches/1/results") {
      resultReads++;
      if (resultReads === 2) {
        await new Promise<void>((resolve) => { failRead = resolve; });
        return route.fulfill({ status: 503, json: { error: { message: "Temporary results failure" } } });
      }
      if (resultReads === 3) await new Promise<void>((resolve) => { finishRead = resolve; });
      return route.fulfill({ json: { data: resultReads === 1 ? results : [...results].reverse(), meta: { nextCursor: null } } });
    }
    return mock(route);
  });
  await page.setViewportSize({ width: 1280, height: 560 });
  await page.clock.install();
  const eventResponse = page.waitForResponse((response) => new URL(response.url()).pathname === "/api/v1/events");
  await page.goto("/searches/1");
  const rows = page.getByRole("table", { name: "Search results", exact: true }).locator("tbody tr");
  await expect(rows.first()).toContainText("First sample");
  await rows.first().scrollIntoViewIfNeeded();
  const scrollY = await page.evaluate(() => window.scrollY);
  const rowTop = await rows.first().evaluate((row) => row.getBoundingClientRect().top);
  await (await eventResponse).finished();
  await page.clock.fastForward(6_000);
  expect(resultReads).toBe(1);
  await page.clock.fastForward(4_000);
  await expect.poll(() => resultReads).toBe(2);
  await expect(rows).toHaveCount(2);
  await expect(rows.first()).toContainText("First sample");
  await page.clock.fastForward(10_000);
  expect(resultReads).toBe(2);
  failRead();
  await expect.poll(() => resultReads).toBe(3);
  await expect(page.locator(".update-warning").filter({ hasText: "Temporary results failure" })).toBeVisible();
  expect(await page.evaluate(() => window.scrollY)).toBe(scrollY);
  expect(await rows.first().evaluate((row) => row.getBoundingClientRect().top)).toBe(rowTop);
  await expect(rows.first()).toContainText("First sample");
  finishRead();
  await expect(rows.first()).toContainText("Second sample");
  await expect(page.locator(".update-warning").filter({ hasText: "Temporary results failure" })).toHaveCount(0);
});

test("a background Downloads read failure preserves the selected details and viewport", async ({ page }) => {
  const mock = installMockApi([]);
  let detailReads = 0;
  let fail = () => {};
  await page.route("**/api/v1/**", async (route) => {
    if (new URL(route.request().url()).pathname === "/api/v1/downloads/1" && ++detailReads === 2) {
      await new Promise<void>((resolve) => { fail = resolve; });
      return route.fulfill({ status: 503, json: { error: { message: "Temporary detail failure" } } });
    }
    return mock(route);
  });
  await page.setViewportSize({ width: 1280, height: 560 });
  await page.clock.install();
  await page.goto("/downloads");
  const download = page.getByRole("button", { name: "Sample Transfer.bin", exact: true });
  await download.click();
  const panel = page.locator("section.panel").filter({ has: page.getByRole("heading", { name: "Download details" }) });
  const detail = panel.locator("pre");
  await expect(detail).toContainText("Sample Transfer.bin");
  await detail.scrollIntoViewIfNeeded();
  const scrollY = await page.evaluate(() => window.scrollY);
  const top = await detail.evaluate((element) => element.getBoundingClientRect().top);
  await page.clock.fastForward(10_000);
  await expect.poll(() => detailReads).toBe(2);
  await expect(detail).toContainText("Sample Transfer.bin");
  fail();
  await expect(panel.locator(".update-warning").filter({ hasText: "Temporary detail failure" })).toBeVisible();
  expect(await page.evaluate(() => window.scrollY)).toBe(scrollY);
  expect(await detail.evaluate((element) => element.getBoundingClientRect().top)).toBe(top);
  await expect(page.locator(".selected-row").getByRole("button", { name: "Sample Transfer.bin" })).toBeAttached();
  await page.clock.fastForward(10_000);
  await expect.poll(() => detailReads).toBe(3);
  await expect(panel.locator(".update-warning").filter({ hasText: "Temporary detail failure" })).toHaveCount(0);
});

test("preserves an eD2K handoff through sign-in and requires explicit confirmation", async ({ page }) => {
  const requests: RecordedApiRequest[] = [];
  const link = "ed2k://|file|Sample%20%26%20Guide.bin|42|00112233445566778899aabbccddeeff|/";
  await page.addInitScript(() => window.sessionStorage.clear());
  await page.route("**/api/v1/**", installMockApi(requests));
  await page.goto(`/downloads/#ed2k=${encodeURIComponent(link)}`);
  await expect(page.getByRole("heading", { name: "Connect to the local daemon" })).toBeVisible();
  await expect(page).toHaveURL(/\/downloads#ed2k=/);
  await page.getByLabel("API key", { exact: true }).fill("sample-key");
  await page.getByRole("button", { name: "Connect", exact: true }).click();
  const input = page.getByRole("textbox", { name: "eD2K links" });
  await expect(input).toHaveValue(link);
  expect(requests.some((request) => request.method === "POST" && request.path === "downloads")).toBe(false);
  await page.getByRole("button", { name: "Cancel links" }).click();
  await expect(input).toHaveValue("");
  await expect(page).toHaveURL(/\/downloads$/);
  await page.evaluate((raw) => { window.location.hash = `ed2k=${encodeURIComponent(raw)}`; }, link);
  await expect(input).toHaveValue(link);
  expect(requests.some((request) => request.method === "POST" && request.path === "downloads")).toBe(false);
  await page.getByRole("button", { name: "Add links" }).click();
  await expect.poll(() => requests.filter((request) => request.method === "POST" && request.path === "downloads").length).toBe(1);
  await expect(page).toHaveURL(/\/downloads$/);
  await expect(input).toHaveValue("");
});

test("loads mocked dashboard data and navigates primary views", async ({ page }) => {
  const requests: RecordedApiRequest[] = [];
  await page.route("**/api/v1/**", installMockApi(requests));

  await page.goto("/");

  await expect(page.getByRole("heading", { name: "eMuleBB WebUI" })).toBeAttached();
  await expect.poll(() => page.evaluate(() => window.localStorage.getItem("emulebb.webui.apiKey"))).toBeNull();
  const brand = page.locator("summary", { hasText: "eMuleBB" });
  await brand.click();
  await expect(page.locator(".build-details").getByText("0.1.0-beta.2", { exact: true })).toBeVisible();
  await brand.click();
  await expect(page.getByText("Sample Transfer.bin")).toBeVisible();
  const topbar = page.locator("header .topbar");
  await expect(topbar).toHaveCSS("display", "grid");
  const primaryViews = topbar.getByRole("navigation", { name: "Primary views" });
  await expect(primaryViews.getByRole("link", { name: "Servers", exact: true })).toHaveAccessibleDescription("HighID");
  await expect(primaryViews.getByRole("link", { name: "KAD", exact: true })).toHaveAccessibleDescription("Connected");
  await expect(primaryViews.getByRole("link", { name: "Downloads", exact: true })).toHaveAccessibleDescription("2.0 KiB/s · 1 unfinished");
  await expect(primaryViews.getByRole("link", { name: "Uploads", exact: true })).toHaveAccessibleDescription("1.0 KiB/s");
  await expect(page.getByRole("button", { name: "Refresh", exact: true })).toHaveCount(0);
  const destinations = ["Dashboard", "Search", "Downloads", "Uploads", "Library", "Sharing", "Categories",
    "Friends", "Servers", "KAD", "Network", "Settings", "Logs", "Diagnostics"];
  expect(await primaryViews.getByRole("link").evaluateAll((links) =>
    links.map((link) => link.getAttribute("aria-label")))).toEqual(destinations);
  await expect(page.locator(".page-header")).toHaveCount(0);
  await expect(primaryViews.getByRole("link")).toHaveCount(14);
  await expect(primaryViews.locator("a svg")).toHaveCount(14);
  await expect.poll(async () => topbar.evaluate((element) => {
    const bounds = element.getBoundingClientRect();
    return bounds.width >= window.innerWidth - 32;
  })).toBe(true);
  await expect.poll(async () => {
    return primaryViews.evaluate((element) => element.scrollWidth <= element.clientWidth + 1);
  }).toBe(true);
  await expect.poll(async () => topbar.evaluate((element) => element.scrollWidth <= element.clientWidth + 1)).toBe(true);
  expect(requests.some((request) => request.method === "GET" && request.path === "snapshot")).toBe(true);
  expect(requests.some((request) => request.method === "GET" && request.path === "events/status")).toBe(false);
  expect(requests.some((request) => request.method === "GET" && request.path === "settings")).toBe(false);
  expect(requests.some((request) => request.method === "GET" && request.path.startsWith("upload-queue"))).toBe(false);

  await primaryViews.getByRole("link", { name: "Downloads", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Downloads" })).toBeVisible();
  await expect(page).toHaveURL(/\/downloads$/);
  await expect(page.locator("tr", { hasText: "Sample Transfer.bin" }).locator("select")).toHaveValue("Sample-Category");
  await page.getByRole("button", { name: "Sample Transfer.bin", exact: true }).click();
  await expect(page.getByText("Sample Peer")).toBeVisible();

  await page.getByRole("link", { name: "Sharing" }).click();
  await expect(page.getByRole("heading", { name: "Shared Folders" })).toBeVisible();
  await expect(page).toHaveURL(/\/sharing$/);
  await expect(page.locator("section.metric", { hasText: "Shared Files" }).locator("strong")).toHaveText("1");
  await expect(page.locator("section.metric", { hasText: "Active Uploads" }).locator("strong")).toHaveText("2");
  await expect(page.locator("section.metric", { hasText: "Waiting Uploads" }).locator("strong")).toHaveText("3");
  await expect(page.getByRole("cell", { name: "C:\\Sample\\Shared", exact: true })).toBeVisible();
  await expect(page.getByRole("cell", { name: longSharedRoot, exact: true })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Recursive Coverage" })).toHaveCount(0);
  const sharingPanel = page.locator("section.panel").filter({ has: page.getByRole("heading", { name: "Shared Folders" }) });
  await expect.poll(async () => sharingPanel.evaluate((element) => element.scrollWidth <= element.clientWidth + 1)).toBe(true);
  await expect(page.getByRole("heading", { name: "Reload Progress" })).toBeVisible();
  await expect(page.getByRole("paragraph").filter({ hasText: "C:\\Sample\\Shared\\Hashing Now.bin" })).toBeVisible();
  await expect(page.getByRole("cell", { name: "C:\\Sample\\Shared\\Queued Next.bin", exact: true })).toBeVisible();
  await expect(page.locator("body")).not.toContainText("\\\\?\\");

  expect(requests.some((request) => request.path === "snapshot")).toBe(true);
});

test("shows connecting and connected-with-unknown-ID server states explicitly", async ({ page }) => {
  const requests: RecordedApiRequest[] = [];
  const state: any = mockSnapshotFixture();
  state.status.servers = {
    connected: false,
    connecting: true,
    currentServer: state.status.servers.currentServer,
    ed2kIdState: "unknown",
    serverCount: 1
  };
  state.status.servers.currentServer.connected = false;
  state.status.servers.currentServer.connecting = true;
  const fallback = installMockApi(requests);
  await page.route("**/api/v1/**", async (route) => {
    const url = new URL(route.request().url());
    const path = url.pathname.replace(/^\/api\/v1\/?/, "");
    if (route.request().method() === "GET" && path === "snapshot") {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ data: state })
      });
      return;
    }
    await fallback(route);
  });

  await page.clock.install();
  await page.goto("/");
  const navigation = page.getByRole("navigation", { name: "Primary views" });
  const servers = navigation.getByRole("link", { name: "Servers", exact: true });
  await expect(servers).toHaveAccessibleDescription("Connecting");
  await servers.click();
  const serversPanel = page.locator("section.panel").filter({ has: page.getByRole("heading", { name: "Servers" }) });
  await expect(serversPanel.getByText(/Server network: Connecting/)).toBeVisible();

  state.status.servers = {
    ...state.status.servers,
    connected: true,
    connecting: false,
    ed2kIdState: "unknown"
  };
  state.status.servers.currentServer.connected = true;
  state.status.servers.currentServer.connecting = false;
  const bounds = await navigation.boundingBox();
  state.status.stats.downloadSpeedKiBps = 125_000;
  state.downloads.unfinished = 12_345;
  await page.clock.fastForward(10_000);
  await expect(servers).toHaveAccessibleDescription("Connected");
  await expect(navigation.getByRole("link", { name: "Downloads" })).toHaveAccessibleDescription(/12345 unfinished/);
  expect(await navigation.boundingBox()).toEqual(bounds);
  await expect(serversPanel.getByText(/Server network: Connected/)).toBeVisible();
  await expect(serversPanel.getByText(/has not supplied a usable eD2K ID state/)).toBeVisible();
  await expect(serversPanel.getByText("Unknown", { exact: true })).toBeVisible();
});

test("keeps the unified toolbar usable at a narrow viewport", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.addInitScript(() => sessionStorage.setItem("emulebb.webui.desktopView", "true"));
  await page.route("**/api/v1/**", installMockApi([]));

  await page.goto("/");

  const topbar = page.locator("header .topbar");
  const primaryViews = topbar.getByRole("navigation", { name: "Primary views" });
  const menu = topbar.getByRole("button", { name: "Menu", exact: true });
  await expect(menu).toHaveAttribute("aria-expanded", "false");
  await expect(primaryViews).toBeHidden();
  await expect(primaryViews.getByRole("link")).toHaveCount(0);
  await menu.click();
  await expect(primaryViews.getByRole("link")).toHaveCount(14);
  await expect(primaryViews.locator("a svg")).toHaveCount(14);
  await expect(primaryViews.getByRole("link", { name: "Library", exact: true })).toBeVisible();
  await expect(primaryViews.getByRole("link", { name: "Logs", exact: true })).toBeVisible();
  await expect(page.locator(".page-header")).toHaveCount(0);
  await expect.poll(async () => topbar.evaluate((element) => element.scrollWidth <= element.clientWidth + 1)).toBe(true);
  await expect.poll(async () => page.locator("body").evaluate((element) => element.scrollWidth <= element.clientWidth + 1)).toBe(true);

  await primaryViews.getByRole("link", { name: "Search", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Search" })).toBeVisible();
  await expect(page).toHaveURL(/\/searches$/);
  await expect(menu).toHaveAttribute("aria-expanded", "false");
  await expect(primaryViews).toBeHidden();
  await expect(page.locator('#primary-views a[href="/searches"]')).toHaveClass(/active/);
});

test("recovers from a stale API key without a manual refresh", async ({ page }) => {
  const requests: RecordedApiRequest[] = [];
  const mockApi = installMockApi(requests);
  await page.route("**/api/v1/**", async (route) => {
    if (route.request().headers()["x-api-key"] !== "fresh-key") {
      await route.fulfill({
        status: 401,
        contentType: "application/json",
        body: JSON.stringify({ error: { code: "UNAUTHORIZED", message: "missing or invalid API key" } })
      });
      return;
    }
    await mockApi(route);
  });

  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Connect to the local daemon" })).toBeVisible();
  await expect(page.getByText(/Could not authenticate.*missing or invalid API key/)).toBeVisible();
  await expect(page.getByRole("link", { name: "Dashboard" })).toHaveCount(0);

  await page.getByPlaceholder("X-API-Key").fill("fresh-key");
  await page.getByRole("button", { name: "Connect" }).click();
  await expect(page.getByText("API key verified")).toBeVisible();
  await expect(page.getByText("Sample Transfer.bin")).toBeVisible();

  await expect
    .poll(() => requests.some((request) => request.path === "snapshot" && request.headers["x-api-key"] === "fresh-key"))
    .toBe(true);
  await expect.poll(() => page.evaluate(() => window.sessionStorage.getItem("emulebb.webui.apiKey"))).toBe("fresh-key");

  await page.getByRole("link", { name: "Network" }).click();
  await expect(page.getByRole("heading", { name: "Network Health" })).toBeVisible();
  await expect
    .poll(() => requests.some((request) => request.path === "settings" && request.headers["x-api-key"] === "fresh-key"))
    .toBe(true);

  await page.getByRole("button", { name: "Log out", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Connect to the local daemon" })).toBeVisible();
  await expect.poll(() => page.evaluate(() => window.sessionStorage.getItem("emulebb.webui.apiKey"))).toBeNull();
});

test("submits a synthetic transfer operation", async ({ page }) => {
  const requests: RecordedApiRequest[] = [];
  await page.route("**/api/v1/**", installMockApi(requests));

  await page.goto("/");
  await page.getByRole("link", { name: "Downloads", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Downloads" })).toBeVisible();

  await page.getByTitle("Stop").click();
  await expect(page.getByText("Download stopped")).toBeVisible();

  expect(
    requests.some(
      (request) =>
        request.method === "POST" &&
        request.path === "downloads/stop"
    )
  ).toBe(true);
});

test("search create form uses REST-native type tokens", async ({ page }) => {
  const requests: RecordedApiRequest[] = [];
  await page.route("**/api/v1/**", installMockApi(requests));

  await page.goto("/");
  await page.getByRole("link", { name: "Search" }).click();
  const searchPanel = page.locator("section.panel").filter({ has: page.getByRole("heading", { name: "Search" }) });
  const startSearch = searchPanel.getByRole("button", { name: "Start" });
  const initialSearchPosts = requests.filter((request) => request.method === "POST" && request.path === "searches").length;

  await expect(startSearch).toBeDisabled();
  await searchPanel.getByPlaceholder("Search query").fill("a".repeat(161));
  await expect(searchPanel.getByText("Search query must be at most 160 characters.")).toBeVisible();
  await expect(startSearch).toBeDisabled();
  expect(requests.filter((request) => request.method === "POST" && request.path === "searches").length).toBe(initialSearchPosts);

  await searchPanel.getByPlaceholder("Search query").fill(`alpha${String.fromCharCode(0x85)}beta`);
  await expect(searchPanel.getByText("Search query must not contain control characters.")).toBeVisible();
  await expect(startSearch).toBeDisabled();
  expect(requests.filter((request) => request.method === "POST" && request.path === "searches").length).toBe(initialSearchPosts);

  await searchPanel.getByPlaceholder("Search query").fill(" alpha   beta ");
  await searchPanel.locator("select").nth(0).selectOption("kad");
  await searchPanel.locator("select").nth(1).selectOption("arc");
  await searchPanel.getByText("Advanced search filters").click();
  await searchPanel.getByPlaceholder("Extension").fill(" zip ");
  await searchPanel.getByPlaceholder("Minimum complete sources").fill("2");
  await searchPanel.getByPlaceholder("Minimum bitrate (kbps)").fill("192");
  await searchPanel.getByPlaceholder("Minimum length (seconds)").fill("180");
  await searchPanel.getByPlaceholder("Codec").fill(" deflate ");
  await searchPanel.getByPlaceholder("Title").fill(" Synthetic Title ");
  await searchPanel.getByPlaceholder("Album").fill(" Sample Album ");
  await searchPanel.getByPlaceholder("Artist").fill(" Example Artist ");
  await expect(searchPanel.getByText("Search query must be at most 160 characters.")).toHaveCount(0);
  await expect(searchPanel.getByText("Search query must not contain control characters.")).toHaveCount(0);
  await startSearch.click();
  await expect(page.getByText("Search started")).toBeVisible();
  const searchPost = requests.find((request) => request.method === "POST" && request.path === "searches");
  expect(searchPost).toBeDefined();
  expect(JSON.parse(searchPost?.body ?? "{}")).toEqual({
    query: "alpha beta",
    method: "kad",
    type: "arc",
    extension: "zip",
    minCompleteSources: 2,
    minBitrateKbps: 192,
    minLengthSeconds: 180,
    codec: "deflate",
    title: "Synthetic Title",
    album: "Sample Album",
    artist: "Example Artist"
  });
});

test("loads a selected search session from a deep link", async ({ page }) => {
  const requests: RecordedApiRequest[] = [];
  const state: any = mockSnapshotFixture();
  state.searches = [{
    id: "7",
    parentSearchId: null,
    query: "synthetic archive",
    requestedMethod: "kad",
    resolvedMethod: "kad",
    status: "completed",
    resultCount: 1
  }];
  const fallback = installMockApi(requests);

  await page.route("**/api/v1/**", async (route) => {
    const request = route.request();
    const requestUrl = new URL(request.url());
    const path = requestUrl.pathname.replace(/^\/api\/v1\/?/, "");
    if (request.method() === "GET" && path === "snapshot") {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ data: state })
      });
      return;
    }
    if (request.method() === "GET" && path === "searches") {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ data: state.searches, meta: { apiVersion: "v1", nextCursor: null, hasMore: false } })
      });
      return;
    }
    if (request.method() === "GET" && path === "searches/7") {
      await route.fulfill({ json: { data: state.searches[0], meta: { apiVersion: "v1" } } });
      return;
    }
    if (request.method() === "GET" && path === "searches/7/results") {
      expect(requestUrl.searchParams.get("limit")).toBe("100");
      expect(requestUrl.searchParams.get("sort")).toBe("sources");
      expect(requestUrl.searchParams.get("order")).toBe("desc");
      await route.fulfill({ json: { data: [{ id: "13", searchId: "7", hash: "00112233445566778899aabbccddeeff",
        displayName: "Synthetic Archive.bin", sizeBytes: 4096, sources: 3, fileType: "arc" }],
        meta: { apiVersion: "v1", nextCursor: null, hasMore: false } } });
      return;
    }
    await fallback(route);
  });

  await page.goto("/searches/7");

  await expect(page.getByRole("heading", { name: "Search" })).toBeVisible();
  await expect(page.getByRole("combobox", { name: "Search session" })).toHaveValue("7");
  await expect(page.getByText("Synthetic Archive.bin")).toBeVisible();
  await expect(page.getByRole("link", { name: "Search" })).toHaveAttribute("aria-current", "page");
  await expect(page).toHaveURL(/\/searches\/7$/);
});

test("runs the complete server, Kad, search, download, and reconnect workflow", async ({ page }) => {
  const requests: RecordedApiRequest[] = [];
  const state: any = mockSnapshotFixture();
  state.status.servers = { connected: false, connecting: false, currentServer: null, ed2kIdState: "unknown", serverCount: 0 };
  let serverRows: any[] = [];
  state.kad = { enabled: true, running: false, connected: false, firewalled: null, contactCount: 0 };
  state.searches = [{
    id: "1",
    parentSearchId: null,
    query: "older search",
    requestedMethod: "server",
    resolvedMethod: "server",
    status: "completed",
    resultCount: 1
  }];
  let downloadRows: any[] = [];
  const resultHash = "AABBCCDDEEFF00112233445566778899";
  const fallback = installMockApi(requests);

  await page.route("**/api/v1/**", async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    const path = url.pathname.replace(/^\/api\/v1\/?/, "");
    const method = request.method();
    const record = () => requests.push({
      method,
      path,
      query: url.search,
      headers: request.headers(),
      body: request.postData()
    });
    const fulfill = async (data: unknown) => route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ data })
    });

    if (method === "GET" && path === "snapshot") {
      record();
      await fulfill(state);
      return;
    }
    if (method === "GET" && path === "searches") {
      record();
      await route.fulfill({ json: { data: [...state.searches].reverse(), meta: { apiVersion: "v1", nextCursor: null, hasMore: false } } });
      return;
    }
    if (method === "GET" && path === "servers") {
      record();
      await route.fulfill({ json: { data: serverRows, meta: { apiVersion: "v1", nextCursor: null, hasMore: false } } });
      return;
    }
    if (method === "POST" && path === "servers/operations/import-met-url") {
      record();
      serverRows = [{ id: "1", endpoint: "192.0.2.10:4661", name: "Imported Server", connected: false, enabled: true }];
      state.status.servers.serverCount = 1;
      await fulfill({ ok: true, imported: true });
      return;
    }
    if (method === "POST" && path === "servers/operations/connect") {
      record();
      state.status.servers = { connected: true, connecting: false, currentServer: serverRows[0], ed2kIdState: "low", serverCount: 1 };
      serverRows[0].connected = true;
      await fulfill({ running: true, connected: true, firewalled: true });
      return;
    }
    if (method === "POST" && path === "servers/1/operations/connect") {
      record();
      state.status.servers = { connected: true, connecting: false, currentServer: serverRows[0], ed2kIdState: "low", serverCount: 1 };
      serverRows[0].connected = true;
      await fulfill({ running: true, connected: true, firewalled: true });
      return;
    }
    if (method === "POST" && path === "servers/operations/disconnect") {
      record();
      state.status.servers = { ...state.status.servers, connected: false, connecting: false, currentServer: null, ed2kIdState: "unknown" };
      serverRows[0].connected = false;
      await fulfill({ running: false, connected: false });
      return;
    }
    if (method === "POST" && path === "kad/operations/import-nodes-url") {
      record();
      state.kad.contactCount = 188;
      await fulfill({ ok: true, imported: true });
      return;
    }
    if (method === "POST" && path === "kad/operations/start") {
      record();
      state.kad = { ...state.kad, running: true, connected: true, firewalled: false };
      await fulfill(state.kad);
      return;
    }
    if (method === "POST" && path === "kad/operations/stop") {
      record();
      state.kad = { ...state.kad, running: false, connected: false, firewalled: null };
      await fulfill(state.kad);
      return;
    }
    if (method === "POST" && path === "searches") {
      record();
      const search = {
        id: "2",
        parentSearchId: request.postDataJSON()?.parentSearchId ?? null,
        query: "linux",
        requestedMethod: "automatic",
        resolvedMethod: "global",
        status: "completed",
        resultCount: 1,
        criteria: { extension: "pdf", maxSizeBytes: 5_242_879 }
      };
      state.searches = [...state.searches, search];
      await route.fulfill({ status: 201, json: { data: { ...search, status: "queued", resultCount: 0 }, meta: { apiVersion: "v1" } } });
      return;
    }
    if (method === "GET" && /^searches\/\d+$/.test(path)) {
      record();
      await fulfill(state.searches.find((candidate: any) => candidate.id === path.split("/")[1]));
      return;
    }
    if (method === "GET" && /^searches\/\d+\/results$/.test(path)) {
      record();
      const searchId = path.split("/")[1];
      await route.fulfill({ json: {
        meta: { apiVersion: "v1", nextCursor: null, hasMore: false },
        data: searchId === "2"
          ? [{
              id: "13",
              hash: resultHash,
              displayName: "Linux Guide.pdf",
              sizeBytes: 1_048_576,
              sources: 5,
              completeSources: 2,
              rating: 4,
              fileType: "doc",
              media: { artist: "Example Author", album: "", title: "Linux Guide", lengthSeconds: 0, bitrateKbps: 0, codec: "PDF" },

            }]
          : [{ id: "14", hash: "00112233445566778899AABBCCDDEEFF", displayName: "Older Result.bin", sizeBytes: 4096, sources: 1 }]
      } });
      return;
    }
    if (method === "GET" && path === "searches/2/results/13/observations") {
      record();
      await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({
        data: ["server", "global"].map((origin, index) => ({
          id: String(index + 1), origin, reporterEndpoint: index ? "192.0.2.10:4661" : null,
          publisherId: null, comment: null,
          rawName: index ? "Linux Manual.pdf" : "Linux Guide.pdf",
          normalizedName: index ? "Linux Manual.pdf" : "Linux Guide.pdf",
          sizeBytes: 1_048_576, sources: index ? 5 : 3, completeSources: index ? 2 : 1,
          sourceClientId: null, sourceClientPort: null, fileType: "doc",
          media: { artist: "Example Author", album: null, title: index ? "Linux Manual" : "Linux Guide", lengthSeconds: null, bitrateKbps: null, codec: "PDF" },
          rating: index ? 3 : 4, aichHash: null, complete: null, directory: null,
          firstSeenAt: 1_791_288_000, lastSeenAt: 1_791_288_001, observationCount: 1,
        })), meta: { apiVersion: "v1", nextCursor: null, hasMore: false },
      }) });
      return;
    }
    if (method === "DELETE" && /^searches\/\d+$/.test(path)) {
      record();
      const searchId = path.split("/")[1];
      state.searches = state.searches.filter((candidate: any) => candidate.id !== searchId);
      await fulfill({ ok: true });
      return;
    }
    if (method === "DELETE" && path === "searches" && url.searchParams.get("confirm") === "true") {
      record();
      state.searches = [];
      await fulfill({ ok: true });
      return;
    }
    if (method === "GET" && path === "downloads") {
      record();
      await route.fulfill({ json: { data: downloadRows, meta: { apiVersion: "2.0.0", nextCursor: null, hasMore: false } } });
      return;
    }
    if (method === "POST" && path === `searches/2/results/13/download`) {
      record();
      downloadRows = [{ id: "2", hash: resultHash.toLowerCase(), name: "Linux Guide.pdf", state: "downloading",
        sizeBytes: 1_048_576, progress: 4096 / 1_048_576, intent: "started", waitingReason: null, category: null, createdAt: 1, updatedAt: 1, completedAt: null }];
      state.downloads = { unfinished: 1, completed: 0 };
      await fulfill(downloadRows[0]);
      return;
    }
    if (method === "POST" && path === "downloads/stop") {
      record();
      downloadRows[0] = { ...downloadRows[0], state: "stopped", intent: "stopped" };
      await route.fulfill({ status: 207, json: { data: [{ id: "2", status: "accepted", httpStatus: 202 }] } });
      return;
    }
    if (method === "POST" && path === "downloads/remove") {
      record();
      expect(request.postDataJSON()).toEqual({ ids: ["2"], deleteData: true });
      downloadRows = [];
      state.downloads = { unfinished: 0, completed: 0 };
      await route.fulfill({ status: 207, json: { data: [{ id: "2", status: "accepted", httpStatus: 202 }] } });
      return;
    }
    if (method === "GET" && path === "downloads/2") {
      record();
      await fulfill({ ...downloadRows[0], payloadVerified: false, delivery: { path: null, state: "pending", ownership: "none" }, failure: null });
      return;
    }
    if (method === "GET" && /^downloads\/2\/(sources|parts|comments)$/.test(path)) {
      record();
      await route.fulfill({ json: { data: [], meta: { apiVersion: "2.0.0", nextCursor: null, hasMore: false } } });
      return;
    }
    await fallback(route);
  });

  await page.goto("/");
  await page.getByRole("link", { name: "Servers" }).click();
  const serversPanel = page.locator("section.panel").filter({ has: page.getByRole("heading", { name: "Servers" }) });
  await expect(serversPanel.getByText(/Server network: Disconnected/)).toBeVisible();
  await serversPanel.getByRole("button", { name: "Import" }).click();
  await expect(page.getByText("server.met imported; the server list is ready")).toBeVisible();
  await serversPanel.locator("tbody tr", { hasText: "192.0.2.10:4661" }).getByTitle("Connect").click();
  await expect(serversPanel.getByText(/Server network: LowID/)).toBeVisible();
  await expect(page.getByRole("navigation", { name: "Primary views" }).getByRole("link", { name: "Servers" })).toHaveAccessibleDescription("LowID");

  await page.getByRole("link", { name: "KAD", exact: true }).click();
  const kadPanel = page.locator("section.panel").filter({ has: page.getByRole("heading", { name: "Kad" }) });
  await expect(kadPanel.getByText(/Kad network: Stopped/)).toBeVisible();
  await kadPanel.getByRole("button", { name: "Import" }).click();
  await expect(page.getByText("Kad contacts saved in your profile database")).toBeVisible();
  await kadPanel.getByRole("button", { name: "Start" }).click();
  await expect(kadPanel.getByText(/Kad network: Connected/)).toBeVisible();

  await page.getByRole("link", { name: "Servers" }).click();
  await serversPanel.locator("button.btn").filter({ hasText: /^Disconnect$/ }).click();
  await expect(serversPanel.getByText(/Server network: Disconnected/)).toBeVisible();
  await page.getByRole("link", { name: "KAD", exact: true }).click();
  await expect(kadPanel.getByText(/Kad network: Connected/)).toBeVisible();
  await page.getByRole("link", { name: "Servers" }).click();
  await serversPanel.locator("button.btn").filter({ hasText: /^Connect$/ }).click();
  await expect(serversPanel.getByText(/Server network: LowID/)).toBeVisible();

  await page.getByRole("link", { name: "Search" }).click();
  const searchPanel = page.locator("section.panel").filter({ has: page.getByRole("heading", { name: "Search" }) });
  await expect(page).toHaveURL(/\/searches\/1$/);
  const searchSessions = searchPanel.getByRole("combobox", { name: "Search session" });
  await expect(searchSessions).toHaveValue("1");
  await expect(searchPanel.getByText("Older Result.bin")).toBeVisible();
  await searchPanel.getByPlaceholder("Search query").fill("linux");
  await searchPanel.getByText("Advanced search filters").click();
  await searchPanel.getByPlaceholder("Extension").fill("pdf");
  await searchPanel.getByPlaceholder("Maximum bytes").fill("5242879");
  await searchPanel.getByRole("button", { name: "Start" }).click();
  await expect(page).toHaveURL(/\/searches\/2$/);
  await expect(searchSessions).toHaveValue("2");
  const resultRow = searchPanel.locator("tr", { hasText: "Linux Guide.pdf" });
  await expect(resultRow).toBeVisible();
  await searchSessions.selectOption("1");
  await expect(page).toHaveURL(/\/searches\/1$/);
  await expect(searchPanel.getByText("Older Result.bin")).toBeVisible();
  await page.goBack();
  await expect(page).toHaveURL(/\/searches\/2$/);
  await expect(resultRow).toBeVisible();
  await expect(searchPanel.getByText("Resolved backend")).toBeVisible();
  await expect(searchPanel.getByText("Extension: .pdf")).toBeVisible();
  await expect(resultRow).toContainText("2 complete");
  await expect(resultRow).toContainText("4/5");
  await resultRow.getByRole("button", { name: "Observations", exact: true }).click();
  const observations = page.getByRole("region", { name: "Search result observations", exact: true });
  await expect(observations.getByRole("cell", { name: "Linux Manual.pdf", exact: true })).toBeVisible();
  await expect(observations.getByRole("cell", { name: "global 192.0.2.10:4661", exact: true })).toBeVisible();
  await expect(observations.getByRole("button", { name: "Next observations page" })).toBeDisabled();
  await observations.getByRole("button", { name: "Close observations" }).click();
  await expect(observations).toHaveCount(0);
  await expect(resultRow).toContainText("Title: Linux Guide");
  await expect(resultRow).toContainText("Artist: Example Author");
  await expect(resultRow).toContainText("Codec: PDF");
  await expect(resultRow).toContainText(resultHash);
  await searchPanel.getByRole("combobox", { name: "Sort search results" }).selectOption("rating:desc");
  await expect.poll(() => requests.some((request) =>
    request.method === "GET" &&
    request.path === "searches/2/results" &&
    new URLSearchParams(request.query).get("sort") === "rating" &&
    new URLSearchParams(request.query).get("order") === "desc"
  )).toBe(true);
  await resultRow.getByRole("button", { name: "Download" }).click();
  await expect(page.getByText("Download queued")).toBeVisible();

  page.once("dialog", async (dialog) => {
    expect(dialog.message()).toContain("Delete this search session");
    await dialog.accept();
  });
  await searchPanel.getByRole("button", { name: "Delete session" }).click();
  await expect(page.getByText("Search session deleted")).toBeVisible();
  await expect(page).toHaveURL(/\/searches\/1$/);

  page.once("dialog", async (dialog) => {
    expect(dialog.message()).toContain("Clear every saved search session");
    await dialog.accept();
  });
  await searchPanel.getByRole("button", { name: "Clear sessions" }).click();
  await expect(page.getByText("Search sessions cleared")).toBeVisible();
  await expect(page).toHaveURL(/\/searches$/);

  await page.getByRole("link", { name: "Downloads", exact: true }).click();
  const transferRow = page.locator("tr", { hasText: "Linux Guide.pdf" });
  await expect(transferRow).toContainText("downloading");
  await transferRow.getByRole("button", { name: "Stop", exact: true }).click();
  await expect(transferRow).toContainText("stopped");
  await expect(transferRow.getByRole("button", { name: "Stop", exact: true })).toBeDisabled();

  page.once("dialog", async (dialog) => {
    expect(dialog.message()).toContain("owned download data");
    await dialog.accept();
  });
  await transferRow.getByRole("button", { name: "Delete", exact: true }).click();
  await expect(page.getByText("Download removed", { exact: true })).toBeVisible();
  await expect(transferRow).toHaveCount(0);
  await expect(page.getByText("No downloads.", { exact: true })).toBeVisible();

  await page.getByRole("link", { name: "KAD", exact: true }).click();
  await kadPanel.getByRole("button", { name: "Stop" }).click();
  await expect(kadPanel.getByText(/Kad network: Stopped/)).toBeVisible();
  await page.getByRole("link", { name: "Servers" }).click();
  await expect(serversPanel.getByText(/Server network: LowID/)).toBeVisible();

  expect(requests.some((request) => request.path === "servers/operations/disconnect")).toBe(true);
  expect(requests.filter((request) => request.path === "servers/operations/connect")).toHaveLength(1);
  expect(requests.filter((request) => request.path === "servers/1/operations/connect")).toHaveLength(1);
  expect(requests.some((request) => request.method === "GET" && request.path === "searches")).toBe(true);
  expect(requests.some((request) => request.method === "GET" && request.path === "searches/2")).toBe(true);
  expect(requests.some((request) =>
    request.method === "GET" &&
    request.path === "searches/2/results" &&
    new URLSearchParams(request.query).get("sort") === "sources" &&
    new URLSearchParams(request.query).get("order") === "desc"
  )).toBe(true);
  const searchDownload = requests.find((request) => request.path === `searches/2/results/13/download`);
  expect(searchDownload).toBeDefined();
  expect(JSON.parse(searchDownload?.body ?? "{}")).toMatchObject({ intent: "started", redownload: false });
  expect(requests.some((request) => request.method === "DELETE" && request.path === "searches/2")).toBe(true);
  expect(requests.some((request) =>
    request.method === "DELETE" &&
    request.path === "searches" &&
    new URLSearchParams(request.query).get("confirm") === "true"
  )).toBe(true);
  expect(requests.some((request) => request.path === "downloads/stop")).toBe(true);
  expect(requests.some((request) =>
    request.method === "POST" && request.path === "downloads/remove" &&
    JSON.parse(request.body ?? "{}").deleteData === true
  )).toBe(true);
  expect(downloadRows).toEqual([]);
});

test("shared folder add form validates root paths", async ({ page }) => {
  const requests: RecordedApiRequest[] = [];
  await page.route("**/api/v1/**", installMockApi(requests));

  await page.goto("/");
  await page.getByRole("link", { name: "Sharing" }).click();
  const sharingPanel = page.locator("section.panel").filter({ has: page.getByRole("heading", { name: "Shared Folders" }) });
  const addFolder = sharingPanel.getByRole("button", { name: "Add root" });
  const initialSharedDirectoryPosts = requests.filter((request) => request.method === "POST" && request.path === "library/roots").length;

  await expect(addFolder).toBeDisabled();
  await sharingPanel.getByPlaceholder("Server folder path").fill("   ");
  await expect(sharingPanel.getByText("Folder path must not be empty.")).toBeVisible();
  await expect(addFolder).toBeDisabled();
  expect(requests.filter((request) => request.method === "POST" && request.path === "library/roots").length).toBe(initialSharedDirectoryPosts);

  await sharingPanel.getByPlaceholder("Server folder path").fill(" C:\\More\\Shared ");
  await expect(sharingPanel.getByText("Folder path must not be empty.")).toHaveCount(0);
  await addFolder.click();
  await expect(page.getByText("Folder added")).toBeVisible();
  const sharedDirectoryPost = requests.find((request) => request.method === "POST" && request.path === "library/roots");
  expect(sharedDirectoryPost).toBeDefined();
  expect(JSON.parse(sharedDirectoryPost?.body ?? "{}")).toEqual({ path: "C:\\More\\Shared", watchEnabled: false });

  const ignoresPanel = page.locator("section.panel").filter({ has: page.getByRole("heading", { name: "Share Ignores" }) });
  await ignoresPanel.getByRole("textbox", { name: "File name ignore pattern" }).fill(" *.private.bin ");
  await ignoresPanel.getByRole("button", { name: "Add pattern" }).click();
  await expect(page.getByText("Ignore pattern added")).toBeVisible();
  const ignorePost = requests.find((request) => request.method === "POST" && request.path === "library/ignores");
  expect(JSON.parse(ignorePost?.body ?? "{}")).toEqual({ pattern: "*.private.bin" });
  await ignoresPanel.getByTitle("Remove pattern").first().click();
  await expect(page.getByText("Ignore pattern removed")).toBeVisible();
  const ignoreDelete = requests.find((request) => request.method === "DELETE" && request.path === "library/ignores");
  expect(new URLSearchParams(ignoreDelete?.query ?? "").get("pattern")).toBe("*.private.bin");

  await sharingPanel.getByRole("button", { name: "Reload" }).click();
  await expect(page.getByText("Reload queued")).toBeVisible();
  expect(requests.some((request) => request.method === "POST" && request.path === "library/scan")).toBe(true);

  await page.getByRole("link", { name: "Library", exact: true }).click();
  const sharedFilesPanel = page.locator("section.panel").filter({ has: page.getByRole("heading", { name: "Library", exact: true }) });
  const sharedFileRow = sharedFilesPanel.locator("tbody tr").filter({ hasText: "Shared Sample.bin" });
  await expect(sharedFileRow).toHaveCount(1);
  await expect(sharedFileRow).toContainText("4.0 KiB");

  await page.getByRole("link", { name: "Sharing", exact: true }).click();

  page.once("dialog", (dialog) => dialog.accept());
  await sharingPanel.getByTitle("Remove").first().click();
  await expect(page.getByText("Folder removed")).toBeVisible();
  const sharedDirectoryDelete = requests.find((request) => request.method === "DELETE" && request.path === "library/roots/1");
  expect(sharedDirectoryDelete).toBeDefined();
  expect(sharedDirectoryDelete?.query).toBe("");
});

test("transfer add form validates eD2K link batches", async ({ page }) => {
  const requests: RecordedApiRequest[] = [];
  await page.route("**/api/v1/**", installMockApi(requests));

  await page.goto("/");
  await page.getByRole("link", { name: "Downloads", exact: true }).click();
  const transfersPanel = page.locator("section.panel").filter({ has: page.getByRole("heading", { name: "Downloads" }) });
  const linkInput = transfersPanel.getByPlaceholder("One eD2K link per line");
  const addLinks = transfersPanel.getByRole("button", { name: "Add links" });
  const initialTransferPosts = requests.filter((request) => request.method === "POST" && request.path === "downloads").length;
  const invalidLinkError = "Each transfer link must start with ed2k://, contain no whitespace or control characters, and be at most 2048 characters.";

  await linkInput.fill("http://example.invalid/file");
  await expect(transfersPanel.getByText(invalidLinkError)).toBeVisible();
  await expect(addLinks).toBeDisabled();
  expect(requests.filter((request) => request.method === "POST" && request.path === "downloads").length).toBe(initialTransferPosts);

  await linkInput.fill(`ed2k://|file|Sample${String.fromCharCode(0x85)}.bin|1|00112233445566778899aabbccddeeff|/`);
  await expect(transfersPanel.getByText(invalidLinkError)).toBeVisible();
  await expect(addLinks).toBeDisabled();
  expect(requests.filter((request) => request.method === "POST" && request.path === "downloads").length).toBe(initialTransferPosts);

  const validLink = "ed2k://|file|Sample.bin|1|00112233445566778899aabbccddeeff|/";
  await linkInput.fill(Array.from({ length: 101 }, () => validLink).join("\n"));
  await expect(transfersPanel.getByText("Add links accepts at most 100 eD2K links.")).toBeVisible();
  await expect(addLinks).toBeDisabled();
  expect(requests.filter((request) => request.method === "POST" && request.path === "downloads").length).toBe(initialTransferPosts);

  await linkInput.fill(validLink);
  await expect(transfersPanel.getByText(invalidLinkError)).toHaveCount(0);
  await expect(transfersPanel.getByText("Add links accepts at most 100 eD2K links.")).toHaveCount(0);
  await addLinks.click();
  await expect(page.getByText("Downloads queued")).toBeVisible();
  const transferPost = requests.find((request) => request.method === "POST" && request.path === "downloads");
  expect(transferPost).toBeDefined();
  expect(JSON.parse(transferPost?.body ?? "{}")).toEqual({
    source: { type: "ed2k-link", link: validLink },
    intent: "started",
    redownload: false
  });
});

test("section resource operation forms validate endpoint addresses and ports", async ({ page }) => {
  const requests: RecordedApiRequest[] = [];
  await page.route("**/api/v1/**", installMockApi(requests));

  await page.goto("/");

  await page.getByRole("link", { name: "Servers" }).click();
  const serversPanel = page.locator("section.panel").filter({ has: page.getByRole("heading", { name: "Servers" }) });
  await expect(serversPanel.getByText("Auxiliary ports")).toBeVisible();
  await expect(serversPanel.getByText("4662, 4663")).toBeVisible();
  const initialServerPosts = requests.filter((request) => request.method === "POST" && request.path === "servers").length;
  await serversPanel.getByPlaceholder("Address").fill("   ");
  await expect(serversPanel.getByText("Address must not be empty.")).toBeVisible();
  await expect(serversPanel.getByRole("button", { name: "Add" })).toBeDisabled();
  expect(requests.filter((request) => request.method === "POST" && request.path === "servers").length).toBe(initialServerPosts);
  await serversPanel.getByPlaceholder("Address").fill(" 127.0.0.1 ");
  await expect(serversPanel.getByText("Address must not be empty.")).toHaveCount(0);
  await serversPanel.getByPlaceholder("Port").fill("0");
  await expect(serversPanel.getByText("Port must be between 1 and 65535.")).toBeVisible();
  await expect(serversPanel.getByRole("button", { name: "Add" })).toBeDisabled();
  expect(requests.filter((request) => request.method === "POST" && request.path === "servers").length).toBe(initialServerPosts);
  await serversPanel.getByPlaceholder("Port").fill("4661");
  await expect(serversPanel.getByText("Port must be between 1 and 65535.")).toHaveCount(0);
  await serversPanel.getByRole("button", { name: "Add" }).click();
  await expect(page.getByText("Server added")).toBeVisible();
  const serverPost = requests.find((request) => request.method === "POST" && request.path === "servers");
  expect(serverPost).toBeDefined();
  expect(JSON.parse(serverPost?.body ?? "{}")).toMatchObject({ address: "127.0.0.1", port: 4661 });

  await page.getByRole("link", { name: "KAD", exact: true }).click();
  const kadPanel = page.locator("section.panel").filter({ has: page.getByRole("heading", { name: "Kad" }) });
  const initialKadBootstrapPosts = requests.filter((request) => request.method === "POST" && request.path === "kad/operations/bootstrap").length;
  await kadPanel.getByPlaceholder("Bootstrap address").fill("   ");
  await expect(kadPanel.getByText("Bootstrap address must not be empty.")).toBeVisible();
  await expect(kadPanel.getByRole("button", { name: "Bootstrap" })).toBeDisabled();
  expect(requests.filter((request) => request.method === "POST" && request.path === "kad/operations/bootstrap").length).toBe(initialKadBootstrapPosts);
  await kadPanel.getByPlaceholder("Bootstrap address").fill(" 203.0.113.10 ");
  await expect(kadPanel.getByText("Bootstrap address must not be empty.")).toHaveCount(0);
  await kadPanel.getByPlaceholder("Port").fill("65536");
  await expect(kadPanel.getByText("Bootstrap port must be between 1 and 65535.")).toBeVisible();
  await expect(kadPanel.getByRole("button", { name: "Bootstrap" })).toBeDisabled();
  expect(requests.filter((request) => request.method === "POST" && request.path === "kad/operations/bootstrap").length).toBe(initialKadBootstrapPosts);
  await kadPanel.getByPlaceholder("Port").fill("4672");
  await expect(kadPanel.getByText("Bootstrap port must be between 1 and 65535.")).toHaveCount(0);
  await kadPanel.getByRole("button", { name: "Bootstrap" }).click();
  await expect(page.getByText("Kad bootstrap started")).toBeVisible();
  const bootstrapPost = requests.find((request) => request.method === "POST" && request.path === "kad/operations/bootstrap");
  expect(bootstrapPost).toBeDefined();
  expect(JSON.parse(bootstrapPost?.body ?? "{}")).toEqual({ address: "203.0.113.10", port: 4672 });
});

test("section resource import forms validate HTTP URLs", async ({ page }) => {
  const requests: RecordedApiRequest[] = [];
  await page.route("**/api/v1/**", installMockApi(requests));

  await page.goto("/");

  await page.getByRole("link", { name: "Servers" }).click();
  const serversPanel = page.locator("section.panel").filter({ has: page.getByRole("heading", { name: "Servers" }) });
  const serverImportButton = serversPanel.getByRole("button", { name: "Import" });
  const initialServerImportPosts = requests.filter((request) => request.method === "POST" && request.path === "servers/operations/import-met-url").length;
  const urlImportError = "must start with http:// or https://, include a host, contain no whitespace or control characters, and be at most 2048 characters.";
  const serverUrlError = `server.met URL ${urlImportError}`;
  const kadUrlError = `nodes.dat URL ${urlImportError}`;
  const c1ControlUrl = `https://exa${String.fromCharCode(0x85)}mple.invalid/server.met`;
  await expect(serversPanel.getByPlaceholder("server.met URL")).toHaveValue("https://upd.emule-security.org/server.met");
  await expect(serverImportButton).toBeEnabled();
  await serversPanel.getByPlaceholder("server.met URL").fill("ftp://example.invalid/server.met");
  await expect(serversPanel.getByText(serverUrlError)).toBeVisible();
  await expect(serverImportButton).toBeDisabled();
  expect(requests.filter((request) => request.method === "POST" && request.path === "servers/operations/import-met-url").length).toBe(initialServerImportPosts);
  await serversPanel.getByPlaceholder("server.met URL").fill(c1ControlUrl);
  await expect(serversPanel.getByText(serverUrlError)).toBeVisible();
  await expect(serverImportButton).toBeDisabled();
  expect(requests.filter((request) => request.method === "POST" && request.path === "servers/operations/import-met-url").length).toBe(initialServerImportPosts);
  await serversPanel.getByPlaceholder("server.met URL").fill(" HTTPS://example.invalid/server.met ");
  await expect(serversPanel.getByText(serverUrlError)).toHaveCount(0);
  await serverImportButton.click();
  await expect(page.getByText("server.met imported; the server list is ready")).toBeVisible();
  const serverImportPost = requests.find((request) => request.method === "POST" && request.path === "servers/operations/import-met-url");
  expect(serverImportPost).toBeDefined();
  expect(JSON.parse(serverImportPost?.body ?? "{}")).toEqual({ url: "HTTPS://example.invalid/server.met" });

  await page.getByRole("link", { name: "KAD", exact: true }).click();
  const kadPanel = page.locator("section.panel").filter({ has: page.getByRole("heading", { name: "Kad" }) });
  const kadImportButton = kadPanel.getByRole("button", { name: "Import" });
  const initialKadImportPosts = requests.filter((request) => request.method === "POST" && request.path === "kad/operations/import-nodes-url").length;
  await expect(kadPanel.getByPlaceholder("nodes.dat URL")).toHaveValue("https://upd.emule-security.org/nodes.dat");
  await expect(kadImportButton).toBeEnabled();
  await kadPanel.getByPlaceholder("nodes.dat URL").fill("https:///nodes.dat");
  await expect(kadPanel.getByText(kadUrlError)).toBeVisible();
  await expect(kadImportButton).toBeDisabled();
  expect(requests.filter((request) => request.method === "POST" && request.path === "kad/operations/import-nodes-url").length).toBe(initialKadImportPosts);
  await kadPanel.getByPlaceholder("nodes.dat URL").fill("http://example.invalid/nodes.dat");
  await expect(kadPanel.getByText(kadUrlError)).toHaveCount(0);
  await kadImportButton.click();
  await expect(page.getByText("Kad contacts saved in your profile database")).toBeVisible();
  const kadImportPost = requests.find((request) => request.method === "POST" && request.path === "kad/operations/import-nodes-url");
  expect(kadImportPost).toBeDefined();
  expect(JSON.parse(kadImportPost?.body ?? "{}")).toEqual({ url: "http://example.invalid/nodes.dat" });
});

test("Kad node dates display calendar seconds including epoch zero", async ({ page }) => {
  await page.route("**/api/v1/**", installMockApi([]));
  await page.route("**/api/v1/kad/nodes?*", async route => {
    await route.fulfill({ json: { data: { items: [
      { nodeId: "00112233445566778899aabbccddeeff", ip: "192.0.2.10", createdAt: 0, lastSeen: 0 },
      { nodeId: "112233445566778899aabbccddeeff00", ip: "192.0.2.11", createdAt: 1_800_000_000, lastSeen: 1_800_000_000 },
    ] } } });
  });
  await page.goto("/");
  await page.getByRole("link", { name: "KAD", exact: true }).click();
  for (const [ip, seconds] of [["192.0.2.10", 0], ["192.0.2.11", 1_800_000_000]] as const) {
    const expected = await page.evaluate(time => new Date(time * 1000).toLocaleString(), seconds);
    await expect(page.getByRole("row").filter({ hasText: ip }).getByRole("cell").nth(7)).toHaveText(expected);
  }
});

test("friends display nullable calendar seconds including epoch zero", async ({ page }) => {
  await page.route("**/api/v1/**", installMockApi([]));
  await page.route("**/api/v1/friends", async route => {
    await route.fulfill({ json: { data: { items: [
      { userHash: "00112233445566778899aabbccddeeff", name: "Epoch Peer", lastSeen: 0 },
      { userHash: "112233445566778899aabbccddeeff00", name: "Unknown Peer", lastSeen: null },
      { userHash: "2233445566778899aabbccddeeff0011", name: "Recent Peer", lastSeen: 1_800_000_000 },
    ] }, meta: { apiVersion: "v1" } } });
  });
  await page.goto("/");
  await page.getByRole("link", { name: "Friends" }).click();
  for (const [name, seconds] of [["Epoch Peer", 0], ["Unknown Peer", null], ["Recent Peer", 1_800_000_000]] as const) {
    const expected = await page.evaluate(time => time == null ? "" : new Date(time * 1000).toLocaleString(), seconds);
    await expect(page.getByRole("row").filter({ hasText: name }).getByRole("cell").nth(3)).toHaveText(expected);
  }
});

test("friend create form validates hash and name", async ({ page }) => {
  const requests: RecordedApiRequest[] = [];
  await page.route("**/api/v1/**", installMockApi(requests));

  await page.goto("/");
  await page.getByRole("link", { name: "Friends" }).click();
  const friendsPanel = page.locator("section.panel").filter({ has: page.getByRole("heading", { name: "Friends" }) });
  const addFriend = friendsPanel.getByRole("button", { name: "Add" });
  const initialFriendPosts = requests.filter((request) => request.method === "POST" && request.path === "friends").length;
  await expect(addFriend).toBeDisabled();

  await friendsPanel.getByPlaceholder("User hash").fill("00112233445566778899AABBCCDDEEFF");
  await expect(friendsPanel.getByText("User hash must be a 32-character lowercase hex string.")).toBeVisible();
  await expect(addFriend).toBeDisabled();
  expect(requests.filter((request) => request.method === "POST" && request.path === "friends").length).toBe(initialFriendPosts);

  const validHash = "00112233445566778899aabbccddeeff";
  await friendsPanel.getByPlaceholder("User hash").fill(` ${validHash} `);
  await friendsPanel.getByPlaceholder("Name").fill("a".repeat(129));
  await expect(friendsPanel.getByText("Friend name must be at most 128 characters.")).toBeVisible();
  await expect(addFriend).toBeDisabled();
  expect(requests.filter((request) => request.method === "POST" && request.path === "friends").length).toBe(initialFriendPosts);

  await friendsPanel.getByPlaceholder("Name").fill(`Harness${String.fromCharCode(1)}Peer`);
  await expect(friendsPanel.getByText("Friend name must not contain control characters.")).toBeVisible();
  await expect(addFriend).toBeDisabled();
  expect(requests.filter((request) => request.method === "POST" && request.path === "friends").length).toBe(initialFriendPosts);

  await friendsPanel.getByPlaceholder("Name").fill("Harness Peer");
  await expect(friendsPanel.getByText("User hash must be a 32-character lowercase hex string.")).toHaveCount(0);
  await expect(friendsPanel.getByText("Friend name must be at most 128 characters.")).toHaveCount(0);
  await expect(friendsPanel.getByText("Friend name must not contain control characters.")).toHaveCount(0);
  await addFriend.click();
  await expect(page.getByText("Friend added")).toBeVisible();
  const friendPost = requests.find((request) => request.method === "POST" && request.path === "friends");
  expect(friendPost).toBeDefined();
  expect(JSON.parse(friendPost?.body ?? "{}")).toEqual({ userHash: validHash, name: "Harness Peer" });
});

test("category names are validated and immutable while paths remain nullable", async ({ page }) => {
  const requests: RecordedApiRequest[] = [];
  await page.route("**/api/v1/**", installMockApi(requests));
  await page.goto("/");
  await page.getByRole("link", { name: "Categories" }).click();
  const panel = page.locator("section.panel").filter({ has: page.getByRole("heading", { name: "Categories" }) });
  const add = panel.getByRole("button", { name: "Add" });
  await expect(add).toBeDisabled();
  const name = panel.getByPlaceholder("Name");
  await name.fill("Média");
  await expect(add).toBeDisabled();
  await name.fill("Media Group");
  await expect(add).toBeDisabled();
  await name.fill(`A${"b".repeat(64)}`);
  await expect(add).toBeDisabled();
  expect(requests.filter((item) => item.method === "POST" && item.path === "categories")).toHaveLength(0);
  await name.fill("Media");
  await panel.getByPlaceholder("Temporary directory").fill("temp/media");
  await add.click();
  await expect(page.getByText("Category created")).toBeVisible();
  const request = requests.find((item) => item.method === "POST" && item.path === "categories");
  expect(JSON.parse(request?.body ?? "{}")).toEqual({ name: "Media", tempDir: "temp/media", destinationDir: null, comment: "" });

  const row = panel.locator("tbody tr", { hasText: "Sample-Category" });
  await expect(row.locator("td").first()).toHaveText("Sample-Category");
  const inputs = row.locator("input.form-control");
  await inputs.nth(0).fill("   ");
  await inputs.nth(1).fill("complete/sample");
  await inputs.nth(2).fill("Updated");
  await row.getByTitle("Save").click();
  await expect(page.getByText("Category saved")).toBeVisible();
  const patch = requests.find((item) => item.method === "PATCH" && item.path === "categories/Sample-Category");
  expect(JSON.parse(patch?.body ?? "{}")).toEqual({ tempDir: null, destinationDir: "complete/sample", comment: "Updated" });
});

test("shared file metadata form validates rating and priority contract", async ({ page }) => {
  const requests: RecordedApiRequest[] = [];
  await page.route("**/api/v1/**", installMockApi(requests));

  await page.goto("/");
  await page.getByRole("link", { name: "Library" }).click();
  const metadataPanel = page.locator("section.panel").filter({ has: page.getByRole("heading", { name: "Metadata" }) });
  await expect(metadataPanel.getByText("Published", { exact: true })).toBeVisible();
  await expect(metadataPanel.getByText("Partial", { exact: true })).toBeVisible();
  const epoch = await page.evaluate(() => new Date(0).toLocaleString());
  const success = await page.evaluate(() => new Date(1_700_000_000 * 1000).toLocaleString());
  await expect(metadataPanel.locator("dd").filter({ hasText: "1/2 keywords" })).toHaveAttribute("title", `Last confirmed success: ${epoch}`);
  await expect(metadataPanel.locator("dd").filter({ hasText: "Published" })).toHaveAttribute("title", `Sent to the connected server; eD2K servers do not acknowledge individual files. Last confirmed success: ${success}`);

  await expect(metadataPanel.getByText("Publishing", { exact: true })).toBeVisible();
  await expect(metadataPanel.getByText("Shared Sample.bin")).toBeVisible();
  await expect(metadataPanel.getByLabel("Upload priority").locator("option")).toHaveText(["Automatic", "Very low", "Low", "Normal", "High", "Release"]);
  const save = metadataPanel.getByRole("button", { name: "Save" });
  const initialSharedFilePatches = requests.filter((request) => request.method === "PATCH" && request.path.startsWith("library/files/")).length;

  await metadataPanel.getByLabel("Rating").fill("6");
  await expect(metadataPanel.getByText("Library file rating must be an integer between 0 and 5.")).toBeVisible();
  await expect(save).toBeDisabled();
  expect(requests.filter((request) => request.method === "PATCH" && request.path.startsWith("library/files/")).length).toBe(initialSharedFilePatches);

  await metadataPanel.getByLabel("Upload priority").selectOption("release");
  await metadataPanel.getByLabel("Rating").fill("5");
  await metadataPanel.getByLabel("Comment").fill("Verified release");
  await expect(metadataPanel.getByText("Library file rating must be an integer between 0 and 5.")).toHaveCount(0);
  await save.click();
  await expect(page.getByText("Library file metadata saved")).toBeVisible();
  const sharedFilePatch = requests.find((request) => request.method === "PATCH" && request.path.startsWith("library/files/"));
  expect(sharedFilePatch).toBeDefined();
  expect(JSON.parse(sharedFilePatch?.body ?? "{}")).toEqual({ uploadPriority: "release", comment: "Verified release", rating: 5 });
});

test("background updates preserve the Library query, page, and selection", async ({ page }) => {
  const requests: RecordedApiRequest[] = [];
  await page.route("**/api/v1/**", installMockApi(requests));

  await page.clock.install();
  await page.goto("/");
  await page.getByRole("link", { name: "Library" }).click();
  const panel = page.locator("section.panel").filter({ has: page.getByRole("heading", { name: "Library", exact: true }) });
  const filenameSearch = panel.getByLabel("Search filename");
  await filenameSearch.fill("é🙂");
  await expect(panel.getByRole("button", { name: "Search" })).toBeDisabled();
  await expect(panel.getByText("Enter at least 3 characters to search filenames.")).toBeVisible();
  await filenameSearch.fill("Shared Sample");
  await panel.getByRole("button", { name: "Search" }).click();
  await panel.getByLabel("View").selectOption("shared");
  await panel.getByRole("button", { name: "Next" }).click();
  await expect(panel.getByText("Second Shared Sample.bin", { exact: true })).toBeVisible();

  const requestCount = requests.filter((request) => request.path === "library/files").length;
  const snapshots = requests.filter((request) => request.path === "snapshot").length;
  await page.clock.fastForward(10_000);
  await expect.poll(() => requests.filter((request) => request.path === "snapshot").length).toBeGreaterThan(snapshots);
  expect(requests.filter((request) => request.path === "library/files")).toHaveLength(requestCount);

  const latest = requests.filter((request) => request.path === "library/files").at(-1);
  const params = new URLSearchParams(latest?.query ?? "");
  expect(params.get("cursor")).toBe("second-page");
  expect(params.get("q")).toBe("Shared Sample");
  expect(params.get("view")).toBe("shared");
  await expect(panel.getByText("Second Shared Sample.bin", { exact: true })).toBeVisible();
  await expect(page.locator("section.panel").filter({ has: page.getByRole("heading", { name: "Metadata" }) }).getByText("Second Shared Sample.bin")).toBeVisible();
});

test("library locations browse one cached copy page at a time", async ({ page }) => {
  const requests: RecordedApiRequest[] = [];
  await page.route("**/api/v1/**", installMockApi(requests));
  await page.goto("/");
  await page.getByRole("link", { name: "Library" }).click();
  const locations = page.locator("section.panel").filter({ has: page.getByRole("heading", { name: "Locations", exact: true }) });
  await expect(locations.getByText("/library/Cached-First.bin")).toBeVisible();
  await locations.getByRole("button", { name: "Next page" }).click();
  await expect(locations.getByText("/library/Cached-Second.bin")).toBeVisible();
  await expect(locations.getByText("/library/Cached-First.bin")).toHaveCount(0);
  await expect(locations.getByText("Unavailable", { exact: true })).toBeVisible();
  await expect(locations.getByRole("button", { name: "Next page" })).toBeDisabled();
  const latest = requests.filter((request) => request.path.endsWith("/locations")).at(-1);
  expect(new URLSearchParams(latest?.query ?? "").get("cursor")).toBe("location-next");
});

test("settings preserve modes, exact revisions and application status", async ({ page }) => {
  const requests: RecordedApiRequest[] = [];
  await page.route("**/api/v1/**", installMockApi(requests));
  await page.goto("/");
  await page.getByRole("link", { name: "Settings" }).click();
  const settingsPanel = page.locator("section.panel").filter({ has: page.getByRole("heading", { name: "Settings", exact: true }) });
  await expect(settingsPanel.getByRole("heading", { name: "Storage", exact: true })).toBeVisible();
  await expect(settingsPanel.getByRole("heading", { name: "Bootstrap REST" })).toBeVisible();
  await expect(settingsPanel.getByText("rest.api_key", { exact: true })).toBeVisible();
  const save = settingsPanel.getByRole("button", { name: "Save", exact: true });
  await expect(save).toBeDisabled();
  await settingsPanel.getByLabel("Use default for Connections · Max connections", { exact: true }).uncheck();
  const connections = settingsPanel.getByLabel("Connections · Max connections", { exact: true });
  await connections.fill("0");
  await expect(settingsPanel.getByText("Enter a whole number from 1 to 2147483647, in steps of 1.")).toBeVisible();
  await expect(save).toBeDisabled();
  await connections.fill("501");
  await settingsPanel.getByLabel("Use default for Incoming directory", { exact: true }).uncheck();
  await settingsPanel.getByLabel("Incoming directory", { exact: true }).fill("C:\\Changed\\Incoming");
  await settingsPanel.getByRole("button", { name: "Revert", exact: true }).click();
  await expect(save).toBeDisabled();
  await expect(settingsPanel.getByLabel("Incoming directory", { exact: true })).toHaveValue("incoming");
  await settingsPanel.getByLabel("Use default for Incoming directory", { exact: true }).uncheck();
  await settingsPanel.getByLabel("Incoming directory", { exact: true }).fill("C:\\Changed\\Incoming");
  await save.click();
  await expect(save).toBeDisabled();
  await expect(settingsPanel.getByText("Saved changes require a daemon restart.")).toBeVisible();
  await expect(settingsPanel.getByText("Running: incoming")).toBeVisible();
  const write = requests.find((request) => request.method === "PATCH" && request.path === "settings");
  expect(JSON.parse(write?.body ?? "{}")).toEqual({ expectedRevision: "9007199254740993", set: { storage: { incomingDirectory: "C:\\Changed\\Incoming" } } });
  await settingsPanel.getByLabel("Use default for Incoming directory", { exact: true }).check();
  await save.click();
  await expect.poll(() => requests.filter((request) => request.method === "PATCH" && request.path === "settings").length).toBe(2);
  const reset = requests.filter((request) => request.method === "PATCH" && request.path === "settings")[1];
  expect(JSON.parse(reset.body ?? "{}")).toEqual({ expectedRevision: "9007199254740994", reset: ["storage.incomingDirectory"] });
  await expect(settingsPanel.getByText("Saved changes require a daemon restart.")).toHaveCount(0);
  const metricValue = (label: string) => page.locator(".metric").filter({ has: page.getByText(label, { exact: true }) }).locator("strong");
  await settingsPanel.getByRole("button", { name: "Reload IP filter" }).click();
  await expect(page.getByText("IP filter reloaded")).toBeVisible();
  expect(requests.some((request) => request.method === "POST" && request.path === "ip-filter/operations/reload")).toBe(true);
  await settingsPanel.getByRole("button", { name: "Refresh NAT" }).click();
  await expect(page.getByText("NAT refresh completed")).toBeVisible();
  expect(requests.some((request) => request.method === "POST" && request.path === "nat/operations/refresh")).toBe(true);
  await settingsPanel.getByRole("button", { name: "Probe VPN Guard" }).click();
  await expect(page.getByText("VPN Guard probe completed")).toBeVisible();
  expect(requests.some((request) => request.method === "POST" && request.path === "vpn-guard/operations/probe")).toBe(true);

  await settingsPanel.getByRole("button", { name: "Open NAT" }).click();
  await expect(page.locator('[data-settings-section="nat"]')).toBeFocused();
  await settingsPanel.getByRole("button", { name: "Open VPN Guard" }).click();
  await expect(page.locator('[data-settings-section="vpnGuard"]')).toBeFocused();
  await settingsPanel.getByRole("button", { name: "Open IP Filter" }).click();
  await expect(page.locator('[data-settings-section="ipFilter"]')).toBeFocused();

  await settingsPanel.getByRole("button", { name: "Open Diagnostics" }).click();
  await expect(page.getByRole("heading", { name: "Diagnostics" })).toBeVisible();
  await expect(metricValue("Hashing")).toHaveText("1");
  await expect(metricValue("Reload")).toHaveText("hashing");
  await expect(metricValue("Hashed")).toHaveText("1/3");
  await expect(metricValue("eD2K Publish")).toHaveText("published");
  await expect(metricValue("Kad Publish")).toHaveText("waiting");
  await expect(metricValue("Event Stream")).toHaveText(/Connecting|Streaming|Reconnecting/);
  await expect(metricValue("Last Event")).toHaveText("sync.reset");
  await expect(metricValue("Last Event ID")).toHaveText("00000000-0000-4000-8000-000000000001:0");
  await expect(metricValue("SSE Subscribers")).toHaveText("1");
  await expect(metricValue("Event Queue")).toHaveText("0/1024");
  await expect(metricValue("Latest Bus Event")).toHaveText("0");
  await expect(metricValue("Resume")).toHaveText("reset");

  await page.getByRole("link", { name: "Settings" }).click();
  await settingsPanel.getByRole("button", { name: "Open Logs" }).click();
  await expect(page.getByRole("heading", { name: "Logs" })).toBeVisible();
});
