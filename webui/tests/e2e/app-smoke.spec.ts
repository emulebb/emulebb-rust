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
  expect(requests.some((request) => request.method === "GET" && request.path === "events/status")).toBe(true);

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

test("search create form uses REST-native type tokens", async ({ page }) => {
  const requests: RecordedApiRequest[] = [];
  await page.route("**/api/v1/**", installMockApi(requests));

  await page.goto("/");
  await page.getByRole("button", { name: "Search" }).click();
  const searchPanel = page.locator("section.panel").filter({ has: page.getByRole("heading", { name: "Search" }) });
  const startSearch = searchPanel.getByRole("button", { name: "Start" });
  const initialSearchPosts = requests.filter((request) => request.method === "POST" && request.path === "searches").length;

  await expect(startSearch).toBeDisabled();
  await searchPanel.getByPlaceholder("Search query").fill("a".repeat(161));
  await expect(searchPanel.getByText("Search query must be at most 160 characters.")).toBeVisible();
  await expect(startSearch).toBeDisabled();
  expect(requests.filter((request) => request.method === "POST" && request.path === "searches").length).toBe(initialSearchPosts);

  await searchPanel.getByPlaceholder("Search query").fill(" alpha   beta ");
  await searchPanel.locator("select").nth(0).selectOption("kad");
  await searchPanel.locator("select").nth(1).selectOption("arc");
  await expect(searchPanel.getByText("Search query must be at most 160 characters.")).toHaveCount(0);
  await startSearch.click();
  await expect(page.getByText("Search started")).toBeVisible();
  const searchPost = requests.find((request) => request.method === "POST" && request.path === "searches");
  expect(searchPost).toBeDefined();
  expect(JSON.parse(searchPost?.body ?? "{}")).toEqual({ query: "alpha beta", method: "kad", type: "arc" });
});

test("shared folder add form validates root paths", async ({ page }) => {
  const requests: RecordedApiRequest[] = [];
  await page.route("**/api/v1/**", installMockApi(requests));

  await page.goto("/");
  await page.getByRole("button", { name: "Sharing" }).click();
  const sharingPanel = page.locator("section.panel").filter({ has: page.getByRole("heading", { name: "Shared Folders" }) });
  const addFolder = sharingPanel.getByRole("button", { name: "Add" });
  const initialSharedDirectoryPatches = requests.filter((request) => request.method === "PATCH" && request.path === "shared-directories").length;

  await expect(addFolder).toBeDisabled();
  await sharingPanel.getByPlaceholder("Folder path").fill("   ");
  await expect(sharingPanel.getByText("Folder path must not be empty.")).toBeVisible();
  await expect(addFolder).toBeDisabled();
  expect(requests.filter((request) => request.method === "PATCH" && request.path === "shared-directories").length).toBe(initialSharedDirectoryPatches);

  await sharingPanel.getByPlaceholder("Folder path").fill(" C:\\More\\Shared ");
  await expect(sharingPanel.getByText("Folder path must not be empty.")).toHaveCount(0);
  await addFolder.click();
  await expect(page.getByText("Folder added")).toBeVisible();
  const sharedDirectoryPatch = requests.find((request) => request.method === "PATCH" && request.path === "shared-directories");
  expect(sharedDirectoryPatch).toBeDefined();
  expect(JSON.parse(sharedDirectoryPatch?.body ?? "{}")).toEqual({
    roots: [{ path: "C:\\Sample\\Shared" }, { path: "C:\\More\\Shared" }],
    confirmReplaceRoots: true
  });
});

test("transfer add form validates eD2K link batches", async ({ page }) => {
  const requests: RecordedApiRequest[] = [];
  await page.route("**/api/v1/**", installMockApi(requests));

  await page.goto("/");
  await page.getByRole("button", { name: "Transfers" }).click();
  const transfersPanel = page.locator("section.panel").filter({ has: page.getByRole("heading", { name: "Transfers" }) });
  const linkInput = transfersPanel.getByPlaceholder("One eD2K link per line");
  const addLinks = transfersPanel.getByRole("button", { name: "Add links" });
  const initialTransferPosts = requests.filter((request) => request.method === "POST" && request.path === "transfers").length;
  const invalidLinkError = "Each transfer link must start with ed2k://, contain no whitespace, and be at most 2048 characters.";

  await linkInput.fill("http://example.invalid/file");
  await expect(transfersPanel.getByText(invalidLinkError)).toBeVisible();
  await expect(addLinks).toBeDisabled();
  expect(requests.filter((request) => request.method === "POST" && request.path === "transfers").length).toBe(initialTransferPosts);

  const validLink = "ed2k://|file|Sample.bin|1|00112233445566778899aabbccddeeff|/";
  await linkInput.fill(Array.from({ length: 101 }, () => validLink).join("\n"));
  await expect(transfersPanel.getByText("Add links accepts at most 100 eD2K links.")).toBeVisible();
  await expect(addLinks).toBeDisabled();
  expect(requests.filter((request) => request.method === "POST" && request.path === "transfers").length).toBe(initialTransferPosts);

  await linkInput.fill(validLink);
  await expect(transfersPanel.getByText(invalidLinkError)).toHaveCount(0);
  await expect(transfersPanel.getByText("Add links accepts at most 100 eD2K links.")).toHaveCount(0);
  await addLinks.click();
  await expect(page.getByText("Transfers queued")).toBeVisible();
  const transferPost = requests.find((request) => request.method === "POST" && request.path === "transfers");
  expect(transferPost).toBeDefined();
  expect(JSON.parse(transferPost?.body ?? "{}")).toEqual({ links: [validLink], paused: false });
});

test("section resource operation forms validate endpoint addresses and ports", async ({ page }) => {
  const requests: RecordedApiRequest[] = [];
  await page.route("**/api/v1/**", installMockApi(requests));

  await page.goto("/");

  await page.getByRole("button", { name: "Servers" }).click();
  const serversPanel = page.locator("section.panel").filter({ has: page.getByRole("heading", { name: "Servers" }) });
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

  await page.getByRole("button", { name: "Kad" }).click();
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

  await page.getByRole("button", { name: "Servers" }).click();
  const serversPanel = page.locator("section.panel").filter({ has: page.getByRole("heading", { name: "Servers" }) });
  const serverImportButton = serversPanel.getByRole("button", { name: "Import" });
  const initialServerImportPosts = requests.filter((request) => request.method === "POST" && request.path === "servers/operations/import-met-url").length;
  const urlImportError = "must start with http:// or https://, include a host, contain no whitespace, and be at most 2048 characters.";
  const serverUrlError = `server.met URL ${urlImportError}`;
  const kadUrlError = `nodes.dat URL ${urlImportError}`;
  await expect(serverImportButton).toBeDisabled();
  await serversPanel.getByPlaceholder("server.met URL").fill("ftp://example.invalid/server.met");
  await expect(serversPanel.getByText(serverUrlError)).toBeVisible();
  await expect(serverImportButton).toBeDisabled();
  expect(requests.filter((request) => request.method === "POST" && request.path === "servers/operations/import-met-url").length).toBe(initialServerImportPosts);
  await serversPanel.getByPlaceholder("server.met URL").fill(" HTTPS://example.invalid/server.met ");
  await expect(serversPanel.getByText(serverUrlError)).toHaveCount(0);
  await serverImportButton.click();
  await expect(page.getByText("Server list import started")).toBeVisible();
  const serverImportPost = requests.find((request) => request.method === "POST" && request.path === "servers/operations/import-met-url");
  expect(serverImportPost).toBeDefined();
  expect(JSON.parse(serverImportPost?.body ?? "{}")).toEqual({ url: "HTTPS://example.invalid/server.met" });

  await page.getByRole("button", { name: "Kad" }).click();
  const kadPanel = page.locator("section.panel").filter({ has: page.getByRole("heading", { name: "Kad" }) });
  const kadImportButton = kadPanel.getByRole("button", { name: "Import" });
  const initialKadImportPosts = requests.filter((request) => request.method === "POST" && request.path === "kad/operations/import-nodes-url").length;
  await expect(kadImportButton).toBeDisabled();
  await kadPanel.getByPlaceholder("nodes.dat URL").fill("https:///nodes.dat");
  await expect(kadPanel.getByText(kadUrlError)).toBeVisible();
  await expect(kadImportButton).toBeDisabled();
  expect(requests.filter((request) => request.method === "POST" && request.path === "kad/operations/import-nodes-url").length).toBe(initialKadImportPosts);
  await kadPanel.getByPlaceholder("nodes.dat URL").fill("http://example.invalid/nodes.dat");
  await expect(kadPanel.getByText(kadUrlError)).toHaveCount(0);
  await kadImportButton.click();
  await expect(page.getByText("Kad nodes import started")).toBeVisible();
  const kadImportPost = requests.find((request) => request.method === "POST" && request.path === "kad/operations/import-nodes-url");
  expect(kadImportPost).toBeDefined();
  expect(JSON.parse(kadImportPost?.body ?? "{}")).toEqual({ url: "http://example.invalid/nodes.dat" });
});

test("friend create form validates hash and name", async ({ page }) => {
  const requests: RecordedApiRequest[] = [];
  await page.route("**/api/v1/**", installMockApi(requests));

  await page.goto("/");
  await page.getByRole("button", { name: "Friends" }).click();
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

test("category forms validate names and priority inputs", async ({ page }) => {
  const requests: RecordedApiRequest[] = [];
  await page.route("**/api/v1/**", installMockApi(requests));

  await page.goto("/");
  await page.getByRole("button", { name: "Categories" }).click();
  const categoriesPanel = page.locator("section.panel").filter({ has: page.getByRole("heading", { name: "Categories" }) });
  const addCategory = categoriesPanel.getByRole("button", { name: "Add" });
  const initialCategoryPosts = requests.filter((request) => request.method === "POST" && request.path === "categories").length;
  const initialCategoryPatches = requests.filter((request) => request.method === "PATCH" && request.path === "categories/1").length;

  await expect(addCategory).toBeDisabled();
  await categoriesPanel.getByPlaceholder("Name").fill("   ");
  await expect(categoriesPanel.getByText("Category name must not be empty.")).toBeVisible();
  await expect(addCategory).toBeDisabled();
  expect(requests.filter((request) => request.method === "POST" && request.path === "categories").length).toBe(initialCategoryPosts);
  await categoriesPanel.getByPlaceholder("Name").fill("Media");
  await categoriesPanel.locator("select").selectOption("verylow");
  await addCategory.click();
  await expect(page.getByText("Category created")).toBeVisible();
  const categoryPost = requests.find((request) => request.method === "POST" && request.path === "categories");
  expect(categoryPost).toBeDefined();
  expect(JSON.parse(categoryPost?.body ?? "{}")).toMatchObject({ name: "Media", priority: "verylow" });

  const categoryRow = categoriesPanel.locator("tbody tr").first();
  const rowInputs = categoryRow.locator("input.form-control");
  await rowInputs.nth(3).fill("auto");
  await expect(categoryRow.getByText("Category priority must be verylow, low, normal, high, veryhigh, or a u32 number.")).toBeVisible();
  await expect(categoryRow.getByTitle("Save")).toBeDisabled();
  expect(requests.filter((request) => request.method === "PATCH" && request.path === "categories/1").length).toBe(initialCategoryPatches);
  await rowInputs.nth(3).fill("4294967295");
  await expect(categoryRow.getByText("Category priority must be verylow, low, normal, high, veryhigh, or a u32 number.")).toHaveCount(0);
  await categoryRow.getByTitle("Save").click();
  await expect(page.getByText("Category saved")).toBeVisible();
  const categoryPatch = requests.find((request) => request.method === "PATCH" && request.path === "categories/1");
  expect(categoryPatch).toBeDefined();
  expect(JSON.parse(categoryPatch?.body ?? "{}").priority).toBe(4294967295);
});

test("shared file metadata form validates rating and priority contract", async ({ page }) => {
  const requests: RecordedApiRequest[] = [];
  await page.route("**/api/v1/**", installMockApi(requests));

  await page.goto("/");
  await page.getByRole("button", { name: "Shared Files" }).click();
  const metadataPanel = page.locator("section.panel").filter({ has: page.getByRole("heading", { name: "Metadata" }) });
  await expect(metadataPanel.getByText("Shared Sample.bin")).toBeVisible();
  await expect(metadataPanel.getByRole("option", { name: "Very high" })).toHaveCount(0);
  const save = metadataPanel.getByRole("button", { name: "Save" });
  const initialSharedFilePatches = requests.filter((request) => request.method === "PATCH" && request.path.startsWith("shared-files/")).length;

  await metadataPanel.getByLabel("Rating").fill("6");
  await expect(metadataPanel.getByText("Shared file rating must be an integer between 0 and 5.")).toBeVisible();
  await expect(save).toBeDisabled();
  expect(requests.filter((request) => request.method === "PATCH" && request.path.startsWith("shared-files/")).length).toBe(initialSharedFilePatches);

  await metadataPanel.getByLabel("Priority").selectOption("release");
  await metadataPanel.getByLabel("Rating").fill("5");
  await metadataPanel.getByLabel("Comment").fill("Verified release");
  await expect(metadataPanel.getByText("Shared file rating must be an integer between 0 and 5.")).toHaveCount(0);
  await save.click();
  await expect(page.getByText("Shared file metadata saved")).toBeVisible();
  const sharedFilePatch = requests.find((request) => request.method === "PATCH" && request.path.startsWith("shared-files/"));
  expect(sharedFilePatch).toBeDefined();
  expect(JSON.parse(sharedFilePatch?.body ?? "{}")).toEqual({ priority: "release", comment: "Verified release", rating: 5 });
});

test("settings use dirty state and advanced surface metadata", async ({ page }) => {
  const requests: RecordedApiRequest[] = [];
  await page.route("**/api/v1/**", installMockApi(requests));

  await page.goto("/");
  await page.getByRole("button", { name: "Settings" }).click();
  const settingsPanel = page.locator("section.panel").filter({ has: page.getByRole("heading", { name: "Settings" }) });

  await expect(settingsPanel.getByRole("heading", { name: "Storage" })).toBeVisible();
  await expect(settingsPanel.getByRole("heading", { name: "Bootstrap REST" })).toBeVisible();
  await expect(settingsPanel.getByText("rest.bindAddr")).toBeVisible();
  await expect(settingsPanel.getByText("rest.apiKey")).toBeVisible();
  await expect(settingsPanel.getByText("emulebb-rust-settings.toml").first()).toBeVisible();
  await expect(settingsPanel.getByRole("heading", { name: "Transfers" })).toBeVisible();
  await expect(settingsPanel.getByRole("heading", { name: "Network" })).toBeVisible();
  await expect(settingsPanel.getByRole("heading", { name: "VPN Guard" })).toBeVisible();

  await expect(settingsPanel.getByText("Max connections")).toHaveCount(0);
  await expect(settingsPanel.getByText("eD2K half-open connections")).toHaveCount(0);
  await expect(settingsPanel.getByText("Concurrent downloads")).toHaveCount(0);
  await expect(settingsPanel.getByText("Keyword server attempts")).toHaveCount(0);
  await expect(settingsPanel.getByText("Server connect timeout seconds")).toHaveCount(0);
  await expect(settingsPanel.getByText("Startup upload slots")).toHaveCount(0);
  await expect(settingsPanel.getByText("Bootstrap contact floor")).toHaveCount(0);
  await expect(settingsPanel.getByText("Discovery timeout seconds")).toHaveCount(0);
  await settingsPanel.getByLabel(/Advanced/).check();
  await expect(settingsPanel.getByLabel("Max connections")).toBeVisible();
  await expect(settingsPanel.getByLabel("eD2K half-open connections")).toBeVisible();
  await expect(settingsPanel.getByLabel("Concurrent downloads")).toBeVisible();
  await expect(settingsPanel.getByLabel("Keyword server attempts")).toBeVisible();
  await expect(settingsPanel.getByLabel("Server connect timeout seconds")).toBeVisible();
  await expect(settingsPanel.getByLabel("Startup upload slots")).toBeVisible();
  await expect(settingsPanel.getByLabel("Bootstrap contact floor")).toBeVisible();
  await expect(settingsPanel.getByLabel("DNS tick seconds")).toBeVisible();
  await expect(settingsPanel.getByLabel("Discovery timeout seconds")).toBeVisible();

  const save = settingsPanel.getByRole("button", { name: "Save" });
  const revert = settingsPanel.getByRole("button", { name: "Revert" });
  await expect(save).toBeDisabled();
  await expect(revert).toBeDisabled();

  await settingsPanel.getByLabel("Max connections").fill("2147483648");
  await expect(settingsPanel.getByText("Max connections must be between 1 and 2147483647.")).toBeVisible();
  await expect(save).toBeDisabled();
  await settingsPanel.getByLabel("Max connections").fill("500");
  await expect(settingsPanel.getByText("Max connections must be between 1 and 2147483647.")).toHaveCount(0);
  await settingsPanel.getByLabel("eD2K listen port").fill("70000");
  await expect(settingsPanel.getByText("eD2K listen port must be between 1 and 65535.")).toBeVisible();
  await expect(save).toBeDisabled();
  await settingsPanel.getByLabel("eD2K listen port").fill("4662");
  await expect(settingsPanel.getByText("eD2K listen port must be between 1 and 65535.")).toHaveCount(0);
  await settingsPanel.getByLabel("DNS tick seconds").fill("4");
  await expect(settingsPanel.getByText("DNS tick seconds must be at least 5.")).toBeVisible();
  await expect(save).toBeDisabled();
  await settingsPanel.getByLabel("DNS tick seconds").fill("30");
  await expect(settingsPanel.getByText("DNS tick seconds must be at least 5.")).toHaveCount(0);
  await settingsPanel.getByLabel("P2P bind IP").fill("not-an-ip");
  await expect(settingsPanel.getByText("P2P bind IP must be an IPv4 address.")).toBeVisible();
  await expect(save).toBeDisabled();
  await settingsPanel.getByLabel("P2P bind IP").fill("192.0.2.10");
  await expect(settingsPanel.getByText("P2P bind IP must be an IPv4 address.")).toHaveCount(0);
  await settingsPanel.getByLabel("UDP firewall interval seconds").fill("59");
  await expect(settingsPanel.getByText("UDP firewall interval seconds must be at least 60.")).toBeVisible();
  await expect(save).toBeDisabled();
  await settingsPanel.getByLabel("UDP firewall interval seconds").fill("3600");
  await expect(settingsPanel.getByText("UDP firewall interval seconds must be at least 60.")).toHaveCount(0);
  await settingsPanel.getByLabel("Dead server retries").fill("11");
  await expect(settingsPanel.getByText("Dead server retries must be between 1 and 10.")).toBeVisible();
  await expect(save).toBeDisabled();
  await settingsPanel.getByLabel("Dead server retries").fill("1");
  await expect(settingsPanel.getByText("Dead server retries must be between 1 and 10.")).toHaveCount(0);
  await settingsPanel.getByLabel("Startup upload slots").fill("0");
  await expect(settingsPanel.getByText("Startup upload slots must be between 1 and 64.")).toBeVisible();
  await expect(save).toBeDisabled();
  await settingsPanel.getByLabel("Startup upload slots").fill("3");
  await expect(settingsPanel.getByText("Startup upload slots must be between 1 and 64.")).toHaveCount(0);
  await settingsPanel.getByLabel("NAT bind IP").fill("not-an-ip");
  await expect(settingsPanel.getByText("NAT bind IP must be an IPv4 address.")).toBeVisible();
  await expect(save).toBeDisabled();
  await settingsPanel.getByLabel("NAT bind IP").fill("192.0.2.11");
  await expect(settingsPanel.getByText("NAT bind IP must be an IPv4 address.")).toHaveCount(0);
  await settingsPanel.getByLabel("Allowed public CIDRs").fill("192.0.2.0/24");
  await expect(settingsPanel.getByText("Allowed public CIDRs must contain only public IPv4 CIDRs or host addresses.")).toBeVisible();
  await expect(save).toBeDisabled();
  await settingsPanel.getByLabel("Allowed public CIDRs").fill("8.8.8.0/24 1.1.1.1");
  await expect(settingsPanel.getByText("Allowed public CIDRs must contain only public IPv4 CIDRs or host addresses.")).toHaveCount(0);
  await settingsPanel.getByLabel("Concurrent downloads").fill("0");
  await settingsPanel.getByLabel("eD2K new connections / 5s").fill("0");
  await settingsPanel.getByLabel("eD2K half-open connections").fill("0");
  await settingsPanel.getByLabel("eD2K source cap").fill("0");
  await settingsPanel.getByLabel("eD2K keepalive seconds").fill("0");
  await settingsPanel.getByLabel("Waiting queue capacity").fill("0");
  await settingsPanel.getByLabel("Session transfer %").fill("0");
  await settingsPanel.getByLabel("Session time limit seconds").fill("0");
  await expect(save).toBeEnabled();
  await expect(settingsPanel.getByText("Concurrent downloads must be at least 1.")).toHaveCount(0);
  await expect(settingsPanel.getByText("eD2K new connections / 5s must be at least 1.")).toHaveCount(0);
  await expect(settingsPanel.getByText("eD2K half-open connections must be at least 1.")).toHaveCount(0);
  await expect(settingsPanel.getByText("eD2K source cap must be at least 1.")).toHaveCount(0);
  await expect(settingsPanel.getByText("eD2K keepalive seconds must be at least 1.")).toHaveCount(0);
  await expect(settingsPanel.getByText("Waiting queue capacity must be at least 1.")).toHaveCount(0);
  await expect(settingsPanel.getByText("Session transfer % must be between 1 and 100.")).toHaveCount(0);
  await expect(settingsPanel.getByText("Session time limit seconds must be at least 1.")).toHaveCount(0);
  await revert.click();
  await expect(save).toBeDisabled();
  const metricValue = (label: string) => page.locator(".metric").filter({ has: page.getByText(label, { exact: true }) }).locator("strong");
  await expect(metricValue("Bind")).toHaveText("resolved");
  await expect(metricValue("Interface")).toHaveText("Test Adapter");
  await expect(metricValue("NAT")).toHaveText("Enabled");
  await expect(metricValue("Gateway")).toHaveText("Discovered");
  await expect(metricValue("Mappings")).toHaveText("2");
  await expect(metricValue("Guard")).toHaveText("Enabled");
  await expect(metricValue("Egress")).toHaveText("Verified 203.0.113.10");
  await expect(metricValue("Configured")).toHaveText("Yes");
  await expect(metricValue("Reloadable")).toHaveText("Yes");
  await expect(metricValue("Ranges")).toHaveText("3");
  await expect(settingsPanel.getByLabel("VPN Guard mode")).toHaveValue("block");

  await settingsPanel.getByLabel("Incoming directory").fill("C:\\Changed\\Incoming");
  await expect(save).toBeEnabled();
  await expect(revert).toBeEnabled();

  await revert.click();
  await expect(settingsPanel.getByLabel("Incoming directory")).toHaveValue("C:\\Sample\\Incoming");
  await expect(save).toBeDisabled();

  await settingsPanel.getByLabel("Incoming directory").fill("C:\\Changed\\Incoming");
  await save.click();
  await expect(page.getByText("Settings saved; restart daemon for bind, port, NAT, VPN, and filter changes")).toBeVisible();
  const settingsPatch = requests.find((request) => request.method === "PATCH" && request.path === "app/settings");
  expect(settingsPatch).toBeDefined();
  expect(JSON.parse(settingsPatch?.body ?? "{}")).toEqual({ daemon: { incomingDir: "C:\\Changed\\Incoming" } });
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
  await expect(metricValue("Last Event ID")).toHaveText("1");
  await expect(metricValue("SSE Subscribers")).toHaveText("1");
  await expect(metricValue("Event Queue")).toHaveText("1/1024");
  await expect(metricValue("Latest Bus Event")).toHaveText("1");
  await expect(metricValue("Resume")).toHaveText("reset");

  await page.getByRole("button", { name: "Settings" }).click();
  await settingsPanel.getByRole("button", { name: "Open Logs" }).click();
  await expect(page.getByRole("heading", { name: "Logs" })).toBeVisible();
});
