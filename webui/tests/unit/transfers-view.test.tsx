import { fireEvent, render, screen, waitFor } from "@testing-library/preact";
import { afterEach, describe, expect, it, vi } from "vitest";

import { RestClient, RestError, type DownloadSummary } from "../../src/api";
import { DownloadsView } from "../../src/views";

afterEach(() => {
  window.history.replaceState(null, "", "/");
});

describe("DownloadsView", () => {
  it.each([
    ["network", "Waiting for network"],
    ["sources", "Waiting for useful sources"],
    ["resources", "Waiting for resources"],
  ] as const)("shows the %s waiting reason from the canonical row", async (waitingReason, label) => {
    const client = new RestClient();
    vi.spyOn(client, "getPage").mockResolvedValue({ data: [{ ...job("1", "Sample.bin"), state: "queued", waitingReason }], meta: { apiVersion: "v1", nextCursor: null, hasMore: false } });
    render(<DownloadsView categories={[]} client={client} run={async (operation) => { await operation(); }} refreshGeneration={0} />);
    expect(await screen.findByText(label)).toBeVisible();
  });

  it("replaces the current page and preserves its cursor on refresh", async () => {
    const client = new RestClient();
    const getPage = vi.spyOn(client, "getPage").mockImplementation(async (path) => ({
      data: [job(path.includes("cursor=") ? "1" : "2", path.includes("cursor=") ? "Second page.bin" : "First page.bin")],
      meta: { apiVersion: "2.0.0", nextCursor: path.includes("cursor=") ? null : "opaque-cursor", hasMore: !path.includes("cursor=") },
    }));
    const props = { categories: [], client, run: async (operation: () => Promise<unknown>) => { await operation(); } };
    const { rerender } = render(<DownloadsView {...props} refreshGeneration={0} />);
    await screen.findByRole("button", { name: "First page.bin" });
    fireEvent.click(screen.getByRole("button", { name: "Next page" }));
    await screen.findByRole("button", { name: "Second page.bin" });
    expect(screen.queryByRole("button", { name: "First page.bin" })).not.toBeInTheDocument();
    expect(getPage).toHaveBeenLastCalledWith("downloads?view=unfinished&limit=100&cursor=opaque-cursor", expect.any(AbortSignal));
    rerender(<DownloadsView {...props} refreshGeneration={1} />);
    await waitFor(() => expect(getPage).toHaveBeenCalledTimes(3));
    expect(getPage).toHaveBeenLastCalledWith("downloads?view=unfinished&limit=100&cursor=opaque-cursor", expect.any(AbortSignal));
    fireEvent.input(screen.getByRole("combobox", { name: "Download view" }), { target: { value: "completed" } });
    await waitFor(() => expect(getPage).toHaveBeenLastCalledWith("downloads?view=completed&limit=100", expect.any(AbortSignal)));
  });

  it("selects distinct same-hash jobs by ID and ignores a late detail from the previous selection", async () => {
    const client = new RestClient();
    vi.spyOn(client, "getPage").mockImplementation(async (path) => ({
      data: path.startsWith("downloads?") ? [job("1", "First copy.bin"), job("2", "Second copy.bin")] : [],
      meta: { apiVersion: "2.0.0", nextCursor: null, hasMore: false },
    }));
    let first!: (value: unknown) => void;
    let second!: (value: unknown) => void;
    const get = vi.spyOn(client, "get").mockReturnValueOnce(new Promise((resolve) => { first = resolve; }))
      .mockReturnValueOnce(new Promise((resolve) => { second = resolve; }));
    render(<DownloadsView categories={[]} client={client} refreshGeneration={0} run={async (operation) => { await operation(); }} />);
    fireEvent.click(await screen.findByRole("button", { name: "First copy.bin" }));
    await waitFor(() => expect(get).toHaveBeenLastCalledWith("downloads/1", expect.any(AbortSignal)));
    fireEvent.click(screen.getByRole("button", { name: "Second copy.bin" }));
    await waitFor(() => expect(get).toHaveBeenLastCalledWith("downloads/2", expect.any(AbortSignal)));
    second({ ...job("2", "Current detail.bin"), payloadVerified: false, delivery: { path: null, state: "pending", ownership: "none" }, failure: null });
    await screen.findByText("Current detail.bin", { selector: ".section-title span" });
    first({ ...job("1", "Stale detail.bin"), payloadVerified: false, delivery: { path: null, state: "pending", ownership: "none" }, failure: null });
    await waitFor(() => expect(screen.queryByText("Stale detail.bin")).not.toBeInTheDocument());
    expect(screen.getByText("Current detail.bin", { selector: ".section-title span" })).toBeVisible();
  });

  it("keeps selected details visible while an overlapping refresh recovers from failure", async () => {
    const client = new RestClient();
    const download = job("1", "Sample.bin");
    const detail = { ...download, name: "Loaded detail.bin", payloadVerified: false, delivery: null, failure: null };
    vi.spyOn(client, "getPage").mockImplementation(async (path) => ({
      data: path.startsWith("downloads?") ? [download] : [],
      meta: { apiVersion: "2.0.0", nextCursor: null, hasMore: false },
    }));
    let fail!: (reason: Error) => void;
    let finish!: (value: unknown) => void;
    const get = vi.spyOn(client, "get").mockResolvedValueOnce(detail)
      .mockReturnValueOnce(new Promise((_, reject) => { fail = reject; }))
      .mockReturnValueOnce(new Promise((resolve) => { finish = resolve; }));
    const props = { categories: [], client, run: async (operation: () => Promise<unknown>) => { await operation(); } };
    const { rerender } = render(<DownloadsView {...props} refreshGeneration={0} />);
    fireEvent.click(await screen.findByRole("button", { name: "Sample.bin" }));
    await screen.findByText("Loaded detail.bin", { selector: ".section-title span" });
    rerender(<DownloadsView {...props} refreshGeneration={1} />);
    rerender(<DownloadsView {...props} refreshGeneration={2} />);
    expect(get).toHaveBeenCalledTimes(2);
    expect(screen.getByText("Loaded detail.bin", { selector: ".section-title span" })).toBeVisible();
    fail(new Error("Temporary detail failure"));
    expect(await screen.findByText(/Temporary detail failure/)).toBeVisible();
    expect(get).toHaveBeenCalledTimes(3);
    expect(screen.getByText("Loaded detail.bin", { selector: ".section-title span" })).toBeVisible();
    finish({ ...detail, name: "Updated detail.bin" });
    await screen.findByText("Updated detail.bin", { selector: ".section-title span" });
    expect(screen.queryByText(/Temporary detail failure/)).not.toBeInTheDocument();
  });

  it("assigns a category by name and clears it with null", async () => {
    const hash = "00112233445566778899aabbccddeeff";
    const client = new RestClient();
    vi.spyOn(client, "getPage").mockResolvedValue({ data: [{ id: "1", hash: "00112233445566778899aabbccddeeff", name: "Sample.bin", category: "Sample-Category", progress: 0, state: "stopped", intent: "stopped" }], meta: { apiVersion: "2.0.0", nextCursor: null, hasMore: false } });
    const patch = vi.spyOn(client, "patch").mockResolvedValue({});
    render(<DownloadsView
      refreshGeneration={0}
      categories={[
        { name: "Sample-Category", tempDir: null, destinationDir: null, comment: "" },
        { name: "Other-Category", tempDir: null, destinationDir: null, comment: "" }
      ]}
      client={client}
      run={async (operation) => { await operation(); }}
    />);

    const category = await screen.findByRole("combobox", { name: "Category for Sample.bin" });
    fireEvent.input(category, { target: { value: "Other-Category" } });
    await waitFor(() => expect(patch).toHaveBeenCalledWith("downloads/1", { category: "Other-Category" }));
    fireEvent.input(category, { target: { value: "" } });
    await waitFor(() => expect(patch).toHaveBeenLastCalledWith("downloads/1", { category: null }));
  });

  it("prefills an encoded external link, waits for submission and consumes the fragment", async () => {
    const link = "ed2k://|file|Sample%20%26%20Guide.bin|42|00112233445566778899aabbccddeeff|/";
    window.history.replaceState(null, "", `/downloads#ed2k=${encodeURIComponent(link)}`);
    const client = new RestClient();
    vi.spyOn(client, "getPage").mockResolvedValue({ data: [{ id: "1", hash: "00112233445566778899aabbccddeeff", name: "Sample.bin", category: "Sample-Category", progress: 0, state: "stopped", intent: "stopped" }], meta: { apiVersion: "2.0.0", nextCursor: null, hasMore: false } });
    const post = vi.spyOn(client, "post").mockResolvedValue({});
    render(<DownloadsView refreshGeneration={0} categories={[]} client={client} run={async (operation) => { await operation(); }} />);
    expect(screen.getByRole("textbox", { name: "eD2K links" })).toHaveValue(link);
    expect(post).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: "Add links" }));
    await waitFor(() => expect(post).toHaveBeenCalledOnce());
    expect(post).toHaveBeenCalledWith("downloads", { source: { type: "ed2k-link", link }, intent: "started", redownload: false });
    expect(window.location.hash).toBe("");
    await waitFor(() => expect(screen.getByRole("textbox", { name: "eD2K links" })).toHaveValue(""));
  });

  it("rejects ambiguous handoffs and cancels a later link without queuing anything", async () => {
    const link = "ed2k://|file|Sample.bin|42|00112233445566778899aabbccddeeff|/";
    window.history.replaceState(null, "", `/downloads#ed2k=${encodeURIComponent(link)}&ed2k=${encodeURIComponent(link)}`);
    const client = new RestClient();
    vi.spyOn(client, "getPage").mockResolvedValue({ data: [{ id: "1", hash: "00112233445566778899aabbccddeeff", name: "Sample.bin", category: "Sample-Category", progress: 0, state: "stopped", intent: "stopped" }], meta: { apiVersion: "2.0.0", nextCursor: null, hasMore: false } });
    const post = vi.spyOn(client, "post");
    render(<DownloadsView refreshGeneration={0} categories={[]} client={client} run={async (operation) => { await operation(); }} />);
    expect(screen.getByText("Unsupported or malformed eD2K file link")).toBeVisible();
    expect(screen.getByRole("textbox", { name: "eD2K links" })).toHaveValue("");
    window.history.replaceState(null, "", `/downloads#ed2k=${encodeURIComponent(link)}`);
    fireEvent(window, new Event("hashchange"));
    await waitFor(() => expect(screen.getByRole("textbox", { name: "eD2K links" })).toHaveValue(link));
    fireEvent.click(screen.getByRole("button", { name: "Cancel links" }));
    expect(window.location.hash).toBe("");
    expect(screen.getByRole("textbox", { name: "eD2K links" })).toHaveValue("");
    expect(post).not.toHaveBeenCalled();
  });

  it("retries a local-content choice only after redownload confirmation", async () => {
    const hash = "00112233445566778899aabbccddeeff";
    const link = `ed2k://|file|Sample.bin|1|${hash}|/`;
    const client = new RestClient();
    vi.spyOn(client, "getPage").mockResolvedValue({ data: [{ id: "1", hash: "00112233445566778899aabbccddeeff", name: "Sample.bin", category: "Sample-Category", progress: 0, state: "stopped", intent: "stopped" }], meta: { apiVersion: "2.0.0", nextCursor: null, hasMore: false } });
    const post = vi.spyOn(client, "post")
      .mockRejectedValueOnce(new RestError(
        "download conflict",
        409,
        "LOCAL_CONTENT_CHOICE_REQUIRED",
        { availability: "present" }
      ))
      .mockResolvedValueOnce({});
    const confirm = vi.spyOn(window, "confirm").mockReturnValue(true);

    render(
      <DownloadsView
        refreshGeneration={0}
        categories={[]}
        client={client}
        run={async (operation) => { await operation(); }}
      />
    );

    expect(screen.queryByRole("textbox", { name: "eD2K links" })).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Add eD2K links" }));
    fireEvent.input(screen.getByPlaceholderText("One eD2K link per line"), { target: { value: link } });
    fireEvent.click(screen.getByRole("button", { name: "Add links" }));

    await waitFor(() => expect(post).toHaveBeenCalledTimes(2));
    expect(post).toHaveBeenNthCalledWith(1, "downloads", { source: { type: "ed2k-link", link }, intent: "started", redownload: false });
    expect(post).toHaveBeenNthCalledWith(2, "downloads", { source: { type: "ed2k-link", link }, intent: "started", redownload: true });
    expect(confirm).toHaveBeenCalledTimes(1);
    confirm.mockRestore();
  });
});

function job(id: string, name: string): DownloadSummary {
  return { id, name, hash: "00112233445566778899aabbccddeeff", sizeBytes: 1, progress: 0,
    intent: "started", state: "queued", waitingReason: "sources", category: null, createdAt: 1, updatedAt: 1, completedAt: null };
}
