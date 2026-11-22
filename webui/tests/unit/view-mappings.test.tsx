import { fireEvent, render, screen, waitFor, within } from "@testing-library/preact";
import { afterEach, describe, expect, it, vi } from "vitest";

import { RestClient, RestError, type Upload } from "../../src/api";
import { uploadFixture, uploadScore } from "../fixtures/mockApi";
import { Overview, ServersView, SharingView, UploadsView } from "../../src/views";

afterEach(() => { vi.restoreAllMocks(); });

const run = async (operation: () => Promise<unknown>) => { await operation(); };

describe("canonical view mappings", () => {
  it("refreshes an expired queue cursor and keeps only the current page", async () => {
    const client = new RestClient();
    vi.spyOn(client, "get").mockResolvedValue({ id: "detail-peer" });
    let attempt = 0;
    const pages = vi.spyOn(client, "getPage").mockImplementation(async (path) => {
      if (path.startsWith("uploads?")) return { data: [], meta: { apiVersion: "v1", nextCursor: null, hasMore: false, total: 0 } };
      attempt++;
      if (attempt === 2) throw new RestError("upload queue cursor expired", 409, "CONFLICT");
      return { data: [uploadFixture({ address: attempt === 1 ? "192.0.2.1" : "192.0.2.2", uploadState: "queued", queueRank: 1 })],
        meta: { apiVersion: "v1", nextCursor: attempt === 1 ? "next-one" : null, hasMore: attempt === 1, total: attempt === 1 ? 3 : 2 } } as never;
    });
    render(<UploadsView refreshGeneration={0} client={client} run={run} />);
    const paging = within(screen.getByLabelText("Waiting upload pages"));
    await waitFor(() => expect(paging.getByRole("button", { name: "Next page" })).toBeEnabled());
    fireEvent.click(paging.getByRole("button", { name: "Next page" }));
    await waitFor(() => expect(screen.getByRole("button", { name: "192.0.2.2:4662" })).toBeInTheDocument());
    const queueCalls = pages.mock.calls.filter(([path]) => path.startsWith("upload-queue?"));
    expect(queueCalls).toHaveLength(3);
    expect(queueCalls[1][0]).toContain("cursor=next-one");
    expect(queueCalls[2][0]).toBe(queueCalls[0][0]);
    expect(screen.queryByRole("button", { name: "192.0.2.1:4662" })).not.toBeInTheDocument();
    expect(paging.getByRole("button", { name: "Next page" })).toBeDisabled();
  });
  it("shows runtime download work separately from retained history and total process memory", () => {
    render(<Overview snapshot={{ downloads: { unfinished: 1000, completed: 99000 } }} stats={{ downloadResources: {
      active: 17, preparing: 2, waiting: 981,
      concurrency: { mode: "fixed", configuredLimit: 16, target: 16, burstActive: 1 },
      residentMemory: { usedBytes: 33554432, softTargetBytes: 67108864, limitBytes: 134217728 }
    } }} transfers={[]} servers={[]} uploads={[]} uploadQueue={[]} libraryScan={null} kad={{}} />);
    expect(screen.getByText("17 active / 2 preparing / 981 waiting")).toBeVisible();
    expect(screen.getByText("1000 unfinished / 99000 completed")).toBeVisible();
    expect(screen.getByText("Configured limit 16")).toBeVisible();
    expect(screen.getByText("Active above target").nextElementSibling).toHaveTextContent("1");
    expect(screen.getByText(/separate from total daemon memory/)).toBeVisible();
  });

  it("opts a new root into watching without replacing other root choices", async () => {
    const client = new RestClient();
    const post = vi.spyOn(client, "post").mockResolvedValue({});
    const patch = vi.spyOn(client, "patch").mockResolvedValue({});
    vi.spyOn(client, "getPage").mockResolvedValue({ data: [], meta: { apiVersion: "v1", nextCursor: null, hasMore: false } });
    render(<SharingView refreshGeneration={0} directories={null} ignores={null} stats={{}} uploads={[]} uploadQueue={[]} client={client} run={run} />);
    expect(screen.getByLabelText("Watch for changes")).not.toBeChecked();
    fireEvent.input(screen.getByRole("textbox", { name: "Server folder path" }), { target: { value: "/new" } });
    fireEvent.click(screen.getByLabelText("Watch for changes"));
    fireEvent.click(screen.getByRole("button", { name: "Add root" }));
    await waitFor(() => expect(post).toHaveBeenCalledWith("library/roots", { path: "/new", watchEnabled: true }));
    expect(post).toHaveBeenCalledOnce();
    expect(patch).not.toHaveBeenCalled();
    await waitFor(() => expect(screen.getByLabelText("Watch for changes")).not.toBeChecked());
  });

  it("updates a managed root watch policy by its ID", async () => {
    const client = new RestClient();
    vi.spyOn(client, "getPage").mockResolvedValue({ data: [
      { id: "17", path: "/intake", watchEnabled: false, managed: true, accessible: true, shareable: true, scanRequired: true, lastScannedAt: null }
    ], meta: { apiVersion: "v1", nextCursor: null, hasMore: false } });
    const patch = vi.spyOn(client, "patch").mockResolvedValue({});
    render(<SharingView refreshGeneration={0} directories={null} ignores={null} stats={{}} uploads={[]} uploadQueue={[]} client={client} run={run} />);
    fireEvent.click(await screen.findByLabelText("Watch /intake"));
    expect(screen.getByText("Scan required")).toBeVisible();
    await waitFor(() => expect(patch).toHaveBeenCalledWith("library/roots/17", { watchEnabled: true }));
    expect(screen.queryByTitle("Remove")).not.toBeInTheDocument();
  });

  it("uses total shared-file diagnostics rather than a bounded snapshot page and does not invent shared bytes", () => {
    vi.spyOn(RestClient.prototype, "getPage").mockResolvedValue({ data: [], meta: { apiVersion: "v1", nextCursor: null, hasMore: false } });
    const { unmount } = render(<Overview snapshot={{ status: { runtimeDiagnostics: { sharedFileCount: 1001 } } }}
      stats={{ sharedFiles: 3, sharedBytes: 123 }} transfers={[]} servers={[]} uploads={[]} uploadQueue={[]} libraryScan={null} kad={{}} />);
    expect(screen.getByText("Shared").parentElement).toHaveTextContent("1001");
    expect(screen.getByText("Shared bytes").nextElementSibling).toHaveTextContent("n/a");
    unmount();
    render(<SharingView refreshGeneration={0} directories={null} ignores={null} stats={{ sharedFiles: 3, sharedBytes: 123 }}
      sharedFileCount={1001} uploads={[]} uploadQueue={[]} client={new RestClient()} run={run} />);
    expect(screen.getByText("Shared Files").parentElement).toHaveTextContent("1001");
    expect(screen.getByText("Shared Bytes").parentElement).toHaveTextContent("n/a");
  });

  it("pages active uploads and uses actual rate, duration and detail score fields", async () => {
    const client = new RestClient();
    const first = uploadFixture();
    const second = uploadFixture({ id: "second", address: "192.0.2.12" });
    vi.spyOn(client, "getPage").mockImplementation(async (path) => ({
      data: path.startsWith("upload-queue?") ? [] : [path.includes("cursor=") ? second : first],
      meta: { apiVersion: "v1", nextCursor: path.startsWith("uploads?") && !path.includes("cursor=") ? "next-active" : null,
        hasMore: path.startsWith("uploads?") && !path.includes("cursor="), total: path.startsWith("uploads?") ? 2 : 0 }
    }) as never);
    vi.spyOn(client, "get").mockResolvedValue(uploadFixture({ scoreBreakdown: { score: 123, creditRatio: 1,
      filePriorityScore: 1, lowRatioApplied: false, lowRatioBonus: 0,
      lowIdPenaltyApplied: false, lowIdDivisor: 1, oldClientPenaltyApplied: false } }));
    render(<UploadsView refreshGeneration={0} client={client} run={run} />);
    await waitFor(() => expect(screen.getByText("Score").nextElementSibling).toHaveTextContent("123"));
    expect(screen.getByText("Wait time").nextElementSibling).toHaveTextContent("12s");
    expect(screen.getByText("Upload duration").nextElementSibling).toHaveTextContent("3s");
    const paging = within(screen.getByLabelText("Active upload pages"));
    fireEvent.click(paging.getByRole("button", { name: "Next page" }));
    await screen.findByRole("button", { name: "192.0.2.12:4662" });
    expect(screen.queryByRole("button", { name: "192.0.2.10:4662" })).not.toBeInTheDocument();
  });

  it("ignores detail responses for a previously selected peer", async () => {
    const client = new RestClient();
    vi.spyOn(client, "getPage").mockImplementation(async (path) => ({
      data: path.startsWith("uploads?") ? [uploadFixture({ id: "first", address: "192.0.2.1" }), uploadFixture({ id: "second", address: "192.0.2.2" })] : [],
      meta: { apiVersion: "v1", nextCursor: null, hasMore: false }
    }) as never);
    let first!: (value: Upload) => void;
    let second!: (value: Upload) => void;
    vi.spyOn(client, "get").mockReturnValueOnce(new Promise<Upload>((done) => { first = done; }))
      .mockReturnValueOnce(new Promise<Upload>((done) => { second = done; }));
    render(<UploadsView refreshGeneration={0} client={client} run={run} />);
    await waitFor(() => expect(first).toBeDefined());
    fireEvent.click(await screen.findByRole("button", { name: "192.0.2.2:4662" }));
    second(uploadFixture({ id: "second", scoreBreakdown: uploadScore(200) }));
    first(uploadFixture({ id: "first", scoreBreakdown: uploadScore(999) }));
    await waitFor(() => expect(screen.getByText("score").parentElement).toHaveTextContent("200"));
    expect(screen.queryByText("999")).not.toBeInTheDocument();
  });

  it("offers one truthful server Disable action instead of pretending DELETE removes a retained row", async () => {
    const client = new RestClient();
    const patch = vi.spyOn(client, "patch").mockResolvedValue({ enabled: false });
    render(<ServersView servers={[{ endpoint: "192.0.2.1:4661", name: "Sample Server", enabled: true }]} status={{}} client={client} run={run} />);
    expect(screen.getAllByTitle("Disable")).toHaveLength(1);
    expect(screen.queryByTitle("Delete")).not.toBeInTheDocument();
    fireEvent.click(screen.getByTitle("Disable"));
    await waitFor(() => expect(patch).toHaveBeenCalledOnce());
    expect(patch).toHaveBeenCalledWith("servers/192.0.2.1%3A4661", { enabled: false });
  });
});
