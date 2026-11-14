import { fireEvent, render, screen, waitFor } from "@testing-library/preact";
import { afterEach, describe, expect, it, vi } from "vitest";

import { RestClient, type Upload } from "../../src/api";
import { Overview, ServersView, SharingView, UploadsView } from "../../src/views";

afterEach(() => { vi.restoreAllMocks(); });

const run = async (operation: () => Promise<unknown>) => { await operation(); };

describe("canonical view mappings", () => {
  it("uses total shared-file diagnostics rather than a bounded snapshot page and does not invent shared bytes", () => {
    const { unmount } = render(<Overview snapshot={{ status: { runtimeDiagnostics: { sharedFileCount: 1001 } } }}
      stats={{ sharedFiles: 3, sharedBytes: 123 }} transfers={[]} servers={[]} uploads={[]} uploadQueue={[]}
      sharedFiles={[{ hash: "synthetic", path: "/sample/shared.bin" }]} sharedDirectories={null} kad={{}} />);
    expect(screen.getByText("Shared").parentElement).toHaveTextContent("1001");
    expect(screen.getByText("Shared bytes").nextElementSibling).toHaveTextContent("n/a");
    unmount();
    render(<SharingView directories={null} ignores={null} stats={{ sharedFiles: 3, sharedBytes: 123 }}
      sharedFileCount={1001} sharedFiles={[{ hash: "synthetic", path: "/sample/shared.bin" }]} uploads={[]} uploadQueue={[]} client={new RestClient()} run={run} />);
    expect(screen.getByText("Shared Files").parentElement).toHaveTextContent("1001");
    expect(screen.getByText("Shared Bytes").parentElement).toHaveTextContent("n/a");
  });

  it("keeps a pending detail request across recreated snapshots and leaves live list fields current", async () => {
    const client = new RestClient();
    let resolve!: (value: Upload) => void;
    const get = vi.spyOn(client, "get").mockReturnValue(new Promise<Upload>((done) => { resolve = done; }));
    const { rerender } = render(<UploadsView uploads={[{ clientId: "sample-peer", userName: "Original Peer" }]} uploadQueue={[]} client={client} run={run} />);
    await waitFor(() => expect(get).toHaveBeenCalledWith("uploads/sample-peer"));
    rerender(<UploadsView uploads={[{ clientId: "sample-peer", userName: "Refreshed Peer" }]} uploadQueue={[]} client={client} run={run} />);
    resolve({ clientId: "sample-peer", userName: "Older Detail Name", scoreBreakdown: { baseScore: 123 } });
    await waitFor(() => expect(screen.getByText("baseScore").parentElement).toHaveTextContent("123"));
    expect(get).toHaveBeenCalledOnce();
    expect(screen.getByRole("heading", { name: "Peer Slot Inspector" }).parentElement).toHaveTextContent("Refreshed Peer");
    expect(screen.queryByText("Older Detail Name")).not.toBeInTheDocument();
    expect(screen.queryByText("Friend", { exact: true })).not.toBeInTheDocument();
    expect(screen.queryByText("Banned", { exact: true })).not.toBeInTheDocument();
  });

  it("ignores detail responses for a previously selected peer", async () => {
    const client = new RestClient();
    let first!: (value: Upload) => void;
    let second!: (value: Upload) => void;
    vi.spyOn(client, "get").mockReturnValueOnce(new Promise<Upload>((done) => { first = done; }))
      .mockReturnValueOnce(new Promise<Upload>((done) => { second = done; }));
    render(<UploadsView uploads={[{ clientId: "first", userName: "First Peer" }, { clientId: "second", userName: "Second Peer" }]}
      uploadQueue={[]} client={client} run={run} />);
    fireEvent.click(screen.getByRole("button", { name: "Second Peer" }));
    second({ clientId: "second", scoreBreakdown: { baseScore: 200 } });
    first({ clientId: "first", scoreBreakdown: { baseScore: 999 } });
    await waitFor(() => expect(screen.getByText("baseScore").parentElement).toHaveTextContent("200"));
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
