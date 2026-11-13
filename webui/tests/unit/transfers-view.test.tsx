import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/preact";
import { afterEach, describe, expect, it, vi } from "vitest";

import { RestClient, RestError } from "../../src/api";
import { TransfersView } from "../../src/views";

afterEach(() => {
  cleanup();
  window.history.replaceState(null, "", "/");
});

describe("TransfersView", () => {
  it("prefills an encoded external link, waits for submission and consumes the fragment", async () => {
    const link = "ed2k://|file|Sample%20%26%20Guide.bin|42|00112233445566778899aabbccddeeff|/";
    window.history.replaceState(null, "", `/transfers#ed2k=${encodeURIComponent(link)}`);
    const client = new RestClient();
    const post = vi.spyOn(client, "post").mockResolvedValue({});
    render(<TransfersView transfers={[]} categories={[]} client={client} run={async (operation) => { await operation(); }} />);
    expect(screen.getByRole("textbox", { name: "eD2K links" })).toHaveValue(link);
    expect(post).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: "Add links" }));
    await waitFor(() => expect(post).toHaveBeenCalledOnce());
    expect(post).toHaveBeenCalledWith("transfers", { links: [link], paused: false, knownFilePolicy: "reject" });
    expect(window.location.hash).toBe("");
    await waitFor(() => expect(screen.getByRole("textbox", { name: "eD2K links" })).toHaveValue(""));
  });

  it("rejects ambiguous handoffs and cancels a later link without queuing anything", async () => {
    const link = "ed2k://|file|Sample.bin|42|00112233445566778899aabbccddeeff|/";
    window.history.replaceState(null, "", `/transfers#ed2k=${encodeURIComponent(link)}&ed2k=${encodeURIComponent(link)}`);
    const client = new RestClient();
    const post = vi.spyOn(client, "post");
    render(<TransfersView transfers={[]} categories={[]} client={client} run={async (operation) => { await operation(); }} />);
    expect(screen.getByText("Unsupported or malformed eD2K file link")).toBeVisible();
    expect(screen.getByRole("textbox", { name: "eD2K links" })).toHaveValue("");
    window.history.replaceState(null, "", `/transfers#ed2k=${encodeURIComponent(link)}`);
    fireEvent(window, new Event("hashchange"));
    await waitFor(() => expect(screen.getByRole("textbox", { name: "eD2K links" })).toHaveValue(link));
    fireEvent.click(screen.getByRole("button", { name: "Cancel links" }));
    expect(window.location.hash).toBe("");
    expect(screen.getByRole("textbox", { name: "eD2K links" })).toHaveValue("");
    expect(post).not.toHaveBeenCalled();
  });

  it("uses reject first and retries only after redownload confirmation", async () => {
    const hash = "00112233445566778899aabbccddeeff";
    const link = `ed2k://|file|Sample.bin|1|${hash}|/`;
    const client = new RestClient();
    const post = vi.spyOn(client, "post")
      .mockRejectedValueOnce(new RestError(
        "download conflict",
        409,
        "DOWNLOAD_CONFLICT",
        {
          conflicts: [{
            hash,
            kind: "presentLocalFile",
            requestedName: "Sample.bin",
            requestedSizeBytes: 1,
            recordedName: "Sample.bin",
            recordedSizeBytes: 1,
            transferState: null,
            currentPaths: ["C:\\Downloads\\Sample.bin"],
            firstCompletedAtMs: null,
            lastCompletedAtMs: null,
            redownloadAllowed: true
          }]
        }
      ))
      .mockResolvedValueOnce({});
    const confirm = vi.spyOn(window, "confirm").mockReturnValue(true);

    render(
      <TransfersView
        transfers={[]}
        categories={[]}
        client={client}
        run={async (operation) => { await operation(); }}
      />
    );

    fireEvent.input(screen.getByPlaceholderText("One eD2K link per line"), { target: { value: link } });
    fireEvent.click(screen.getByRole("button", { name: "Add links" }));

    await waitFor(() => expect(post).toHaveBeenCalledTimes(2));
    expect(post).toHaveBeenNthCalledWith(1, "transfers", {
      links: [link],
      paused: false,
      knownFilePolicy: "reject"
    });
    expect(post).toHaveBeenNthCalledWith(2, "transfers", {
      links: [link],
      paused: false,
      knownFilePolicy: "redownload"
    });
    expect(confirm).toHaveBeenCalledTimes(1);
    confirm.mockRestore();
  });
});
