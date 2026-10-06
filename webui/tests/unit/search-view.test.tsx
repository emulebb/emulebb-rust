import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/preact";
import { afterEach, describe, expect, it, vi } from "vitest";

import { RestClient, type SearchItem } from "../../src/api";
import { SearchView } from "../../src/views";

afterEach(cleanup);

describe("SearchView", () => {
  it("shows the exact result window and requests adjacent pages", () => {
    const selectSearchPage = vi.fn();
    const search: SearchItem = {
      id: "7",
      query: "linux",
      status: "completed",
      resultCount: 250,
      total: 250,
      offset: 100,
      limit: 100,
      items: [
        { hash: "00112233445566778899aabbccddeeff", name: "Result 101.bin" },
        { hash: "ffeeddccbbaa99887766554433221100", name: "Result 102.bin" }
      ]
    };

    render(
      <SearchView
        searches={[search]}
        selectedSearch={search}
        selectedSearchId="7"
        categories={[]}
        client={new RestClient()}
        run={async () => {}}
        selectSearch={() => {}}
        searchSort="sources"
        searchOrder="desc"
        selectSearchSort={() => {}}
        selectSearchPage={selectSearchPage}
        onSearchCreated={() => {}}
        onSearchDeleted={() => {}}
        onSearchesCleared={() => {}}
      />
    );

    expect(screen.getByText("Showing 101–102 of 250 results")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Previous search results page" }));
    fireEvent.click(screen.getByRole("button", { name: "Next search results page" }));

    expect(selectSearchPage).toHaveBeenNthCalledWith(1, 0);
    expect(selectSearchPage).toHaveBeenNthCalledWith(2, 200);
  });

  it("presents search provenance and manages result ordering and sessions", async () => {
    const client = new RestClient();
    const deleteRequest = vi.spyOn(client, "delete").mockResolvedValue({});
    const selectSearchSort = vi.fn();
    const onSearchDeleted = vi.fn();
    const onSearchesCleared = vi.fn();
    const confirm = vi.spyOn(window, "confirm").mockReturnValue(true);
    const search: SearchItem = {
      id: "9",
      query: "sample",
      requestedMethod: "automatic",
      resolvedMethod: "global",
      type: "audio",
      status: "error",
      statusReason: "network-search-failed",
      resultCount: 1,
      total: 1,
      offset: 0,
      limit: 100,
      criteria: {
        extension: "flac",
        minAvailability: 4,
        minCompleteSources: 2,
        codec: "flac",
        artist: "Example Artist"
      },
      items: [{
        hash: "00112233445566778899aabbccddeeff",
        name: "Primary.flac",
        sizeBytes: 4096,
        sources: 12,
        completeSources: 5,
        rating: 4,
        fileType: "audio",
        observations: [
          {
            origin: "server",
            name: "Primary.flac",
            sizeBytes: 4096,
            sources: 8,
            completeSources: 3,
            fileType: "audio",
            rating: 4,
            hasAichHash: true,
            complete: false,
            directory: "",
            observedAt: "2026-10-06T12:00:00Z"
          },
          {
            origin: "global",
            name: "Alternate.flac",
            sizeBytes: 4096,
            sources: 12,
            completeSources: 5,
            fileType: "audio",
            rating: 3,
            hasAichHash: false,
            complete: false,
            directory: "",
            observedAt: "2026-10-06T12:00:01Z"
          }
        ]
      }]
    };

    render(
      <SearchView
        searches={[search]}
        selectedSearch={search}
        selectedSearchId="9"
        categories={[]}
        client={client}
        run={async (operation) => { await operation(); }}
        selectSearch={() => {}}
        searchSort="sources"
        searchOrder="desc"
        selectSearchSort={selectSearchSort}
        selectSearchPage={() => {}}
        onSearchCreated={() => {}}
        onSearchDeleted={onSearchDeleted}
        onSearchesCleared={onSearchesCleared}
      />
    );

    expect(screen.getByText("network-search-failed")).toBeInTheDocument();
    expect(screen.getByText("Extension: .flac")).toBeInTheDocument();
    expect(screen.getByText("Minimum complete: 2")).toBeInTheDocument();
    expect(screen.getByText("Also seen as: Alternate.flac")).toBeInTheDocument();
    expect(screen.getByText("5 complete")).toBeInTheDocument();
    expect(screen.getByText("4/5")).toBeInTheDocument();
    expect(screen.getByText("server, global")).toBeInTheDocument();
    expect(screen.getAllByText("00112233445566778899aabbccddeeff").length).toBeGreaterThan(0);

    fireEvent.input(screen.getByRole("combobox", { name: "Sort search results" }), {
      target: { value: "rating:desc" }
    });
    expect(selectSearchSort).toHaveBeenCalledWith("rating", "desc");

    fireEvent.click(screen.getByRole("button", { name: "Delete session" }));
    await waitFor(() => expect(deleteRequest).toHaveBeenCalledWith("searches/9"));
    expect(onSearchDeleted).toHaveBeenCalledWith("9");

    fireEvent.click(screen.getByRole("button", { name: "Clear sessions" }));
    await waitFor(() => expect(deleteRequest).toHaveBeenCalledWith("searches?confirm=true"));
    expect(onSearchesCleared).toHaveBeenCalled();
    expect(confirm).toHaveBeenCalledTimes(2);
    confirm.mockRestore();
  });
});
