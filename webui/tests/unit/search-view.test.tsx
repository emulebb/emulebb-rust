import { fireEvent, render, screen, waitFor, within } from "@testing-library/preact";
import { describe, expect, it, vi } from "vitest";

import { RestClient, RestError, type SearchItem, type CursorPage, type SearchResult } from "../../src/api";
import { SearchView } from "../../src/views";

describe("SearchView", () => {
  it("confirms and retries an overrideable download conflict", async () => {
    const hash = "00112233445566778899aabbccddeeff";
    const client = new RestClient();
    const post = vi.spyOn(client, "post")
      .mockRejectedValueOnce(new RestError("Choose whether to download again", 409, "LOCAL_CONTENT_CHOICE_REQUIRED", { availability: "unavailable" }))
      .mockResolvedValueOnce({});
    const confirm = vi.spyOn(window, "confirm").mockReturnValue(true);
    const search: SearchItem = {
      id: "7",
      query: "linux",
      status: "completed",
      resultCount: 1,

    };
    const resultPage: CursorPage<SearchResult> = { data: [{ id: "11", hash, displayName: "Sample.bin", sizeBytes: 1 }], meta: { apiVersion: "v1", nextCursor: "next", hasMore: true } };

    render(
      <SearchView
        searches={[search]}
        selectedSearch={search}
        resultPage={resultPage}
        resultCursor="current"
        sessionCursor={null}
        sessionNextCursor={null}
        selectSearchSessionsPage={() => {}}
        selectedSearchId="7"
        categories={[]}
        client={client}
        run={async (operation) => { await operation(); }}
        selectSearch={() => {}}
        searchSort="sources"
        searchOrder="desc"
        selectSearchSort={() => {}}
        selectSearchPage={() => {}}
        onSearchCreated={() => {}}
        onSearchDeleted={() => {}}
        onSearchesCleared={() => {}}
      />
    );

    fireEvent.click(screen.getByRole("button", { name: "Download" }));

    await waitFor(() => expect(post).toHaveBeenCalledTimes(2));
    expect(post).toHaveBeenNthCalledWith(1, `searches/7/results/11/download`, {
      intent: "started",
      category: null,
      redownload: false
    });
    expect(post).toHaveBeenNthCalledWith(2, `searches/7/results/11/download`, {
      intent: "started",
      category: null,
      redownload: true
    });
    expect(confirm).toHaveBeenCalledWith(
      "This content is already recorded locally. Download again? Existing library files will be preserved."
    );
    confirm.mockRestore();
  });

  it("uses result cursors while distinguishing unknown size from zero", () => {
    const selectSearchPage = vi.fn();
    const search: SearchItem = {
      id: "7",
      query: "linux",
      status: "completed",
      resultCount: 250,

    };
    const resultPage: CursorPage<SearchResult> = { data: [
        { id: "11", hash: "00112233445566778899aabbccddeeff", displayName: "Result 101.bin", sizeBytes: null },
        { id: "12", hash: "ffeeddccbbaa99887766554433221100", displayName: "Result 102.bin", sizeBytes: 0 }
      ], meta: { apiVersion: "v1", nextCursor: "next", hasMore: true } };

    render(
      <SearchView
        searches={[search]}
        selectedSearch={search}
        resultPage={resultPage}
        resultCursor="current"
        sessionCursor={null}
        sessionNextCursor={null}
        selectSearchSessionsPage={() => {}}
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

    expect(screen.getByText("2 results on this page · 250 collected")).toBeInTheDocument();
    for (const button of screen.getAllByRole("button", { name: "Download" })) {
      expect(button).toBeEnabled();
    }

    expect(screen.getByText("Unknown")).toBeInTheDocument();
    expect(screen.getByText("0 B")).toBeInTheDocument();
    fireEvent.click(within(screen.getByRole("group", { name: "Search result pages" })).getByRole("button", { name: "First page" }));
    fireEvent.click(within(screen.getByRole("group", { name: "Search result pages" })).getByRole("button", { name: "Next page" }));

    expect(selectSearchPage).toHaveBeenNthCalledWith(1, null);
    expect(selectSearchPage).toHaveBeenNthCalledWith(2, "next");
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
      progress: {
        phase: "failed",
        completedUnits: 4,
        totalUnits: 10,
        unit: "servers"
      },
      resultCount: 1,
      criteria: {
        extension: "flac",
        minAvailability: 4,
        minCompleteSources: 2,
        codec: "flac",
        artist: "Example Artist"
      },

    };
    const resultPage: CursorPage<SearchResult> = { data: [{
        id: "13",
        hash: "00112233445566778899aabbccddeeff",
        displayName: "Primary.flac",
        sizeBytes: 4096,
        sources: 12,
        completeSources: 5,
        rating: 4,
        aichHash: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        complete: true,
        directory: "Curated Audio",
        fileType: "audio",
        media: {
          artist: "Example Artist",
          album: "Example Album",
          title: "Example Title",
          lengthSeconds: 321,
          bitrateKbps: 192,
          codec: "FLAC"
        },

      }], meta: { apiVersion: "v1", nextCursor: "next", hasMore: true } };

    render(
      <SearchView
        searches={[search]}
        selectedSearch={search}
        resultPage={resultPage}
        resultCursor="current"
        sessionCursor={null}
        sessionNextCursor={null}
        selectSearchSessionsPage={() => {}}
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
    expect(screen.getByText("failed")).toBeInTheDocument();
    expect(screen.getByText("4 / 10 servers")).toBeInTheDocument();
    expect(screen.getByText("Extension: .flac")).toBeInTheDocument();
    expect(screen.getByText("Minimum complete: 2")).toBeInTheDocument();
    expect(screen.getByText("Complete file")).toBeInTheDocument();
    expect(screen.getByText("AICH: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Observations" })).toBeInTheDocument();
    expect(screen.getByText("Folder: Curated Audio")).toBeInTheDocument();
    expect(screen.getByText("Title: Example Title · Artist: Example Artist · Album: Example Album · 5:21 · 192 kbps · Codec: FLAC")).toBeInTheDocument();
    expect(screen.getByText("5 complete")).toBeInTheDocument();
    expect(screen.getByText("4/5")).toBeInTheDocument();
    expect(screen.getAllByText("00112233445566778899aabbccddeeff").length).toBeGreaterThan(0);

    fireEvent.input(screen.getByRole("combobox", { name: "Sort search results" }), {
      target: { value: "bitrateKbps:desc" }
    });
    expect(selectSearchSort).toHaveBeenCalledWith("bitrateKbps", "desc");

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
