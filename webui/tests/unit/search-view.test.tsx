import { fireEvent, render, screen } from "@testing-library/preact";
import { describe, expect, it, vi } from "vitest";

import { RestClient, type SearchItem } from "../../src/api";
import { SearchView } from "../../src/views";

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
        selectSearchPage={selectSearchPage}
        onSearchCreated={() => {}}
      />
    );

    expect(screen.getByText("Showing 101–102 of 250 results")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Previous search results page" }));
    fireEvent.click(screen.getByRole("button", { name: "Next search results page" }));

    expect(selectSearchPage).toHaveBeenNthCalledWith(1, 0);
    expect(selectSearchPage).toHaveBeenNthCalledWith(2, 200);
  });
});
