import { fireEvent, render, screen, waitFor } from "@testing-library/preact";
import { afterEach, expect, it, vi } from "vitest";
import { RestClient } from "../../src/api";
import { LibraryLocations } from "../../src/libraryLocations";

afterEach(() => vi.restoreAllMocks());

it("keeps only the visible location page and resets paging when the selected hash changes", async () => {
  const client = new RestClient();
  const pages = vi.spyOn(client, "getPage")
    .mockResolvedValueOnce({ data: [{ path: "/library/First.bin", present: true }], meta: { apiVersion: "v1", nextCursor: "next", hasMore: true } })
    .mockResolvedValueOnce({ data: [{ path: "/library/Second.bin", present: false }], meta: { apiVersion: "v1", nextCursor: null, hasMore: false } })
    .mockResolvedValueOnce({ data: [], meta: { apiVersion: "v1", nextCursor: null, hasMore: false } });
  const hash = "11".repeat(16);
  const other = "22".repeat(16);
  const { rerender } = render(<LibraryLocations key={hash} client={client} hash={hash} refreshGeneration={0} />);
  await screen.findByText("/library/First.bin");
  fireEvent.click(screen.getByRole("button", { name: "Next page" }));
  await screen.findByText("/library/Second.bin");
  expect(screen.queryByText("/library/First.bin")).not.toBeInTheDocument();
  expect(screen.getByText("Unavailable")).toBeInTheDocument();
  expect(pages).toHaveBeenNthCalledWith(2, `library/files/${hash}/locations?limit=100&cursor=next`);
  rerender(<LibraryLocations key={other} client={client} hash={other} refreshGeneration={0} />);
  await waitFor(() => expect(pages).toHaveBeenLastCalledWith(`library/files/${other}/locations?limit=100`));
  await screen.findByText("No cached copies.");
  expect(screen.queryByText("/library/Second.bin")).not.toBeInTheDocument();
});
