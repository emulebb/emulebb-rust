import { fireEvent, render, screen, waitFor } from "@testing-library/preact";
import { describe, expect, it, vi } from "vitest";
import { RestClient, type SearchObservation } from "../../src/api";
import { SearchObservations } from "../../src/searchObservations";

function row(id: string, name: string): SearchObservation {
  return { id, rawName: name, normalizedName: name, origin: "server", reporterEndpoint: null,
    publisherId: null, comment: null,
    sizeBytes: null, sources: 0, completeSources: null, sourceClientId: null, sourceClientPort: null,
    fileType: null, media: { artist: null, album: null, title: null, lengthSeconds: null, bitrateKbps: null, codec: null },
    rating: null, aichHash: null, complete: null, directory: null,
    firstSeenAt: 10, lastSeenAt: 20, observationCount: 1 };
}
const meta = (cursor: string | null) => ({ apiVersion: "v1", nextCursor: cursor, hasMore: cursor !== null });

describe("SearchObservations", () => {
  it("replaces each bounded page and preserves the difference between zero and unknown", async () => {
    const client = new RestClient();
    const get = vi.spyOn(client, "getPage")
      .mockResolvedValueOnce({ data: [{ ...row("1", "Alpha.bin"), origin: "kad", publisherId: "53".repeat(16), comment: "Remote note" }], meta: meta("next") })
      .mockResolvedValueOnce({ data: [row("2", "Beta.bin")], meta: meta(null) })
      .mockResolvedValueOnce({ data: [row("1", "Alpha.bin")], meta: meta("next") });
    const close = vi.fn();
    render(<SearchObservations client={client} session="7" claim="11" close={close} />);
    await screen.findByText("Alpha.bin");
    expect(screen.getByText("Remote note")).toBeInTheDocument();
    expect(screen.getByText("53".repeat(16))).toBeInTheDocument();
    expect(screen.getByText("0")).toBeInTheDocument();
    expect(screen.getAllByText("Unknown").length).toBeGreaterThan(0);
    fireEvent.click(screen.getByRole("button", { name: "Next observations page" }));
    await screen.findByText("Beta.bin");
    expect(screen.queryByText("Alpha.bin")).not.toBeInTheDocument();
    expect(get).toHaveBeenNthCalledWith(2, "searches/7/results/11/observations?limit=50&cursor=next");
    expect(screen.getByRole("button", { name: "Next observations page" })).toBeDisabled();
    fireEvent.click(screen.getByRole("button", { name: "First observations page" }));
    await screen.findByText("Alpha.bin");
    expect(screen.queryByText("Beta.bin")).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Close observations" }));
    expect(close).toHaveBeenCalledOnce();
  });
  it("shows a failed read once and retries only after explicit action", async () => {
    const client = new RestClient();
    const get = vi.spyOn(client, "getPage").mockRejectedValueOnce(new Error("Read failed"))
      .mockResolvedValueOnce({ data: [], meta: meta(null) });
    render(<SearchObservations client={client} session="7" claim="11" close={() => {}} />);
    await screen.findByRole("alert");
    expect(get).toHaveBeenCalledOnce();
    fireEvent.click(screen.getByRole("button", { name: "Retry observations" }));
    await waitFor(() => expect(screen.getByText("No observations.")).toBeInTheDocument());
    expect(get).toHaveBeenCalledTimes(2);
  });
});
