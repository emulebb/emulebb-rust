import { act, fireEvent, render, screen, waitFor } from "@testing-library/preact";
import { describe, expect, it, vi } from "vitest";

import { Action, JsonPanel, StatusPill, TableScroll } from "../../src/components";

describe("components", () => {
  it("releases table observers and the resize listener on its owning window before teardown", async () => {
    const frame = document.createElement("iframe");
    document.body.append(frame);
    const ownerWindow = frame.contentWindow!;
    const host = ownerWindow.document.createElement("div");
    ownerWindow.document.body.append(host);
    const addListener = vi.spyOn(ownerWindow, "addEventListener");
    const removeListener = vi.spyOn(ownerWindow, "removeEventListener");
    const observe = vi.fn();
    const disconnect = vi.fn();
    vi.stubGlobal("ResizeObserver", class {
      observe = observe;
      disconnect = disconnect;
    });
    const { unmount } = render(<TableScroll><table /></TableScroll>, { container: host });
    try {
      await waitFor(() => expect(observe).toHaveBeenCalledTimes(2));
      const resizeListener = addListener.mock.calls.find(([event]) => event === "resize")?.[1];
      expect(resizeListener).toEqual(expect.any(Function));

      await act(unmount);

      expect(disconnect).toHaveBeenCalledOnce();
      expect(removeListener).toHaveBeenCalledWith("resize", resizeListener);
    } finally {
      await act(unmount);
      frame.remove();
      vi.unstubAllGlobals();
    }
  });

  it("makes only overflowing tables focusable and exposes the scrolling hint", async () => {
    const { container } = render(<TableScroll label="Sample table"><table><tbody><tr><td>Sample</td></tr></tbody></table></TableScroll>);
    const scroll = container.querySelector(".table-wrap")!;
    Object.defineProperty(scroll, "clientWidth", { configurable: true, value: 100 });
    Object.defineProperty(scroll, "scrollWidth", { configurable: true, value: 200 });
    fireEvent(window, new Event("resize"));
    await waitFor(() => expect(screen.getByRole("region", { name: "Sample table" })).toHaveAttribute("tabindex", "0"));
    expect(screen.getByText("Swipe horizontally for more columns")).not.toHaveAttribute("hidden");
    Object.defineProperty(scroll, "scrollWidth", { configurable: true, value: 90 });
    fireEvent(window, new Event("resize"));
    await waitFor(() => expect(scroll).not.toHaveAttribute("tabindex"));
    expect(screen.getByText("Swipe horizontally for more columns")).toHaveAttribute("hidden");
  });
  it("marks connected-style statuses as good", () => {
    render(<StatusPill value="Connected" />);

    expect(screen.getByText("Connected")).toHaveClass("status-pill", "badge", "bg-success-lt");
  });

  it("distinguishes HighID and LowID connection quality", () => {
    const { rerender } = render(<StatusPill value="HighID" />);
    expect(screen.getByText("HighID")).toHaveClass("bg-success-lt");

    rerender(<StatusPill value="LowID" />);
    expect(screen.getByText("LowID")).toHaveClass("bg-warning-lt");
  });

  it("marks error-style statuses as bad", () => {
    render(<StatusPill value="firewalled" />);

    expect(screen.getByText("firewalled")).toHaveClass("status-pill", "badge", "bg-danger-lt");
  });

  it("invokes action button callbacks", () => {
    const onClick = vi.fn();
    render(<Action title="Refresh" icon={<span>icon</span>} onClick={onClick} />);

    fireEvent.click(screen.getByTitle("Refresh"));

    expect(onClick).toHaveBeenCalledOnce();
  });

  it("renders JSON values for diagnostics panels", () => {
    render(<JsonPanel value={{ enabled: true }} />);

    expect(screen.getByText(/"enabled": true/)).toBeInTheDocument();
  });
});
