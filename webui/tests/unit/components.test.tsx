import { fireEvent, render, screen } from "@testing-library/preact";
import { describe, expect, it, vi } from "vitest";

import { Action, JsonPanel, StatusPill } from "../../src/components";

describe("components", () => {
  it("marks connected-style statuses as good", () => {
    render(<StatusPill value="Connected" />);

    expect(screen.getByText("Connected")).toHaveClass("pill", "good");
  });

  it("marks error-style statuses as bad", () => {
    render(<StatusPill value="firewalled" />);

    expect(screen.getByText("firewalled")).toHaveClass("pill", "bad");
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
