import { render, screen } from "@testing-library/preact";
import { describe, expect, it } from "vitest";

import { AppIdentity } from "../../src/AppIdentity";

describe("application build identity", () => {
  it("shows the server identity and full source commit in About details", () => {
    const revision = "0123456789abcdef0123456789abcdef01234567";
    render(<AppIdentity app={{ version: "0.1.0-beta.2.nightly.20261111", channel: "nightly",
      platform: "arm64", build: "release", sourceRevision: revision }} />);
    expect(screen.getByLabelText("About this build").tagName).toBe("DETAILS");
    expect(screen.getByText(revision)).toBeInTheDocument();
    for (value of ["nightly", "arm64", "release"]) expect(screen.getByText(value)).toBeInTheDocument();
  });

  it("does not infer an unreported channel or commit", () => {
    render(<AppIdentity app={{ version: "local" }} />);
    expect(screen.getAllByText("unknown")).toHaveLength(4);
    expect(screen.queryByText("nightly")).not.toBeInTheDocument();
  });
});
