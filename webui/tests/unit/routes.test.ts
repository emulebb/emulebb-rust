import { describe, expect, it } from "vitest";

import { pathForRoute, pathForSearch, pathForTab, routeFromPathname } from "../../src/routes";

describe("WebUI routes", () => {
  it("maps primary views to stable paths", () => {
    expect(routeFromPathname("/")).toEqual({ tab: "overview" });
    expect(routeFromPathname("/transfers")).toEqual({ tab: "transfers" });
    expect(routeFromPathname("/shared-files/")).toEqual({ tab: "shared-files" });
    expect(pathForTab("settings")).toBe("/settings");
  });

  it("round-trips a selected search session", () => {
    const route = routeFromPathname("/searches/17");
    expect(route).toEqual({ tab: "search", searchId: "17" });
    expect(pathForRoute(route!)).toBe("/searches/17");
    expect(pathForSearch("4294967295")).toBe("/searches/4294967295");
  });

  it("rejects unknown paths and invalid search ids", () => {
    expect(routeFromPathname("/unknown")).toBeNull();
    expect(routeFromPathname("/searches/0")).toBeNull();
    expect(routeFromPathname("/searches/01")).toBeNull();
    expect(routeFromPathname("/searches/4294967296")).toBeNull();
    expect(() => pathForSearch("not-a-number")).toThrow("Invalid search session id");
  });
});
