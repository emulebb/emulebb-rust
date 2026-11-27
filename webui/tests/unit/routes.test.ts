import { describe, expect, it } from "vitest";

import { defaultMobileRoute, pathForRoute, pathForSearch, pathForTab, routeFromPathname } from "../../src/routes";

describe("WebUI routes", () => {
  it("maps primary views to stable paths", () => {
    expect(routeFromPathname("/")).toEqual({ tab: "overview" });
    expect(routeFromPathname("/downloads")).toEqual({ tab: "downloads" });
    expect(routeFromPathname("/library/")).toEqual({ tab: "library" });
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

  it("chooses phone routes only for supported views and round-trips mobile search links", () => {
    expect(pathForRoute(defaultMobileRoute({ tab: "overview" }))).toBe("/mobile");
    expect(pathForRoute(defaultMobileRoute({ tab: "downloads" }))).toBe("/mobile");
    expect(pathForRoute(defaultMobileRoute({ tab: "settings" }))).toBe("/settings");
    expect(defaultMobileRoute({ tab: "overview", mobile: true })).toEqual({ tab: "overview", mobile: true });
    expect(pathForRoute(routeFromPathname("/mobile/more")!)).toBe("/mobile/more");
    expect(pathForRoute(defaultMobileRoute({ tab: "search", searchId: "17" }))).toBe("/mobile/searches/17");
    expect(routeFromPathname("/mobile/searches/17")).toEqual({ tab: "search", searchId: "17", mobile: true });
    expect(routeFromPathname("/mobile/searches/01")).toBeNull();
  });
});
