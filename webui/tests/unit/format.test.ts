import { describe, expect, it } from "vitest";

import {
  formatBytes,
  formatDurationMs,
  formatRate,
  formatPercent,
  formatProgress,
  lifecycleLabel,
  optionalString,
  parseNumber
} from "../../src/format";

describe("format helpers", () => {
  it("formats byte counts with binary units", () => {
    expect(formatBytes(undefined)).toBe("0 B");
    expect(formatBytes(-1)).toBe("0 B");
    expect(formatBytes(512)).toBe("512 B");
    expect(formatBytes(1536)).toBe("1.5 KiB");
    expect(formatBytes(12 * 1024 * 1024)).toBe("12 MiB");
  });

  it("formats rates from bytes per second", () => {
    expect(formatRate(2048)).toBe("2.0 KiB/s");
  });

  it("formats progress percentages and durations", () => {
    expect(formatPercent(512, 1024)).toBe("50%");
    expect(formatPercent(1, 100)).toBe("1.0%");
    expect(formatDurationMs(65_000)).toBe("1m 5s");
  });

  it("prefers explicit progress and clamps it", () => {
    expect(formatProgress({ progress: 1 })).toBe("100.0%");
    expect(formatProgress({ progress: 0.3829 })).toBe("38.3%");
    expect(formatProgress({ progress: 123 })).toBe("100.0%");
    expect(formatProgress({ progress: -4 })).toBe("0.0%");
  });

  it("shows unknown progress without inventing a size", () => {
    expect(formatProgress({ progress: null })).toBe("Unknown");
  });

  it("formats lifecycle state", () => {
    expect(lifecycleLabel({ state: "running" })).toBe("running");
    expect(lifecycleLabel({ state: "starting" })).toBe("starting");
    expect(lifecycleLabel(undefined)).toBe("unknown");
  });

  it("normalizes optional strings and numeric form values", () => {
    expect(optionalString("  ")).toBeNull();
    expect(optionalString(" value ")).toBe("value");
    expect(parseNumber("42")).toBe(42);
    expect(parseNumber("bad", 7)).toBe(7);
  });
});
