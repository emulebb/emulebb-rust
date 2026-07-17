import { describe, expect, it } from "vitest";

import { formatBytes, formatKiBRate, formatProgress, lifecycleLabel, optionalString, parseNumber } from "../../src/format";

describe("format helpers", () => {
  it("formats byte counts with binary units", () => {
    expect(formatBytes(undefined)).toBe("0 B");
    expect(formatBytes(-1)).toBe("0 B");
    expect(formatBytes(512)).toBe("512 B");
    expect(formatBytes(1536)).toBe("1.5 KiB");
    expect(formatBytes(12 * 1024 * 1024)).toBe("12 MiB");
  });

  it("formats rates from KiB inputs", () => {
    expect(formatKiBRate(2)).toBe("2.0 KiB/s");
  });

  it("prefers explicit progress and clamps it", () => {
    expect(formatProgress({ hash: "hash", progress: 123 })).toBe("100.0%");
    expect(formatProgress({ hash: "hash", progress: -4 })).toBe("0.0%");
  });

  it("derives progress from completed bytes when needed", () => {
    expect(formatProgress({ hash: "hash", sizeBytes: 1000, completedBytes: 499 })).toBe("50%");
    expect(formatProgress({ hash: "hash", sizeBytes: 0, completedBytes: 499 })).toBe("0%");
  });

  it("normalizes lifecycle values", () => {
    expect(lifecycleLabel("running")).toBe("running");
    expect(lifecycleLabel({ state: "starting" })).toBe("starting");
    expect(lifecycleLabel({ state: 1 })).toBe("unknown");
  });

  it("normalizes optional strings and numeric form values", () => {
    expect(optionalString("  ")).toBeNull();
    expect(optionalString(" value ")).toBe("value");
    expect(parseNumber("42")).toBe(42);
    expect(parseNumber("bad", 7)).toBe(7);
  });
});
