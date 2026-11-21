/** Shared public-name rules for immutable categories and library tags. */
export function identityNameError(value: string): string | undefined {
  // WHY: JavaScript's $ also matches before a final newline; names must match in full.
  return value && !/^[A-Za-z0-9][A-Za-z0-9-]{0,63}(?![\s\S])/.test(value) ? "Use 1–64 ASCII letters, digits or hyphens, starting with a letter or digit." : undefined;
}

export function formatProgress(download: { progress: number | null }): string {
  if (download.progress === null) return "Unknown";
  return `${(Math.min(1, Math.max(0, download.progress)) * 100).toFixed(1)}%`;
}

export function formatRate(value?: number): string {
  return `${formatBytes(value)}/s`;
}

export function formatPercent(completed?: number, total?: number): string {
  if (!total || total <= 0) {
    return "0%";
  }
  const percent = Math.min(100, Math.max(0, ((completed ?? 0) / total) * 100));
  return `${percent >= 10 ? percent.toFixed(0) : percent.toFixed(1)}%`;
}

export function formatDurationMs(value?: number | null): string {
  if (!value || value < 0) {
    return "0s";
  }
  const seconds = Math.round(value / 1000);
  if (seconds < 60) {
    return `${seconds}s`;
  }
  const minutes = Math.floor(seconds / 60);
  const remainingSeconds = seconds % 60;
  if (minutes < 60) {
    return `${minutes}m ${remainingSeconds}s`;
  }
  const hours = Math.floor(minutes / 60);
  const remainingMinutes = minutes % 60;
  return `${hours}h ${remainingMinutes}m`;
}

export function formatBytes(value?: number | null): string {
  if (!value || value < 0) {
    return "0 B";
  }
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let scaled = value;
  let unit = 0;
  while (scaled >= 1024 && unit < units.length - 1) {
    scaled /= 1024;
    unit += 1;
  }
  return `${scaled >= 10 || unit === 0 ? scaled.toFixed(0) : scaled.toFixed(1)} ${units[unit]}`;
}

export function firewallLabel(value: boolean | null | undefined): string {
  if (value === true) {
    return "firewalled";
  }
  if (value === false) {
    return "open";
  }
  return "unknown";
}

export function lifecycleLabel(value: unknown): string {
  if (typeof value === "string") {
    return value;
  }
  if (value && typeof value === "object" && "state" in value) {
    const state = (value as { state?: unknown }).state;
    return typeof state === "string" ? state : "unknown";
  }
  return "unknown";
}

export function numberField(object: Record<string, unknown> | undefined, key: string): number | undefined {
  const value = object?.[key];
  return typeof value === "number" ? value : undefined;
}

export function stringField(object: Record<string, unknown> | undefined, key: string): string {
  const value = object?.[key];
  return typeof value === "string" ? value : "";
}

export function boolField(object: Record<string, unknown> | undefined, key: string): boolean {
  return object?.[key] === true;
}

export function optionalString(value: string): string | null {
  const trimmed = value.trim();
  return trimmed ? trimmed : null;
}

export function parseNumber(value: string, fallback = 0): number {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

export function errorMessage(caught: unknown): string {
  return caught instanceof Error ? caught.message : String(caught);
}
