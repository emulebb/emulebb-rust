export type Ed2kHandoff = { link: string; error?: string };

/** Read a browser handoff as form input only; the daemon validates on submission. */
export function readEd2kHandoff(fragment: string): Ed2kHandoff | null {
  if (!fragment) return null;
  const invalid = { link: "", error: "Unsupported or malformed eD2K file link" };
  if (fragment.length > 8192) return invalid;
  const fields = new URLSearchParams(fragment.slice(1));
  if (!fields.has("ed2k")) return null;
  const link = fields.get("ed2k") ?? "";
  if (fields.size !== 1 || link.length > 2048 || !/^ed2k:\/\/\|file\|[^\s\u0000-\u001f\u007f-\u009f]+\|\/$/.test(link)) {
    return invalid;
  }
  return { link };
}

export function clearEd2kHandoff(): void {
  window.history.replaceState(null, "", window.location.pathname + window.location.search);
}
