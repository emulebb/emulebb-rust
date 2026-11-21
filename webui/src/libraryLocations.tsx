import { useEffect, useState } from "preact/hooks";
import { type RestClient, type CursorPage, type LibraryLocation, encodeSegment } from "./api";
import { CursorControls, TableScroll, EmptyRow } from "./components";

export function LibraryLocations(props: { client: RestClient; hash: string; refreshGeneration: number }) {
  const [cursor, setCursor] = useState<string | null>(null);
  const [page, setPage] = useState<CursorPage<LibraryLocation> | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError("");
    const params = new URLSearchParams({ limit: "100" });
    if (cursor) params.set("cursor", cursor);
    void props.client.getPage<LibraryLocation>(`library/files/${encodeSegment(props.hash)}/locations?${params}`).then((value) => {
      if (!cancelled) setPage(value);
    }).catch((caught) => {
      if (!cancelled) { setPage(null); setError(caught instanceof Error ? caught.message : String(caught)); }
    }).finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [props.client, props.hash, props.refreshGeneration, cursor]);
  return <section class="panel card">
    <div class="section-title"><h2>Locations</h2><span>{page?.data.length ?? 0} on this page</span></div>
    <p class="hint">Cached copy paths. Scans update their presence; sharing permission is separate.</p>
    {error && <p class="field-error">{error}</p>}
    <TableScroll label="Library locations"><table class="table table-vcenter card-table">
      <thead><tr><th>Path</th><th>Presence</th></tr></thead>
      <tbody>{page?.data.map((location) => <tr key={location.path}>
        <td class="path-cell">{location.path}</td><td>{location.present ? "Present" : "Unavailable"}</td>
      </tr>)}{!loading && !page?.data.length && !error && <EmptyRow colSpan={2} text="No cached copies." />}</tbody>
    </table></TableScroll>
    <CursorControls cursor={cursor} nextCursor={page?.meta.nextCursor ?? null} loading={loading}
      change={(value) => { setPage(null); setCursor(value); }} />
  </section>;
}
