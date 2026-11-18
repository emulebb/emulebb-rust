import { useEffect, useState } from "preact/hooks";
import { type CursorPage, type RestClient, type SearchObservation } from "./api";

/** One selected result and one bounded provenance page; no accumulated row cache. */
export function SearchObservations(props: {
  client: RestClient; session: string; claim: string; close: () => void;
}) {
  const [cursor, setCursor] = useState<string | null>(null);
  const [page, setPage] = useState<CursorPage<SearchObservation> | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [retry, setRetry] = useState(0);
  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError("");
    setPage(null);
    const query = new URLSearchParams({ limit: "50" });
    if (cursor) query.set("cursor", cursor);
    void props.client.getPage<SearchObservation>(
      `searches/${props.session}/results/${props.claim}/observations?${query}`
    ).then((value) => { if (!cancelled) setPage(value); })
      .catch((failure: unknown) => { if (!cancelled) setError(failure instanceof Error ? failure.message : String(failure)); })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [props.client, props.session, props.claim, cursor, retry]);
  return <section class="card" aria-label="Search result observations">
    <div class="form-row">
      <h3>Reported observations</h3>
      <button class="btn" type="button" onClick={props.close}>Close observations</button>
    </div>
    {loading && <p role="status">Loading observations…</p>}
    {error && <p role="alert">{error} <button class="btn" type="button" onClick={() => setRetry((value) => value + 1)}>Retry observations</button></p>}
    {page && <>
      <table class="table table-vcenter card-table">
        <thead><tr><th>Reporter</th><th>Reported name</th><th>Sources</th><th>Complete sources</th><th>Last seen</th></tr></thead>
        <tbody>{page.data.map((row) => <tr key={row.id}>
          <td>{row.origin}<br />{row.reporterEndpoint ?? "Unknown reporter"}</td>
          <td>{row.rawName ?? "Unreported"}
            <details><summary>Reported metadata</summary><dl>
              <dt>Size</dt><dd>{row.sizeBytes === null ? "Unknown" : `${row.sizeBytes.toLocaleString()} bytes`}</dd>
              <dt>Type</dt><dd>{row.fileType ?? "Unreported"}</dd>
              <dt>Artist</dt><dd>{row.media.artist ?? "Unreported"}</dd>
              <dt>Album</dt><dd>{row.media.album ?? "Unreported"}</dd>
              <dt>Title</dt><dd>{row.media.title ?? "Unreported"}</dd>
              <dt>Codec</dt><dd>{row.media.codec ?? "Unreported"}</dd>
              <dt>Duration</dt><dd>{row.media.lengthSeconds === null ? "Unreported" : `${row.media.lengthSeconds} seconds`}</dd>
              <dt>Bitrate</dt><dd>{row.media.bitrateKbps === null ? "Unreported" : `${row.media.bitrateKbps} kbps`}</dd>
              <dt>Rating</dt><dd>{row.rating === null ? "Unreported" : `${row.rating}/5`}</dd>
              <dt>AICH</dt><dd>{row.aichHash ?? "Unreported"}</dd>
              <dt>Directory</dt><dd>{row.directory ?? "Unreported"}</dd>
              <dt>Reported complete</dt><dd>{row.complete === null ? "Unreported" : row.complete ? "Yes" : "No"}</dd>
              <dt>Source client ID</dt><dd>{row.sourceClientId ?? "Unreported"}</dd>
              <dt>Source client port</dt><dd>{row.sourceClientPort ?? "Unreported"}</dd>
              <dt>Occurrences in this search</dt><dd>{row.observationCount}</dd>
            </dl></details>
          </td>
          <td>{row.sources ?? "Unknown"}</td><td>{row.completeSources ?? "Unknown"}</td>
          <td>{new Date(row.lastSeenAt * 1000).toLocaleString()}</td>
        </tr>)}</tbody>
      </table>
      {page.data.length === 0 && <p>No observations.</p>}
      <div class="form-row" aria-label="Observation pages">
        <button class="btn" type="button" disabled={!cursor || loading} onClick={() => setCursor(null)}>First observations page</button>
        <button class="btn" type="button" disabled={!page.meta.hasMore || loading} onClick={() => setCursor(page.meta.nextCursor)}>Next observations page</button>
      </div>
    </>}
  </section>;
}
