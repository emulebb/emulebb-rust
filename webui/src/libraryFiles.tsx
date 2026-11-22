import { useEffect, useRef, useState } from "preact/hooks";
import { Clipboard, Save, Search } from "lucide-preact";
import { RestError, type CursorPage, type LibraryFile, type LibraryFileDetail, type LibraryRoot, type RestClient } from "./api";
import { EmptyRow, StatusPill, TableScroll } from "./components";
import { errorMessage, formatBytes } from "./format";
import { FileTags } from "./libraryTags";
import { LibraryLocations } from "./libraryLocations";
import type { RunFunction } from "./views";

const sorts = ["displayName", "sizeBytes", "sessionUploadedBytes", "sessionUploadRequests", "sessionAcceptedUploads",
  "lifetimeUploadedBytes", "lifetimeUploadRequests", "lifetimeAcceptedUploads", "lastUploadRequestedAt", "lastUploadedAt"];
const priorities = [["auto", "Automatic"], ["verylow", "Very low"], ["low", "Low"], ["normal", "Normal"], ["high", "High"], ["release", "Release"]];

function parseRating(value: string): number | null {
  const normalized = value.trim();
  if (!/^\d+$/.test(normalized)) return null;
  const parsed = Number(normalized);
  return parsed <= 5 ? parsed : null;
}

export function LibraryView(props: { client: RestClient; run: RunFunction; refreshGeneration: number }) {
  const [page, setPage] = useState<CursorPage<LibraryFile> | null>(null);
  const [cursor, setCursor] = useState<string | null>(null);
  const [history, setHistory] = useState<Array<string | null>>([]);
  const [searchDraft, setSearchDraft] = useState("");
  const [search, setSearch] = useState("");
  const [view, setView] = useState("present");
  const [sort, setSort] = useState("displayName");
  const [order, setOrder] = useState("asc");
  const [tagDraft, setTagDraft] = useState("");
  const [tag, setTag] = useState("");
  const [rootId, setRootId] = useState("");
  const [rootLabel, setRootLabel] = useState("");
  const [roots, setRoots] = useState<CursorPage<LibraryRoot> | null>(null);
  const [rootCursor, setRootCursor] = useState<string | null>(null);
  const [rootsError, setRootsError] = useState("");
  const [sharing, setSharing] = useState("");
  const [pageSize, setPageSize] = useState(100);
  const [generation, setGeneration] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [selectedHash, setSelectedHash] = useState("");
  const [detail, setDetail] = useState<LibraryFileDetail | null>(null);
  const [detailError, setDetailError] = useState("");
  const [priority, setPriority] = useState("normal");
  const [comment, setComment] = useState("");
  const [rating, setRating] = useState("0");
  const dirty = useRef(false);
  const editorHash = useRef("");
  const selected = page?.data.find((file) => file.hash === selectedHash) ?? page?.data[0];
  const hash = selected?.hash ?? "";
  const searchError = searchDraft.trim() && [...searchDraft.trim()].length < 3 ? "Enter at least 3 characters to search filenames." : "";
  const ratingError = parseRating(rating) === null ? "Library file rating must be an integer between 0 and 5." : "";
  const tagError = tagDraft && !/^[A-Za-z0-9-]{1,64}$/.test(tagDraft) ? "Tag names use ASCII letters, digits and hyphens." : "";
  const reset = () => { setCursor(null); setHistory([]); };

  useEffect(() => {
    let current = true;
    setRootsError("");
    const params = new URLSearchParams({ limit: "100" });
    if (rootCursor) params.set("cursor", rootCursor);
    void props.client.getPage<LibraryRoot>(`library/roots?${params}`).then((value) => {
      if (current) setRoots(value);
    }).catch((caught) => { if (current) { setRoots(null); setRootsError(errorMessage(caught)); } });
    return () => { current = false; };
  }, [props.client, props.refreshGeneration, rootCursor]);

  useEffect(() => {
    let current = true;
    setLoading(true); setError("");
    const params = new URLSearchParams({ limit: String(pageSize), view, sort, order, countTotal: "true" });
    if (cursor) params.set("cursor", cursor);
    if (search) params.set("q", search);
    if (tag) params.set("tag", tag);
    if (rootId) params.set("rootId", rootId);
    if (sharing) params.set("sharingEnabled", sharing);
    void props.client.getPage<LibraryFile>(`library/files?${params}`).then((value) => {
      if (current) setPage(value);
    }).catch((caught) => {
      if (!current) return;
      if (caught instanceof RestError && caught.status === 409 && cursor) { setPage(null); reset(); }
      else { setPage(null); setError(errorMessage(caught)); }
    }).finally(() => { if (current) setLoading(false); });
    return () => { current = false; };
  }, [props.client, props.refreshGeneration, generation, cursor, search, view, sort, order, tag, rootId, sharing, pageSize]);

  useEffect(() => {
    let current = true;
    if (editorHash.current !== hash) { dirty.current = false; editorHash.current = hash; setDetail(null); }
    setDetailError("");
    if (!hash) { setDetail(null); return; }
    void props.client.get<LibraryFileDetail>(`library/files/${hash}`).then((value) => {
      if (!current) return;
      setDetail(value);
      if (!dirty.current) { setPriority(value.uploadPriority); setComment(value.comment); setRating(String(value.rating)); }
    }).catch((caught) => { if (current) { setDetail(null); setDetailError(errorMessage(caught)); } });
    return () => { current = false; };
  }, [props.client, props.refreshGeneration, generation, hash]);

  const save = async () => {
    const parsed = parseRating(rating);
    if (!detail || detail.hash !== hash || parsed === null) return;
    await props.client.patch(`library/files/${hash}`, { uploadPriority: priority, comment, rating: parsed });
    dirty.current = false; setGeneration((value) => value + 1);
  };
  const toggleSharing = async () => {
    if (!selected) return;
    const results = await props.client.post<Array<{ status: string; error?: { message: string } }>>("library/files/sharing", {
      hashes: [selected.hash], enabled: !selected.sharingEnabled
    });
    if (results[0]?.status === "failed") throw new Error(results[0].error?.message ?? "Sharing update failed");
    setGeneration((value) => value + 1);
  };

  return <section class="view-stack">
    <section class="panel card">
      <div class="section-title"><h2>Library</h2><span>{loading ? "Loading…" : `${page?.data.length ?? 0} of ${page?.meta.total?.toLocaleString() ?? "?"}`} · Page {history.length + 1}</span></div>
      <form class="library-files-toolbar" onSubmit={(event) => { event.preventDefault(); if (searchError || tagError) return; setSearch(searchDraft.trim()); setTag(tagDraft); reset(); }}>
        <label class="library-files-search">Search filename<div class="copy-row"><input class="form-control" value={searchDraft} onInput={(event) => setSearchDraft(event.currentTarget.value)} />
          <button class="btn" type="submit" disabled={Boolean(searchError || tagError)}><Search size={15} />Search</button></div>{searchError && <span class="field-error">{searchError}</span>}</label>
        <label>View<select class="form-select" value={view} onInput={(event) => { setView(event.currentTarget.value); reset(); }}>
          {[ ["present", "Present"], ["shared", "Shared"], ["unavailable", "Unavailable"], ["allKnown", "All known"] ].map(([value, label]) => <option value={value}>{label}</option>)}</select></label>
        <label>Sort<select class="form-select" value={sort} onInput={(event) => { setSort(event.currentTarget.value); reset(); }}>{sorts.map((value) => <option value={value}>{value.replace(/([A-Z])/g, " $1").replace(/^./, (letter) => letter.toUpperCase())}</option>)}</select></label>
        <label>Order<select class="form-select" value={order} onInput={(event) => { setOrder(event.currentTarget.value); reset(); }}><option value="asc">Ascending</option><option value="desc">Descending</option></select></label>
        <label>Tag<input class="form-control" value={tagDraft} onInput={(event) => setTagDraft(event.currentTarget.value)} />{tagError && <span class="field-error">{tagError}</span>}</label>
        <label>Root<select class="form-select" value={rootId} onInput={(event) => { setRootId(event.currentTarget.value); setRootLabel(event.currentTarget.selectedOptions[0]?.textContent ?? ""); reset(); }}>
          <option value="">All roots</option>{rootId && !roots?.data.some((root) => root.id === rootId) && <option value={rootId}>{rootLabel}</option>}
          {roots?.data.map((root) => <option key={root.id} value={root.id}>{root.path}</option>)}</select>
          {(rootCursor || roots?.meta.nextCursor) && <div class="copy-row"><button class="btn" type="button" disabled={!rootCursor} onClick={() => setRootCursor(null)}>First roots</button>
            <button class="btn" type="button" disabled={!roots?.meta.nextCursor} onClick={() => setRootCursor(roots?.meta.nextCursor ?? null)}>More roots</button></div>}
          {rootsError && <span class="field-error">{rootsError}</span>}</label>
        <label>Sharing<select class="form-select" value={sharing} onInput={(event) => { setSharing(event.currentTarget.value); reset(); }}><option value="">All</option><option value="true">Enabled</option><option value="false">Disabled</option></select></label>
        <label>Page size<select class="form-select" value={String(pageSize)} onInput={(event) => { setPageSize(Number(event.currentTarget.value)); reset(); }}>{[50,100,200].map((value) => <option value={value}>{value}</option>)}</select></label>
      </form>
      {error && <p class="field-error">{error}</p>}
      <TableScroll label="Library files"><table class="table table-vcenter card-table"><thead><tr><th>Name</th><th>Size</th><th>Presence</th><th>Sharing</th><th>Session uploaded</th><th>Lifetime uploaded</th><th>Lifetime requests</th></tr></thead>
        <tbody>{page?.data.map((file) => <tr key={file.hash} class={hash === file.hash ? "selected-row" : ""}>
          <td><button type="button" class="link-button" onClick={() => setSelectedHash(file.hash)}>{file.displayName}</button></td><td>{formatBytes(file.sizeBytes ?? undefined)}</td>
          <td>{file.present ? "Present" : "Unavailable"}</td><td>{file.sharingEnabled ? "Enabled" : "Disabled"}</td><td>{formatBytes(file.sessionUploadedBytes)}</td><td>{formatBytes(file.lifetimeUploadedBytes)}</td><td>{file.lifetimeUploadRequests}</td>
        </tr>)}{!page?.data.length && <EmptyRow colSpan={7} text={loading ? "Loading library…" : "No library files match the current filters."} />}</tbody></table></TableScroll>
      <div class="library-files-pagination"><button class="btn" type="button" disabled={!history.length || loading} onClick={() => { const previous = [...history]; setCursor(previous.pop() ?? null); setHistory(previous); }}>Previous</button>
        <button class="btn" type="button" disabled={!page?.meta.nextCursor || loading} onClick={() => { setHistory((value) => [...value,cursor]); setCursor(page?.meta.nextCursor ?? null); }}>Next</button></div>
    </section>
    <section class="panel card"><div class="section-title"><h2>Metadata</h2><span>{selected?.displayName ?? "No selection"}</span></div>
      {detailError && <p class="field-error">{detailError}</p>}
      {selected && detail?.hash === hash && <><button class="btn" type="button" onClick={() => void props.run(toggleSharing, "Sharing policy saved", { refresh: false })}>{selected.sharingEnabled ? "Disable sharing" : "Enable sharing"}</button>
        <form class="editor-grid" onSubmit={(event) => { event.preventDefault(); void props.run(save,"Library file metadata saved", { refresh: false }); }}>
          <label>Upload priority<select class="form-select" value={priority} onInput={(event) => { dirty.current = true; setPriority(event.currentTarget.value); }}>{priorities.map(([value,label]) => <option value={value}>{label}</option>)}</select></label>
          <label>Rating<input class="form-control" value={rating} inputMode="numeric" aria-invalid={ratingError ? "true" : "false"} onInput={(event) => { dirty.current = true; setRating(event.currentTarget.value); }} /></label>
          <label class="wide-field">Comment<textarea class="form-control" value={comment} onInput={(event) => { dirty.current = true; setComment(event.currentTarget.value); }} /></label>
          <label class="wide-field">eD2K link<div class="copy-row"><input class="form-control" value={detail.ed2kLink ?? ""} readOnly /><button class="btn" type="button" disabled={!detail.ed2kLink} onClick={() => void navigator.clipboard?.writeText(detail.ed2kLink ?? "")}><Clipboard size={15} />Copy</button></div></label>
          {ratingError && <p class="field-error">{ratingError}</p>}<button class="btn" type="submit" disabled={Boolean(ratingError)}><Save size={15} />Save</button>
        </form>
        <h3>Publication</h3><dl class="detail-grid">{[
          { label: "eD2K", lane: detail.publication.ed2k, extra: "", description: "Sent to the connected server; eD2K servers do not acknowledge individual files." },
          { label: "Kad keywords", lane: detail.publication.kadKeyword, extra: ` ${detail.publication.kadKeyword.publishedKeywords}/${detail.publication.kadKeyword.totalKeywords} keywords`, description: "" },
          { label: "Kad source", lane: detail.publication.kadSource, extra: "", description: "" }
        ].map(({ label, lane, extra, description }) => <div key={label}><dt>{label}</dt><dd title={`${description ? `${description} ` : ""}${lane.lastSuccessAt != null ? `Last confirmed success: ${new Date(lane.lastSuccessAt * 1000).toLocaleString()}` : "No confirmed success in this runtime"}`}>
          <StatusPill value={lane.state.charAt(0).toUpperCase() + lane.state.slice(1)} />
          {extra}
        </dd></div>)}</dl>
      </>}
      {selected && <FileTags key={hash} client={props.client} hash={hash} />}
    </section>
    {selected && <LibraryLocations key={hash} client={props.client} hash={hash} refreshGeneration={props.refreshGeneration + generation} />}
  </section>;
}
