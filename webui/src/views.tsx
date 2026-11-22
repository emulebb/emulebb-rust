import type { ComponentChildren } from "preact";
import { useEffect, useMemo, useState } from "preact/hooks";
import { SearchObservations } from "./searchObservations";
import { LibraryTags } from "./libraryTags";
import { clearEd2kHandoff, readEd2kHandoff } from "./ed2kHandoff";
import {
  Ban,
  Clipboard,
  Download,
  FileText,
  FolderPlus,
  Link,
  Pause,
  Play,
  Plug,
  RefreshCw,
  Save,
  Search,
  Server,
  Shield,
  Trash2,
  UserPlus
} from "lucide-preact";
import {
  Category,
  SettingsSnapshot,
  DownloadDetail,
  DownloadSummary,
  Stats,
  CursorPage,
  Friend,
  IpFilterStatus,
  KadNode,
  KadStatus,
  LogRecord,
  NatStatus,
  NetworkStatus,
  Page,
  RestClient,
  RuntimeDiagnostics,
  SearchItem,
  SearchResultMedia,
  SearchResult,
  ServerItem,
  LibraryScan,
  LibraryRoot,
  SharedFileIgnores,
  Snapshot,
  Status,
  DownloadSource,
  Upload,
  VpnGuardStatus,
  RestError,
  encodeSegment
} from "./api";
import { Action, CursorControls, EmptyRow, JsonPanel, Metric, StatusPill, TableScroll } from "./components";
import {
  boolField,
  errorMessage,
  identityNameError,
  firewallLabel,
  formatBytes,
  formatDurationMs,
  formatPercent,
  formatProgress,
  formatRate,
  lifecycleLabel,
  numberField,
  optionalString,
  parseNumber,
  stringField
} from "./format";

export type RunFunction = (
  operation: () => Promise<unknown>,
  success: string,
  options?: { refresh?: boolean }
) => Promise<void>;

export class OperationCancelledError extends Error {
  constructor() {
    super("Operation cancelled");
    this.name = "OperationCancelledError";
  }
}

async function createDownloadWithChoice<T>(create: (redownload: boolean) => Promise<T>): Promise<T> {
  try {
    return await create(false);
  } catch (caught) {
    if (!(caught instanceof RestError) || caught.code !== "LOCAL_CONTENT_CHOICE_REQUIRED") throw caught;
    if (!window.confirm("This content is already recorded locally. Download again? Existing library files will be preserved.")) {
      throw new OperationCancelledError();
    }
    return create(true);
  }
}

export function Overview(props: {
  snapshot: Snapshot | null;
  stats: Partial<Stats>;
  transfers: DownloadSummary[];
  servers: ServerItem[];
  uploads: Upload[];
  uploadQueue: Upload[];
  libraryScan: LibraryScan | null;
  kad: KadStatus;
}) {
  const connectedServers = props.servers.filter((item) => item.connected).length;
  const resources = props.stats.downloadResources;
  const reload = props.libraryScan?.reloadProgress ?? props.snapshot?.status?.runtimeDiagnostics?.sharedDirectoryReloadProgress ?? props.snapshot?.status?.sharedStartupCache?.reloadProgress ?? {};
  const startupStages = startupStageRows(props.snapshot, props.libraryScan, props.kad, connectedServers);
  return (
    <section class="view-grid">
      <Metric
        label="Download"
        value={formatRate(numberField(props.stats, "downloadRateBytesPerSec") ?? kibToBytes(numberField(props.stats, "downloadSpeedKiBps")))}
      />
      <Metric
        label="Upload"
        value={formatRate(numberField(props.stats, "uploadRateBytesPerSec") ?? kibToBytes(numberField(props.stats, "uploadSpeedKiBps")))}
      />
      <Metric label="Transfers" value={props.snapshot?.downloads ? `${props.snapshot.downloads.unfinished} unfinished / ${props.snapshot.downloads.completed} completed` : "n/a"} />
      <Metric label="Download work" value={resources ? `${resources.active} active / ${resources.preparing} preparing / ${resources.waiting} waiting` : "n/a"} />
      <Metric label="Uploads" value={`${props.stats.activeUploads ?? "unknown"}/${props.stats.waitingUploads ?? "unknown"}`} />
      <Metric label="Shared" value={String(props.snapshot?.status?.runtimeDiagnostics?.sharedFileCount ?? "n/a")} />
      <Metric label="Kad" value={props.kad.connected ? "Connected" : "Idle"} />

      {resources && <section class="panel card wide">
        <h2>Download resources</h2>
        <div class="kv">
          <span>Concurrency</span>
          <strong>{resources.concurrency.mode === "automatic" ? "Automatic" : `Configured limit ${resources.concurrency.configuredLimit}`}</strong>
          <span>Current target</span><strong>{resources.concurrency.target}</strong>
          <span>Active above target</span><strong>{resources.concurrency.burstActive}</strong>
          <span>Resident download cache</span>
          <strong>{formatBytes(resources.residentMemory.usedBytes)} / {formatBytes(resources.residentMemory.limitBytes)}</strong>
          <span>Soft cache target</span><strong>{formatBytes(resources.residentMemory.softTargetBytes)}</strong>
        </div>
        <p class="muted">Counts are live observations. Existing work drains when capacity falls. The cache budget is separate from total daemon memory.</p>
      </section>}

      <section class="panel card wide">
        <h2>Startup & Indexing</h2>
        <div class="stage-list">
          {startupStages.map((stage) => (
            <div class="stage-row" key={stage.label}>
              <span>{stage.label}</span>
              <StatusPill value={stage.status} />
              <strong>{stage.detail}</strong>
            </div>
          ))}
        </div>
        <ProgressLine
          label="Hash reads"
          completed={reload.completedReadBytes}
          total={reload.plannedReadBytes}
          rate={reload.readRateBytesPerSec}
        />
      </section>

      <section class="panel card wide">
        <h2>Network</h2>
        <div class="kv">
          <span>Lifecycle</span>
          <strong>{lifecycleLabel(props.snapshot?.status?.lifecycle)}</strong>
          <span>Server</span>
          <strong>{connectedServers > 0 ? "connected" : "disconnected"}</strong>
          <span>Kad firewall</span>
          <strong>{firewallLabel(props.kad.firewalled)}</strong>
          <span>Shared bytes</span>
          <strong>n/a</strong>
        </div>
      </section>

      <section class="panel card wide">
        <h2>Recent Transfers</h2>
        <CompactTransferList transfers={props.transfers.slice(0, 8)} />
      </section>
    </section>
  );
}

function startupStageRows(
  snapshot: Snapshot | null,
  directories: LibraryScan | null,
  kad: KadStatus,
  connectedServers: number
) {
  const status = snapshot?.status;
  const lifecycle = lifecycleLabel(status?.lifecycle);
  const reload = directories?.reloadProgress ?? status?.runtimeDiagnostics?.sharedDirectoryReloadProgress ?? status?.sharedStartupCache?.reloadProgress ?? {};
  const ed2kPublish = status?.runtimeDiagnostics?.ed2kPublish;
  const kadPublish = status?.runtimeDiagnostics?.kadPublish;
  const ed2kPhase = stringField(ed2kPublish, "phase") || (connectedServers > 0 ? "connected" : "waiting");
  const kadPhase = stringField(kadPublish, "phase") || (kad.connected ? "connected" : "waiting");
  return [
    { label: "Core", status: lifecycle === "running" ? "complete" : lifecycle, detail: lifecycle },
    {
      label: "Shared scan",
      status: reload.running ? (reload.phase ?? "active") : "complete",
      detail: `${reload.scannedCount ?? 0} scanned`
    },
    {
      label: "Hashing",
      status: (reload.activeHashCount ?? directories?.hashingCount ?? 0) > 0 ? "active" : "complete",
      detail: `${reload.hashedCount ?? 0}/${reload.plannedHashCount ?? 0} files`
    },
    { label: "eD2K publish", status: ed2kPhase, detail: ed2kPhase },
    { label: "Kad publish", status: kad.connected ? "connected" : kadPhase, detail: kadPhase }
  ];
}

function ProgressLine(props: { label: string; completed?: number; total?: number; rate?: number }) {
  const percent = props.total ? Math.min(100, Math.max(0, ((props.completed ?? 0) / props.total) * 100)) : 0;
  return (
    <div class="progress-line">
      <div class="progress-head">
        <span>{props.label}</span>
        <strong>{formatPercent(props.completed, props.total)}</strong>
      </div>
      <div class="progress-track">
        <div class="progress-fill" style={{ width: `${percent}%` }} />
      </div>
      <div class="progress-foot">
        <span>{formatBytes(props.completed)} / {formatBytes(props.total)}</span>
        <span>{formatRate(props.rate)}</span>
      </div>
    </div>
  );
}

/** One independently paged evidence resource; refresh replaces its current page. */
function DownloadEvidence<T>(props: { path: string; label: string; client: RestClient; refreshGeneration: number; render: (items: T[]) => ComponentChildren }) {
  const [cursor, setCursor] = useState<string | null>(null);
  const [page, setPage] = useState<CursorPage<T> | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError("");
    const query = new URLSearchParams({ limit: "100" });
    if (cursor) query.set("cursor", cursor);
    void props.client.getPage<T>(`${props.path}?${query}`).then((value) => {
      if (!cancelled) setPage(value);
    }).catch((caught) => { if (!cancelled) setError(errorMessage(caught)); })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [props.client, props.path, cursor, props.refreshGeneration]);
  const change = (value: string | null) => { setPage(null); setCursor(value); };
  return <section class="panel card">
    <div class="section-title"><h2>{props.label}</h2><CursorControls cursor={cursor} nextCursor={page?.meta.nextCursor ?? null} loading={loading} change={change} /></div>
    {error && <div class="notice alert alert-danger">{error}</div>}
    {props.render(page?.data ?? [])}
  </section>;
}

export function TransfersView(props: { categories: Category[]; client: RestClient; run: RunFunction; refreshGeneration: number }) {
  const [view, setView] = useState("unfinished");
  const [category, setCategory] = useState("");
  const [cursor, setCursor] = useState<string | null>(null);
  const [page, setPage] = useState<CursorPage<DownloadSummary> | null>(null);
  const [loading, setLoading] = useState(false);
  const [listError, setListError] = useState("");
  const [handoff, setHandoff] = useState(() => readEd2kHandoff(window.location.hash));
  const [ed2kLinks, setEd2kLinks] = useState(handoff?.link ?? "");
  const [stoppedCreate, setStoppedCreate] = useState(false);
  const [selectedId, setSelectedId] = useState("");
  const [details, setDetails] = useState<DownloadDetail | null>(null);
  const [detailError, setDetailError] = useState("");
  const linksError = transferLinksValidationError(ed2kLinks);
  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setListError("");
    const query = new URLSearchParams({ view, limit: "100" });
    if (category) query.set("category", category);
    if (cursor) query.set("cursor", cursor);
    void props.client.getPage<DownloadSummary>(`downloads?${query}`).then((value) => {
      if (!cancelled) setPage(value);
    }).catch((caught) => { if (!cancelled) setListError(errorMessage(caught)); })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [props.client, view, category, cursor, props.refreshGeneration]);
  useEffect(() => {
    const receive = () => {
      const next = readEd2kHandoff(window.location.hash);
      setHandoff(next);
      if (next) setEd2kLinks(next.link);
    };
    window.addEventListener("hashchange", receive);
    return () => window.removeEventListener("hashchange", receive);
  }, []);
  const consumeHandoff = () => { if (handoff) clearEd2kHandoff(); setHandoff(null); };
  useEffect(() => {
    let cancelled = false;
    setDetails(null);
    setDetailError("");
    if (selectedId) void props.client.get<DownloadDetail>(`downloads/${selectedId}`).then((value) => {
      if (!cancelled) setDetails(value);
    }).catch((caught) => { if (!cancelled) setDetailError(errorMessage(caught)); });
    return () => { cancelled = true; };
  }, [props.client, selectedId, props.refreshGeneration]);
  const changePage = (value: string | null) => { setPage(null); setCursor(value); setSelectedId(""); };
  const createDownloads = async () => {
    const links = transferLinksFromText(ed2kLinks);
    if (!links.length) throw new Error("At least one eD2K link is required");
    if (linksError) throw new Error(linksError);
    consumeHandoff();
    // Separate creations preserve admitted results if a later input fails.
    // Retrying the form returns unchanged duplicates for already-created jobs.
    for (const link of links) await createDownloadWithChoice((redownload) => props.client.post("downloads", {
      source: { type: "ed2k-link", link }, intent: stoppedCreate ? "stopped" : "started", redownload,
    }));
    setEd2kLinks("");
  };
  const remove = (job: DownloadSummary, deleteData: boolean) => {
    if (!window.confirm(deleteData
      ? `Delete "${job.name}" and its owned download data? This cannot be undone.`
      : `Remove "${job.name}"? Completed outputs are preserved; internal temporary pieces are retired.`)) return;
    void props.run(async () => {
      await props.client.controlDownloads("remove", [job.id], deleteData);
      if (selectedId === job.id) setSelectedId("");
    }, "Download removed");
  };
  return <section class="view-stack">
    <section class="panel card">
      <div class="section-title"><h2>Transfers</h2><div class="row-actions">
        <select class="form-select" aria-label="Download view" value={view} onInput={(event) => { setView(event.currentTarget.value); changePage(null); }}>
          <option value="unfinished">Unfinished</option><option value="completed">Completed</option><option value="all">All downloads</option>
        </select>
        <select class="form-select" aria-label="Download category" value={category} onInput={(event) => { setCategory(event.currentTarget.value); changePage(null); }}>
          <option value="">All categories</option>{props.categories.map((item) => <option key={item.name} value={item.name}>{item.name}</option>)}
        </select>
        <CursorControls cursor={cursor} nextCursor={page?.meta.nextCursor ?? null} loading={loading} change={changePage} />
      </div></div>
      {listError && <div class="notice alert alert-danger">{listError}</div>}
      {handoff && <p class={handoff.error ? "field-error" : "text-secondary"}>{handoff.error ?? "Review the linked file and press Add links to queue it."}</p>}
      <form class="form-row" onSubmit={(event) => { event.preventDefault(); void props.run(createDownloads, "Downloads queued"); }}>
        <textarea class="form-control" aria-label="eD2K links" value={ed2kLinks} placeholder="One eD2K link per line" aria-invalid={linksError ? "true" : "false"} onInput={(event) => setEd2kLinks(event.currentTarget.value)} />
        <label class="check"><input class="form-check-input" type="checkbox" checked={stoppedCreate} onInput={(event) => setStoppedCreate(event.currentTarget.checked)} />Stopped</label>
        <button class="btn" type="submit" disabled={Boolean(linksError)}><Download size={16} />Add links</button>
        {handoff && <button class="btn" type="button" onClick={() => { consumeHandoff(); setEd2kLinks(""); }}>Cancel links</button>}
      </form>
      {linksError && <p class="field-error">{linksError}</p>}
      <TableScroll label="Transfers"><table class="table table-vcenter card-table"><thead><tr><th>Name</th><th>State</th><th>Progress</th><th>Category</th><th>Actions</th></tr></thead><tbody>
        {(page?.data ?? []).map((job) => <tr key={job.id} class={selectedId === job.id ? "selected-row" : ""}>
          <td><button type="button" class="link-button" onClick={() => setSelectedId(job.id)}>{job.name}</button></td>
          <td><DownloadStateLabel download={job} /></td><td>{formatProgress(job)}</td>
          <td><select class="form-select" aria-label={`Category for ${job.name}`} value={job.category ?? ""} onInput={(event) => void props.run(() => props.client.patch(`downloads/${job.id}`, { category: event.currentTarget.value || null }), "Category updated")}>
            <option value="">Uncategorized</option>{props.categories.map((item) => <option key={item.name} value={item.name}>{item.name}</option>)}
          </select></td>
          <td><div class="row-actions">
            <Action title="Start" icon={<Play size={15} />} disabled={job.state === "completed"} onClick={() => void props.run(() => props.client.controlDownloads("start", [job.id]), "Download started")} />
            <Action title="Stop" icon={<Ban size={15} />} disabled={job.state === "completed" || job.intent === "stopped"} onClick={() => void props.run(() => props.client.controlDownloads("stop", [job.id]), "Download stopped")} />
            <Action title="Verify" icon={<RefreshCw size={15} />} onClick={() => void props.run(() => props.client.controlDownloads("verify", [job.id]), "Download verified")} />
            <Action title="Remove from list" icon={<FileText size={15} />} onClick={() => remove(job, false)} />
            <Action title="Delete" icon={<Trash2 size={15} />} onClick={() => remove(job, true)} />
          </div></td>
        </tr>)}
        {page?.data.length === 0 && <EmptyRow colSpan={5} text="No transfers." />}
      </tbody></table></TableScroll>
    </section>
    <section class="panel card"><div class="section-title"><h2>Transfer Details</h2><span>{details?.name ?? (selectedId || "No selection")}</span></div>
      {detailError && <div class="notice alert alert-danger">{detailError}</div>}<JsonPanel value={details} />
    </section>
    {selectedId && <>
      <DownloadEvidence<DownloadSource> key={`${selectedId}:sources`} path={`downloads/${selectedId}/sources`} label="Download sources" client={props.client} refreshGeneration={props.refreshGeneration} render={(sources) => <TableScroll label="Transfer sources"><table class="table table-vcenter card-table"><thead><tr><th>Source</th><th>State</th><th>Rate</th><th>Reported names</th><th>Actions</th></tr></thead><tbody>
        {sources.map((source) => { const peer = source.clientId ?? ""; const path = `downloads/${selectedId}/sources/${encodeSegment(peer)}/operations`; return <tr key={peer}>
          <td>{source.userName ?? peer}</td><td><StatusPill value={source.downloadState ?? "unknown"} /></td><td>{formatRate(source.downloadRateBytesPerSecond)}</td>
          <td>{(source.reportedFileNames ?? []).map((name) => name.normalizedName).join(", ")}{source.reportedFileNamesHasMore ? " …" : ""}</td>
          <td><div class="row-actions"><Action title="Browse" icon={<Search size={15} />} onClick={() => void props.run(() => props.client.post(`${path}/browse`), "Browse requested")} />
            <Action title="Add friend" icon={<UserPlus size={15} />} onClick={() => void props.run(() => props.client.post(`${path}/add-friend`), "Friend added")} />
            <Action title="Remove source" icon={<Trash2 size={15} />} onClick={() => void props.run(() => props.client.post(`${path}/remove`), "Source removed")} />
            <Action title="Ban" icon={<Ban size={15} />} onClick={() => void props.run(() => props.client.post(`${path}/ban`), "Source banned")} /></div></td>
        </tr>; })}{sources.length === 0 && <EmptyRow colSpan={5} text="No sources for this download." />}
      </tbody></table></TableScroll>} />
      <DownloadEvidence<unknown> key={`${selectedId}:parts`} path={`downloads/${selectedId}/parts`} label="Download parts" client={props.client} refreshGeneration={props.refreshGeneration} render={(items) => <JsonPanel value={items} />} />
      <DownloadEvidence<unknown> key={`${selectedId}:comments`} path={`downloads/${selectedId}/comments`} label="Download comments" client={props.client} refreshGeneration={props.refreshGeneration} render={(items) => <JsonPanel value={items} />} />
    </>}
  </section>;
}

export function SearchView(props: {
  searches: SearchItem[];
  selectedSearch: SearchItem | null;
  resultPage: CursorPage<SearchResult> | null;
  resultCursor: string | null;
  sessionCursor: string | null;
  sessionNextCursor: string | null;
  selectSearchSessionsPage: (cursor: string | null) => void;
  selectedSearchId?: string;
  categories: Category[];
  client: RestClient;
  run: RunFunction;
  selectSearch: (searchId: string) => void;
  searchSort: string;
  searchOrder: string;
  selectSearchSort: (sort: string, order: string) => void;
  selectSearchPage: (cursor: string | null) => void;
  onSearchCreated: (search: SearchItem) => void;
  onSearchDeleted: (searchId: string) => void;
  onSearchesCleared: () => void;
}) {
  const [query, setQuery] = useState("");
  const [parentSearchId, setParentSearchId] = useState<string | null>(null);
  const [method, setMethod] = useState("automatic");
  const [fileType, setFileType] = useState("");
  const [extension, setExtension] = useState("");
  const [minSizeBytes, setMinSizeBytes] = useState("");
  const [maxSizeBytes, setMaxSizeBytes] = useState("");
  const [minAvailability, setMinAvailability] = useState("");
  const [minCompleteSources, setMinCompleteSources] = useState("");
  const [minBitrateKbps, setMinBitrateKbps] = useState("");
  const [minLengthSeconds, setMinLengthSeconds] = useState("");
  const [codec, setCodec] = useState("");
  const [title, setTitle] = useState("");
  const [album, setAlbum] = useState("");
  const [artist, setArtist] = useState("");
  const [category, setCategory] = useState("");
  const [paused, setPaused] = useState(false);
  const [observationSelection, setObservationSelection] = useState<{ session: string; claim: string } | null>(null);
  const selectedSearch = props.selectedSearch?.id === props.selectedSearchId ? props.selectedSearch : null;
  const orderedSearches = props.searches;
  const selectedSummary = props.searches.find((search) => search.id === props.selectedSearchId);
  const displayedSearch = selectedSearch ?? selectedSummary;
  const results = props.resultPage?.data ?? [];
  const searchQueryError = searchQueryValidationError(query);
  const displayedStatus = displayedSearch?.status ?? "unknown";
  const searchProgress = displayedSearch?.progress;
  const searchPhaseLabel = searchProgress?.phase
    ? searchProgress.phase.replace(/-/g, " ")
    : "—";
  const searchProgressLabel = searchProgress?.totalUnits != null
    ? `${searchProgress.completedUnits.toLocaleString()} / ${searchProgress.totalUnits.toLocaleString()} ${searchProgress.unit}`.trim()
    : displayedStatus === "running"
      ? "Active · dynamic scope"
      : displayedStatus === "queued"
        ? "Waiting"
        : "—";
  const resolvedMethodLabel = displayedSearch?.resolvedMethod
    ?? (displayedStatus === "queued" || displayedStatus === "running" ? "pending" : "none");
  const criteria = displayedSearch?.criteria;
  const criteriaRows = [
    criteria?.extension ? ["Extension", `.${criteria.extension.replace(/^\./, "")}`] : null,
    criteria?.minSizeBytes != null ? ["Minimum size", formatBytes(criteria.minSizeBytes)] : null,
    criteria?.maxSizeBytes != null ? ["Maximum size", formatBytes(criteria.maxSizeBytes)] : null,
    criteria?.minAvailability != null ? ["Minimum sources", String(criteria.minAvailability)] : null,
    criteria?.minCompleteSources != null ? ["Minimum complete", String(criteria.minCompleteSources)] : null,
    criteria?.minBitrateKbps != null ? ["Minimum bitrate", `${criteria.minBitrateKbps.toLocaleString()} kbps`] : null,
    criteria?.minLengthSeconds != null ? ["Minimum length", `${criteria.minLengthSeconds.toLocaleString()} s`] : null,
    criteria?.codec ? ["Codec", criteria.codec] : null,
    criteria?.title ? ["Title", criteria.title] : null,
    criteria?.album ? ["Album", criteria.album] : null,
    criteria?.artist ? ["Artist", criteria.artist] : null
  ].filter((row): row is string[] => row !== null);

  const startSearch = async () => {
    const normalizedQuery = normalizeSearchQuery(query);
    const error = searchQueryValidationError(query);
    if (error) {
      throw new Error(error);
    }
    const next = await props.client.post<SearchItem>("searches", {
      query: normalizedQuery,
      ...(parentSearchId ? { parentSearchId } : {}),
      method,
      type: fileType,
      ...(extension.trim() ? { extension: extension.trim() } : {}),
      ...(minSizeBytes ? { minSizeBytes: Number(minSizeBytes) } : {}),
      ...(maxSizeBytes ? { maxSizeBytes: Number(maxSizeBytes) } : {}),
      ...(minAvailability ? { minAvailability: Number(minAvailability) } : {}),
      ...(minCompleteSources ? { minCompleteSources: Number(minCompleteSources) } : {}),
      ...(minBitrateKbps ? { minBitrateKbps: Number(minBitrateKbps) } : {}),
      ...(minLengthSeconds ? { minLengthSeconds: Number(minLengthSeconds) } : {}),
      ...(codec.trim() ? { codec: codec.trim() } : {}),
      ...(title.trim() ? { title: title.trim() } : {}),
      ...(album.trim() ? { album: album.trim() } : {}),
      ...(artist.trim() ? { artist: artist.trim() } : {})
    });
    setParentSearchId(null);
    props.onSearchCreated(next);
  };

  const useSelectedCriteria = () => {
    if (!displayedSearch) return;
    const source = displayedSearch.criteria;
    const numberText = (value: number | null | undefined) => value == null ? "" : String(value);
    setParentSearchId(displayedSearch.id);
    setQuery(displayedSearch.query ?? "");
    setMethod(displayedSearch.requestedMethod ?? "automatic");
    setFileType(displayedSearch.type ?? "");
    setExtension(source?.extension ?? "");
    setMinSizeBytes(numberText(source?.minSizeBytes));
    setMaxSizeBytes(numberText(source?.maxSizeBytes));
    setMinAvailability(numberText(source?.minAvailability));
    setMinCompleteSources(numberText(source?.minCompleteSources));
    setMinBitrateKbps(numberText(source?.minBitrateKbps));
    setMinLengthSeconds(numberText(source?.minLengthSeconds));
    setCodec(source?.codec ?? ""); setTitle(source?.title ?? "");
    setAlbum(source?.album ?? ""); setArtist(source?.artist ?? "");
  };

  const deleteSelectedSearch = async () => {
    const searchId = displayedSearch?.id;
    if (!searchId) {
      return;
    }
    await props.client.delete(`searches/${searchId}`);
    if (parentSearchId === searchId) setParentSearchId(null);
    props.onSearchDeleted(searchId);
  };

  const clearSearches = async () => {
    await props.client.delete("searches?confirm=true");
    setParentSearchId(null);
    props.onSearchesCleared();
  };

  return (
    <section class="panel card">
      <div class="section-title">
        <h2>Search</h2>
        <span>{props.searches.length} sessions on this page</span>
      </div>
      {parentSearchId && <div class="form-row"><span>New search linked to #{parentSearchId}</span>
        <button class="btn" type="button" onClick={() => setParentSearchId(null)}>Clear link</button></div>}
      <form class="form-row" onSubmit={(event) => {
        event.preventDefault();
        if (!searchQueryError) {
          void props.run(startSearch, "Search started", { refresh: false });
        }
      }}>
        <input class="form-control" value={query} placeholder="Search query" aria-invalid={searchQueryError ? "true" : "false"} onInput={(event) => setQuery(event.currentTarget.value)} />
        <select class="form-select" value={method} onInput={(event) => setMethod(event.currentTarget.value)}>
          <option value="automatic">Automatic</option>
          <option value="server">Server</option>
          <option value="global">Global</option>
          <option value="kad">Kad</option>
        </select>
        <select class="form-select" value={fileType} onInput={(event) => setFileType(event.currentTarget.value)}>
          <option value="">Any</option>
          <option value="audio">Audio</option>
          <option value="video">Video</option>
          <option value="image">Image</option>
          <option value="doc">Document</option>
          <option value="arc">Archive</option>
          <option value="iso">ISO</option>
          <option value="pro">Program</option>
          <option value="emulecollection">eMule collection</option>
        </select>
        <button class="btn" type="submit" disabled={!normalizeSearchQuery(query) || Boolean(searchQueryError)}><Search size={16} />Start</button>
      </form>
      {searchQueryError && <p class="field-error">{searchQueryError}</p>}
      {(orderedSearches.length > 0 || displayedSearch != null) && (
        <div class="form-row subtle-row search-session-row">
          <label for="search-session">Search session</label>
          <select
            id="search-session"
            class="form-select search-session-select"
            value={props.selectedSearchId ?? ""}
            onInput={(event) => props.selectSearch(event.currentTarget.value)}
          >
            {!props.selectedSearchId && <option value="" disabled>Select a search session</option>}
            {displayedSearch && !orderedSearches.some((search) => search.id === displayedSearch.id) &&
              <option value={displayedSearch.id}>#{displayedSearch.id} {displayedSearch.query} · {displayedStatus}</option>}
            {orderedSearches.map((search) => (
              <option key={search.id} value={search.id}>
                #{search.id} {search.query || "Untitled search"} · {search.status ?? "unknown"} · {search.resultCount} results
              </option>
            ))}
          </select>
          {displayedSearch && <StatusPill value={displayedStatus} />}
          <button class="btn btn-outline-secondary" type="button" disabled={!displayedSearch} onClick={useSelectedCriteria}>
            Use criteria for new search
          </button>
          {displayedSearch?.parentSearchId && <button class="btn" type="button"
            onClick={() => props.selectSearch(displayedSearch.parentSearchId!)}>View parent #{displayedSearch.parentSearchId}</button>}
          <button class="btn btn-outline-secondary" type="button"
            disabled={!displayedSearch || !["queued", "running"].includes(displayedStatus)}
            onClick={() => { void props.run(() => props.client.post(`searches/${displayedSearch!.id}/stop`), "Search stopped"); }}>
            Stop search
          </button>
          <button
            class="btn btn-outline-secondary"
            type="button"
            disabled={!displayedSearch}
            onClick={() => {
              if (window.confirm("Delete this search session and its saved results?")) {
                void props.run(deleteSelectedSearch, "Search session deleted", { refresh: false });
              }
            }}
          >
            <Trash2 size={15} />
            Delete session
          </button>
          <button
            class="btn btn-outline-danger"
            type="button"
            disabled={props.searches.length === 0 && !displayedSearch}
            onClick={() => {
              if (window.confirm("Clear every saved search session and result?")) {
                void props.run(clearSearches, "Search sessions cleared", { refresh: false });
              }
            }}
          >
            <Trash2 size={15} />
            Clear sessions
          </button>
        </div>
      )}
      {displayedSearch && (
        <section class="search-session-inspector" aria-label="Search session details">
          <div class="kv search-session-kv">
            <span>Requested backend</span>
            <strong>{displayedSearch.requestedMethod ?? "unknown"}</strong>
            <span>Resolved backend</span>
            <strong>{resolvedMethodLabel}</strong>
            <span>File type</span>
            <strong>{displayedSearch.type || "any"}</strong>
            <span>Status reason</span>
            <strong>{displayedSearch.statusReason ?? "—"}</strong>
            <span>Search phase</span>
            <strong>{searchPhaseLabel}</strong>
            <span>Phase progress</span>
            <strong>{searchProgressLabel}</strong>
          </div>
          <div class="search-criteria" aria-label="Applied search criteria">
            <strong>Applied criteria</strong>
            {criteriaRows.length > 0 ? criteriaRows.map(([label, value]) => (
              <span class="search-criterion" key={label}>{label}: {value}</span>
            )) : <span class="text-secondary">No additional filters</span>}
          </div>
        </section>
      )}
      <details class="search-filters">
        <summary>Advanced search filters</summary>
        <div class="form-row subtle-row">
          <input class="form-control" value={extension} maxlength={256} placeholder="Extension" onInput={(event) => setExtension(event.currentTarget.value)} />
          <input class="form-control" type="number" min="0" step="1" value={minSizeBytes} placeholder="Minimum bytes" onInput={(event) => setMinSizeBytes(event.currentTarget.value)} />
          <input class="form-control" type="number" min="0" step="1" value={maxSizeBytes} placeholder="Maximum bytes" onInput={(event) => setMaxSizeBytes(event.currentTarget.value)} />
          <input class="form-control" type="number" min="0" max="1000000" step="1" value={minAvailability} placeholder="Minimum sources" onInput={(event) => setMinAvailability(event.currentTarget.value)} />
          <input class="form-control" type="number" min="0" max="1000000" step="1" value={minCompleteSources} placeholder="Minimum complete sources" onInput={(event) => setMinCompleteSources(event.currentTarget.value)} />
          <input class="form-control" type="number" min="0" max="4294967295" step="1" value={minBitrateKbps} placeholder="Minimum bitrate (kbps)" onInput={(event) => setMinBitrateKbps(event.currentTarget.value)} />
          <input class="form-control" type="number" min="0" max="4294967295" step="1" value={minLengthSeconds} placeholder="Minimum length (seconds)" onInput={(event) => setMinLengthSeconds(event.currentTarget.value)} />
          <input class="form-control" value={codec} maxlength={256} placeholder="Codec" onInput={(event) => setCodec(event.currentTarget.value)} />
          <input class="form-control" value={title} maxlength={256} placeholder="Title" onInput={(event) => setTitle(event.currentTarget.value)} />
          <input class="form-control" value={album} maxlength={256} placeholder="Album" onInput={(event) => setAlbum(event.currentTarget.value)} />
          <input class="form-control" value={artist} maxlength={256} placeholder="Artist" onInput={(event) => setArtist(event.currentTarget.value)} />
        </div>
      </details>
      <div class="form-row subtle-row">
        <select class="form-select" value={category} onInput={(event) => setCategory(event.currentTarget.value)}>
          <option value="">Download uncategorized</option>
          {props.categories.map((category) => (
            <option key={category.name} value={category.name}>Download to {category.name}</option>
          ))}
        </select>
        <label class="check">
          <input class="form-check-input" type="checkbox" checked={paused} onInput={(event) => setPaused(event.currentTarget.checked)} />
          Queue paused
        </label>
        <label class="search-sort-label" for="search-result-sort">Sort results</label>
        <select
          id="search-result-sort"
          class="form-select"
          aria-label="Sort search results"
          value={`${props.searchSort}:${props.searchOrder}`}
          onInput={(event) => {
            const [sort, order] = event.currentTarget.value.split(":");
            props.selectSearchSort(sort, order);
          }}
        >
          <option value="sources:desc">Sources, most first</option>
          <option value="completeSources:desc">Complete sources, most first</option>
          <option value="rating:desc">Rating, highest first</option>
          <option value="sizeBytes:desc">Size, largest first</option>
          <option value="sizeBytes:asc">Size, smallest first</option>
          <option value="displayName:asc">Name, A–Z</option>
          <option value="displayName:desc">Name, Z–A</option>
          <option value="fileType:asc">Type, A–Z</option>
          <option value="title:asc">Media title, A–Z</option>
          <option value="artist:asc">Artist, A–Z</option>
          <option value="album:asc">Album, A–Z</option>
          <option value="lengthSeconds:desc">Duration, longest first</option>
          <option value="bitrateKbps:desc">Bitrate, highest first</option>
          <option value="codec:asc">Codec, A–Z</option>
        </select>
      </div>
      <div class="form-row" role="group" aria-label="Search session pages">
        <span>Session pages</span><CursorControls cursor={props.sessionCursor} nextCursor={props.sessionNextCursor}
          loading={false} change={props.selectSearchSessionsPage} />
      </div>
      <TableScroll label="Search results">
        <table class="table table-vcenter card-table">
          <thead>
            <tr>
              <th>Name</th>
              <th>Size</th>
              <th>Sources</th>
              <th>Rating</th>
              <th>Type</th>
              <th>Observations</th>
              <th>Hash</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            {results.map((result) => {
              const mediaSummary = searchResultMediaSummary(result.media);
              return (
              <tr key={result.id}>
                <td class="search-result-name-cell">
                  <strong>{result.displayName ?? result.hash}</strong>
                  {result.complete && <span class="search-result-complete">Complete file</span>}
                  {result.directory && <span class="search-result-directory">Folder: {result.directory}</span>}
                  {mediaSummary && <span class="search-result-media">{mediaSummary}</span>}
                  {result.aichHash && <span class="search-result-aich">AICH: {result.aichHash}</span>}
                </td>
                <td>{result.sizeBytes === null ? "Unknown" : formatBytes(result.sizeBytes)}</td>
                <td>
                  {result.sources ?? 0}
                  <span class="search-complete-sources">{result.completeSources ?? 0} complete</span>
                </td>
                <td>{(result.rating ?? 0) > 0 ? `${result.rating}/5` : "—"}</td>
                <td>{result.fileType ?? ""}</td>
                <td><button class="btn" type="button" onClick={() => setObservationSelection({ session: selectedSearch!.id, claim: result.id })}>Observations</button></td>
                <td><code class="search-result-hash">{result.hash}</code></td>
                <td>
                  <button class="btn"
                    type="button"
                    title="Download this result"
                    onClick={() => void props.run(
                      () => createDownloadWithChoice((redownload) =>
                        props.client.post(`searches/${selectedSearch?.id}/results/${result.id}/download`, {
                          intent: paused ? "stopped" : "started",
                          category: category || null,
                          redownload
                        })
                      ),
                      "Download queued"
                    )}
                  >
                    <Download size={15} />
                    Download
                  </button>
                </td>
              </tr>
              );
            })}
            {results.length === 0 && <EmptyRow colSpan={8} text="No results." />}
          </tbody>
        </table>
      </TableScroll>
      {observationSelection && observationSelection.session === selectedSearch?.id && (
        <SearchObservations key={`${observationSelection.session}:${observationSelection.claim}`}
          client={props.client} session={observationSelection.session} claim={observationSelection.claim}
          close={() => setObservationSelection(null)} />
      )}
      {selectedSearch && (
        <div class="form-row subtle-row search-pagination" role="group" aria-label="Search result pages">
          <span>{results.length.toLocaleString()} results on this page · {(displayedSearch?.resultCount ?? 0).toLocaleString()} collected</span>
          <CursorControls cursor={props.resultCursor} nextCursor={props.resultPage?.meta.nextCursor ?? null}
            loading={props.resultPage === null} change={props.selectSearchPage} />
        </div>
      )}
    </section>
  );
}

function searchResultMediaSummary(media?: SearchResultMedia): string {
  if (!media) {
    return "";
  }
  const title = media.title.trim();
  const artist = media.artist.trim();
  const album = media.album.trim();
  const codec = media.codec.trim();
  const fields = [
    title ? `Title: ${title}` : "",
    artist ? `Artist: ${artist}` : "",
    album ? `Album: ${album}` : "",
    media.lengthSeconds > 0 ? formatMediaDuration(media.lengthSeconds) : "",
    media.bitrateKbps > 0 ? `${media.bitrateKbps.toLocaleString()} kbps` : "",
    codec ? `Codec: ${codec}` : ""
  ];
  return fields.filter(Boolean).join(" · ");
}


function formatMediaDuration(totalSeconds: number): string {
  const seconds = Math.max(0, Math.trunc(totalSeconds));
  const hours = Math.floor(seconds / 3_600);
  const minutes = Math.floor((seconds % 3_600) / 60);
  const remainder = seconds % 60;
  return hours > 0
    ? `${hours}:${String(minutes).padStart(2, "0")}:${String(remainder).padStart(2, "0")}`
    : `${minutes}:${String(remainder).padStart(2, "0")}`;
}

export function SharingView(props: {
  refreshGeneration: number;
  directories: LibraryScan | null;
  ignores: SharedFileIgnores | null;
  stats: Record<string, unknown>;
  sharedFileCount?: number;
  uploads: Upload[];
  uploadQueue: Upload[];
  client: RestClient;
  run: RunFunction;
}) {
  const [path, setPath] = useState("");
  const [watchNewRoot, setWatchNewRoot] = useState(false);
  const [ignorePattern, setIgnorePattern] = useState("");
  const [rootCursor, setRootCursor] = useState<string | null>(null);
  const [rootPage, setRootPage] = useState<CursorPage<LibraryRoot> | null>(null);
  const [rootsLoading, setRootsLoading] = useState(false);
  const [rootsError, setRootsError] = useState("");
  useEffect(() => {
    let cancelled = false;
    setRootsLoading(true);
    setRootsError("");
    const query = new URLSearchParams({ limit: "100" });
    if (rootCursor) query.set("cursor", rootCursor);
    void props.client.getPage<LibraryRoot>(`library/roots?${query}`)
      .then((value) => { if (!cancelled) setRootPage(value); })
      .catch((error) => { if (!cancelled) setRootsError(errorMessage(error)); })
      .finally(() => { if (!cancelled) setRootsLoading(false); });
    return () => { cancelled = true; };
  }, [props.client, props.refreshGeneration, rootCursor]);
  const roots = rootPage?.data ?? [];
  const customPatterns = props.ignores?.custom ?? [];
  const defaultIgnores = props.ignores?.defaults ?? [];
  const reload = props.directories?.reloadProgress ?? {};
  const pathError = sharedRootPathError(path);
  const sharedFileCount = props.sharedFileCount;

  const addRoot = async () => {
    const nextPath = path.trim();
    if (!nextPath || pathError) {
      return;
    }
    await props.client.post("library/roots", { path: nextPath, watchEnabled: watchNewRoot });
    setPath("");
    setWatchNewRoot(false);
  };

  const removeRoot = (id: string) => props.client.delete(`library/roots/${id}`);

  const addIgnorePattern = async () => {
    const pattern = ignorePattern.trim();
    if (!pattern) {
      return;
    }
    await props.client.post("library/ignores", { pattern });
    setIgnorePattern("");
  };

  const removeIgnorePattern = (pattern: string) =>
    props.client.delete(`library/ignores?pattern=${encodeURIComponent(pattern)}`);

  return (
    <section class="view-grid">
      <Metric label="Roots on page" value={String(roots.length)} />
      <Metric label="Shared Files" value={String(sharedFileCount ?? "n/a")} />
      <Metric label="Shared Bytes" value="n/a" />
      <Metric label="Active Uploads" value={String(props.stats.activeUploads ?? "unknown")} />
      <Metric label="Waiting Uploads" value={String(props.stats.waitingUploads ?? "unknown")} />
      <Metric label="Hashing" value={String(props.directories?.hashingCount ?? 0)} />
      <Metric label="Reload" value={reload.phase ?? "idle"} />
      <Metric label="Hashed" value={`${reload.hashedCount ?? 0}/${reload.plannedHashCount ?? 0}`} />
      <Metric label="Read Rate" value={formatRate(reload.readRateBytesPerSec)} />

      <section class="panel card wide sharing-panel">
        <div class="section-title">
          <h2>Shared Folders</h2>
          <div class="row-actions">
            <StatusPill value={sharingRunState(reload, props.directories?.hashingCount ?? 0)} />
            <button class="btn" type="button" onClick={() => void props.run(() => props.client.post("library/scan"), "Reload queued")}>
              <RefreshCw size={15} />
              Reload
            </button>
          </div>
        </div>
        <p class="hint">Incoming and category folders are shared automatically. Additional folder trees are recursive. Watching is optional and off by default; use Reload to scan on demand.</p>
        <form class="form-row" onSubmit={(event) => {
          event.preventDefault();
          if (!pathError) {
            void props.run(addRoot, "Folder added");
          }
        }}>
          <input class="form-control share-root-input" value={path} placeholder="Server folder path" aria-label="Server folder path" aria-invalid={pathError ? "true" : "false"} onInput={(event) => setPath(event.currentTarget.value)} />
          <label><input type="checkbox" checked={watchNewRoot} onChange={(event) => setWatchNewRoot(event.currentTarget.checked)} /> Watch for changes</label>
          <button class="btn" type="submit" disabled={!path.trim() || Boolean(pathError)}><FolderPlus size={16} />Add root</button>
        </form>
        {pathError && <p class="field-error">{pathError}</p>}
        <div class="section-title"><h3 class="panel-subhead">Configured Roots</h3>
          <CursorControls cursor={rootCursor} nextCursor={rootPage?.meta.nextCursor ?? null} loading={rootsLoading}
            change={(cursor) => { setRootPage(null); setRootCursor(cursor); }} />
        </div>
        {rootsError && <div class="notice alert alert-danger">{rootsError}</div>}
        <TableScroll label="Shared folders">
          <table class="table table-vcenter card-table root-table">
            <thead>
              <tr>
                <th class="root-path-column">Folder</th>
                <th class="root-mode-column">Mode</th>
                <th>Watch</th>
                <th class="root-status-column">Status</th>
                <th class="root-actions-column">Actions</th>
              </tr>
            </thead>
            <tbody>
              {roots.map((root) => (
                <tr key={root.id}>
                  <td class="path-cell" title={displayPath(root.path)}>{displayPath(root.path)}</td>
                  <td>{root.managed ? "Managed" : "Folder tree"}</td>
                  <td><input type="checkbox" checked={root.watchEnabled} aria-label={`Watch ${displayPath(root.path)}`}
                    onChange={(event) => {
                      const watchEnabled = event.currentTarget.checked;
                      void props.run(() => props.client.patch(`library/roots/${root.id}`, { watchEnabled }), "Watch policy updated");
                    }} /></td>
                  <td><StatusPill value={root.accessible === false || root.shareable === false ? "unavailable" : "available"} />
                    {root.scanRequired && <div role="status"><strong>Scan required</strong><small> Use Reload to refresh library files.</small></div>}</td>
                  <td>
                    {!root.managed && <Action title="Remove" icon={<Trash2 size={15} />} onClick={() => {
                      if (window.confirm("Remove this shared folder tree?")) {
                        void props.run(() => removeRoot(root.id), "Folder removed");
                      }
                    }} />}
                  </td>
                </tr>
              ))}
              {roots.length === 0 && <EmptyRow colSpan={5} text="No shared folders." />}
            </tbody>
          </table>
        </TableScroll>
      </section>

      <section class="panel card wide sharing-panel">
        <div class="section-title">
          <h2>Share Ignores</h2>
          <StatusPill value={`${customPatterns.length} custom`} />
        </div>
        <p class="hint">File name glob patterns apply across all shared trees. Matching files are removed from scans, live monitoring, and publication.</p>
        <form class="form-row" onSubmit={(event) => {
          event.preventDefault();
          if (ignorePattern.trim()) {
            void props.run(addIgnorePattern, "Ignore pattern added");
          }
        }}>
          <input class="form-control share-root-input" value={ignorePattern} placeholder="*.part or sample-*.bin" aria-label="File name ignore pattern" onInput={(event) => setIgnorePattern(event.currentTarget.value)} />
          <button class="btn" type="submit" disabled={!ignorePattern.trim()}><FolderPlus size={16} />Add pattern</button>
        </form>
        <h3 class="panel-subhead">Custom Patterns</h3>
        <TableScroll label="Default file ignores">
          <table class="table table-vcenter card-table root-table">
            <thead><tr><th>Pattern</th><th>Actions</th></tr></thead>
            <tbody>
              {customPatterns.map((item) => (
                <tr key={item.pattern}>
                  <td><code>{item.pattern}</code></td>
                  <td><Action title="Remove pattern" icon={<Trash2 size={15} />} onClick={() => void props.run(() => removeIgnorePattern(item.pattern), "Ignore pattern removed")} /></td>
                </tr>
              ))}
              {customPatterns.length === 0 && <EmptyRow colSpan={2} text="No custom ignore patterns." />}
            </tbody>
          </table>
        </TableScroll>
        <h3 class="panel-subhead">Default Rules</h3>
        <TableScroll label="Custom file ignores">
          <table class="table table-vcenter card-table root-table">
            <thead><tr><th>Pattern</th><th>Match</th><th>Status</th><th>Actions</th></tr></thead>
            <tbody>
              {defaultIgnores.map((rule) => (
                <tr key={rule.key}>
                  <td><code>{rule.pattern}</code></td>
                  <td>{rule.matchKind}</td>
                  <td><StatusPill value={rule.enabled ? "enabled" : "disabled"} /></td>
                  <td><button class="btn btn-sm" type="button" onClick={() => void props.run(() => props.client.patch(`library/ignores/defaults/${encodeURIComponent(rule.key)}`, { enabled: !rule.enabled }), rule.enabled ? "Default ignore disabled" : "Default ignore enabled")}>{rule.enabled ? "Disable" : "Enable"}</button></td>
                </tr>
              ))}
            </tbody>
          </table>
        </TableScroll>
      </section>

      <LibraryTags client={props.client} />

      <section class="panel card wide progress-panel">
        <div class="section-title">
          <h2>Reload Progress</h2>
          <StatusPill value={reload.running ? (reload.phase ?? "running") : "idle"} />
        </div>
        <ProgressLine
          label="Total hashing reads"
          completed={reload.completedReadBytes}
          total={reload.plannedReadBytes}
          rate={reload.readRateBytesPerSec}
        />
        <div class="kv progress-kv">
          <span>Pending reload</span>
          <strong>{reload.pending ? "yes" : "no"}</strong>
          <span>Scanned</span>
          <strong>{reload.scannedCount ?? 0}</strong>
          <span>Planned</span>
          <strong>{reload.plannedHashCount ?? 0}</strong>
          <span>Active</span>
          <strong>{reload.activeHashCount ?? 0}</strong>
          <span>Recently hashed</span>
          <strong>{reload.hashedCount ?? 0}</strong>
          <span>Failed</span>
          <strong>{reload.failedHashCount ?? 0}</strong>
          <span>Reused</span>
          <strong>{reload.reusedCount ?? 0}</strong>
          <span>Changed</span>
          <strong>{reload.changedCount ?? 0}</strong>
          <span>New</span>
          <strong>{reload.newCount ?? 0}</strong>
          <span>Escaped paths</span>
          <strong>{reload.escapedDisplayPathCount ?? 0}</strong>
          <span>Skipped</span>
          <strong>{reload.skippedIntakeCount ?? 0}</strong>
          <span>Pruned</span>
          <strong>{reload.prunedCount ?? 0}</strong>
        </div>
      </section>

      <section class="panel card wide progress-panel">
        <h2>Hashing Now</h2>
        <ActiveHashList files={reload.active ?? []} />
      </section>

      <section class="panel card wide">
        <h2>Per Drive</h2>
        <DiskProgressTable disks={reload.disks ?? []} />
      </section>

      <section class="panel card wide">
        <h2>Recently Hashed</h2>
        <RecentHashTable files={reload.recent ?? []} />
      </section>

      <section class="panel card wide">
        <h2>Up Next</h2>
        <QueuedHashTable files={reload.upcoming ?? []} />
      </section>
    </section>
  );
}

function sharingRunState(reload: NonNullable<LibraryScan["reloadProgress"]>, hashingCount: number): string {
  if (reload.pending) {
    return "queued";
  }
  if (reload.running || hashingCount > 0) {
    return reload.phase ?? "hashing";
  }
  return "monitored";
}

function ActiveHashList(props: { files: NonNullable<LibraryScan["reloadProgress"]>["active"] }) {
  const files = props.files ?? [];
  if (files.length === 0) {
    return <p class="empty">No files are hashing right now.</p>;
  }
  return (
    <div class="hash-card-list">
      {files.map((file) => (
        <div class="hash-card" key={file.id ?? file.path}>
          <div class="hash-card-title">
            <strong>{file.name || displayPath(file.path) || "Unnamed file"}</strong>
            <StatusPill value={file.stage ?? "hashing"} />
          </div>
          <p class="path-cell">{displayPath(file.path)}</p>
          <ProgressLine
            label={`${file.reason ?? "hash"} on ${file.diskKey ?? "disk"}`}
            completed={file.readBytes}
            total={file.readBytesTotal}
            rate={file.readRateBytesPerSec}
          />
          <div class="progress-foot">
            <span>Stage {formatBytes(file.stageReadBytes)} / {formatBytes(file.stageTotalBytes)}</span>
            <span>{formatBytes(file.sizeBytes)}</span>
          </div>
        </div>
      ))}
    </div>
  );
}

function DiskProgressTable(props: { disks: NonNullable<LibraryScan["reloadProgress"]>["disks"] }) {
  const disks = props.disks ?? [];
  return (
    <TableScroll label="Disk hashing progress">
      <table class="table table-vcenter card-table">
        <thead>
          <tr>
            <th>Drive</th>
            <th>Files</th>
            <th>Read</th>
            <th>Rate</th>
            <th>Current</th>
          </tr>
        </thead>
        <tbody>
          {disks.map((disk) => (
            <tr key={disk.diskKey ?? "disk"}>
              <td>{disk.diskKey ?? "unknown"}</td>
              <td>{disk.completedCount ?? 0}/{disk.plannedCount ?? 0} done, {disk.queuedCount ?? 0} queued</td>
              <td>{formatPercent(disk.completedReadBytes, disk.plannedReadBytes)}</td>
              <td>{formatRate(disk.readRateBytesPerSec)}</td>
              <td class="path-cell">{displayPath(disk.currentPath) || disk.currentName || ""}</td>
            </tr>
          ))}
          {disks.length === 0 && <EmptyRow colSpan={5} text="No drive hashing activity." />}
        </tbody>
      </table>
    </TableScroll>
  );
}

function RecentHashTable(props: { files: NonNullable<LibraryScan["reloadProgress"]>["recent"] }) {
  const files = props.files ?? [];
  return (
    <TableScroll label="Recently hashed files">
      <table class="table table-vcenter card-table">
        <thead>
          <tr>
            <th>File</th>
            <th>Result</th>
            <th>Read</th>
            <th>Rate</th>
            <th>Time</th>
          </tr>
        </thead>
        <tbody>
          {files.map((file) => (
            <tr key={file.id ?? file.path}>
              <td class="path-cell">{displayPath(file.path) || file.name}</td>
              <td><StatusPill value={file.result ?? "unknown"} /></td>
              <td>{formatBytes(file.readBytes)} / {formatBytes(file.readBytesTotal)}</td>
              <td>{formatRate(file.averageReadRateBytesPerSec)}</td>
              <td>{formatDurationMs(file.durationMs)}</td>
            </tr>
          ))}
          {files.length === 0 && <EmptyRow colSpan={5} text="No recently hashed files." />}
        </tbody>
      </table>
    </TableScroll>
  );
}

function QueuedHashTable(props: { files: NonNullable<LibraryScan["reloadProgress"]>["upcoming"] }) {
  const files = props.files ?? [];
  return (
    <TableScroll label="Queued hashing work">
      <table class="table table-vcenter card-table">
        <thead>
          <tr>
            <th>Order</th>
            <th>File</th>
            <th>Size</th>
            <th>Drive</th>
            <th>Reason</th>
          </tr>
        </thead>
        <tbody>
          {files.map((file) => (
            <tr key={file.id ?? file.path}>
              <td>{(file.order ?? 0) + 1}</td>
              <td class="path-cell">{displayPath(file.path) || file.name}</td>
              <td>{formatBytes(file.sizeBytes)}</td>
              <td>{file.diskKey ?? ""}</td>
              <td>{file.reason ?? ""}</td>
            </tr>
          ))}
          {files.length === 0 && <EmptyRow colSpan={5} text="No queued hashing work." />}
        </tbody>
      </table>
    </TableScroll>
  );
}

type UploadLane = "active" | "queue";

type UploadRow = {
  key: string;
  lane: UploadLane;
  item: Upload;
};

function useUploadPage(client: RestClient, refreshGeneration: number, resource: "uploads" | "upload-queue") {
  const [cursor, setCursor] = useState<string | null>(null);
  const [page, setPage] = useState<CursorPage<Upload> | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  useEffect(() => {
    let current = true;
    setLoading(true);
    setError("");
    const query = new URLSearchParams({ limit: "100", countTotal: "true" });
    if (cursor) query.set("cursor", cursor);
    void client.getPage<Upload>(`${resource}?${query}`).then((page) => {
      if (current) setPage(page);
    }).catch((error) => {
      if (!current) return;
      if (error instanceof RestError && error.status === 409 && cursor) {
        setPage(null);
        setCursor(null);
      } else setError(errorMessage(error));
    }).finally(() => { if (current) setLoading(false); });
    return () => { current = false; };
  }, [client, refreshGeneration, cursor, resource]);
  return { cursor, page, loading, error, change: (value: string | null) => { setPage(null); setCursor(value); } };
}

export function UploadsView(props: { refreshGeneration: number; client: RestClient; run: RunFunction }) {
  const active = useUploadPage(props.client, props.refreshGeneration, "uploads");
  const queue = useUploadPage(props.client, props.refreshGeneration, "upload-queue");
  const uploads = active.page?.data ?? [];
  const uploadQueue = queue.page?.data ?? [];
  const [filter, setFilter] = useState("");
  const [sort, setSort] = useState("rank");
  const [selectedKey, setSelectedKey] = useState("");
  const rows = useMemo(
    () => [
      ...uploads.map((item) => ({ key: uploadRowKey("active", item), lane: "active" as const, item })),
      ...uploadQueue.map((item) => ({ key: uploadRowKey("queue", item), lane: "queue" as const, item }))
    ],
    [uploadQueue, uploads]
  );
  const visibleRows = useMemo(() => {
    const needle = filter.trim().toLowerCase();
    const filtered = needle
      ? rows.filter((row) => uploadSearchText(row).includes(needle))
      : rows;
    return [...filtered].sort((left, right) => compareUploadRows(left, right, sort));
  }, [filter, rows, sort]);
  const activeRows = visibleRows.filter((row) => row.lane === "active");
  const queueRows = visibleRows.filter((row) => row.lane === "queue");
  const selected = rows.find((row) => row.key === selectedKey) ?? visibleRows[0];
  const [detail, setDetail] = useState<{ key: string; item: Upload } | null>(null);
  const [detailError, setDetailError] = useState("");
  useEffect(() => {
    let current = true;
    setDetailError("");
    const clientId = selected?.item.id;
    if (!selected || !clientId) return;
    const key = selected.key;
    const path = selected.lane === "active" ? "uploads" : "upload-queue";
    void props.client.get<Upload>(`${path}/${encodeSegment(clientId)}`).then((item) => {
      if (current) setDetail({ key, item });
    }).catch((error) => {
      if (current) setDetailError(errorMessage(error));
    });
    return () => { current = false; };
  }, [selected?.key, props.client, props.refreshGeneration]);
  const lowIdCount = rows.filter((row) => row.item.lowId).length;
  const friendSlotCount = rows.filter((row) => row.item.friendSlot).length;
  const topFile = topRequestedFile(rows);

  return (
    <section class="view-stack">
      <section class="view-grid">
        <Metric label="Active Slots" value={active.page?.meta.total == null ? "unknown" : String(active.page.meta.total)} />
        <Metric label="Waiting" value={queue.page?.meta.total == null ? "unknown" : String(queue.page.meta.total)} />
        <Metric label="Friend Slots (page)" value={String(friendSlotCount)} />
        <Metric label="LowID Peers (page)" value={String(lowIdCount)} />
        <Metric label="Top File (page)" value={topFile.name} />
        <Metric label="Top Requests (page)" value={String(topFile.count)} />
      </section>
      <section class="panel card">
        <div class="section-title">
          <h2>Upload Queue Inspector</h2>
          <span>{visibleRows.length} clients</span>
        </div>
        <div class="form-row">
          <input class="form-control" value={filter} placeholder="Filter visible clients, files, hashes, software or state" onInput={(event) => setFilter(event.currentTarget.value)} />
          <select class="form-select" value={sort} onInput={(event) => setSort(event.currentTarget.value)}>
            <option value="rank">Rank</option>
            <option value="rate">Rate</option>
            <option value="uploaded">Uploaded</option>
            <option value="wait">Wait</option>
            <option value="file">File</option>
          </select>
        </div>
      </section>
      <UploadTable title="Active Uploads" rows={activeRows} basePath="uploads" client={props.client} run={props.run} selectedKey={selected?.key ?? ""} onSelect={setSelectedKey} />
      {active.error && <p class="notice alert alert-danger">Active uploads: {active.error}</p>}
      <div aria-label="Active upload pages">
        <CursorControls cursor={active.cursor} nextCursor={active.page?.meta.nextCursor ?? null}
          loading={active.loading} change={active.change} />
      </div>
      <p class="hint">{active.loading ? "Loading active uploads…" : `${uploads.length} active clients on this page`}</p>
      <UploadTable title="Upload Queue" rows={queueRows} basePath="upload-queue" client={props.client} run={props.run} selectedKey={selected?.key ?? ""} onSelect={setSelectedKey} />
      {queue.error && <p class="notice alert alert-danger">Upload queue: {queue.error}</p>}
      <div aria-label="Waiting upload pages">
        <CursorControls cursor={queue.cursor} nextCursor={queue.page?.meta.nextCursor ?? null}
          loading={queue.loading} change={queue.change} />
      </div>
      <p class="hint">{queue.loading ? "Loading queue…" : `${uploadQueue.length} waiting clients on this page`}</p>
      {detailError && <p class="notice alert alert-danger">Upload details: {detailError}</p>}
      <UploadPeerInspector row={selected && detail?.key === selected.key
        ? { ...selected, item: { ...selected.item, scoreBreakdown: detail.item.scoreBreakdown } } : selected} />
    </section>
  );
}

function UploadTable(props: {
  title: string;
  rows: UploadRow[];
  basePath: string;
  client: RestClient;
  run: RunFunction;
  selectedKey: string;
  onSelect: (key: string) => void;
}) {
  return (
    <section class="panel card">
      <div class="section-title">
        <h2>{props.title}</h2>
        <span>{props.rows.length} clients</span>
      </div>
      <TableScroll label={props.title}>
        <table class="table table-vcenter card-table">
          <thead>
            <tr>
              <th>Client</th>
              <th>State</th>
              <th>Rank</th>
              <th>File</th>
              <th>Parts</th>
              <th>Rate</th>
              <th>Uploaded</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {props.rows.map((row) => {
              const upload = row.item;
              const clientId = upload.id ?? "";
              const encoded = encodeSegment(clientId);
              return (
                <tr key={row.key} class={props.selectedKey === row.key ? "selected-row" : ""} onClick={() => props.onSelect(row.key)}>
                  <td>
                    <button type="button" class="link-button" onClick={() => props.onSelect(row.key)}>
                      {uploadEndpoint(upload)}
                    </button>
                  </td>
                  <td><StatusPill value={uploadState(upload)} /></td>
                  <td>{upload.queueRank ?? ""}</td>
                  <td>{upload.requestedFileName ?? ""}</td>
                  <td>{uploadParts(upload)}</td>
                  <td>{formatRate(upload.uploadRateBytesPerSec)}</td>
                  <td>{formatBytes(upload.sessionUploadedBytes)}</td>
                  <td>
                    <div class="row-actions">
                      <Action title="Release slot" icon={<Play size={15} />} onClick={() => void props.run(() => props.client.post(`${props.basePath}/${encoded}/operations/release-slot`), "Upload slot released")} />
                      <Action title="Add friend" icon={<UserPlus size={15} />} onClick={() => void props.run(() => props.client.post(`${props.basePath}/${encoded}/operations/add-friend`), "Friend added")} />
                      <Action title="Remove friend" icon={<Trash2 size={15} />} onClick={() => void props.run(() => props.client.post(`${props.basePath}/${encoded}/operations/remove-friend`), "Friend removed")} />
                      <Action title="Ban" icon={<Ban size={15} />} onClick={() => void props.run(() => props.client.post(`${props.basePath}/${encoded}/operations/ban`), "Client banned")} />
                      <Action title="Unban" icon={<Shield size={15} />} onClick={() => void props.run(() => props.client.post(`${props.basePath}/${encoded}/operations/unban`), "Client unbanned")} />
                      <Action title="Remove" icon={<Trash2 size={15} />} onClick={() => void props.run(() => props.client.post(`${props.basePath}/${encoded}/operations/remove`), "Upload client removed")} />
                    </div>
                  </td>
                </tr>
              );
            })}
            {props.rows.length === 0 && <EmptyRow colSpan={8} text="No clients." />}
          </tbody>
        </table>
      </TableScroll>
    </section>
  );
}

function UploadPeerInspector(props: { row?: UploadRow }) {
  const upload = props.row?.item;
  if (!props.row || !upload) {
    return <section class="panel card"><p class="empty">No upload peer selected.</p></section>;
  }
  return (
    <section class="panel card">
      <div class="section-title">
        <h2>Peer Slot Inspector</h2>
        <span>{uploadEndpoint(upload)}</span>
      </div>
      <div class="upload-inspector">
        <div class="kv compact">
          <span>Lane</span><strong>{props.row.lane === "active" ? "active upload" : "waiting queue"}</strong>
          <span>State</span><strong>{uploadState(upload)}</strong>
          <span>Queue rank</span><strong>{upload.queueRank ?? ""}</strong>
          <span>Score</span><strong>{upload.scoreBreakdown?.score ?? ""}</strong>
          <span>Wait time</span><strong>{formatDurationMs(upload.waitTimeSeconds * 1000)}</strong>
          <span>Rate</span><strong>{formatRate(upload.uploadRateBytesPerSec)}</strong>
          <span>Uploaded</span><strong>{formatBytes(upload.sessionUploadedBytes)}</strong>
          <span>Upload duration</span><strong>{upload.uploadDurationSeconds == null ? "unknown" : formatDurationMs(upload.uploadDurationSeconds * 1000)}</strong>
        </div>
        <div class="kv compact">
          <span>User hash</span><strong>{upload.userHash ?? ""}</strong>
          <span>Client</span><strong>{upload.clientSoftware ?? "unknown"}</strong>
          <span>Endpoint</span><strong>{uploadEndpoint(upload)}</strong>
          <span>LowID</span><strong>{upload.lowId == null ? "unknown" : yesNo(upload.lowId)}</strong>
          <span>Friend slot</span><strong>{yesNo(upload.friendSlot)}</strong>
        </div>
        <div class="kv compact">
          <span>Requested file</span><strong>{upload.requestedFileName ?? ""}</strong>
          <span>File hash</span><strong>{upload.requestedFileHash ?? ""}</strong>
          <span>File size</span><strong>{formatBytes(upload.requestedFileSizeBytes)}</strong>
          <span>Requested parts</span><strong>{uploadParts(upload)}</strong>
        </div>
        <ScoreBreakdown value={upload.scoreBreakdown} />
      </div>
    </section>
  );
}

function ScoreBreakdown(props: { value?: Upload["scoreBreakdown"] }) {
  const entries = Object.entries(props.value ?? {});
  return (
    <div class="score-box">
      <h3>Score Breakdown</h3>
      {entries.length === 0 ? (
        <p class="empty">No score breakdown for this peer.</p>
      ) : (
        <div class="score-grid">
          {entries.map(([key, value]) => (
            <div class="score-row" key={key}>
              <span>{key}</span>
              <strong>{formatScoreValue(value)}</strong>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function uploadRowKey(lane: UploadLane, upload: Upload): string {
  return `${lane}:${upload.id}`;
}

function uploadState(upload: Upload): string {
  return upload.uploadState;
}

function uploadSearchText(row: UploadRow): string {
  const upload = row.item;
  return [
    row.lane,
    upload.userHash,
    upload.id,
    upload.clientSoftware,
    upload.address,
    uploadState(upload),
    upload.requestedFileName,
    upload.requestedFileHash,
    uploadParts(upload)
  ].map((value) => String(value ?? "").toLowerCase()).join(" ");
}

function compareUploadRows(left: UploadRow, right: UploadRow, sort: string): number {
  if (sort === "rate") {
    return right.item.uploadRateBytesPerSec - left.item.uploadRateBytesPerSec;
  }
  if (sort === "uploaded") {
    return right.item.sessionUploadedBytes - left.item.sessionUploadedBytes;
  }
  if (sort === "wait") {
    return right.item.waitTimeSeconds - left.item.waitTimeSeconds;
  }
  if (sort === "file") {
    return String(left.item.requestedFileName ?? "").localeCompare(String(right.item.requestedFileName ?? ""));
  }
  return (left.item.queueRank ?? Number.MAX_SAFE_INTEGER) - (right.item.queueRank ?? Number.MAX_SAFE_INTEGER);
}

function topRequestedFile(rows: UploadRow[]): { name: string; count: number } {
  const counts = new Map<string, number>();
  for (const row of rows) {
    const name = row.item.requestedFileName || row.item.requestedFileHash || "";
    if (name) {
      counts.set(name, (counts.get(name) ?? 0) + 1);
    }
  }
  const [name = "", count = 0] = [...counts.entries()].sort((left, right) => right[1] - left[1])[0] ?? [];
  return { name: name || "none", count };
}

function formatScoreValue(value: unknown): string {
  if (typeof value === "number") {
    return Number.isInteger(value) ? String(value) : value.toFixed(2);
  }
  if (typeof value === "boolean") {
    return value ? "yes" : "no";
  }
  if (typeof value === "string") {
    return value;
  }
  return JSON.stringify(value ?? "");
}

function uploadEndpoint(upload: Upload): string {
  return `${upload.address.includes(":") ? `[${upload.address}]` : upload.address}:${upload.port}`;
}

function uploadParts(upload: Upload): string {
  return upload.filePartsAvailable == null || upload.filePartsTotal == null
    ? "unknown" : `${upload.filePartsAvailable}/${upload.filePartsTotal}`;
}

type NetworkEndpointRow = {
  key: string;
  kind: string;
  endpoint: string;
  ip: string;
  host: string;
  dnsStatus: string;
  state: string;
  detail: string;
  lastSeen: string;
  bindPolicy: string;
};

type NetworkDownloadSource = DownloadSource & {
  transferHash?: string;
  transferName?: string;
};

export function NetworkHealthView(props: {
  servers: ServerItem[];
  transfers: DownloadSummary[];
  uploads: Upload[];
  uploadQueue: Upload[];
  kad: KadStatus;
  settings: SettingsSnapshot | null;
  client: RestClient;
}) {
  const [nodes, setNodes] = useState<KadNode[]>([]);
  const [sources, setSources] = useState<NetworkDownloadSource[]>([]);
  const [filter, setFilter] = useState("");
  const [selectedKey, setSelectedKey] = useState("");
  const [loadError, setLoadError] = useState("");
  const sourceTargets = useMemo(
    () => props.transfers
      .filter((transfer) => transfer.state !== "completed")
      .slice(0, 12)
      .map((transfer) => ({
        id: transfer.id,
        hash: transfer.hash,
        name: transfer.name
      })),
    [props.transfers]
  );
  const sourceTargetSignature = sourceTargets.map((transfer) => `${transfer.id}:${transfer.name}`).join("|");

  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      setLoadError("");
      try {
        const [nodePage, sourcePages] = await Promise.all([
          props.client.get<Page<KadNode>>("kad/nodes?limit=300"),
          Promise.all(
            sourceTargets.map(async (transfer) => {
              try {
                const page = await props.client.getPage<DownloadSource>(`downloads/${transfer.id}/sources?limit=100`);
                return page.data.map((source) => ({
                  ...source,
                  transferHash: transfer.hash,
                  transferName: transfer.name
                }));
              } catch {
                return [] as NetworkDownloadSource[];
              }
            })
          )
        ]);
        if (!cancelled) {
          setNodes(nodePage.items ?? []);
          setSources(sourcePages.flat());
        }
      } catch (caught) {
        if (!cancelled) {
          setLoadError(caught instanceof Error ? caught.message : String(caught));
        }
      }
    };
    void load();
    return () => {
      cancelled = true;
    };
  }, [props.client, props.kad.contactCount, props.kad.connected, sourceTargetSignature]);

  const bindPolicy = networkBindPolicy(props.settings);
  const rows = useMemo(
    () => networkEndpointRows(props.servers, nodes, sources, props.uploads, props.uploadQueue, bindPolicy),
    [bindPolicy, nodes, props.servers, props.uploadQueue, props.uploads, sources]
  );
  const filteredRows = useMemo(() => {
    const needle = filter.trim().toLowerCase();
    if (!needle) {
      return rows;
    }
    return rows.filter((row) => [
      row.kind,
      row.endpoint,
      row.ip,
      row.host,
      row.dnsStatus,
      row.state,
      row.detail,
      row.bindPolicy
    ].some((value) => value.toLowerCase().includes(needle)));
  }, [filter, rows]);
  const selected = rows.find((row) => row.key === selectedKey) ?? filteredRows[0];
  const dnsBlocked = rows.filter((row) => row.dnsStatus === "blockedByBindPolicy").length;
  const dnsFailed = rows.filter((row) => row.dnsStatus === "failed").length;
  const unresolved = rows.filter((row) => !row.host && row.dnsStatus && !["resolved", "not-requested"].includes(row.dnsStatus)).length;

  return (
    <section class="view-stack">
      <section class="view-grid">
        <Metric label="Kad Nodes" value={String(nodes.length)} />
        <Metric label="Servers" value={`${props.servers.filter((server) => server.connected).length}/${props.servers.length}`} />
        <Metric label="Peer Endpoints (page)" value={String(sources.length + props.uploads.length + props.uploadQueue.length)} />
        <Metric label="DNS Pending" value={String(unresolved)} />
        <Metric label="DNS Failed" value={String(dnsFailed)} />
        <Metric label="Bind Policy" value={bindPolicy.label} />
      </section>

      <section class="panel card">
        <div class="section-title">
          <h2>Kad Graph</h2>
          <span>{props.kad.connected ? "connected" : props.kad.running ? "running" : "stopped"}</span>
        </div>
        <KadGraph nodes={nodes} selectedNodeId={selected?.kind === "Kad" ? selected.key.replace(/^kad:/, "") : ""} onSelect={(nodeId) => setSelectedKey(`kad:${nodeId}`)} />
      </section>

      <section class="panel card">
        <div class="section-title">
          <h2>Network Health</h2>
          <span>{rows.length} endpoints</span>
        </div>
        {loadError && <div class="notice alert alert-danger">{loadError}</div>}
        <div class="network-summary">
          <div class="kv compact">
            <span>P2P bind</span><strong>{bindPolicy.detail}</strong>
            <span>Hostname lookup</span><strong>{hostnameLookupPolicy(props.settings)}</strong>
            <span>Blocked DNS</span><strong>{dnsBlocked}</strong>
          </div>
          <div class="form-row">
            <input class="form-control" value={filter} placeholder="Filter kind, endpoint, IP, host, DNS, state" onInput={(event) => setFilter(event.currentTarget.value)} />
          </div>
        </div>
        <TableScroll label="Network connections">
          <table class="table table-vcenter card-table">
            <thead>
              <tr>
                <th>Kind</th>
                <th>Endpoint</th>
                <th>IP</th>
                <th>Host</th>
                <th>DNS</th>
                <th>State</th>
                <th>Bind</th>
                <th>Detail</th>
              </tr>
            </thead>
            <tbody>
              {filteredRows.map((row) => (
                <tr key={row.key} class={selected?.key === row.key ? "selected-row" : ""} onClick={() => setSelectedKey(row.key)}>
                  <td>{row.kind}</td>
                  <td>{row.endpoint}</td>
                  <td>{row.ip}</td>
                  <td>{row.host}</td>
                  <td><StatusPill value={row.dnsStatus || "not-requested"} /></td>
                  <td><StatusPill value={row.state || "unknown"} /></td>
                  <td>{row.bindPolicy}</td>
                  <td>{row.detail}</td>
                </tr>
              ))}
              {filteredRows.length === 0 && <EmptyRow colSpan={8} text="No endpoints." />}
            </tbody>
          </table>
        </TableScroll>
        {selected && (
          <div class="kv compact detail-split">
            <span>Selected</span><strong>{selected.kind} {selected.endpoint}</strong>
            <span>IP / host</span><strong>{selected.ip} / {selected.host || "unresolved"}</strong>
            <span>DNS state</span><strong>{selected.dnsStatus || "not-requested"}</strong>
            <span>Bind policy</span><strong>{selected.bindPolicy}</strong>
            <span>Last seen</span><strong>{selected.lastSeen}</strong>
            <span>Detail</span><strong>{selected.detail}</strong>
          </div>
        )}
      </section>
    </section>
  );
}

export function ServersView(props: { status: Status; client: RestClient; run: RunFunction }) {
  const [address, setAddress] = useState("");
  const [port, setPort] = useState("4661");
  const [importUrl, setImportUrl] = useState("https://upd.emule-security.org/server.met");
  const [filter, setFilter] = useState("");
  const [selectedId, setSelectedId] = useState("");
  const [cursor, setCursor] = useState<string | null>(null);
  const [page, setPage] = useState<{ data: (ServerItem & { id: string })[]; meta: { nextCursor: string | null } } | null>(null);
  const [loading, setLoading] = useState(false);
  const [readError, setReadError] = useState("");
  useEffect(() => {
    let current = true;
    setLoading(true);
    void props.client.getPage<ServerItem & { id: string }>(`servers?limit=100${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ""}`)
      .then((value) => { if (current) { setPage(value); setReadError(""); } })
      .catch((error) => { if (current) { setPage(null); setReadError(errorMessage(error)); } })
      .finally(() => { if (current) setLoading(false); });
    return () => { current = false; };
  }, [props.client, props.status, cursor]);
  const servers = page?.data ?? [];
  const serverAddress = address.trim();
  const serverAddressError = endpointAddressError(address, "Address");
  const serverPortError = endpointPortError(port, "Port");
  const serverImportUrlError = urlImportError(importUrl, "server.met URL");
  const serverStatus = props.status.servers;
  const connected = Boolean(serverStatus?.connected ?? servers.some((server) => server.connected));
  const connecting = Boolean(serverStatus?.connecting ?? servers.some((server) => server.connecting));
  const ed2kIdState = connected ? serverStatus?.ed2kIdState ?? "unknown" : "unknown";
  const connectionLabel = connected
    ? ed2kIdState === "high"
      ? "HighID"
      : ed2kIdState === "low"
        ? "LowID"
        : "Connected"
    : connecting
      ? "Connecting"
      : "Disconnected";
  const connectedEd2kId = ed2kIdState === "high"
    ? "HighID"
    : ed2kIdState === "low"
      ? "LowID"
      : "Connected";

  const filteredServers = useMemo(() => {
    const needle = filter.trim().toLowerCase();
    if (!needle) {
      return servers;
    }
    return servers.filter((server) => [
      serverEndpoint(server),
      server.name,
      server.address,
      server.ip,
      server.dynIp,
      server.hostName,
      server.description
    ].some((value) => String(value ?? "").toLowerCase().includes(needle)));
  }, [filter, servers]);
  const selected = useMemo(() => {
    if (!servers.length) {
      return undefined;
    }
    return servers.find((server) => server.id === selectedId) ?? servers[0];
  }, [servers, selectedId]);
  const selectedIsCurrent = selected != null && (
    selected.connected === true
    || selected.current === true
    || serverEndpoint(serverStatus?.currentServer ?? {}) === serverEndpoint(selected)
  );
  const selectedEd2kId = selectedIsCurrent && connected
    ? connectedEd2kId === "Connected" ? "Unknown" : connectedEd2kId
    : "Not connected";

  const createServer = () => {
    const parsedPort = parseEndpointPort(port);
    if (!serverAddress || parsedPort === null) {
      return Promise.resolve();
    }
    return props.client.post("servers", {
      address: serverAddress,
      port: parsedPort,
      priority: "normal",
      static: true
    });
  };

  return (
    <section class="panel card">
      <div class="section-title">
        <h2>Servers</h2>
        <div class="row-actions">
          <button class="btn" type="button" disabled={connected || connecting || servers.length === 0} onClick={() => void props.run(() => props.client.post("servers/operations/connect"), "Server connection started")}><Plug size={15} />Connect</button>
          <button class="btn" type="button" disabled={!connected && !connecting} onClick={() => void props.run(() => props.client.post("servers/operations/disconnect"), "Server disconnected; Kad remains available")}><Ban size={15} />Disconnect</button>
        </div>
      </div>
      <div class="notice alert alert-info" role="status">
        Server network: {connectionLabel}.
        {connected && ed2kIdState === "low" && " Connected, but inbound TCP is not reachable; downloads and searches still work, while callbacks may be slower. Enable UPnP in Settings or forward the shown TCP/UDP ports to try for HighID."}
        {connected && ed2kIdState === "high" && " Inbound TCP reachability is confirmed."}
        {connected && ed2kIdState === "unknown" && " The server has not supplied a usable eD2K ID state."}
        {!connected && servers.length === 0 && " Import server.met or add a server before connecting."}
      </div>
      <form class="form-row" onSubmit={(event) => {
        event.preventDefault();
        if (!serverAddressError && !serverPortError) {
          void props.run(createServer, "Server added");
        }
      }}>
        <input class="form-control" value={address} placeholder="Address" aria-invalid={serverAddressError ? "true" : "false"} onInput={(event) => setAddress(event.currentTarget.value)} />
        <input class="form-control" value={port} placeholder="Port" inputMode="numeric" aria-invalid={serverPortError ? "true" : "false"} onInput={(event) => setPort(event.currentTarget.value)} />
        <button class="btn" type="submit" disabled={!serverAddress || Boolean(serverAddressError) || Boolean(serverPortError)}><Server size={16} />Add</button>
      </form>
      {serverAddressError && <p class="field-error">{serverAddressError}</p>}
      {serverPortError && <p class="field-error">{serverPortError}</p>}
      <form class="form-row" onSubmit={(event) => {
        event.preventDefault();
        const url = parseUrlImportText(importUrl);
        if (url) {
          void props.run(() => props.client.post("servers/operations/import-met-url", { url }), "server.met imported; the server list is ready");
        }
      }}>
        <input class="form-control" value={importUrl} placeholder="server.met URL" aria-invalid={serverImportUrlError ? "true" : "false"} onInput={(event) => setImportUrl(event.currentTarget.value)} />
        <button class="btn" type="submit" disabled={!importUrl.trim() || Boolean(serverImportUrlError)}><Download size={16} />Import</button>
      </form>
      {serverImportUrlError && <p class="field-error">{serverImportUrlError}</p>}
      <div class="form-row">
        <input class="form-control" value={filter} placeholder="Filter endpoint, host, IP, name" onInput={(event) => setFilter(event.currentTarget.value)} />
      </div>
      <CursorControls cursor={cursor} nextCursor={page?.meta.nextCursor ?? null} loading={loading} change={(value) => { setPage(null); setCursor(value); }} />
      <p class="hint">Filter applies to this page. Names are reported by servers.</p>
      {readError && <p role="alert">{readError}</p>}
      <TableScroll label="Servers">
        <table class="table table-vcenter card-table">
          <thead>
            <tr>
              <th>Endpoint</th>
              <th>Host</th>
              <th>IP</th>
              <th>Name</th>
              <th>Status</th>
              <th>Users</th>
              <th>Files</th>
              <th>Ping</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {filteredServers.map((server) => {
              const endpoint = serverEndpoint(server);
              const encoded = encodeSegment(server.id);
              return (
                <tr key={server.id} class={selected?.id === server.id ? "selected-row" : ""} onClick={() => setSelectedId(server.id)}>
                  <td>{endpoint}</td>
                  <td>{hostNameLabel(server)}</td>
                  <td>{server.ip || server.dynIp || ""}</td>
                  <td>{server.name ?? ""}</td>
                  <td><StatusPill value={server.connected ? connectedEd2kId : server.connecting ? "connecting" : server.enabled === false ? "disabled" : server.current ? "current" : "idle"} /></td>
                  <td>{server.users ?? 0}</td>
                  <td>{server.files ?? 0}</td>
                  <td>{server.ping ? `${server.ping} ms` : ""}</td>
                  <td>
                    <div class="row-actions">
                      <Action title="Connect" icon={<Plug size={15} />} onClick={() => void props.run(() => props.client.post(`servers/${encoded}/operations/connect`), "Server connection queued")} />
                      <Action title="Enable" icon={<Play size={15} />} onClick={() => void props.run(() => props.client.patch(`servers/${encoded}`, { enabled: true }), "Server enabled")} />
                      <Action title="Disable" icon={<Pause size={15} />} onClick={() => void props.run(() => props.client.patch(`servers/${encoded}`, { enabled: false }), "Server disabled")} />
                      <Action title="Toggle static" icon={<Save size={15} />} onClick={() => void props.run(() => props.client.patch(`servers/${encoded}`, { static: !server.static }), "Server updated")} />
                    </div>
                  </td>
                </tr>
              );
            })}
            {filteredServers.length === 0 && <EmptyRow colSpan={9} text="No servers." />}
          </tbody>
        </table>
      </TableScroll>
      {selected && (
        <div class="split detail-split">
          <div class="kv compact">
            <span>Configured address</span><strong>{selected.address ?? ""}</strong>
            <span>Resolved IP</span><strong>{selected.ip || ""}</strong>
            <span>Dynamic IP/name</span><strong>{selected.dynIp || ""}</strong>
            <span>Auxiliary ports</span><strong>{selected.auxiliaryPorts?.join(", ") || ""}</strong>
            <span>Hostname</span><strong>{hostNameLabel(selected)}</strong>
            <span>DNS status</span><strong>{selected.hostNameStatus ?? "unknown"}</strong>
            <span>Description</span><strong>{selected.description || ""}</strong>
          </div>
          <div class="kv compact">
            <span>Priority</span><strong>{selected.priority ?? "normal"}</strong>
            <span>Enabled/static</span><strong>{yesNo(selected.enabled !== false)} / {yesNo(selected.static)}</strong>
            <span>Current</span><strong>{yesNo(selected.current)}</strong>
            <span>eD2K ID</span><strong>{selectedEd2kId}</strong>
            <span>Soft/hard files</span><strong>{selected.softFiles ?? 0} / {selected.hardFiles ?? 0}</strong>
            <span>Offer publishing</span><strong>{selected.offerFilesMode ?? "unavailable"}</strong>
            <span>Offer batch/interval</span><strong>{selected.offerFilesBatchMax ?? 0} / {selected.offerFilesMinIntervalMs ?? 0} ms</strong>
            <span>Offer progress</span><strong>{selected.offerFilesPublishedEntries ?? 0} / {(selected.offerFilesPublishedEntries ?? 0) + (selected.offerFilesPendingEntries ?? 0)}</strong>
            <span>Offer fallback</span><strong>{selected.offerFilesFallbackReason ?? ""}</strong>
            <span>Version</span><strong>{selected.version || ""}</strong>
            <span>Obfuscation/UDP flags</span><strong>{selected.obfuscationTcpPort ?? ""} / {selected.udpFlags ?? ""}</strong>
            <span>Failures</span><strong>{selected.failedCount ?? 0}</strong>
          </div>
        </div>
      )}
    </section>
  );
}

export function KadView(props: { kad: KadStatus; client: RestClient; run: RunFunction }) {
  const [bootstrapAddress, setBootstrapAddress] = useState("");
  const [bootstrapPort, setBootstrapPort] = useState("4662");
  const [importUrl, setImportUrl] = useState("https://upd.emule-security.org/nodes.dat");
  const [nodes, setNodes] = useState<KadNode[]>([]);
  const [filter, setFilter] = useState("");
  const [selectedNodeId, setSelectedNodeId] = useState("");
  const bootstrapAddressValue = bootstrapAddress.trim();
  const bootstrapAddressError = endpointAddressError(bootstrapAddress, "Bootstrap address");
  const bootstrapPortError = endpointPortError(bootstrapPort, "Bootstrap port");
  const kadImportUrlError = urlImportError(importUrl, "nodes.dat URL");

  const loadNodes = async () => {
    const page = await props.client.get<Page<KadNode>>("kad/nodes?limit=100");
    setNodes(page.items ?? []);
  };

  useEffect(() => {
    void loadNodes();
  }, [props.kad.contactCount, props.kad.connected]);

  const filteredNodes = useMemo(() => {
    const needle = filter.trim().toLowerCase();
    if (!needle) {
      return nodes;
    }
    return nodes.filter((node) => [
      node.nodeId,
      node.ip,
      node.hostName,
      node.contactType,
      node.udpPort,
      node.tcpPort
    ].some((value) => String(value ?? "").toLowerCase().includes(needle)));
  }, [filter, nodes]);
  const selected = useMemo(() => {
    if (!nodes.length) {
      return undefined;
    }
    return nodes.find((node) => node.nodeId === selectedNodeId) ?? nodes[0];
  }, [nodes, selectedNodeId]);

  return (
    <section class="panel card">
      <div class="section-title">
        <h2>Kad</h2>
        <div class="row-actions">
          <button class="btn" type="button" onClick={() => void loadNodes()}><RefreshCw size={15} />Refresh</button>
          <button class="btn" type="button" disabled={Boolean(props.kad.running)} onClick={() => void props.run(() => props.client.post("kad/operations/start"), "Kad started")}><Play size={15} />Start</button>
          <button class="btn" type="button" disabled={!props.kad.running} onClick={() => void props.run(() => props.client.post("kad/operations/stop"), "Kad stopped; the server connection remains available")}><Pause size={15} />Stop</button>
          <button class="btn" type="button" disabled={!props.kad.running} onClick={() => void props.run(() => props.client.post("kad/operations/recheck-firewall"), "Kad firewall recheck started")}><Shield size={15} />Recheck</button>
        </div>
      </div>
      <div class="notice alert alert-info" role="status">
        Kad network: {props.kad.connected ? "Connected" : props.kad.running ? props.kad.bootstrapping ? "Bootstrapping" : "Starting" : "Stopped"}.
        {!props.kad.running && " You can import nodes.dat now; validated contacts are saved in your profile database for the next Start."}
      </div>
      <div class="kv compact">
        <span>Running</span>
        <strong>{props.kad.running ? "yes" : "no"}</strong>
        <span>Connected</span>
        <strong>{props.kad.connected ? "yes" : "no"}</strong>
        <span>Firewall</span>
        <strong>{firewallLabel(props.kad.firewalled)}</strong>
        <span>Bootstrapping</span>
        <strong>{yesNo(props.kad.bootstrapping)}</strong>
        <span>Contacts</span>
        <strong>{props.kad.contactCount ?? props.kad.nodes ?? 0}</strong>
        <span>Users/files</span>
        <strong>{props.kad.users ?? 0} / {props.kad.files ?? 0}</strong>
        <span>Keywords</span>
        <strong>{props.kad.indexedKeywordCount ?? 0}</strong>
        <span>Sources</span>
        <strong>{props.kad.indexedSourceCount ?? 0}</strong>
      </div>
      <form class="form-row" onSubmit={(event) => {
        event.preventDefault();
        const url = parseUrlImportText(importUrl);
        if (url) {
          void props.run(() => props.client.post("kad/operations/import-nodes-url", { url }), "Kad contacts saved in your profile database");
        }
      }}>
        <input class="form-control" value={importUrl} placeholder="nodes.dat URL" aria-invalid={kadImportUrlError ? "true" : "false"} onInput={(event) => setImportUrl(event.currentTarget.value)} />
        <button class="btn" type="submit" disabled={!importUrl.trim() || Boolean(kadImportUrlError)}><Download size={16} />Import</button>
      </form>
      {kadImportUrlError && <p class="field-error">{kadImportUrlError}</p>}
      <form class="form-row" onSubmit={(event) => {
        event.preventDefault();
        const parsedPort = parseEndpointPort(bootstrapPort);
        if (bootstrapAddressValue && !bootstrapAddressError && parsedPort !== null) {
          void props.run(() => props.client.post("kad/operations/bootstrap", { address: bootstrapAddressValue, port: parsedPort }), "Kad bootstrap started");
        }
      }}>
        <input class="form-control" value={bootstrapAddress} placeholder="Bootstrap address" aria-invalid={bootstrapAddressError ? "true" : "false"} onInput={(event) => setBootstrapAddress(event.currentTarget.value)} />
        <input class="form-control" value={bootstrapPort} inputMode="numeric" placeholder="Port" aria-invalid={bootstrapPortError ? "true" : "false"} onInput={(event) => setBootstrapPort(event.currentTarget.value)} />
        <button class="btn" type="submit" disabled={!bootstrapAddressValue || Boolean(bootstrapAddressError) || Boolean(bootstrapPortError)}><Plug size={16} />Bootstrap</button>
      </form>
      {bootstrapAddressError && <p class="field-error">{bootstrapAddressError}</p>}
      {bootstrapPortError && <p class="field-error">{bootstrapPortError}</p>}
      <div class="form-row">
        <input class="form-control" value={filter} placeholder="Filter Kad node, IP, host, state" onInput={(event) => setFilter(event.currentTarget.value)} />
      </div>
      <TableScroll label="Kad nodes">
        <table class="table table-vcenter card-table">
          <thead>
            <tr>
              <th>IP</th>
              <th>Host</th>
              <th>UDP/TCP</th>
              <th>Version</th>
              <th>State</th>
              <th>Verified</th>
              <th>Flags</th>
              <th>Last seen</th>
            </tr>
          </thead>
          <tbody>
            {filteredNodes.map((node) => (
              <tr key={node.nodeId ?? `${node.ip}:${node.udpPort}`} class={selected && selected.nodeId === node.nodeId ? "selected-row" : ""} onClick={() => setSelectedNodeId(node.nodeId ?? "")}>
                <td>{node.ip ?? ""}</td>
                <td>{hostNameLabel(node)}</td>
                <td>{node.udpPort ?? 0} / {node.tcpPort ?? 0}</td>
                <td>{node.kadVersion ?? 0}</td>
                <td><StatusPill value={node.contactType ?? "unknown"} /></td>
                <td>{yesNo(node.verified)}</td>
                <td>{node.udpKeyKnown ? "key " : ""}{node.bootstrap ? "boot " : ""}{node.udpFirewalled ? "udp-fw " : ""}{node.tcpFirewalled ? "tcp-fw" : ""}</td>
                <td>{shortTime(node.lastSeen)}</td>
              </tr>
            ))}
            {filteredNodes.length === 0 && <EmptyRow colSpan={8} text="No Kad nodes." />}
          </tbody>
        </table>
      </TableScroll>
      {selected && (
        <div class="split detail-split">
          <div class="kv compact">
            <span>Node ID</span><strong>{selected.nodeId ?? ""}</strong>
            <span>IP</span><strong>{selected.ip ?? ""}</strong>
            <span>Hostname</span><strong>{hostNameLabel(selected)}</strong>
            <span>DNS status</span><strong>{selected.hostNameStatus ?? "unknown"}</strong>
            <span>UDP/TCP ports</span><strong>{selected.udpPort ?? 0} / {selected.tcpPort ?? 0}</strong>
            <span>Kad version</span><strong>{selected.kadVersion ?? 0}</strong>
          </div>
          <div class="kv compact">
            <span>Contact type</span><strong>{selected.contactType ?? "unknown"}</strong>
            <span>Probe type</span><strong>{selected.probeType ?? 0}</strong>
            <span>Verified</span><strong>{yesNo(selected.verified)}</strong>
            <span>UDP key known</span><strong>{yesNo(selected.udpKeyKnown)}</strong>
            <span>Hello source UDP</span><strong>{selected.helloSourceUdpPort ?? ""}</strong>
            <span>Created / last seen</span><strong>{shortTime(selected.createdAt)} / {shortTime(selected.lastSeen)}</strong>
          </div>
        </div>
      )}
    </section>
  );
}

function KadGraph(props: { nodes: KadNode[]; selectedNodeId?: string; onSelect: (nodeId: string) => void }) {
  const visible = props.nodes.slice(0, 120);
  const width = 760;
  const height = 340;
  const centerX = width / 2;
  const centerY = height / 2;
  const radiusX = 310;
  const radiusY = 122;
  const points = visible.map((node, index) => {
    const angle = visible.length > 0 ? (Math.PI * 2 * index) / visible.length - Math.PI / 2 : 0;
    const verifiedOffset = node.verified ? 0 : -28;
    return {
      node,
      x: centerX + Math.cos(angle) * (radiusX + verifiedOffset),
      y: centerY + Math.sin(angle) * (radiusY + verifiedOffset * 0.45),
      selected: node.nodeId === props.selectedNodeId
    };
  });
  return (
    <div class="kad-graph-wrap">
      <svg class="kad-graph" viewBox={`0 0 ${width} ${height}`} role="img" aria-label="Kad routing contact graph">
        <rect x="0" y="0" width={width} height={height} rx="8" />
        <g class="kad-graph-edges">
          {points.map((point) => (
            <line key={`edge-${point.node.nodeId ?? `${point.node.ip}:${point.node.udpPort}`}`} x1={centerX} y1={centerY} x2={point.x} y2={point.y} />
          ))}
        </g>
        <g class="kad-graph-self">
          <circle cx={centerX} cy={centerY} r="18" />
          <text x={centerX} y={centerY + 4} text-anchor="middle">self</text>
        </g>
        <g>
          {points.map((point) => {
            const nodeId = point.node.nodeId ?? `${point.node.ip}:${point.node.udpPort}`;
            const className = [
              "kad-graph-node",
              point.node.verified ? "verified" : "unverified",
              point.node.bootstrap ? "bootstrap" : "",
              point.node.udpFirewalled || point.node.tcpFirewalled ? "firewalled" : "",
              point.selected ? "selected" : ""
            ].filter(Boolean).join(" ");
            return (
              <g key={nodeId} class={className} onClick={() => props.onSelect(nodeId)}>
                <circle cx={point.x} cy={point.y} r={point.selected ? 8 : 5.5} />
                <title>{`${point.node.ip ?? ""}:${point.node.udpPort ?? ""} ${point.node.contactType ?? ""}`}</title>
              </g>
            );
          })}
        </g>
      </svg>
      <div class="graph-legend">
        <span><i class="legend-dot verified" />Verified</span>
        <span><i class="legend-dot unverified" />Unverified</span>
        <span><i class="legend-dot bootstrap" />Bootstrap</span>
        <span><i class="legend-dot firewalled" />Firewalled</span>
      </div>
    </div>
  );
}

function networkEndpointRows(
  servers: ServerItem[],
  nodes: KadNode[],
  sources: NetworkDownloadSource[],
  uploads: Upload[],
  uploadQueue: Upload[],
  bindPolicy: { label: string; detail: string }
): NetworkEndpointRow[] {
  const rows: NetworkEndpointRow[] = [];
  for (const server of servers) {
    const endpoint = serverEndpoint(server);
    rows.push({
      key: `server:${endpoint}`,
      kind: "eD2K Server",
      endpoint,
      ip: server.ip || server.dynIp || server.address || "",
      host: server.hostName ?? "",
      dnsStatus: server.hostNameStatus ?? (server.hostName ? "resolved" : "not-requested"),
      state: server.connected ? "connected" : server.connecting ? "connecting" : server.enabled === false ? "disabled" : "idle",
      detail: server.name || server.description || `${server.users ?? 0} users / ${server.files ?? 0} files`,
      lastSeen: server.ping ? `${server.ping} ms ping` : "",
      bindPolicy: bindPolicy.label
    });
  }
  for (const node of nodes) {
    const endpoint = `${node.ip ?? ""}:${node.udpPort ?? ""}`;
    rows.push({
      key: `kad:${node.nodeId ?? endpoint}`,
      kind: "Kad",
      endpoint,
      ip: node.ip ?? "",
      host: node.hostName ?? "",
      dnsStatus: node.hostNameStatus ?? (node.hostName ? "resolved" : "not-requested"),
      state: node.contactType ?? "unknown",
      detail: `v${node.kadVersion ?? 0} ${node.verified ? "verified" : "unverified"}${node.bootstrap ? " bootstrap" : ""}`,
      lastSeen: shortTime(node.lastSeen),
      bindPolicy: bindPolicy.label
    });
  }
  for (const source of sources) {
    rows.push(peerEndpointRow("Transfer Source", `source:${source.transferHash ?? ""}:${source.clientId ?? source.address ?? ""}`, source, bindPolicy, source.transferName ?? source.requestedFileName ?? ""));
  }
  for (const upload of uploads) {
    rows.push(peerEndpointRow("Upload", `upload:${upload.id}`, upload, bindPolicy, upload.requestedFileName ?? ""));
  }
  for (const peer of uploadQueue) {
    rows.push(peerEndpointRow("Upload Queue", `queue:${peer.id}`, peer, bindPolicy, peer.requestedFileName ?? ""));
  }
  return rows;
}

function peerEndpointRow(kind: string, key: string, peer: DownloadSource | Upload, bindPolicy: { label: string; detail: string }, detail: string): NetworkEndpointRow {
  const address = stringField(peer, "address");
  const port = numberField(peer, "port");
  return {
    key,
    kind,
    endpoint: port ? `${address}:${port}` : address || stringField(peer, "clientId"),
    ip: address,
    host: "",
    dnsStatus: "not-exposed",
    state: stringField(peer, "uploadState") || stringField(peer, "downloadState") || "unknown",
    detail: detail || stringField(peer, "userName") || stringField(peer, "clientSoftware"),
    lastSeen: "",
    bindPolicy: bindPolicy.label
  };
}

function networkBindPolicy(settings: SettingsSnapshot | null): { label: string; detail: string } {
  const network = recordField(settings?.data.effective, "network");
  const p2p = recordField(network, "p2p");
  const bindIp = stringField(p2p, "bindIp");
  const bindInterface = stringField(p2p, "bindInterface");
  if (bindIp || bindInterface) {
    return {
      label: "bound",
      detail: [bindInterface && `interface ${bindInterface}`, bindIp && `IP ${bindIp}`].filter(Boolean).join(", ")
    };
  }
  return { label: "unbound", detail: "No P2P bind IP/interface configured" };
}

function hostnameLookupPolicy(settings: SettingsSnapshot | null): string {
  const lookup = recordField(recordField(settings?.data.effective, "network"), "hostnameLookup");
  const enabled = boolField(lookup, "enabled");
  const servers = arrayField(lookup, "dnsServers");
  if (!enabled) {
    return "disabled";
  }
  return servers.length ? `enabled via ${servers.join(", ")}` : "enabled without DNS servers";
}

function serverEndpoint(server: ServerItem): string {
  return server.endpoint ?? server.id ?? `${server.address ?? ""}:${server.port ?? ""}`;
}

function hostNameLabel(item: { hostName?: string | null; hostNameStatus?: string | null; hostNameError?: string | null }): string {
  if (item.hostName) {
    return item.hostName;
  }
  if (item.hostNameStatus && item.hostNameStatus !== "unknown") {
    return item.hostNameStatus;
  }
  return "";
}

function yesNo(value: unknown): string {
  return value === true ? "yes" : "no";
}

function shortTime(value?: number | null): string {
  if (value == null) {
    return "";
  }
  const date = new Date(value * 1000);
  if (Number.isNaN(date.getTime())) {
    return "";
  }
  return date.toLocaleString();
}

export function CategoriesView(props: { categories: Category[]; client: RestClient; run: RunFunction }) {
  const [name, setName] = useState("");
  const [tempDir, setTempDir] = useState("");
  const [destinationDir, setDestinationDir] = useState("");
  const [comment, setComment] = useState("");
  const nameError = identityNameError(name);
  const create = async () => {
    await props.client.post("categories", { name, tempDir: optionalString(tempDir), destinationDir: optionalString(destinationDir), comment });
    setName(""); setTempDir(""); setDestinationDir(""); setComment("");
  };
  return <section class="panel card">
    <div class="section-title"><h2>Categories</h2><span>{props.categories.length} configured</span></div>
    <form class="form-row" onSubmit={(event) => { event.preventDefault(); if (!nameError && name) void props.run(create, "Category created"); }}>
      <input class="form-control" value={name} placeholder="Name" onInput={(event) => setName(event.currentTarget.value)} />
      <input class="form-control" value={tempDir} placeholder="Temporary directory" onInput={(event) => setTempDir(event.currentTarget.value)} />
      <input class="form-control" value={destinationDir} placeholder="Destination directory" onInput={(event) => setDestinationDir(event.currentTarget.value)} />
      <input class="form-control" value={comment} placeholder="Comment" onInput={(event) => setComment(event.currentTarget.value)} />
      <button class="btn" type="submit" disabled={!name || Boolean(nameError)}><FolderPlus size={16} />Add</button>
    </form>
    {nameError && <p class="field-error">{nameError}</p>}
    <TableScroll label="Categories"><table class="table table-vcenter card-table">
      <thead><tr><th>Name</th><th>Temporary directory</th><th>Destination directory</th><th>Comment</th><th>Actions</th></tr></thead>
      <tbody>{props.categories.map((category) => <CategoryRow key={category.name} category={category} client={props.client} run={props.run} />)}
      {props.categories.length === 0 && <EmptyRow colSpan={5} text="No categories." />}</tbody>
    </table></TableScroll>
  </section>;
}

function CategoryRow(props: { category: Category; client: RestClient; run: RunFunction }) {
  const [tempDir, setTempDir] = useState(props.category.tempDir ?? "");
  const [destinationDir, setDestinationDir] = useState(props.category.destinationDir ?? "");
  const [comment, setComment] = useState(props.category.comment);
  return <tr>
    <td>{props.category.name}</td>
    <td><input class="form-control" value={tempDir} onInput={(event) => setTempDir(event.currentTarget.value)} /></td>
    <td><input class="form-control" value={destinationDir} onInput={(event) => setDestinationDir(event.currentTarget.value)} /></td>
    <td><input class="form-control" value={comment} onInput={(event) => setComment(event.currentTarget.value)} /></td>
    <td><div class="row-actions">
      <Action title="Save" icon={<Save size={15} />} onClick={() => void props.run(() => props.client.patch(`categories/${encodeURIComponent(props.category.name)}`, { tempDir: optionalString(tempDir), destinationDir: optionalString(destinationDir), comment }), "Category saved")} />
      <Action title="Delete" icon={<Trash2 size={15} />} onClick={() => { if (window.confirm("Delete this category? Its downloads will become uncategorized.")) void props.run(() => props.client.delete(`categories/${encodeURIComponent(props.category.name)}`), "Category deleted"); }} />
    </div></td>
  </tr>;
}

export function FriendsView(props: { friends: Friend[]; client: RestClient; run: RunFunction }) {
  const [userHash, setUserHash] = useState("");
  const [name, setName] = useState("");
  const userHashError = friendUserHashError(userHash);
  const nameError = friendNameError(name);
  const create = async () => {
    const normalizedUserHash = userHash.trim();
    if (!normalizedUserHash || userHashError || nameError) {
      return;
    }
    await props.client.post("friends", { userHash: normalizedUserHash, name: name || undefined });
    setUserHash("");
    setName("");
  };
  return (
    <section class="panel card">
      <div class="section-title">
        <h2>Friends</h2>
        <span>{props.friends.length} peers</span>
      </div>
      <form class="form-row" onSubmit={(event) => {
        event.preventDefault();
        void props.run(create, "Friend added");
      }}>
        <input class="form-control" value={userHash} placeholder="User hash" aria-invalid={userHashError ? "true" : "false"} onInput={(event) => setUserHash(event.currentTarget.value)} />
        <input class="form-control" value={name} placeholder="Name" aria-invalid={nameError ? "true" : "false"} onInput={(event) => setName(event.currentTarget.value)} />
        <button class="btn" type="submit" disabled={!userHash.trim() || Boolean(userHashError) || Boolean(nameError)}><UserPlus size={16} />Add</button>
      </form>
      {userHashError && <p class="field-error">{userHashError}</p>}
      {nameError && <p class="field-error">{nameError}</p>}
      <TableScroll label="Friends">
        <table class="table table-vcenter card-table">
          <thead>
            <tr>
              <th>Name</th>
              <th>User hash</th>
              <th>Address</th>
              <th>Last seen</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {props.friends.map((friend) => {
              const hash = friend.userHash ?? "";
              return (
                <tr key={hash}>
                  <td>{friend.name ?? ""}</td>
                  <td>{hash}</td>
                  <td>{friend.address ?? ""}{friend.port ? `:${friend.port}` : ""}</td>
                  <td>{friend.lastSeen == null ? "" : new Date(friend.lastSeen * 1000).toLocaleString()}</td>
                  <td><Action title="Delete" icon={<Trash2 size={15} />} onClick={() => void props.run(() => props.client.delete(`friends/${hash}`), "Friend deleted")} /></td>
                </tr>
              );
            })}
            {props.friends.length === 0 && <EmptyRow colSpan={5} text="No friends." />}
          </tbody>
        </table>
      </TableScroll>
    </section>
  );
}

function recordField(object: Record<string, unknown> | undefined, key: string): Record<string, unknown> {
  const value = object?.[key];
  return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {};
}

function arrayField(object: Record<string, unknown> | undefined, key: string): string[] {
  const value = object?.[key];
  return Array.isArray(value) ? value.map((item) => String(item)) : [];
}

const TRANSFER_ADD_LINK_TEXT_ERROR = "Each transfer link must start with ed2k://, contain no whitespace or control characters, and be at most 2048 characters.";
const URL_IMPORT_TEXT_ERROR = "must start with http:// or https://, include a host, contain no whitespace or control characters, and be at most 2048 characters.";

function transferLinksFromText(value: string): string[] {
  return value.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
}

function transferLinksValidationError(value: string): string | undefined {
  const links = transferLinksFromText(value);
  if (links.length === 0) {
    return undefined;
  }
  if (links.length > 100) {
    return "Add links accepts at most 100 eD2K links.";
  }
  if (links.some((link) => !isTransferAddLinkText(link))) {
    return TRANSFER_ADD_LINK_TEXT_ERROR;
  }
  return undefined;
}

function isTransferAddLinkText(value: string): boolean {
  return value.length <= 2048 && /^[eE][dD]2[kK]:\/\/[^\s\u0000-\u001f\u007f-\u009f]+$/.test(value);
}

function parseUrlImportText(value: string): string | null {
  const normalized = value.trim();
  if (!normalized) {
    return null;
  }
  return normalized.length <= 2048
    && /^[hH][tT][tT][pP][sS]?:\/\/[^\s/?#\u0000-\u001f\u007f-\u009f][^\s\u0000-\u001f\u007f-\u009f]*$/.test(normalized)
    ? normalized
    : null;
}

function displayPath(value: string | null | undefined): string {
  if (!value) {
    return "";
  }
  if (value.startsWith("\\\\?\\UNC\\")) {
    return `\\\\${value.slice("\\\\?\\UNC\\".length)}`;
  }
  if (value.startsWith("\\\\?\\")) {
    const rest = value.slice("\\\\?\\".length);
    if (rest[1] === ":") {
      return rest;
    }
  }
  return value;
}

function urlImportError(value: string, label: string): string | undefined {
  return value.trim() && parseUrlImportText(value) === null ? `${label} ${URL_IMPORT_TEXT_ERROR}` : undefined;
}

function friendUserHashError(value: string): string | undefined {
  const normalized = value.trim();
  if (!normalized) {
    return undefined;
  }
  return /^[0-9a-f]{32}$/.test(normalized) ? undefined : "User hash must be a 32-character lowercase hex string.";
}

function friendNameError(value: string): string | undefined {
  if (!value) {
    return undefined;
  }
  if (/[\u0000-\u001f\u007f]/.test(value)) {
    return "Friend name must not contain control characters.";
  }
  return value.length <= 128 ? undefined : "Friend name must be at most 128 characters.";
}





function normalizeSearchQuery(value: string): string {
  return value.trim().split(/[ \t\n\r\f\v]+/).filter(Boolean).join(" ");
}

function searchQueryValidationError(value: string): string | undefined {
  const normalized = normalizeSearchQuery(value);
  if (!normalized) {
    return undefined;
  }
  if (/[\u0000-\u001f\u007f-\u009f]/.test(normalized)) {
    return "Search query must not contain control characters.";
  }
  return normalized.length <= 160 ? undefined : "Search query must be at most 160 characters.";
}

function sharedRootPathError(value: string): string | undefined {
  return value && !value.trim() ? "Folder path must not be empty." : undefined;
}

function endpointAddressError(value: string, label: string): string | undefined {
  return value && !value.trim() ? `${label} must not be empty.` : undefined;
}

function optionalPort(value: string): number | null {
  const trimmed = value.trim();
  return trimmed ? Number(trimmed) : null;
}

function parseEndpointPort(value: string): number | null {
  const trimmed = value.trim();
  if (!/^\d+$/.test(trimmed)) {
    return null;
  }
  const port = Number(trimmed);
  return port >= 1 && port <= 65535 ? port : null;
}

function endpointPortError(value: string, label: string): string | undefined {
  return parseEndpointPort(value) === null ? `${label} must be between 1 and 65535.` : undefined;
}



export type EventStreamStatus = {
  mode: "polling" | "connecting" | "streaming" | "reconnecting";
  enabled: boolean;
  connected: boolean;
  lastEventId?: string;
  lastEventType?: string;
  lastEventAt?: string;
  reconnectAttempts: number;
  lastError?: string;
  pollIntervalMs: number;
  retryIntervalMs: number;
};

export function DiagnosticsView(props: {
  app: unknown;
  capabilities: unknown;
  runtimeDiagnostics: RuntimeDiagnostics | null;
  eventStreamStatus: EventStreamStatus;
  client: RestClient;
  run: RunFunction;
}) {
  const [bundleFileName, setBundleFileName] = useState("");
  const diagnostics = props.runtimeDiagnostics ?? {};
  const resources = diagnostics.processResources;
  const eventStream = props.eventStreamStatus;
  const downloadEvents = diagnostics.downloadEvents ?? {};
  const reload = diagnostics.sharedDirectoryReloadProgress ?? {};
  const ed2kPublishPhase = stringField(recordField(diagnostics, "ed2kPublish"), "phase") || "unknown";
  const kadPublishPhase = stringField(recordField(diagnostics, "kadPublish"), "phase") || "unknown";
  const eventStreamMode = eventStream.mode === "streaming"
    ? "Streaming"
    : eventStream.mode === "reconnecting"
      ? "Reconnecting"
      : eventStream.mode === "connecting"
        ? "Connecting"
        : "Polling";

  const captureBundle = async () => {
    const bundle = await props.client.captureDiagnosticBundle(16 * 1024 * 1024);
    const stamp = String(bundle.capturedAt);
    const fileName = `emulebb-rust-diagnostic-bundle-${stamp}.json`;
    const blob = new Blob([`${JSON.stringify(bundle, null, 2)}\n`], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = fileName;
    anchor.click();
    URL.revokeObjectURL(url);
    setBundleFileName(fileName);
  };

  return (
    <section class="view-stack">
      <section class="panel card">
        <div class="section-title">
          <h2>Diagnostics</h2>
        </div>
        <div class="row-actions">
          <button class="btn" type="button" onClick={() => void props.run(captureBundle, "Diagnostic bundle downloaded")}>
            <FileText size={15} />
            Capture private bundle
          </button>
        </div>
        {bundleFileName && <p class="hint">Downloaded: {bundleFileName}</p>}
        <div class="form-row danger-row">
          <button class="btn"
            type="button"
            onClick={() => void props.run(() => props.client.post("diagnostics/crash-tests", { confirmCrash: true }), "Crash test triggered")}
          >
            <Ban size={15} />
            Crash test
          </button>
          <button class="btn"
            type="button"
            onClick={() => void props.run(() => props.client.post("app/shutdown", { confirmShutdown: true }), "Shutdown requested")}
          >
            <Plug size={15} />
            Shutdown
          </button>
        </div>
      </section>
      <section class="panel card">
        <div class="section-title"><h2>Daemon resources</h2></div>
        <div class="view-grid">
          <Metric label="Resident memory" value={resources?.residentMemoryBytes == null ? "n/a" : formatBytes(resources.residentMemoryBytes)} />
          <Metric label="CPU usage" value={resources?.cpuUsagePercent == null ? "n/a" : `${resources.cpuUsagePercent.toFixed(1)}%`} />
        </div>
        <p class="hint">Memory is the daemon's resident RAM. CPU: 100% means one fully occupied core; multiple cores can exceed 100%.</p>
        <p class="hint">
          {resources?.sampledAt == null
            ? "Resource metrics are unavailable."
            : `Sampled ${new Date(resources.sampledAt * 1000).toLocaleTimeString()}. ${resources.cpuSampleIntervalMs == null
              ? "CPU usage needs two samples at least one second apart; unavailable counters show n/a."
              : `CPU average over ${(resources.cpuSampleIntervalMs / 1000).toFixed(1)} s.`}`}
        </p>
      </section>
      <section class="view-grid">
        <Metric label="Process" value={String(diagnostics.processId ?? "n/a")} />
        <Metric label="Known Files" value={String(diagnostics.knownFileCount ?? 0)} />
        <Metric label="Shared Files" value={String(diagnostics.sharedFileCount ?? 0)} />
        <Metric label="Hashing" value={String(diagnostics.sharedHashingCount ?? 0)} />
        <Metric label="Reload" value={reload.phase ?? "idle"} />
        <Metric label="Hashed" value={`${reload.hashedCount ?? 0}/${reload.plannedHashCount ?? 0}`} />
        <Metric label="Read Rate" value={formatRate(reload.readRateBytesPerSec)} />
        <Metric label="Downloads" value={String(diagnostics.downloadFileCount ?? 0)} />
        <Metric label="Active Uploads" value={String(diagnostics.activeUploads ?? 0)} />
        <Metric label="Waiting Uploads" value={String(diagnostics.waitingUploads ?? 0)} />
        <Metric label="eD2K Publish" value={ed2kPublishPhase} />
        <Metric label="Kad Publish" value={kadPublishPhase} />
        <Metric label="Event Stream" value={eventStreamMode} />
        <Metric label="Last Event" value={eventStream.lastEventType ?? "n/a"} />
        <Metric label="Last Event ID" value={eventStream.lastEventId ?? "n/a"} />
        <Metric label="Reconnects" value={String(eventStream.reconnectAttempts)} />
        <Metric label="Poll Interval" value={`${eventStream.pollIntervalMs} ms`} />
        <Metric label="Stream Error" value={eventStream.lastError ?? "n/a"} />
        <Metric label="SSE Subscribers" value={String(downloadEvents.subscriberCount ?? 0)} />
        <Metric label="Event Queue" value={`${downloadEvents.queuedEventCount ?? 0}/${downloadEvents.channelCapacity ?? 0}`} />
        <Metric label="Latest Bus Event" value={String(downloadEvents.latestEventId ?? 0)} />
        <Metric label="Resume" value={downloadEvents.resumeBehavior ?? "n/a"} />
      </section>
      <section class="panel card">
        <div class="section-title">
          <h2>Runtime</h2>
        </div>
        <JsonPanel value={props.runtimeDiagnostics} />
      </section>
      <section class="panel card split">
        <div>
          <h2>App</h2>
          <JsonPanel value={props.app} />
        </div>
        <div>
          <h2>Capabilities</h2>
          <JsonPanel value={props.capabilities} />
        </div>
      </section>
    </section>
  );
}

export function LogsView(props: { logs: LogRecord[]; client: RestClient; run: RunFunction }) {
  return (
    <section class="panel card">
      <div class="section-title">
        <h2>Logs</h2>
        <button class="btn" type="button" onClick={() => void props.run(() => props.client.post("logs/operations/clear", { confirmClearLogs: true }), "Logs cleared")}>
          <Trash2 size={15} />
          Clear
        </button>
      </div>
      <div class="logs">
        {props.logs.map((log, index) => (
          <div class="log-row" key={`${log.timestamp ?? index}-${index}`}>
            <time>{shortTime(log.timestamp)}</time>
            <span>{log.level ?? "INFO"}</span>
            <p>{log.message ?? ""}</p>
          </div>
        ))}
      </div>
    </section>
  );
}

function DownloadStateLabel({ download }: { download: DownloadSummary }) {
  const labels = { network: "Waiting for network", sources: "Waiting for useful sources", resources: "Waiting for resources" };
  return <span><StatusPill value={download.state} />{download.state === "queued" && <small class="text-muted"> {labels[download.waitingReason]}</small>}</span>;
}

function CompactTransferList(props: { transfers: DownloadSummary[] }) {
  if (props.transfers.length === 0) {
    return <p class="empty">No transfers.</p>;
  }
  return (
    <div class="compact-list">
      {props.transfers.map((transfer) => (
        <div class="compact-row" key={transfer.id}>
          <span>{transfer.name ?? transfer.hash}</span>
          <DownloadStateLabel download={transfer} />
          <strong>{formatProgress(transfer)}</strong>
        </div>
      ))}
    </div>
  );
}

function kibToBytes(value?: number): number | undefined {
  return value === undefined ? undefined : value * 1024;
}
