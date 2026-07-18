import { useEffect, useMemo, useState } from "preact/hooks";
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
  AppSettings,
  Category,
  Friend,
  KadStatus,
  LogRecord,
  Page,
  RestClient,
  SearchItem,
  ServerItem,
  SharedDirectories,
  SharedFile,
  Snapshot,
  Transfer,
  TransferSource,
  Upload,
  encodeSegment
} from "./api";
import { Action, EmptyRow, JsonPanel, Metric, StatusPill } from "./components";
import {
  boolField,
  firewallLabel,
  formatBytes,
  formatDurationMs,
  formatKiBRate,
  formatPercent,
  formatProgress,
  formatRate,
  lifecycleLabel,
  numberField,
  optionalString,
  parseNumber,
  stringField
} from "./format";

export type RunFunction = (operation: () => Promise<unknown>, success: string) => Promise<void>;

export function Overview(props: {
  snapshot: Snapshot | null;
  stats: Record<string, unknown>;
  transfers: Transfer[];
  servers: ServerItem[];
  uploads: Upload[];
  uploadQueue: Upload[];
  sharedFiles: SharedFile[];
  sharedDirectories: SharedDirectories | null;
  kad: KadStatus;
}) {
  const activeTransfers = props.transfers.filter((item) => item.state !== "completed").length;
  const connectedServers = props.servers.filter((item) => item.connected).length;
  const reload = props.sharedDirectories?.reloadProgress ?? props.snapshot?.status?.runtimeDiagnostics?.sharedDirectoryReloadProgress ?? props.snapshot?.status?.sharedStartupCache?.reloadProgress ?? {};
  const startupStages = startupStageRows(props.snapshot, props.sharedDirectories, props.kad, connectedServers);
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
      <Metric label="Transfers" value={`${activeTransfers}/${props.transfers.length}`} />
      <Metric label="Uploads" value={`${props.uploads.length}/${props.uploadQueue.length}`} />
      <Metric label="Shared" value={String(numberField(props.stats, "sharedFiles") ?? props.sharedFiles.length)} />
      <Metric label="Kad" value={props.kad.connected ? "Connected" : "Idle"} />

      <section class="panel wide">
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

      <section class="panel wide">
        <h2>Network</h2>
        <div class="kv">
          <span>Lifecycle</span>
          <strong>{lifecycleLabel(props.snapshot?.status?.lifecycle)}</strong>
          <span>Server</span>
          <strong>{connectedServers > 0 ? "connected" : "disconnected"}</strong>
          <span>Kad firewall</span>
          <strong>{firewallLabel(props.kad.firewalled)}</strong>
          <span>Shared bytes</span>
          <strong>{formatBytes(numberField(props.stats, "sharedBytes"))}</strong>
        </div>
      </section>

      <section class="panel wide">
        <h2>Recent Transfers</h2>
        <CompactTransferList transfers={props.transfers.slice(0, 8)} />
      </section>
    </section>
  );
}

function startupStageRows(
  snapshot: Snapshot | null,
  directories: SharedDirectories | null,
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

export function TransfersView(props: {
  transfers: Transfer[];
  categories: Category[];
  client: RestClient;
  run: RunFunction;
}) {
  const [stateFilter, setStateFilter] = useState("");
  const [ed2kLinks, setEd2kLinks] = useState("");
  const [pausedCreate, setPausedCreate] = useState(false);
  const [selectedHash, setSelectedHash] = useState("");
  const [details, setDetails] = useState<unknown>(null);
  const [sources, setSources] = useState<TransferSource[]>([]);
  const [detailError, setDetailError] = useState("");

  const filtered = useMemo(
    () => props.transfers.filter((transfer) => !stateFilter || transfer.state === stateFilter),
    [props.transfers, stateFilter]
  );
  const selected = props.transfers.find((transfer) => transfer.hash === selectedHash) ?? props.transfers[0];
  const selectedId = selected?.hash ?? "";

  useEffect(() => {
    if (!selectedId) {
      setDetails(null);
      setSources([]);
      return;
    }
    let cancelled = false;
    const load = async () => {
      setDetailError("");
      try {
        const [nextDetails, nextSources] = await Promise.all([
          props.client.get<unknown>(`transfers/${selectedId}/details`),
          props.client.get<Page<TransferSource>>(`transfers/${selectedId}/sources`)
        ]);
        if (!cancelled) {
          setDetails(nextDetails);
          setSources(nextSources.items ?? []);
        }
      } catch (caught) {
        if (!cancelled) {
          setDetailError(caught instanceof Error ? caught.message : String(caught));
        }
      }
    };
    void load();
    return () => {
      cancelled = true;
    };
  }, [props.client, selectedId]);

  const createTransfers = async () => {
    const links = ed2kLinks.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
    if (links.length === 0) {
      throw new Error("At least one eD2K link is required");
    }
    await props.client.post("transfers", { links, paused: pausedCreate });
    setEd2kLinks("");
  };

  const patchCategory = (transfer: Transfer, categoryId: string) =>
    props.client.patch(`transfers/${transfer.hash}`, { categoryId: Number(categoryId) });

  return (
    <section class="view-stack">
      <section class="panel">
        <div class="section-title">
          <h2>Transfers</h2>
          <div class="row-actions">
            <select value={stateFilter} onInput={(event) => setStateFilter(event.currentTarget.value)}>
              <option value="">All states</option>
              <option value="downloading">Downloading</option>
              <option value="paused">Paused</option>
              <option value="completed">Completed</option>
              <option value="error">Error</option>
            </select>
            <button
              type="button"
              onClick={() => {
                if (window.confirm("Clear completed transfer rows and preserve files?")) {
                  void props.run(
                    () => props.client.post("transfers/operations/clear-completed", { confirmClearCompleted: true }),
                    "Completed transfer rows cleared"
                  );
                }
              }}
            >
              <Trash2 size={15} />
              Clear completed
            </button>
          </div>
        </div>
        <form
          class="form-row"
          onSubmit={(event) => {
            event.preventDefault();
            void props.run(createTransfers, "Transfers queued");
          }}
        >
          <textarea
            value={ed2kLinks}
            placeholder="One eD2K link per line"
            onInput={(event) => setEd2kLinks(event.currentTarget.value)}
          />
          <label class="check">
            <input type="checkbox" checked={pausedCreate} onInput={(event) => setPausedCreate(event.currentTarget.checked)} />
            Paused
          </label>
          <button type="submit">
            <Download size={16} />
            Add links
          </button>
        </form>
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>State</th>
                <th>Progress</th>
                <th>Down</th>
                <th>Category</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((transfer) => (
                <tr key={transfer.hash} class={selectedId === transfer.hash ? "selected-row" : ""}>
                  <td>
                    <button type="button" class="link-button" onClick={() => setSelectedHash(transfer.hash)}>
                      {transfer.name ?? transfer.hash}
                    </button>
                  </td>
                  <td><StatusPill value={transfer.state ?? "unknown"} /></td>
                  <td>{formatProgress(transfer)}</td>
                  <td>{formatKiBRate(transfer.downloadSpeedKiBps) || formatRate(transfer.downloadRateBytesPerSec)}</td>
                  <td>
                    <select
                      value={String(transfer.categoryId ?? 0)}
                      onInput={(event) => void props.run(() => patchCategory(transfer, event.currentTarget.value), "Category updated")}
                    >
                      <option value="0">Uncategorized</option>
                      {props.categories.map((category) => (
                        <option key={category.id} value={category.id}>{category.name}</option>
                      ))}
                    </select>
                  </td>
                  <td>
                    <div class="row-actions">
                      <Action title="Pause" icon={<Pause size={15} />} onClick={() => void props.run(() => props.client.post(`transfers/${transfer.hash}/operations/pause`), "Transfer paused")} />
                      <Action title="Resume" icon={<Play size={15} />} onClick={() => void props.run(() => props.client.post(`transfers/${transfer.hash}/operations/resume`), "Transfer resumed")} />
                      <Action title="Stop" icon={<Ban size={15} />} onClick={() => void props.run(() => props.client.post(`transfers/${transfer.hash}/operations/stop`), "Transfer stopped")} />
                      <Action title="Recheck" icon={<RefreshCw size={15} />} onClick={() => void props.run(() => props.client.post(`transfers/${transfer.hash}/operations/recheck`), "Recheck queued")} />
                      <Action title="Delete row" icon={<Trash2 size={15} />} onClick={() => void props.run(() => props.client.delete(`transfers/${transfer.hash}`), "Transfer row deleted")} />
                      <Action title="Delete files" icon={<FileText size={15} />} onClick={() => {
                        if (window.confirm("Delete this transfer and its local files?")) {
                          void props.run(() => props.client.delete(`transfers/${transfer.hash}/files?confirm=true`), "Transfer files deleted");
                        }
                      }} />
                    </div>
                  </td>
                </tr>
              ))}
              {filtered.length === 0 && <EmptyRow colSpan={6} text="No transfers." />}
            </tbody>
          </table>
        </div>
      </section>

      <section class="panel">
        <div class="section-title">
          <h2>Transfer Details</h2>
          <span>{selected?.name ?? (selectedId || "No selection")}</span>
        </div>
        {detailError && <div class="notice error">{detailError}</div>}
        <div class="split">
          <JsonPanel value={details} />
          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Source</th>
                  <th>State</th>
                  <th>Rate</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {sources.map((source) => {
                  const clientId = source.clientId ?? "";
                  const encodedClient = encodeSegment(clientId);
                  return (
                    <tr key={clientId}>
                      <td>{source.userName ?? clientId}</td>
                      <td><StatusPill value={source.state ?? "unknown"} /></td>
                      <td>{formatKiBRate(source.downloadSpeedKiBps) || formatRate(source.downloadRateBytesPerSec)}</td>
                      <td>
                        <div class="row-actions">
                          <Action title="Browse" icon={<Search size={15} />} onClick={() => void props.run(() => props.client.post(`transfers/${selectedId}/sources/${encodedClient}/operations/browse`), "Browse requested")} />
                          <Action title="Add friend" icon={<UserPlus size={15} />} onClick={() => void props.run(() => props.client.post(`transfers/${selectedId}/sources/${encodedClient}/operations/add-friend`), "Friend added")} />
                          <Action title="Remove source" icon={<Trash2 size={15} />} onClick={() => void props.run(() => props.client.post(`transfers/${selectedId}/sources/${encodedClient}/operations/remove`), "Source removed")} />
                          <Action title="Ban" icon={<Ban size={15} />} onClick={() => void props.run(() => props.client.post(`transfers/${selectedId}/sources/${encodedClient}/operations/ban`), "Source banned")} />
                        </div>
                      </td>
                    </tr>
                  );
                })}
                {sources.length === 0 && <EmptyRow colSpan={4} text="No sources for this transfer." />}
              </tbody>
            </table>
          </div>
        </div>
      </section>
    </section>
  );
}

export function SearchView(props: {
  searches: SearchItem[];
  latestSearch: SearchItem | null;
  categories: Category[];
  client: RestClient;
  run: RunFunction;
  refresh: () => Promise<void>;
  setLatestSearch: (search: SearchItem | null) => void;
}) {
  const [query, setQuery] = useState("");
  const [method, setMethod] = useState("automatic");
  const [fileType, setFileType] = useState("any");
  const [categoryId, setCategoryId] = useState("0");
  const [paused, setPaused] = useState(false);
  const results = props.latestSearch?.results ?? [];

  const startSearch = async () => {
    const next = await props.client.post<SearchItem>("searches", { query, method, type: fileType });
    props.setLatestSearch(next);
    await props.refresh();
  };

  return (
    <section class="panel">
      <div class="section-title">
        <h2>Search</h2>
        <span>{props.searches.length} sessions</span>
      </div>
      <form class="form-row" onSubmit={(event) => {
        event.preventDefault();
        void props.run(startSearch, "Search started");
      }}>
        <input value={query} placeholder="Search query" onInput={(event) => setQuery(event.currentTarget.value)} />
        <select value={method} onInput={(event) => setMethod(event.currentTarget.value)}>
          <option value="automatic">Automatic</option>
          <option value="server">Server</option>
          <option value="global">Global</option>
          <option value="kad">Kad</option>
        </select>
        <select value={fileType} onInput={(event) => setFileType(event.currentTarget.value)}>
          <option value="any">Any</option>
          <option value="audio">Audio</option>
          <option value="video">Video</option>
          <option value="archive">Archive</option>
          <option value="document">Document</option>
        </select>
        <button type="submit"><Search size={16} />Start</button>
      </form>
      <div class="form-row subtle-row">
        <select value={categoryId} onInput={(event) => setCategoryId(event.currentTarget.value)}>
          <option value="0">Download uncategorized</option>
          {props.categories.map((category) => (
            <option key={category.id} value={category.id}>Download to {category.name}</option>
          ))}
        </select>
        <label class="check">
          <input type="checkbox" checked={paused} onInput={(event) => setPaused(event.currentTarget.checked)} />
          Queue paused
        </label>
      </div>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Size</th>
              <th>Sources</th>
              <th>Type</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            {results.map((result) => (
              <tr key={result.hash}>
                <td>{result.name ?? result.hash}</td>
                <td>{formatBytes(result.sizeBytes)}</td>
                <td>{result.sources ?? result.availability ?? 0}</td>
                <td>{result.fileType ?? ""}</td>
                <td>
                  <button
                    type="button"
                    onClick={() => void props.run(
                      () => props.client.post(`searches/${props.latestSearch?.id}/results/${result.hash}/operations/download`, {
                        paused,
                        categoryId: Number(categoryId)
                      }),
                      "Download queued"
                    )}
                  >
                    <Download size={15} />
                    Download
                  </button>
                </td>
              </tr>
            ))}
            {results.length === 0 && <EmptyRow colSpan={5} text="No results." />}
          </tbody>
        </table>
      </div>
    </section>
  );
}

export function SharingView(props: {
  directories: SharedDirectories | null;
  client: RestClient;
  run: RunFunction;
}) {
  const [path, setPath] = useState("");
  const roots = props.directories?.roots ?? [];
  const items = props.directories?.items ?? [];
  const reload = props.directories?.reloadProgress ?? {};

  const replaceRoots = (paths: string[]) =>
    props.client.patch("shared-directories", {
      roots: paths.map((rootPath) => ({ path: rootPath })),
      confirmReplaceRoots: true
    });

  const addRoot = async () => {
    const nextPath = path.trim();
    if (!nextPath) {
      throw new Error("Path is required");
    }
    await replaceRoots([...roots.map((root) => root.path), nextPath]);
    setPath("");
  };

  const removeRoot = (rootPath: string) =>
    replaceRoots(roots.filter((root) => root.path !== rootPath).map((root) => root.path));

  return (
    <section class="view-grid">
      <Metric label="Roots" value={String(roots.length)} />
      <Metric label="Folders" value={String(items.length)} />
      <Metric label="Hashing" value={String(props.directories?.hashingCount ?? 0)} />
      <Metric label="Reload" value={reload.phase ?? "idle"} />
      <Metric label="Hashed" value={`${reload.hashedCount ?? 0}/${reload.plannedHashCount ?? 0}`} />
      <Metric label="Read Rate" value={formatRate(reload.readRateBytesPerSec)} />

      <section class="panel wide sharing-panel">
        <div class="section-title">
          <h2>Shared Folders</h2>
          <button type="button" onClick={() => void props.run(() => props.client.post("shared-directories/operations/reload"), "Reload queued")}>
            <RefreshCw size={15} />
            Reload
          </button>
        </div>
        <p class="hint">Folder trees are always recursive and monitored. Single-file sharing is not supported.</p>
        <form class="form-row" onSubmit={(event) => {
          event.preventDefault();
          void props.run(addRoot, "Folder added");
        }}>
          <input value={path} placeholder="Folder path" onInput={(event) => setPath(event.currentTarget.value)} />
          <button type="submit"><FolderPlus size={16} />Add</button>
        </form>
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Folder</th>
                <th>Mode</th>
                <th>Status</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {roots.map((root) => (
                <tr key={root.path}>
                  <td class="path-cell">{root.path}</td>
                  <td>Folder tree</td>
                  <td><StatusPill value={root.accessible === false || root.shareable === false ? "unavailable" : "monitored"} /></td>
                  <td>
                    <Action title="Remove" icon={<Trash2 size={15} />} onClick={() => {
                      if (window.confirm("Remove this shared folder tree?")) {
                        void props.run(() => removeRoot(root.path), "Folder removed");
                      }
                    }} />
                  </td>
                </tr>
              ))}
              {roots.length === 0 && <EmptyRow colSpan={4} text="No shared folders." />}
            </tbody>
          </table>
        </div>
      </section>

      <section class="panel wide progress-panel">
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
          <span>Skipped</span>
          <strong>{reload.skippedIntakeCount ?? 0}</strong>
          <span>Pruned</span>
          <strong>{reload.prunedCount ?? 0}</strong>
        </div>
      </section>

      <section class="panel wide progress-panel">
        <h2>Hashing Now</h2>
        <ActiveHashList files={reload.active ?? []} />
      </section>

      <section class="panel wide">
        <h2>Per Drive</h2>
        <DiskProgressTable disks={reload.disks ?? []} />
      </section>

      <section class="panel wide">
        <h2>Recently Hashed</h2>
        <RecentHashTable files={reload.recent ?? []} />
      </section>

      <section class="panel wide">
        <h2>Up Next</h2>
        <QueuedHashTable files={reload.upcoming ?? []} />
      </section>
    </section>
  );
}

function ActiveHashList(props: { files: NonNullable<SharedDirectories["reloadProgress"]>["active"] }) {
  const files = props.files ?? [];
  if (files.length === 0) {
    return <p class="empty">No files are hashing right now.</p>;
  }
  return (
    <div class="hash-card-list">
      {files.map((file) => (
        <div class="hash-card" key={file.id ?? file.path}>
          <div class="hash-card-title">
            <strong>{file.name || file.path || "Unnamed file"}</strong>
            <StatusPill value={file.stage ?? "hashing"} />
          </div>
          <p class="path-cell">{file.path}</p>
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

function DiskProgressTable(props: { disks: NonNullable<SharedDirectories["reloadProgress"]>["disks"] }) {
  const disks = props.disks ?? [];
  return (
    <div class="table-wrap">
      <table>
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
              <td class="path-cell">{disk.currentPath ?? disk.currentName ?? ""}</td>
            </tr>
          ))}
          {disks.length === 0 && <EmptyRow colSpan={5} text="No drive hashing activity." />}
        </tbody>
      </table>
    </div>
  );
}

function RecentHashTable(props: { files: NonNullable<SharedDirectories["reloadProgress"]>["recent"] }) {
  const files = props.files ?? [];
  return (
    <div class="table-wrap">
      <table>
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
              <td class="path-cell">{file.path ?? file.name}</td>
              <td><StatusPill value={file.result ?? "unknown"} /></td>
              <td>{formatBytes(file.readBytes)} / {formatBytes(file.readBytesTotal)}</td>
              <td>{formatRate(file.averageReadRateBytesPerSec)}</td>
              <td>{formatDurationMs(file.durationMs)}</td>
            </tr>
          ))}
          {files.length === 0 && <EmptyRow colSpan={5} text="No recently hashed files." />}
        </tbody>
      </table>
    </div>
  );
}

function QueuedHashTable(props: { files: NonNullable<SharedDirectories["reloadProgress"]>["upcoming"] }) {
  const files = props.files ?? [];
  return (
    <div class="table-wrap">
      <table>
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
              <td class="path-cell">{file.path ?? file.name}</td>
              <td>{formatBytes(file.sizeBytes)}</td>
              <td>{file.diskKey ?? ""}</td>
              <td>{file.reason ?? ""}</td>
            </tr>
          ))}
          {files.length === 0 && <EmptyRow colSpan={5} text="No queued hashing work." />}
        </tbody>
      </table>
    </div>
  );
}

export function SharedFilesView(props: { files: SharedFile[]; client: RestClient; run: RunFunction }) {
  const [selectedHash, setSelectedHash] = useState("");
  const [priority, setPriority] = useState("normal");
  const [comment, setComment] = useState("");
  const [rating, setRating] = useState("0");
  const [linkValue, setLinkValue] = useState("");
  const [comments, setComments] = useState<unknown[]>([]);
  const selected = props.files.find((file) => file.hash === selectedHash) ?? props.files[0];

  useEffect(() => {
    if (!selected) {
      return;
    }
    setSelectedHash(selected.hash);
    setPriority(selected.priority ?? "normal");
    setComment(selected.comment ?? "");
    setRating(String(selected.rating ?? 0));
    let cancelled = false;
    const load = async () => {
      const [linkResult, commentResult] = await Promise.all([
        props.client.get<{ link?: string }>(`shared-files/${selected.hash}/ed2k-link`),
        props.client.get<Page<unknown>>(`shared-files/${selected.hash}/comments`)
      ]);
      if (!cancelled) {
        setLinkValue(linkResult.link ?? "");
        setComments(commentResult.items ?? []);
      }
    };
    void load();
    return () => {
      cancelled = true;
    };
  }, [props.client, selected?.hash]);

  const save = () => props.client.patch(`shared-files/${selected?.hash}`, {
    priority,
    comment,
    rating: Number(rating)
  });

  return (
    <section class="view-stack">
      <section class="panel">
        <div class="section-title">
          <h2>Shared Files</h2>
          <span>{props.files.length} visible</span>
        </div>
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Size</th>
                <th>Priority</th>
                <th>Requests</th>
                <th>Uploaded</th>
              </tr>
            </thead>
            <tbody>
              {props.files.map((file) => (
                <tr key={file.hash} class={selected?.hash === file.hash ? "selected-row" : ""}>
                  <td><button type="button" class="link-button" onClick={() => setSelectedHash(file.hash)}>{file.name ?? file.hash}</button></td>
                  <td>{formatBytes(file.sizeBytes)}</td>
                  <td>{file.priority ?? "normal"}</td>
                  <td>{file.allTimeUploadRequests ?? file.requests ?? 0}</td>
                  <td>{formatBytes(file.allTimeUploadedBytes ?? file.transferredBytes)}</td>
                </tr>
              ))}
              {props.files.length === 0 && <EmptyRow colSpan={5} text="No shared files." />}
            </tbody>
          </table>
        </div>
      </section>

      <section class="panel">
        <div class="section-title">
          <h2>Metadata</h2>
          <span>{selected?.name ?? "No selection"}</span>
        </div>
        {selected && (
          <form class="editor-grid" onSubmit={(event) => {
            event.preventDefault();
            void props.run(save, "Shared file metadata saved");
          }}>
            <label>
              Priority
              <select value={priority} onInput={(event) => setPriority(event.currentTarget.value)}>
                <option value="low">Low</option>
                <option value="normal">Normal</option>
                <option value="high">High</option>
                <option value="veryhigh">Very high</option>
                <option value="release">Release</option>
              </select>
            </label>
            <label>
              Rating
              <input value={rating} inputMode="numeric" onInput={(event) => setRating(event.currentTarget.value)} />
            </label>
            <label class="wide-field">
              Comment
              <textarea value={comment} onInput={(event) => setComment(event.currentTarget.value)} />
            </label>
            <label class="wide-field">
              eD2K link
              <div class="copy-row">
                <input value={linkValue} readOnly />
                <button type="button" onClick={() => void navigator.clipboard?.writeText(linkValue)}>
                  <Clipboard size={15} />
                  Copy
                </button>
              </div>
            </label>
            <button type="submit"><Save size={15} />Save</button>
          </form>
        )}
        <h3>Comments</h3>
        <JsonPanel value={comments} />
      </section>
    </section>
  );
}

export function UploadsView(props: { uploads: Upload[]; uploadQueue: Upload[]; client: RestClient; run: RunFunction }) {
  return (
    <section class="view-stack">
      <UploadTable title="Active Uploads" items={props.uploads} basePath="uploads" client={props.client} run={props.run} />
      <UploadTable title="Upload Queue" items={props.uploadQueue} basePath="upload-queue" client={props.client} run={props.run} />
    </section>
  );
}

function UploadTable(props: { title: string; items: Upload[]; basePath: string; client: RestClient; run: RunFunction }) {
  return (
    <section class="panel">
      <div class="section-title">
        <h2>{props.title}</h2>
        <span>{props.items.length} clients</span>
      </div>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Client</th>
              <th>State</th>
              <th>File</th>
              <th>Rate</th>
              <th>Uploaded</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {props.items.map((upload) => {
              const clientId = upload.clientId ?? "";
              const encoded = encodeSegment(clientId);
              return (
                <tr key={clientId}>
                  <td>{upload.userName ?? clientId}</td>
                  <td><StatusPill value={upload.uploadState ?? (upload.waitingQueue ? "queued" : "unknown")} /></td>
                  <td>{upload.requestedFileName ?? ""}</td>
                  <td>{formatKiBRate(upload.uploadSpeedKiBps)}</td>
                  <td>{formatBytes(upload.uploadedBytes)}</td>
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
            {props.items.length === 0 && <EmptyRow colSpan={6} text="No clients." />}
          </tbody>
        </table>
      </div>
    </section>
  );
}

export function ServersView(props: { servers: ServerItem[]; client: RestClient; run: RunFunction }) {
  const [address, setAddress] = useState("");
  const [port, setPort] = useState("4661");
  const [name, setName] = useState("");
  const [importUrl, setImportUrl] = useState("");

  const createServer = () => props.client.post("servers", {
    address,
    port: Number(port),
    name: name || undefined,
    priority: "normal",
    static: true
  });

  return (
    <section class="panel">
      <div class="section-title">
        <h2>Servers</h2>
        <div class="row-actions">
          <button type="button" onClick={() => void props.run(() => props.client.post("servers/operations/connect"), "Server connect started")}><Plug size={15} />Connect</button>
          <button type="button" onClick={() => void props.run(() => props.client.post("servers/operations/disconnect"), "Servers disconnected")}><Ban size={15} />Disconnect</button>
        </div>
      </div>
      <form class="form-row" onSubmit={(event) => {
        event.preventDefault();
        void props.run(createServer, "Server added");
      }}>
        <input value={address} placeholder="Address" onInput={(event) => setAddress(event.currentTarget.value)} />
        <input value={port} placeholder="Port" inputMode="numeric" onInput={(event) => setPort(event.currentTarget.value)} />
        <input value={name} placeholder="Name" onInput={(event) => setName(event.currentTarget.value)} />
        <button type="submit"><Server size={16} />Add</button>
      </form>
      <form class="form-row" onSubmit={(event) => {
        event.preventDefault();
        void props.run(() => props.client.post("servers/operations/import-met-url", { url: importUrl }), "Server list import started");
      }}>
        <input value={importUrl} placeholder="server.met URL" onInput={(event) => setImportUrl(event.currentTarget.value)} />
        <button type="submit"><Download size={16} />Import</button>
      </form>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Endpoint</th>
              <th>Name</th>
              <th>Status</th>
              <th>Priority</th>
              <th>Users</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {props.servers.map((server) => {
              const endpoint = server.endpoint ?? server.id ?? `${server.address}:${server.port}`;
              const encoded = encodeSegment(endpoint);
              return (
                <tr key={endpoint}>
                  <td>{endpoint}</td>
                  <td>{server.name ?? ""}</td>
                  <td><StatusPill value={server.connected ? "connected" : server.connecting ? "connecting" : server.enabled === false ? "disabled" : "idle"} /></td>
                  <td>{server.priority ?? "normal"}</td>
                  <td>{server.users ?? 0}</td>
                  <td>
                    <div class="row-actions">
                      <Action title="Connect" icon={<Plug size={15} />} onClick={() => void props.run(() => props.client.post(`servers/${encoded}/operations/connect`), "Server connect started")} />
                      <Action title="Enable" icon={<Play size={15} />} onClick={() => void props.run(() => props.client.patch(`servers/${encoded}`, { enabled: true }), "Server enabled")} />
                      <Action title="Disable" icon={<Pause size={15} />} onClick={() => void props.run(() => props.client.patch(`servers/${encoded}`, { enabled: false }), "Server disabled")} />
                      <Action title="Toggle static" icon={<Save size={15} />} onClick={() => void props.run(() => props.client.patch(`servers/${encoded}`, { static: !server.static }), "Server updated")} />
                      <Action title="Delete" icon={<Trash2 size={15} />} onClick={() => void props.run(() => props.client.delete(`servers/${encoded}`), "Server deleted")} />
                    </div>
                  </td>
                </tr>
              );
            })}
            {props.servers.length === 0 && <EmptyRow colSpan={6} text="No servers." />}
          </tbody>
        </table>
      </div>
    </section>
  );
}

export function KadView(props: { kad: KadStatus; client: RestClient; run: RunFunction }) {
  const [bootstrapAddress, setBootstrapAddress] = useState("");
  const [bootstrapPort, setBootstrapPort] = useState("4662");
  const [importUrl, setImportUrl] = useState("");
  return (
    <section class="panel">
      <div class="section-title">
        <h2>Kad</h2>
        <div class="row-actions">
          <button type="button" onClick={() => void props.run(() => props.client.post("kad/operations/start"), "Kad started")}><Play size={15} />Start</button>
          <button type="button" onClick={() => void props.run(() => props.client.post("kad/operations/stop"), "Kad stopped")}><Pause size={15} />Stop</button>
          <button type="button" onClick={() => void props.run(() => props.client.post("kad/operations/recheck-firewall"), "Kad firewall recheck started")}><Shield size={15} />Recheck</button>
        </div>
      </div>
      <div class="kv compact">
        <span>Connected</span>
        <strong>{props.kad.connected ? "yes" : "no"}</strong>
        <span>Firewall</span>
        <strong>{firewallLabel(props.kad.firewalled)}</strong>
        <span>Keywords</span>
        <strong>{props.kad.indexedKeywordCount ?? 0}</strong>
        <span>Sources</span>
        <strong>{props.kad.indexedSourceCount ?? 0}</strong>
      </div>
      <form class="form-row" onSubmit={(event) => {
        event.preventDefault();
        void props.run(() => props.client.post("kad/operations/import-nodes-url", { url: importUrl }), "Kad nodes import started");
      }}>
        <input value={importUrl} placeholder="nodes.dat URL" onInput={(event) => setImportUrl(event.currentTarget.value)} />
        <button type="submit"><Download size={16} />Import</button>
      </form>
      <form class="form-row" onSubmit={(event) => {
        event.preventDefault();
        void props.run(() => props.client.post("kad/operations/bootstrap", { address: bootstrapAddress, port: Number(bootstrapPort) }), "Kad bootstrap started");
      }}>
        <input value={bootstrapAddress} placeholder="Bootstrap address" onInput={(event) => setBootstrapAddress(event.currentTarget.value)} />
        <input value={bootstrapPort} inputMode="numeric" placeholder="Port" onInput={(event) => setBootstrapPort(event.currentTarget.value)} />
        <button type="submit"><Plug size={16} />Bootstrap</button>
      </form>
    </section>
  );
}

export function CategoriesView(props: { categories: Category[]; client: RestClient; run: RunFunction }) {
  const [name, setName] = useState("");
  const [path, setPath] = useState("");
  const [comment, setComment] = useState("");
  const [priority, setPriority] = useState("normal");

  const create = async () => {
    await props.client.post("categories", {
      name,
      path: optionalString(path),
      comment,
      priority: categoryPriorityValue(priority)
    });
    setName("");
    setPath("");
    setComment("");
  };

  return (
    <section class="panel">
      <div class="section-title">
        <h2>Categories</h2>
        <span>{props.categories.length} configured</span>
      </div>
      <form class="form-row" onSubmit={(event) => {
        event.preventDefault();
        void props.run(create, "Category created");
      }}>
        <input value={name} placeholder="Name" onInput={(event) => setName(event.currentTarget.value)} />
        <input value={path} placeholder="Incoming path" onInput={(event) => setPath(event.currentTarget.value)} />
        <input value={comment} placeholder="Comment" onInput={(event) => setComment(event.currentTarget.value)} />
        <select value={priority} onInput={(event) => setPriority(event.currentTarget.value)}>
          <option value="low">Low</option>
          <option value="normal">Normal</option>
          <option value="high">High</option>
          <option value="veryhigh">Very high</option>
        </select>
        <button type="submit"><FolderPlus size={16} />Add</button>
      </form>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Path</th>
              <th>Comment</th>
              <th>Priority</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {props.categories.map((category) => (
              <CategoryRow key={category.id} category={category} client={props.client} run={props.run} />
            ))}
            {props.categories.length === 0 && <EmptyRow colSpan={5} text="No categories." />}
          </tbody>
        </table>
      </div>
    </section>
  );
}

function CategoryRow(props: { category: Category; client: RestClient; run: RunFunction }) {
  const [name, setName] = useState(props.category.name);
  const [path, setPath] = useState(props.category.path ?? "");
  const [comment, setComment] = useState(props.category.comment ?? "");
  const [priority, setPriority] = useState(String(props.category.priority ?? "normal"));
  const encoded = String(props.category.id);

  return (
    <tr>
      <td><input value={name} onInput={(event) => setName(event.currentTarget.value)} /></td>
      <td><input value={path} onInput={(event) => setPath(event.currentTarget.value)} /></td>
      <td><input value={comment} onInput={(event) => setComment(event.currentTarget.value)} /></td>
      <td><input value={priority} onInput={(event) => setPriority(event.currentTarget.value)} /></td>
      <td>
        <div class="row-actions">
          <Action title="Save" icon={<Save size={15} />} onClick={() => void props.run(() => props.client.patch(`categories/${encoded}`, {
            name,
            path: optionalString(path),
            comment,
            priority: categoryPriorityValue(priority)
          }), "Category saved")} />
          <Action title="Delete" icon={<Trash2 size={15} />} onClick={() => {
            if (window.confirm("Delete this category? Later category IDs will be reindexed.")) {
              void props.run(() => props.client.delete(`categories/${encoded}`), "Category deleted");
            }
          }} />
        </div>
      </td>
    </tr>
  );
}

export function FriendsView(props: { friends: Friend[]; client: RestClient; run: RunFunction }) {
  const [userHash, setUserHash] = useState("");
  const [name, setName] = useState("");
  const create = async () => {
    await props.client.post("friends", { userHash, name: name || undefined });
    setUserHash("");
    setName("");
  };
  return (
    <section class="panel">
      <div class="section-title">
        <h2>Friends</h2>
        <span>{props.friends.length} peers</span>
      </div>
      <form class="form-row" onSubmit={(event) => {
        event.preventDefault();
        void props.run(create, "Friend added");
      }}>
        <input value={userHash} placeholder="User hash" onInput={(event) => setUserHash(event.currentTarget.value)} />
        <input value={name} placeholder="Name" onInput={(event) => setName(event.currentTarget.value)} />
        <button type="submit"><UserPlus size={16} />Add</button>
      </form>
      <div class="table-wrap">
        <table>
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
                  <td>{friend.lastSeen ?? ""}</td>
                  <td><Action title="Delete" icon={<Trash2 size={15} />} onClick={() => void props.run(() => props.client.delete(`friends/${hash}`), "Friend deleted")} /></td>
                </tr>
              );
            })}
            {props.friends.length === 0 && <EmptyRow colSpan={5} text="No friends." />}
          </tbody>
        </table>
      </div>
    </section>
  );
}

type SettingsForm = {
  uploadLimitKiBps: string;
  downloadLimitKiBps: string;
  maxConnections: string;
  maxConnectionsPerFiveSeconds: string;
  maxSourcesPerFile: string;
  uploadClientDataRate: string;
  maxUploadSlots: string;
  uploadSlotElasticPercent: string;
  queueSize: string;
  autoConnect: boolean;
  reconnect: boolean;
  creditSystem: boolean;
  safeServerConnect: boolean;
  addServersFromServer: boolean;
  networkKademlia: boolean;
  networkEd2k: boolean;
  incomingDir: string;
  p2pBindIp: string;
  p2pBindInterface: string;
  ed2kListenPort: string;
  kadListenPort: string;
  obfuscationEnabled: boolean;
  ed2kReconnectEnabled: boolean;
  enableUdpReask: boolean;
  publishEmuleRustIdentity: boolean;
  kadPublishSharedFilesEnabled: boolean;
  kadRepublishIntervalSecs: string;
  udpFirewallCheckEnabled: boolean;
  tcpFirewallCheckEnabled: boolean;
  buddyEnabled: boolean;
  routingMaintenanceEnabled: boolean;
  natEnabled: boolean;
  natRequireInitialMapping: boolean;
  natBindIp: string;
  natBackendOrder: string;
  vpnGuardEnabled: boolean;
  vpnGuardMode: string;
  vpnGuardAllowedPublicIpCidrs: string;
  ipFilterEnabled: boolean;
  ipFilterPath: string;
  ipFilterLevel: string;
};

const emptySettingsForm: SettingsForm = {
  uploadLimitKiBps: "",
  downloadLimitKiBps: "",
  maxConnections: "",
  maxConnectionsPerFiveSeconds: "",
  maxSourcesPerFile: "",
  uploadClientDataRate: "",
  maxUploadSlots: "",
  uploadSlotElasticPercent: "",
  queueSize: "",
  autoConnect: false,
  reconnect: false,
  creditSystem: false,
  safeServerConnect: false,
  addServersFromServer: false,
  networkKademlia: false,
  networkEd2k: false,
  incomingDir: "",
  p2pBindIp: "",
  p2pBindInterface: "",
  ed2kListenPort: "",
  kadListenPort: "",
  obfuscationEnabled: false,
  ed2kReconnectEnabled: false,
  enableUdpReask: false,
  publishEmuleRustIdentity: false,
  kadPublishSharedFilesEnabled: false,
  kadRepublishIntervalSecs: "",
  udpFirewallCheckEnabled: false,
  tcpFirewallCheckEnabled: false,
  buddyEnabled: false,
  routingMaintenanceEnabled: false,
  natEnabled: false,
  natRequireInitialMapping: false,
  natBindIp: "",
  natBackendOrder: "",
  vpnGuardEnabled: false,
  vpnGuardMode: "",
  vpnGuardAllowedPublicIpCidrs: "",
  ipFilterEnabled: false,
  ipFilterPath: "",
  ipFilterLevel: ""
};

export function SettingsView(props: { settings: AppSettings | null; client: RestClient; run: RunFunction }) {
  const [form, setForm] = useState<SettingsForm>(emptySettingsForm);

  useEffect(() => {
    if (props.settings) {
      setForm(settingsFormFrom(props.settings));
    }
  }, [props.settings]);

  const update = <K extends keyof SettingsForm>(key: K, value: SettingsForm[K]) => {
    setForm((current) => ({ ...current, [key]: value }));
  };

  const save = () => {
    const settings = props.settings ?? {};
    return props.client.patch("app/settings", {
      core: {
        ...(settings.core ?? {}),
        uploadLimitKiBps: parseNumber(form.uploadLimitKiBps),
        downloadLimitKiBps: parseNumber(form.downloadLimitKiBps),
        maxConnections: parseNumber(form.maxConnections),
        maxConnectionsPerFiveSeconds: parseNumber(form.maxConnectionsPerFiveSeconds),
        maxSourcesPerFile: parseNumber(form.maxSourcesPerFile),
        uploadClientDataRate: parseNumber(form.uploadClientDataRate),
        maxUploadSlots: parseNumber(form.maxUploadSlots),
        uploadSlotElasticPercent: parseNumber(form.uploadSlotElasticPercent),
        queueSize: parseNumber(form.queueSize),
        autoConnect: form.autoConnect,
        reconnect: form.reconnect,
        creditSystem: form.creditSystem,
        safeServerConnect: form.safeServerConnect,
        addServersFromServer: form.addServersFromServer,
        networkKademlia: form.networkKademlia,
        networkEd2k: form.networkEd2k
      },
      daemon: {
        ...(settings.daemon ?? {}),
        incomingDir: optionalString(form.incomingDir),
        p2pBindIp: optionalString(form.p2pBindIp),
        p2pBindInterface: optionalString(form.p2pBindInterface)
      },
      ed2k: {
        ...(settings.ed2k ?? {}),
        listenPort: optionalPort(form.ed2kListenPort),
        obfuscationEnabled: form.obfuscationEnabled,
        reconnectEnabled: form.ed2kReconnectEnabled,
        enableUdpReask: form.enableUdpReask,
        publishEmuleRustIdentity: form.publishEmuleRustIdentity,
        addServersFromServer: form.addServersFromServer,
        safeServerConnect: form.safeServerConnect
      },
      kad: {
        ...(settings.kad ?? {}),
        listenPort: optionalPort(form.kadListenPort),
        publishSharedFilesEnabled: form.kadPublishSharedFilesEnabled,
        republishIntervalSecs: parseNumber(form.kadRepublishIntervalSecs),
        udpFirewallCheckEnabled: form.udpFirewallCheckEnabled,
        tcpFirewallCheckEnabled: form.tcpFirewallCheckEnabled,
        buddyEnabled: form.buddyEnabled,
        routingMaintenanceEnabled: form.routingMaintenanceEnabled
      },
      nat: {
        ...(settings.nat ?? {}),
        enabled: form.natEnabled,
        requireInitialMapping: form.natRequireInitialMapping,
        bindIp: optionalString(form.natBindIp),
        backendOrder: form.natBackendOrder.split(",").map((item) => item.trim()).filter(Boolean)
      },
      vpnGuard: {
        ...(settings.vpnGuard ?? {}),
        enabled: form.vpnGuardEnabled,
        mode: form.vpnGuardMode,
        allowedPublicIpCidrs: form.vpnGuardAllowedPublicIpCidrs
      },
      ipFilter: {
        ...(settings.ipFilter ?? {}),
        enabled: form.ipFilterEnabled,
        path: optionalString(form.ipFilterPath),
        level: parseNumber(form.ipFilterLevel)
      }
    });
  };

  if (!props.settings) {
    return <section class="panel"><p class="empty">Settings are not loaded.</p></section>;
  }

  return (
    <section class="panel">
      <div class="section-title">
        <h2>Settings</h2>
        <button type="button" onClick={() => void props.run(save, "Settings saved; restart daemon for bind, port, NAT, VPN, and filter changes")}>
          <Save size={15} />
          Save
        </button>
      </div>
      <div class="settings-grid">
        <Field label="Upload limit KiB/s" value={form.uploadLimitKiBps} onInput={(value) => update("uploadLimitKiBps", value)} />
        <Field label="Download limit KiB/s" value={form.downloadLimitKiBps} onInput={(value) => update("downloadLimitKiBps", value)} />
        <Field label="Max connections" value={form.maxConnections} onInput={(value) => update("maxConnections", value)} />
        <Field label="New connections / 5s" value={form.maxConnectionsPerFiveSeconds} onInput={(value) => update("maxConnectionsPerFiveSeconds", value)} />
        <Field label="Max sources / file" value={form.maxSourcesPerFile} onInput={(value) => update("maxSourcesPerFile", value)} />
        <Field label="Upload client KiB/s" value={form.uploadClientDataRate} onInput={(value) => update("uploadClientDataRate", value)} />
        <Field label="Max upload slots" value={form.maxUploadSlots} onInput={(value) => update("maxUploadSlots", value)} />
        <Field label="Upload elasticity %" value={form.uploadSlotElasticPercent} onInput={(value) => update("uploadSlotElasticPercent", value)} />
        <Field label="Queue size" value={form.queueSize} onInput={(value) => update("queueSize", value)} />
        <Field label="Incoming directory" value={form.incomingDir} onInput={(value) => update("incomingDir", value)} />
        <Field label="P2P bind IP" value={form.p2pBindIp} onInput={(value) => update("p2pBindIp", value)} />
        <Field label="P2P bind interface" value={form.p2pBindInterface} onInput={(value) => update("p2pBindInterface", value)} />
        <Field label="eD2K listen port" value={form.ed2kListenPort} onInput={(value) => update("ed2kListenPort", value)} />
        <Field label="Kad listen port" value={form.kadListenPort} onInput={(value) => update("kadListenPort", value)} />
        <Field label="Kad republish seconds" value={form.kadRepublishIntervalSecs} onInput={(value) => update("kadRepublishIntervalSecs", value)} />
        <Field label="NAT bind IP" value={form.natBindIp} onInput={(value) => update("natBindIp", value)} />
        <Field label="NAT backend order" value={form.natBackendOrder} onInput={(value) => update("natBackendOrder", value)} />
        <Field label="VPN Guard mode" value={form.vpnGuardMode} onInput={(value) => update("vpnGuardMode", value)} />
        <Field label="Allowed public CIDRs" value={form.vpnGuardAllowedPublicIpCidrs} onInput={(value) => update("vpnGuardAllowedPublicIpCidrs", value)} />
        <Field label="IP filter path" value={form.ipFilterPath} onInput={(value) => update("ipFilterPath", value)} />
        <Field label="IP filter level" value={form.ipFilterLevel} onInput={(value) => update("ipFilterLevel", value)} />
      </div>
      <div class="toggle-grid">
        <Toggle label="Auto connect" checked={form.autoConnect} onInput={(value) => update("autoConnect", value)} />
        <Toggle label="Reconnect" checked={form.reconnect} onInput={(value) => update("reconnect", value)} />
        <Toggle label="Credit system" checked={form.creditSystem} onInput={(value) => update("creditSystem", value)} />
        <Toggle label="Safe server connect" checked={form.safeServerConnect} onInput={(value) => update("safeServerConnect", value)} />
        <Toggle label="Add servers from server" checked={form.addServersFromServer} onInput={(value) => update("addServersFromServer", value)} />
        <Toggle label="Network Kad" checked={form.networkKademlia} onInput={(value) => update("networkKademlia", value)} />
        <Toggle label="Network eD2K" checked={form.networkEd2k} onInput={(value) => update("networkEd2k", value)} />
        <Toggle label="Obfuscation" checked={form.obfuscationEnabled} onInput={(value) => update("obfuscationEnabled", value)} />
        <Toggle label="eD2K reconnect" checked={form.ed2kReconnectEnabled} onInput={(value) => update("ed2kReconnectEnabled", value)} />
        <Toggle label="UDP reask" checked={form.enableUdpReask} onInput={(value) => update("enableUdpReask", value)} />
        <Toggle label="Publish Rust identity" checked={form.publishEmuleRustIdentity} onInput={(value) => update("publishEmuleRustIdentity", value)} />
        <Toggle label="Kad publish shared files" checked={form.kadPublishSharedFilesEnabled} onInput={(value) => update("kadPublishSharedFilesEnabled", value)} />
        <Toggle label="Kad UDP firewall checks" checked={form.udpFirewallCheckEnabled} onInput={(value) => update("udpFirewallCheckEnabled", value)} />
        <Toggle label="Kad TCP firewall checks" checked={form.tcpFirewallCheckEnabled} onInput={(value) => update("tcpFirewallCheckEnabled", value)} />
        <Toggle label="Kad buddy" checked={form.buddyEnabled} onInput={(value) => update("buddyEnabled", value)} />
        <Toggle label="Routing maintenance" checked={form.routingMaintenanceEnabled} onInput={(value) => update("routingMaintenanceEnabled", value)} />
        <Toggle label="NAT" checked={form.natEnabled} onInput={(value) => update("natEnabled", value)} />
        <Toggle label="Require initial NAT mapping" checked={form.natRequireInitialMapping} onInput={(value) => update("natRequireInitialMapping", value)} />
        <Toggle label="VPN Guard" checked={form.vpnGuardEnabled} onInput={(value) => update("vpnGuardEnabled", value)} />
        <Toggle label="IP filter" checked={form.ipFilterEnabled} onInput={(value) => update("ipFilterEnabled", value)} />
      </div>
    </section>
  );
}

function Field(props: { label: string; value: string; onInput: (value: string) => void }) {
  return (
    <label>
      {props.label}
      <input value={props.value} onInput={(event) => props.onInput(event.currentTarget.value)} />
    </label>
  );
}

function Toggle(props: { label: string; checked: boolean; onInput: (value: boolean) => void }) {
  return (
    <label class="check">
      <input type="checkbox" checked={props.checked} onInput={(event) => props.onInput(event.currentTarget.checked)} />
      {props.label}
    </label>
  );
}

function settingsFormFrom(settings: AppSettings): SettingsForm {
  return {
    ...emptySettingsForm,
    uploadLimitKiBps: String(numberField(settings.core, "uploadLimitKiBps") ?? ""),
    downloadLimitKiBps: String(numberField(settings.core, "downloadLimitKiBps") ?? ""),
    maxConnections: String(numberField(settings.core, "maxConnections") ?? ""),
    maxConnectionsPerFiveSeconds: String(numberField(settings.core, "maxConnectionsPerFiveSeconds") ?? ""),
    maxSourcesPerFile: String(numberField(settings.core, "maxSourcesPerFile") ?? ""),
    uploadClientDataRate: String(numberField(settings.core, "uploadClientDataRate") ?? ""),
    maxUploadSlots: String(numberField(settings.core, "maxUploadSlots") ?? ""),
    uploadSlotElasticPercent: String(numberField(settings.core, "uploadSlotElasticPercent") ?? ""),
    queueSize: String(numberField(settings.core, "queueSize") ?? ""),
    autoConnect: boolField(settings.core, "autoConnect"),
    reconnect: boolField(settings.core, "reconnect"),
    creditSystem: boolField(settings.core, "creditSystem"),
    safeServerConnect: boolField(settings.core, "safeServerConnect"),
    addServersFromServer: boolField(settings.core, "addServersFromServer"),
    networkKademlia: boolField(settings.core, "networkKademlia"),
    networkEd2k: boolField(settings.core, "networkEd2k"),
    incomingDir: stringField(settings.daemon, "incomingDir"),
    p2pBindIp: stringField(settings.daemon, "p2pBindIp"),
    p2pBindInterface: stringField(settings.daemon, "p2pBindInterface"),
    ed2kListenPort: String(numberField(settings.ed2k, "listenPort") ?? ""),
    kadListenPort: String(numberField(settings.kad, "listenPort") ?? ""),
    obfuscationEnabled: boolField(settings.ed2k, "obfuscationEnabled"),
    ed2kReconnectEnabled: boolField(settings.ed2k, "reconnectEnabled"),
    enableUdpReask: boolField(settings.ed2k, "enableUdpReask"),
    publishEmuleRustIdentity: boolField(settings.ed2k, "publishEmuleRustIdentity"),
    kadPublishSharedFilesEnabled: boolField(settings.kad, "publishSharedFilesEnabled"),
    kadRepublishIntervalSecs: String(numberField(settings.kad, "republishIntervalSecs") ?? ""),
    udpFirewallCheckEnabled: boolField(settings.kad, "udpFirewallCheckEnabled"),
    tcpFirewallCheckEnabled: boolField(settings.kad, "tcpFirewallCheckEnabled"),
    buddyEnabled: boolField(settings.kad, "buddyEnabled"),
    routingMaintenanceEnabled: boolField(settings.kad, "routingMaintenanceEnabled"),
    natEnabled: boolField(settings.nat, "enabled"),
    natRequireInitialMapping: boolField(settings.nat, "requireInitialMapping"),
    natBindIp: stringField(settings.nat, "bindIp"),
    natBackendOrder: Array.isArray(settings.nat?.backendOrder) ? settings.nat.backendOrder.join(", ") : "",
    vpnGuardEnabled: boolField(settings.vpnGuard, "enabled"),
    vpnGuardMode: stringField(settings.vpnGuard, "mode"),
    vpnGuardAllowedPublicIpCidrs: stringField(settings.vpnGuard, "allowedPublicIpCidrs"),
    ipFilterEnabled: boolField(settings.ipFilter, "enabled"),
    ipFilterPath: stringField(settings.ipFilter, "path"),
    ipFilterLevel: String(numberField(settings.ipFilter, "level") ?? "")
  };
}

function optionalPort(value: string): number | null {
  const trimmed = value.trim();
  return trimmed ? Number(trimmed) : null;
}

function categoryPriorityValue(value: string): string | number {
  const trimmed = value.trim();
  return /^\d+$/.test(trimmed) ? Number(trimmed) : trimmed;
}

export function DiagnosticsView(props: { app: unknown; capabilities: unknown; client: RestClient; run: RunFunction }) {
  const [fullMemory, setFullMemory] = useState(false);
  const [crashConfirm, setCrashConfirm] = useState("");
  const [shutdownConfirm, setShutdownConfirm] = useState("");
  const [dumpPath, setDumpPath] = useState("");

  const captureDump = async () => {
    const result = await props.client.post<{ path?: string }>("diagnostics/dumps", { confirmDump: true, fullMemory });
    setDumpPath(result.path ?? "");
  };

  return (
    <section class="view-stack">
      <section class="panel">
        <div class="section-title">
          <h2>Diagnostics</h2>
        </div>
        <div class="row-actions">
          <label class="check">
            <input type="checkbox" checked={fullMemory} onInput={(event) => setFullMemory(event.currentTarget.checked)} />
            Full memory dump
          </label>
          <button type="button" onClick={() => void props.run(captureDump, "Diagnostic dump captured")}>
            <FileText size={15} />
            Capture dump
          </button>
        </div>
        {dumpPath && <p class="hint">Dump path: {dumpPath}</p>}
        <div class="form-row danger-row">
          <input value={crashConfirm} placeholder="Type CRASH" onInput={(event) => setCrashConfirm(event.currentTarget.value)} />
          <button
            type="button"
            disabled={crashConfirm !== "CRASH"}
            onClick={() => void props.run(() => props.client.post("diagnostics/crash-tests", { confirmCrash: true }), "Crash test triggered")}
          >
            <Ban size={15} />
            Crash test
          </button>
          <input value={shutdownConfirm} placeholder="Type SHUTDOWN" onInput={(event) => setShutdownConfirm(event.currentTarget.value)} />
          <button
            type="button"
            disabled={shutdownConfirm !== "SHUTDOWN"}
            onClick={() => void props.run(() => props.client.post("app/shutdown", { confirmShutdown: true }), "Shutdown requested")}
          >
            <Plug size={15} />
            Shutdown
          </button>
        </div>
      </section>
      <section class="panel split">
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
    <section class="panel">
      <div class="section-title">
        <h2>Logs</h2>
        <button type="button" onClick={() => void props.run(() => props.client.post("logs/operations/clear", { confirmClearLogs: true }), "Logs cleared")}>
          <Trash2 size={15} />
          Clear
        </button>
      </div>
      <div class="logs">
        {props.logs.map((log, index) => (
          <div class="log-row" key={`${log.timestamp ?? log.ts ?? index}-${index}`}>
            <time>{log.timestamp ?? log.ts ?? ""}</time>
            <span>{log.level ?? "INFO"}</span>
            <p>{log.message ?? ""}</p>
          </div>
        ))}
      </div>
    </section>
  );
}

function CompactTransferList(props: { transfers: Transfer[] }) {
  if (props.transfers.length === 0) {
    return <p class="empty">No transfers.</p>;
  }
  return (
    <div class="compact-list">
      {props.transfers.map((transfer) => (
        <div class="compact-row" key={transfer.hash}>
          <span>{transfer.name ?? transfer.hash}</span>
          <StatusPill value={transfer.state ?? "unknown"} />
          <strong>{formatProgress(transfer)}</strong>
        </div>
      ))}
    </div>
  );
}

function kibToBytes(value?: number): number | undefined {
  return value === undefined ? undefined : value * 1024;
}
