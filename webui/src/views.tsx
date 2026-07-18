import type { ComponentChildren } from "preact";
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
  KadNode,
  KadStatus,
  LogRecord,
  Page,
  RestClient,
  SearchItem,
  ServerItem,
  SharedDirectories,
  SharedFile,
  SettingsSectionResourceSpec,
  SettingSurfaceSpec,
  SettingsSurface,
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
          <strong>{formatBytes(numberField(props.stats, "sharedBytes"))}</strong>
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
      <section class="panel card">
        <div class="section-title">
          <h2>Transfers</h2>
          <div class="row-actions">
            <select class="form-select" value={stateFilter} onInput={(event) => setStateFilter(event.currentTarget.value)}>
              <option value="">All states</option>
              <option value="downloading">Downloading</option>
              <option value="paused">Paused</option>
              <option value="completed">Completed</option>
              <option value="error">Error</option>
            </select>
            <button class="btn"
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
          <textarea class="form-control"
            value={ed2kLinks}
            placeholder="One eD2K link per line"
            onInput={(event) => setEd2kLinks(event.currentTarget.value)}
          />
          <label class="check">
            <input class="form-check-input" type="checkbox" checked={pausedCreate} onInput={(event) => setPausedCreate(event.currentTarget.checked)} />
            Paused
          </label>
          <button class="btn" type="submit">
            <Download size={16} />
            Add links
          </button>
        </form>
        <div class="table-wrap">
          <table class="table table-vcenter card-table">
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
                    <select class="form-select"
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

      <section class="panel card">
        <div class="section-title">
          <h2>Transfer Details</h2>
          <span>{selected?.name ?? (selectedId || "No selection")}</span>
        </div>
        {detailError && <div class="notice alert alert-danger">{detailError}</div>}
        <div class="split">
          <JsonPanel value={details} />
          <div class="table-wrap">
            <table class="table table-vcenter card-table">
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
    <section class="panel card">
      <div class="section-title">
        <h2>Search</h2>
        <span>{props.searches.length} sessions</span>
      </div>
      <form class="form-row" onSubmit={(event) => {
        event.preventDefault();
        void props.run(startSearch, "Search started");
      }}>
        <input class="form-control" value={query} placeholder="Search query" onInput={(event) => setQuery(event.currentTarget.value)} />
        <select class="form-select" value={method} onInput={(event) => setMethod(event.currentTarget.value)}>
          <option value="automatic">Automatic</option>
          <option value="server">Server</option>
          <option value="global">Global</option>
          <option value="kad">Kad</option>
        </select>
        <select class="form-select" value={fileType} onInput={(event) => setFileType(event.currentTarget.value)}>
          <option value="any">Any</option>
          <option value="audio">Audio</option>
          <option value="video">Video</option>
          <option value="archive">Archive</option>
          <option value="document">Document</option>
        </select>
        <button class="btn" type="submit"><Search size={16} />Start</button>
      </form>
      <div class="form-row subtle-row">
        <select class="form-select" value={categoryId} onInput={(event) => setCategoryId(event.currentTarget.value)}>
          <option value="0">Download uncategorized</option>
          {props.categories.map((category) => (
            <option key={category.id} value={category.id}>Download to {category.name}</option>
          ))}
        </select>
        <label class="check">
          <input class="form-check-input" type="checkbox" checked={paused} onInput={(event) => setPaused(event.currentTarget.checked)} />
          Queue paused
        </label>
      </div>
      <div class="table-wrap">
        <table class="table table-vcenter card-table">
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
                  <button class="btn"
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

      <section class="panel card wide sharing-panel">
        <div class="section-title">
          <h2>Shared Folders</h2>
          <button class="btn" type="button" onClick={() => void props.run(() => props.client.post("shared-directories/operations/reload"), "Reload queued")}>
            <RefreshCw size={15} />
            Reload
          </button>
        </div>
        <p class="hint">Folder trees are always recursive and monitored. Single-file sharing is not supported.</p>
        <form class="form-row" onSubmit={(event) => {
          event.preventDefault();
          void props.run(addRoot, "Folder added");
        }}>
          <input class="form-control" value={path} placeholder="Folder path" onInput={(event) => setPath(event.currentTarget.value)} />
          <button class="btn" type="submit"><FolderPlus size={16} />Add</button>
        </form>
        <div class="table-wrap">
          <table class="table table-vcenter card-table">
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
      <section class="panel card">
        <div class="section-title">
          <h2>Shared Files</h2>
          <span>{props.files.length} visible</span>
        </div>
        <div class="table-wrap">
          <table class="table table-vcenter card-table">
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

      <section class="panel card">
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
              <select class="form-select" value={priority} onInput={(event) => setPriority(event.currentTarget.value)}>
                <option value="low">Low</option>
                <option value="normal">Normal</option>
                <option value="high">High</option>
                <option value="veryhigh">Very high</option>
                <option value="release">Release</option>
              </select>
            </label>
            <label>
              Rating
              <input class="form-control" value={rating} inputMode="numeric" onInput={(event) => setRating(event.currentTarget.value)} />
            </label>
            <label class="wide-field">
              Comment
              <textarea class="form-control" value={comment} onInput={(event) => setComment(event.currentTarget.value)} />
            </label>
            <label class="wide-field">
              eD2K link
              <div class="copy-row">
                <input class="form-control" value={linkValue} readOnly />
                <button class="btn" type="button" onClick={() => void navigator.clipboard?.writeText(linkValue)}>
                  <Clipboard size={15} />
                  Copy
                </button>
              </div>
            </label>
            <button class="btn" type="submit"><Save size={15} />Save</button>
          </form>
        )}
        <h3>Comments</h3>
        <JsonPanel value={comments} />
      </section>
    </section>
  );
}

type UploadLane = "active" | "queue";

type UploadRow = {
  key: string;
  lane: UploadLane;
  item: Upload;
};

export function UploadsView(props: { uploads: Upload[]; uploadQueue: Upload[]; client: RestClient; run: RunFunction }) {
  const [filter, setFilter] = useState("");
  const [sort, setSort] = useState("rank");
  const [selectedKey, setSelectedKey] = useState("");
  const rows = useMemo(
    () => [
      ...props.uploads.map((item) => ({ key: uploadRowKey("active", item), lane: "active" as const, item })),
      ...props.uploadQueue.map((item) => ({ key: uploadRowKey("queue", item), lane: "queue" as const, item }))
    ],
    [props.uploadQueue, props.uploads]
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
  const lowIdCount = rows.filter((row) => row.item.lowId).length;
  const friendSlotCount = rows.filter((row) => row.item.friendSlot).length;
  const topFile = topRequestedFile(rows);

  return (
    <section class="view-stack">
      <section class="view-grid">
        <Metric label="Active Slots" value={String(props.uploads.length)} />
        <Metric label="Waiting" value={String(props.uploadQueue.length)} />
        <Metric label="Friend Slots" value={String(friendSlotCount)} />
        <Metric label="LowID Peers" value={String(lowIdCount)} />
        <Metric label="Top File" value={topFile.name} />
        <Metric label="Top Requests" value={String(topFile.count)} />
      </section>
      <section class="panel card">
        <div class="section-title">
          <h2>Upload Queue Inspector</h2>
          <span>{visibleRows.length} clients</span>
        </div>
        <div class="form-row">
          <input class="form-control" value={filter} placeholder="Filter client, file, hash, software, state" onInput={(event) => setFilter(event.currentTarget.value)} />
          <select class="form-select" value={sort} onInput={(event) => setSort(event.currentTarget.value)}>
            <option value="rank">Rank</option>
            <option value="score">Score</option>
            <option value="rate">Rate</option>
            <option value="uploaded">Uploaded</option>
            <option value="wait">Wait</option>
            <option value="file">File</option>
          </select>
        </div>
      </section>
      <UploadTable title="Active Uploads" rows={activeRows} basePath="uploads" client={props.client} run={props.run} selectedKey={selected?.key ?? ""} onSelect={setSelectedKey} />
      <UploadTable title="Upload Queue" rows={queueRows} basePath="upload-queue" client={props.client} run={props.run} selectedKey={selected?.key ?? ""} onSelect={setSelectedKey} />
      <UploadPeerInspector row={selected} />
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
      <div class="table-wrap">
        <table class="table table-vcenter card-table">
          <thead>
            <tr>
              <th>Client</th>
              <th>State</th>
              <th>Rank</th>
              <th>Score</th>
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
              const clientId = upload.clientId ?? "";
              const encoded = encodeSegment(clientId);
              return (
                <tr key={row.key} class={props.selectedKey === row.key ? "selected-row" : ""} onClick={() => props.onSelect(row.key)}>
                  <td>
                    <button type="button" class="link-button" onClick={() => props.onSelect(row.key)}>
                      {upload.userName ?? clientId}
                    </button>
                  </td>
                  <td><StatusPill value={uploadState(upload)} /></td>
                  <td>{upload.queueRank ?? ""}</td>
                  <td>{upload.score ?? ""}</td>
                  <td>{upload.requestedFileName ?? ""}</td>
                  <td>{upload.requestedPartsProgressText ?? ""}</td>
                  <td>{formatKiBRate(upload.uploadSpeedKiBps)}</td>
                  <td>{formatBytes(upload.uploadedBytes ?? upload.queueSessionUploaded)}</td>
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
            {props.rows.length === 0 && <EmptyRow colSpan={9} text="No clients." />}
          </tbody>
        </table>
      </div>
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
        <span>{upload.userName ?? upload.clientId ?? "Selected peer"}</span>
      </div>
      <div class="upload-inspector">
        <div class="kv compact">
          <span>Lane</span><strong>{props.row.lane === "active" ? "active upload" : "waiting queue"}</strong>
          <span>State</span><strong>{uploadState(upload)}</strong>
          <span>Queue rank</span><strong>{upload.queueRank ?? ""}</strong>
          <span>Score</span><strong>{upload.score ?? ""}</strong>
          <span>Wait time</span><strong>{formatDurationMs(upload.waitTimeMs)}</strong>
          <span>Rate</span><strong>{formatKiBRate(upload.uploadSpeedKiBps)}</strong>
          <span>Uploaded</span><strong>{formatBytes(upload.uploadedBytes)}</strong>
          <span>Session uploaded</span><strong>{formatBytes(upload.queueSessionUploaded)}</strong>
        </div>
        <div class="kv compact">
          <span>User hash</span><strong>{upload.userHash ?? ""}</strong>
          <span>Client</span><strong>{[upload.clientSoftware, upload.clientMod].filter(Boolean).join(" ")}</strong>
          <span>Endpoint</span><strong>{upload.port ? `${upload.address ?? ""}:${upload.port}` : upload.address ?? ""}</strong>
          <span>LowID</span><strong>{yesNo(upload.lowId)}</strong>
          <span>Friend slot</span><strong>{yesNo(upload.friendSlot)}</strong>
          <span>Friend</span><strong>{yesNo(boolField(upload, "friend"))}</strong>
          <span>Banned</span><strong>{yesNo(boolField(upload, "banned"))}</strong>
        </div>
        <div class="kv compact">
          <span>Requested file</span><strong>{upload.requestedFileName ?? ""}</strong>
          <span>File hash</span><strong>{upload.requestedFileHash ?? ""}</strong>
          <span>File size</span><strong>{formatBytes(upload.requestedFileSizeBytes)}</strong>
          <span>Requested parts</span><strong>{upload.requestedPartsProgressText ?? ""}</strong>
        </div>
        <ScoreBreakdown value={upload.scoreBreakdown} />
      </div>
    </section>
  );
}

function ScoreBreakdown(props: { value?: Record<string, unknown> | null }) {
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
  return `${lane}:${upload.clientId ?? upload.userHash ?? upload.address ?? upload.userName ?? ""}`;
}

function uploadState(upload: Upload): string {
  return upload.uploadState ?? (upload.uploading ? "uploading" : upload.waitingQueue ? "queued" : "unknown");
}

function uploadSearchText(row: UploadRow): string {
  const upload = row.item;
  return [
    row.lane,
    upload.userName,
    upload.userHash,
    upload.clientId,
    upload.clientSoftware,
    upload.clientMod,
    upload.address,
    uploadState(upload),
    upload.requestedFileName,
    upload.requestedFileHash,
    upload.requestedPartsProgressText
  ].map((value) => String(value ?? "").toLowerCase()).join(" ");
}

function compareUploadRows(left: UploadRow, right: UploadRow, sort: string): number {
  if (sort === "score") {
    return (right.item.score ?? -1) - (left.item.score ?? -1);
  }
  if (sort === "rate") {
    return (right.item.uploadSpeedKiBps ?? -1) - (left.item.uploadSpeedKiBps ?? -1);
  }
  if (sort === "uploaded") {
    return (right.item.uploadedBytes ?? right.item.queueSessionUploaded ?? -1) - (left.item.uploadedBytes ?? left.item.queueSessionUploaded ?? -1);
  }
  if (sort === "wait") {
    return (right.item.waitTimeMs ?? -1) - (left.item.waitTimeMs ?? -1);
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

type NetworkTransferSource = TransferSource & {
  transferHash?: string;
  transferName?: string;
};

export function NetworkHealthView(props: {
  servers: ServerItem[];
  transfers: Transfer[];
  uploads: Upload[];
  uploadQueue: Upload[];
  kad: KadStatus;
  settings: AppSettings | null;
  client: RestClient;
}) {
  const [nodes, setNodes] = useState<KadNode[]>([]);
  const [sources, setSources] = useState<NetworkTransferSource[]>([]);
  const [filter, setFilter] = useState("");
  const [selectedKey, setSelectedKey] = useState("");
  const [loadError, setLoadError] = useState("");

  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      setLoadError("");
      try {
        const [nodePage, sourcePages] = await Promise.all([
          props.client.get<Page<KadNode>>("kad/nodes?limit=300"),
          Promise.all(
            props.transfers
              .filter((transfer) => transfer.state !== "completed")
              .slice(0, 12)
              .map(async (transfer) => {
                try {
                  const page = await props.client.get<Page<TransferSource>>(`transfers/${transfer.hash}/sources`);
                  return (page.items ?? []).map((source) => ({
                    ...source,
                    transferHash: transfer.hash,
                    transferName: transfer.name
                  }));
                } catch {
                  return [] as NetworkTransferSource[];
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
  }, [props.client, props.kad.contactCount, props.kad.connected, props.transfers]);

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
        <Metric label="Peer Endpoints" value={String(sources.length + props.uploads.length + props.uploadQueue.length)} />
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
        <div class="table-wrap">
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
        </div>
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

export function ServersView(props: { servers: ServerItem[]; client: RestClient; run: RunFunction }) {
  const [address, setAddress] = useState("");
  const [port, setPort] = useState("4661");
  const [name, setName] = useState("");
  const [importUrl, setImportUrl] = useState("");
  const [filter, setFilter] = useState("");
  const [selectedEndpoint, setSelectedEndpoint] = useState("");

  const filteredServers = useMemo(() => {
    const needle = filter.trim().toLowerCase();
    if (!needle) {
      return props.servers;
    }
    return props.servers.filter((server) => [
      serverEndpoint(server),
      server.name,
      server.address,
      server.ip,
      server.dynIp,
      server.hostName,
      server.description
    ].some((value) => String(value ?? "").toLowerCase().includes(needle)));
  }, [filter, props.servers]);
  const selected = useMemo(() => {
    if (!props.servers.length) {
      return undefined;
    }
    return props.servers.find((server) => serverEndpoint(server) === selectedEndpoint) ?? props.servers[0];
  }, [props.servers, selectedEndpoint]);

  const createServer = () => props.client.post("servers", {
    address,
    port: Number(port),
    name: name || undefined,
    priority: "normal",
    static: true
  });

  return (
    <section class="panel card">
      <div class="section-title">
        <h2>Servers</h2>
        <div class="row-actions">
          <button class="btn" type="button" onClick={() => void props.run(() => props.client.post("servers/operations/connect"), "Server connect started")}><Plug size={15} />Connect</button>
          <button class="btn" type="button" onClick={() => void props.run(() => props.client.post("servers/operations/disconnect"), "Servers disconnected")}><Ban size={15} />Disconnect</button>
        </div>
      </div>
      <form class="form-row" onSubmit={(event) => {
        event.preventDefault();
        void props.run(createServer, "Server added");
      }}>
        <input class="form-control" value={address} placeholder="Address" onInput={(event) => setAddress(event.currentTarget.value)} />
        <input class="form-control" value={port} placeholder="Port" inputMode="numeric" onInput={(event) => setPort(event.currentTarget.value)} />
        <input class="form-control" value={name} placeholder="Name" onInput={(event) => setName(event.currentTarget.value)} />
        <button class="btn" type="submit"><Server size={16} />Add</button>
      </form>
      <form class="form-row" onSubmit={(event) => {
        event.preventDefault();
        void props.run(() => props.client.post("servers/operations/import-met-url", { url: importUrl }), "Server list import started");
      }}>
        <input class="form-control" value={importUrl} placeholder="server.met URL" onInput={(event) => setImportUrl(event.currentTarget.value)} />
        <button class="btn" type="submit"><Download size={16} />Import</button>
      </form>
      <div class="form-row">
        <input class="form-control" value={filter} placeholder="Filter endpoint, host, IP, name" onInput={(event) => setFilter(event.currentTarget.value)} />
      </div>
      <div class="table-wrap">
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
              const encoded = encodeSegment(endpoint);
              return (
                <tr key={endpoint} class={selected && serverEndpoint(selected) === endpoint ? "selected-row" : ""} onClick={() => setSelectedEndpoint(endpoint)}>
                  <td>{endpoint}</td>
                  <td>{hostNameLabel(server)}</td>
                  <td>{server.ip || server.dynIp || ""}</td>
                  <td>{server.name ?? ""}</td>
                  <td><StatusPill value={server.connected ? "connected" : server.connecting ? "connecting" : server.enabled === false ? "disabled" : server.current ? "current" : "idle"} /></td>
                  <td>{server.users ?? 0}</td>
                  <td>{server.files ?? 0}</td>
                  <td>{server.ping ? `${server.ping} ms` : ""}</td>
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
            {filteredServers.length === 0 && <EmptyRow colSpan={9} text="No servers." />}
          </tbody>
        </table>
      </div>
      {selected && (
        <div class="split detail-split">
          <div class="kv compact">
            <span>Configured address</span><strong>{selected.address ?? ""}</strong>
            <span>Resolved IP</span><strong>{selected.ip || ""}</strong>
            <span>Dynamic IP/name</span><strong>{selected.dynIp || ""}</strong>
            <span>Hostname</span><strong>{hostNameLabel(selected)}</strong>
            <span>DNS status</span><strong>{selected.hostNameStatus ?? "unknown"}</strong>
            <span>Description</span><strong>{selected.description || ""}</strong>
          </div>
          <div class="kv compact">
            <span>Priority</span><strong>{selected.priority ?? "normal"}</strong>
            <span>Enabled/static</span><strong>{yesNo(selected.enabled !== false)} / {yesNo(selected.static)}</strong>
            <span>Current</span><strong>{yesNo(selected.current)}</strong>
            <span>Soft/hard files</span><strong>{selected.softFiles ?? 0} / {selected.hardFiles ?? 0}</strong>
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
  const [importUrl, setImportUrl] = useState("");
  const [nodes, setNodes] = useState<KadNode[]>([]);
  const [filter, setFilter] = useState("");
  const [selectedNodeId, setSelectedNodeId] = useState("");

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
          <button class="btn" type="button" onClick={() => void props.run(() => props.client.post("kad/operations/start"), "Kad started")}><Play size={15} />Start</button>
          <button class="btn" type="button" onClick={() => void props.run(() => props.client.post("kad/operations/stop"), "Kad stopped")}><Pause size={15} />Stop</button>
          <button class="btn" type="button" onClick={() => void props.run(() => props.client.post("kad/operations/recheck-firewall"), "Kad firewall recheck started")}><Shield size={15} />Recheck</button>
        </div>
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
        void props.run(() => props.client.post("kad/operations/import-nodes-url", { url: importUrl }), "Kad nodes import started");
      }}>
        <input class="form-control" value={importUrl} placeholder="nodes.dat URL" onInput={(event) => setImportUrl(event.currentTarget.value)} />
        <button class="btn" type="submit"><Download size={16} />Import</button>
      </form>
      <form class="form-row" onSubmit={(event) => {
        event.preventDefault();
        void props.run(() => props.client.post("kad/operations/bootstrap", { address: bootstrapAddress, port: Number(bootstrapPort) }), "Kad bootstrap started");
      }}>
        <input class="form-control" value={bootstrapAddress} placeholder="Bootstrap address" onInput={(event) => setBootstrapAddress(event.currentTarget.value)} />
        <input class="form-control" value={bootstrapPort} inputMode="numeric" placeholder="Port" onInput={(event) => setBootstrapPort(event.currentTarget.value)} />
        <button class="btn" type="submit"><Plug size={16} />Bootstrap</button>
      </form>
      <div class="form-row">
        <input class="form-control" value={filter} placeholder="Filter Kad node, IP, host, state" onInput={(event) => setFilter(event.currentTarget.value)} />
      </div>
      <div class="table-wrap">
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
      </div>
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
  sources: NetworkTransferSource[],
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
    rows.push(peerEndpointRow("Upload", `upload:${upload.clientId ?? upload.address ?? ""}`, upload, bindPolicy, upload.requestedFileName ?? ""));
  }
  for (const peer of uploadQueue) {
    rows.push(peerEndpointRow("Upload Queue", `queue:${peer.clientId ?? peer.address ?? ""}`, peer, bindPolicy, peer.requestedFileName ?? ""));
  }
  return rows;
}

function peerEndpointRow(kind: string, key: string, peer: TransferSource | Upload, bindPolicy: { label: string; detail: string }, detail: string): NetworkEndpointRow {
  const address = stringField(peer, "address");
  const port = numberField(peer, "port");
  return {
    key,
    kind,
    endpoint: port ? `${address}:${port}` : address || stringField(peer, "clientId"),
    ip: address,
    host: "",
    dnsStatus: "not-exposed",
    state: stringField(peer, "state") || stringField(peer, "uploadState") || (boolField(peer, "uploading") ? "uploading" : boolField(peer, "waitingQueue") ? "queued" : "active"),
    detail: detail || stringField(peer, "userName") || stringField(peer, "clientSoftware"),
    lastSeen: "",
    bindPolicy: bindPolicy.label
  };
}

function networkBindPolicy(settings: AppSettings | null): { label: string; detail: string } {
  const daemon = settings?.daemon;
  const bindIp = stringField(daemon, "p2pBindIp");
  const bindInterface = stringField(daemon, "p2pBindInterface");
  if (bindIp || bindInterface) {
    return {
      label: "bound",
      detail: [bindInterface && `interface ${bindInterface}`, bindIp && `IP ${bindIp}`].filter(Boolean).join(", ")
    };
  }
  return { label: "unbound", detail: "No P2P bind IP/interface configured" };
}

function hostnameLookupPolicy(settings: AppSettings | null): string {
  const lookup = recordField(settings?.daemon, "hostnameLookup");
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

function shortTime(value?: string | null): string {
  if (!value) {
    return "";
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }
  return date.toLocaleString();
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
    <section class="panel card">
      <div class="section-title">
        <h2>Categories</h2>
        <span>{props.categories.length} configured</span>
      </div>
      <form class="form-row" onSubmit={(event) => {
        event.preventDefault();
        void props.run(create, "Category created");
      }}>
        <input class="form-control" value={name} placeholder="Name" onInput={(event) => setName(event.currentTarget.value)} />
        <input class="form-control" value={path} placeholder="Incoming path" onInput={(event) => setPath(event.currentTarget.value)} />
        <input class="form-control" value={comment} placeholder="Comment" onInput={(event) => setComment(event.currentTarget.value)} />
        <select class="form-select" value={priority} onInput={(event) => setPriority(event.currentTarget.value)}>
          <option value="low">Low</option>
          <option value="normal">Normal</option>
          <option value="high">High</option>
          <option value="veryhigh">Very high</option>
        </select>
        <button class="btn" type="submit"><FolderPlus size={16} />Add</button>
      </form>
      <div class="table-wrap">
        <table class="table table-vcenter card-table">
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
      <td><input class="form-control" value={name} onInput={(event) => setName(event.currentTarget.value)} /></td>
      <td><input class="form-control" value={path} onInput={(event) => setPath(event.currentTarget.value)} /></td>
      <td><input class="form-control" value={comment} onInput={(event) => setComment(event.currentTarget.value)} /></td>
      <td><input class="form-control" value={priority} onInput={(event) => setPriority(event.currentTarget.value)} /></td>
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
    <section class="panel card">
      <div class="section-title">
        <h2>Friends</h2>
        <span>{props.friends.length} peers</span>
      </div>
      <form class="form-row" onSubmit={(event) => {
        event.preventDefault();
        void props.run(create, "Friend added");
      }}>
        <input class="form-control" value={userHash} placeholder="User hash" onInput={(event) => setUserHash(event.currentTarget.value)} />
        <input class="form-control" value={name} placeholder="Name" onInput={(event) => setName(event.currentTarget.value)} />
        <button class="btn" type="submit"><UserPlus size={16} />Add</button>
      </form>
      <div class="table-wrap">
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
  hostnameLookupEnabled: boolean;
  hostnameLookupDnsServers: string;
  hostnameLookupCacheTtlSecs: string;
  hostnameLookupMaxLookupsPerTick: string;
  hostnameLookupTickIntervalSecs: string;
  ed2kListenPort: string;
  ed2kConnectTimeoutSecs: string;
  ed2kServerConnectTimeoutSecs: string;
  ed2kCallbackTimeoutSecs: string;
  ed2kReconnectIntervalSecs: string;
  ed2kKeepaliveSecs: string;
  ed2kDeadServerRetries: string;
  ed2kSessionRotationSecs: string;
  ed2kMaxConcurrentDownloads: string;
  ed2kMaxNewConnectionsPerFiveSeconds: string;
  ed2kMaxHalfOpenConnections: string;
  ed2kMaxSourcesPerFile: string;
  ed2kMaxParallelDownloadPeers: string;
  ed2kDownloadLimitBytesPerSec: string;
  ed2kKeywordServerAttemptBudget: string;
  ed2kExactHashKeywordServerAttemptBudget: string;
  ed2kSourceServerAttemptBudget: string;
  ed2kUploadQueueActiveSlots: string;
  ed2kUploadQueueElasticPercent: string;
  ed2kUploadQueueUploadLimitBytesPerSec: string;
  ed2kUploadQueueElasticUnderfillBytesPerSec: string;
  ed2kUploadQueueElasticUnderfillSecs: string;
  ed2kUploadQueueWaitingCapacity: string;
  ed2kUploadQueueWaitingTimeoutSecs: string;
  ed2kUploadQueueGrantedTimeoutSecs: string;
  ed2kUploadQueueUploadTimeoutSecs: string;
  ed2kUploadQueueSessionTransferPercent: string;
  ed2kUploadQueueSessionTimeLimitSecs: string;
  kadListenPort: string;
  obfuscationEnabled: boolean;
  ed2kReconnectEnabled: boolean;
  enableUdpReask: boolean;
  publishEmuleRustIdentity: boolean;
  kadPublishSharedFilesEnabled: boolean;
  kadBootstrapMinRoutingContacts: string;
  kadLocalStoreEnabled: boolean;
  kadRepublishIntervalSecs: string;
  kadPublishContactFanout: string;
  udpFirewallCheckEnabled: boolean;
  kadUdpFirewallCheckIntervalSecs: string;
  tcpFirewallCheckEnabled: boolean;
  kadTcpFirewallCheckIntervalSecs: string;
  buddyEnabled: boolean;
  routingMaintenanceEnabled: boolean;
  natEnabled: boolean;
  natRequireInitialMapping: boolean;
  natBindIp: string;
  natBackendOrder: string;
  natIgdIp: string;
  natMinissdpdSocket: string;
  natSsdpLocalPort: string;
  natDiscoveryTimeoutSecs: string;
  natLeaseDurationSecs: string;
  natRenewMarginSecs: string;
  natExternalIpOverride: string;
  vpnGuardEnabled: boolean;
  vpnGuardMode: string;
  vpnGuardAllowedPublicIpCidrs: string;
  ipFilterEnabled: boolean;
  ipFilterPath: string;
  ipFilterLevel: string;
};

type SettingsTextKey = {
  [K in keyof SettingsForm]: SettingsForm[K] extends string ? K : never;
}[keyof SettingsForm];

type SettingsBooleanKey = {
  [K in keyof SettingsForm]: SettingsForm[K] extends boolean ? K : never;
}[keyof SettingsForm];

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
  hostnameLookupEnabled: false,
  hostnameLookupDnsServers: "",
  hostnameLookupCacheTtlSecs: "",
  hostnameLookupMaxLookupsPerTick: "",
  hostnameLookupTickIntervalSecs: "",
  ed2kListenPort: "",
  ed2kConnectTimeoutSecs: "",
  ed2kServerConnectTimeoutSecs: "",
  ed2kCallbackTimeoutSecs: "",
  ed2kReconnectIntervalSecs: "",
  ed2kKeepaliveSecs: "",
  ed2kDeadServerRetries: "",
  ed2kSessionRotationSecs: "",
  ed2kMaxConcurrentDownloads: "",
  ed2kMaxNewConnectionsPerFiveSeconds: "",
  ed2kMaxHalfOpenConnections: "",
  ed2kMaxSourcesPerFile: "",
  ed2kMaxParallelDownloadPeers: "",
  ed2kDownloadLimitBytesPerSec: "",
  ed2kKeywordServerAttemptBudget: "",
  ed2kExactHashKeywordServerAttemptBudget: "",
  ed2kSourceServerAttemptBudget: "",
  ed2kUploadQueueActiveSlots: "",
  ed2kUploadQueueElasticPercent: "",
  ed2kUploadQueueUploadLimitBytesPerSec: "",
  ed2kUploadQueueElasticUnderfillBytesPerSec: "",
  ed2kUploadQueueElasticUnderfillSecs: "",
  ed2kUploadQueueWaitingCapacity: "",
  ed2kUploadQueueWaitingTimeoutSecs: "",
  ed2kUploadQueueGrantedTimeoutSecs: "",
  ed2kUploadQueueUploadTimeoutSecs: "",
  ed2kUploadQueueSessionTransferPercent: "",
  ed2kUploadQueueSessionTimeLimitSecs: "",
  kadListenPort: "",
  obfuscationEnabled: false,
  ed2kReconnectEnabled: false,
  enableUdpReask: false,
  publishEmuleRustIdentity: false,
  kadPublishSharedFilesEnabled: false,
  kadBootstrapMinRoutingContacts: "",
  kadLocalStoreEnabled: false,
  kadRepublishIntervalSecs: "",
  kadPublishContactFanout: "",
  udpFirewallCheckEnabled: false,
  kadUdpFirewallCheckIntervalSecs: "",
  tcpFirewallCheckEnabled: false,
  kadTcpFirewallCheckIntervalSecs: "",
  buddyEnabled: false,
  routingMaintenanceEnabled: false,
  natEnabled: false,
  natRequireInitialMapping: false,
  natBindIp: "",
  natBackendOrder: "",
  natIgdIp: "",
  natMinissdpdSocket: "",
  natSsdpLocalPort: "",
  natDiscoveryTimeoutSecs: "",
  natLeaseDurationSecs: "",
  natRenewMarginSecs: "",
  natExternalIpOverride: "",
  vpnGuardEnabled: false,
  vpnGuardMode: "",
  vpnGuardAllowedPublicIpCidrs: "",
  ipFilterEnabled: false,
  ipFilterPath: "",
  ipFilterLevel: ""
};

export function SettingsView(props: { settings: AppSettings | null; surface: SettingsSurface | null; client: RestClient; run: RunFunction; openSection: (name: string) => void }) {
  const [form, setForm] = useState<SettingsForm>(emptySettingsForm);
  const [showAdvanced, setShowAdvanced] = useState(false);

  const baseline = useMemo(() => props.settings ? settingsFormFrom(props.settings) : emptySettingsForm, [props.settings]);
  const surfaceByPath = useMemo(() => {
    const byPath = new Map<string, SettingSurfaceSpec>();
    for (const spec of props.surface?.settings ?? []) {
      byPath.set(spec.path, spec);
    }
    return byPath;
  }, [props.surface]);

  useEffect(() => {
    setForm(baseline);
  }, [baseline]);

  const update = <K extends keyof SettingsForm>(key: K, value: SettingsForm[K]) => {
    setForm((current) => ({ ...current, [key]: value }));
  };

  const validationErrors = validateSettingsForm(form);
  const hasValidationErrors = validationErrors.size > 0;
  const dirty = props.settings ? JSON.stringify(form) !== JSON.stringify(baseline) : false;
  const advancedCount = props.surface?.settings.filter((spec) => spec.class === "advancedControl").length ?? 0;
  const shouldRender = (path: string) => {
    const spec = surfaceByPath.get(path);
    if (spec?.class === "notUserFacing") {
      return false;
    }
    return showAdvanced || spec?.class !== "advancedControl";
  };
  const sectionVisible = (paths: string[]) => paths.some(shouldRender);
  const renderField = (path: string, key: SettingsTextKey, label: string) => shouldRender(path)
    ? <Field label={label} value={form[key]} surface={surfaceByPath.get(path)} error={validationErrors.get(key)} onInput={(value) => update(key, value)} />
    : null;
  const renderToggle = (path: string, key: SettingsBooleanKey, label: string) => shouldRender(path)
    ? <Toggle label={label} checked={form[key]} surface={surfaceByPath.get(path)} onInput={(value) => update(key, value)} />
    : null;

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
        p2pBindInterface: optionalString(form.p2pBindInterface),
        hostnameLookup: {
          ...(recordField(settings.daemon, "hostnameLookup")),
          enabled: form.hostnameLookupEnabled,
          dnsServers: form.hostnameLookupDnsServers.split(",").map((item) => item.trim()).filter(Boolean),
          cacheTtlSecs: parseNumber(form.hostnameLookupCacheTtlSecs, 86400),
          maxLookupsPerTick: parseNumber(form.hostnameLookupMaxLookupsPerTick, 32),
          tickIntervalSecs: parseNumber(form.hostnameLookupTickIntervalSecs, 30)
        }
      },
      ed2k: {
        ...(settings.ed2k ?? {}),
        listenPort: optionalPort(form.ed2kListenPort),
        connectTimeoutSecs: parseNumber(form.ed2kConnectTimeoutSecs),
        serverConnectTimeoutSecs: parseNumber(form.ed2kServerConnectTimeoutSecs),
        callbackTimeoutSecs: parseNumber(form.ed2kCallbackTimeoutSecs),
        reconnectIntervalSecs: parseNumber(form.ed2kReconnectIntervalSecs),
        keepaliveSecs: parseNumber(form.ed2kKeepaliveSecs),
        sessionRotationSecs: parseNumber(form.ed2kSessionRotationSecs),
        maxConcurrentDownloads: parseNumber(form.ed2kMaxConcurrentDownloads),
        maxNewConnectionsPerFiveSeconds: parseNumber(form.ed2kMaxNewConnectionsPerFiveSeconds),
        maxHalfOpenConnections: parseNumber(form.ed2kMaxHalfOpenConnections),
        maxSourcesPerFile: parseNumber(form.ed2kMaxSourcesPerFile),
        maxParallelDownloadPeers: parseNumber(form.ed2kMaxParallelDownloadPeers),
        keywordServerAttemptBudget: parseNumber(form.ed2kKeywordServerAttemptBudget),
        exactHashKeywordServerAttemptBudget: parseNumber(form.ed2kExactHashKeywordServerAttemptBudget),
        sourceServerAttemptBudget: parseNumber(form.ed2kSourceServerAttemptBudget),
        downloadLimitBytesPerSec: parseNumber(form.ed2kDownloadLimitBytesPerSec),
        obfuscationEnabled: form.obfuscationEnabled,
        reconnectEnabled: form.ed2kReconnectEnabled,
        enableUdpReask: form.enableUdpReask,
        publishEmuleRustIdentity: form.publishEmuleRustIdentity,
        addServersFromServer: form.addServersFromServer,
        safeServerConnect: form.safeServerConnect,
        deadServerRetries: parseNumber(form.ed2kDeadServerRetries),
        uploadQueue: {
          ...(recordField(settings.ed2k, "uploadQueue")),
          activeSlots: parseNumber(form.ed2kUploadQueueActiveSlots),
          elasticPercent: parseNumber(form.ed2kUploadQueueElasticPercent),
          uploadLimitBytesPerSec: parseNumber(form.ed2kUploadQueueUploadLimitBytesPerSec),
          elasticUnderfillBytesPerSec: parseNumber(form.ed2kUploadQueueElasticUnderfillBytesPerSec),
          elasticUnderfillSecs: parseNumber(form.ed2kUploadQueueElasticUnderfillSecs),
          waitingCapacity: parseNumber(form.ed2kUploadQueueWaitingCapacity),
          waitingTimeoutSecs: parseNumber(form.ed2kUploadQueueWaitingTimeoutSecs),
          grantedTimeoutSecs: parseNumber(form.ed2kUploadQueueGrantedTimeoutSecs),
          uploadTimeoutSecs: parseNumber(form.ed2kUploadQueueUploadTimeoutSecs),
          sessionTransferPercent: parseNumber(form.ed2kUploadQueueSessionTransferPercent),
          sessionTimeLimitSecs: parseNumber(form.ed2kUploadQueueSessionTimeLimitSecs)
        }
      },
      kad: {
        ...(settings.kad ?? {}),
        listenPort: optionalPort(form.kadListenPort),
        bootstrapMinRoutingContacts: parseNumber(form.kadBootstrapMinRoutingContacts),
        localStoreEnabled: form.kadLocalStoreEnabled,
        publishSharedFilesEnabled: form.kadPublishSharedFilesEnabled,
        republishIntervalSecs: parseNumber(form.kadRepublishIntervalSecs),
        publishContactFanout: parseNumber(form.kadPublishContactFanout),
        udpFirewallCheckEnabled: form.udpFirewallCheckEnabled,
        udpFirewallCheckIntervalSecs: parseNumber(form.kadUdpFirewallCheckIntervalSecs),
        tcpFirewallCheckEnabled: form.tcpFirewallCheckEnabled,
        tcpFirewallCheckIntervalSecs: parseNumber(form.kadTcpFirewallCheckIntervalSecs),
        buddyEnabled: form.buddyEnabled,
        routingMaintenanceEnabled: form.routingMaintenanceEnabled
      },
      nat: {
        ...(settings.nat ?? {}),
        enabled: form.natEnabled,
        requireInitialMapping: form.natRequireInitialMapping,
        bindIp: optionalString(form.natBindIp),
        backendOrder: form.natBackendOrder.split(",").map((item) => item.trim()).filter(Boolean),
        igdIp: optionalString(form.natIgdIp),
        minissdpdSocket: optionalString(form.natMinissdpdSocket),
        ssdpLocalPort: optionalPort(form.natSsdpLocalPort),
        discoveryTimeoutSecs: parseNumber(form.natDiscoveryTimeoutSecs),
        leaseDurationSecs: parseNumber(form.natLeaseDurationSecs),
        renewMarginSecs: parseNumber(form.natRenewMarginSecs),
        externalIpOverride: optionalString(form.natExternalIpOverride)
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

  const revert = () => {
    setForm(baseline);
  };

  if (!props.settings) {
    return <section class="panel card"><p class="empty">Settings are not loaded.</p></section>;
  }

  return (
    <section class="panel card">
      <div class="section-title">
        <h2>Settings</h2>
        <div class="settings-actions">
          <label class="check">
            <input class="form-check-input" type="checkbox" checked={showAdvanced} onInput={(event) => setShowAdvanced(event.currentTarget.checked)} />
            Advanced ({advancedCount})
          </label>
          <button class="btn" type="button" disabled={!dirty} onClick={revert}>
            <RefreshCw size={15} />
            Revert
          </button>
          <button class="btn" type="button" disabled={!dirty || hasValidationErrors} onClick={() => void props.run(save, "Settings saved; restart daemon for bind, port, NAT, VPN, and filter changes")}>
            <Save size={15} />
            Save
          </button>
        </div>
      </div>
      {hasValidationErrors && <p class="settings-error-summary">Fix highlighted settings before saving.</p>}
      <div class="settings-sections">
        {sectionVisible(["daemon.incomingDir"]) && (
          <SettingsControlSection title="Storage">
            <div class="settings-grid">
              {renderField("daemon.incomingDir", "incomingDir", "Incoming directory")}
            </div>
          </SettingsControlSection>
        )}
        {sectionVisible([
          "core.uploadLimitKiBps",
          "core.downloadLimitKiBps",
          "core.maxSourcesPerFile",
          "core.uploadClientDataRate",
          "core.maxUploadSlots",
          "core.uploadSlotElasticPercent",
          "core.queueSize",
          "core.creditSystem",
          "ed2k.sessionRotationSecs",
          "ed2k.maxConcurrentDownloads",
          "ed2k.maxSourcesPerFile",
          "ed2k.maxParallelDownloadPeers",
          "ed2k.downloadLimitBytesPerSec",
          "ed2k.enableUdpReask"
        ]) && (
          <SettingsControlSection title="Transfers">
            <div class="settings-grid">
              {renderField("core.uploadLimitKiBps", "uploadLimitKiBps", "Upload limit KiB/s")}
              {renderField("core.downloadLimitKiBps", "downloadLimitKiBps", "Download limit KiB/s")}
              {renderField("core.maxSourcesPerFile", "maxSourcesPerFile", "Max sources / file")}
              {renderField("core.uploadClientDataRate", "uploadClientDataRate", "Upload client KiB/s")}
              {renderField("core.maxUploadSlots", "maxUploadSlots", "Max upload slots")}
              {renderField("core.uploadSlotElasticPercent", "uploadSlotElasticPercent", "Upload elasticity %")}
              {renderField("core.queueSize", "queueSize", "Queue size")}
              {renderToggle("core.creditSystem", "creditSystem", "Credit system")}
              {renderField("ed2k.sessionRotationSecs", "ed2kSessionRotationSecs", "Session rotation seconds")}
              {renderField("ed2k.maxConcurrentDownloads", "ed2kMaxConcurrentDownloads", "Concurrent downloads")}
              {renderField("ed2k.maxSourcesPerFile", "ed2kMaxSourcesPerFile", "eD2K source cap")}
              {renderField("ed2k.maxParallelDownloadPeers", "ed2kMaxParallelDownloadPeers", "Parallel download peers")}
              {renderField("ed2k.downloadLimitBytesPerSec", "ed2kDownloadLimitBytesPerSec", "Download limit B/s")}
              {renderToggle("ed2k.enableUdpReask", "enableUdpReask", "UDP reask")}
            </div>
          </SettingsControlSection>
        )}
        {sectionVisible([
          "daemon.p2pBindIp",
          "daemon.p2pBindInterface",
          "core.maxConnections",
          "core.maxConnectionsPerFiveSeconds",
          "core.networkEd2k",
          "core.networkKademlia",
          "ed2k.listenPort",
          "ed2k.connectTimeoutSecs",
          "ed2k.keepaliveSecs",
          "ed2k.maxNewConnectionsPerFiveSeconds",
          "ed2k.maxHalfOpenConnections",
          "kad.listenPort",
          "ed2k.obfuscationEnabled",
          "ed2k.publishEmuleRustIdentity"
        ]) && (
          <SettingsControlSection title="Network">
            <div class="settings-grid">
              {renderField("daemon.p2pBindIp", "p2pBindIp", "P2P bind IP")}
              {renderField("daemon.p2pBindInterface", "p2pBindInterface", "P2P bind interface")}
              {renderField("core.maxConnections", "maxConnections", "Max connections")}
              {renderField("core.maxConnectionsPerFiveSeconds", "maxConnectionsPerFiveSeconds", "New connections / 5s")}
              {renderField("ed2k.listenPort", "ed2kListenPort", "eD2K listen port")}
              {renderField("ed2k.connectTimeoutSecs", "ed2kConnectTimeoutSecs", "eD2K connect timeout seconds")}
              {renderField("ed2k.keepaliveSecs", "ed2kKeepaliveSecs", "eD2K keepalive seconds")}
              {renderField("ed2k.maxNewConnectionsPerFiveSeconds", "ed2kMaxNewConnectionsPerFiveSeconds", "eD2K new connections / 5s")}
              {renderField("ed2k.maxHalfOpenConnections", "ed2kMaxHalfOpenConnections", "eD2K half-open connections")}
              {renderField("kad.listenPort", "kadListenPort", "Kad listen port")}
              {renderToggle("core.networkEd2k", "networkEd2k", "Network eD2K")}
              {renderToggle("core.networkKademlia", "networkKademlia", "Network Kad")}
              {renderToggle("ed2k.obfuscationEnabled", "obfuscationEnabled", "Obfuscation")}
              {renderToggle("ed2k.publishEmuleRustIdentity", "publishEmuleRustIdentity", "Publish Rust identity")}
            </div>
          </SettingsControlSection>
        )}
        {sectionVisible([
          "daemon.hostnameLookup.enabled",
          "daemon.hostnameLookup.dnsServers",
          "daemon.hostnameLookup.cacheTtlSecs",
          "daemon.hostnameLookup.maxLookupsPerTick",
          "daemon.hostnameLookup.tickIntervalSecs"
        ]) && (
          <SettingsControlSection title="Hostname Lookup">
            <div class="settings-grid">
              {renderToggle("daemon.hostnameLookup.enabled", "hostnameLookupEnabled", "Hostname lookup")}
              {renderField("daemon.hostnameLookup.dnsServers", "hostnameLookupDnsServers", "DNS servers")}
              {renderField("daemon.hostnameLookup.cacheTtlSecs", "hostnameLookupCacheTtlSecs", "DNS cache TTL seconds")}
              {renderField("daemon.hostnameLookup.maxLookupsPerTick", "hostnameLookupMaxLookupsPerTick", "DNS lookups / tick")}
              {renderField("daemon.hostnameLookup.tickIntervalSecs", "hostnameLookupTickIntervalSecs", "DNS tick seconds")}
            </div>
          </SettingsControlSection>
        )}
        {sectionVisible([
          "core.autoConnect",
          "core.reconnect",
          "core.safeServerConnect",
          "core.addServersFromServer",
          "ed2k.reconnectEnabled",
          "ed2k.serverConnectTimeoutSecs",
          "ed2k.callbackTimeoutSecs",
          "ed2k.reconnectIntervalSecs",
          "ed2k.deadServerRetries"
        ]) && (
          <SettingsControlSection title="Servers">
            <div class="settings-grid">
              {renderToggle("core.autoConnect", "autoConnect", "Auto connect")}
              {renderToggle("core.reconnect", "reconnect", "Reconnect")}
              {renderToggle("core.safeServerConnect", "safeServerConnect", "Safe server connect")}
              {renderToggle("core.addServersFromServer", "addServersFromServer", "Add servers from server")}
              {renderToggle("ed2k.reconnectEnabled", "ed2kReconnectEnabled", "eD2K reconnect")}
              {renderField("ed2k.serverConnectTimeoutSecs", "ed2kServerConnectTimeoutSecs", "Server connect timeout seconds")}
              {renderField("ed2k.callbackTimeoutSecs", "ed2kCallbackTimeoutSecs", "Callback timeout seconds")}
              {renderField("ed2k.reconnectIntervalSecs", "ed2kReconnectIntervalSecs", "Reconnect interval seconds")}
              {renderField("ed2k.deadServerRetries", "ed2kDeadServerRetries", "Dead server retries")}
            </div>
          </SettingsControlSection>
        )}
        {sectionVisible([
          "ed2k.keywordServerAttemptBudget",
          "ed2k.exactHashKeywordServerAttemptBudget",
          "ed2k.sourceServerAttemptBudget"
        ]) && (
          <SettingsControlSection title="Search">
            <div class="settings-grid">
              {renderField("ed2k.keywordServerAttemptBudget", "ed2kKeywordServerAttemptBudget", "Keyword server attempts")}
              {renderField("ed2k.exactHashKeywordServerAttemptBudget", "ed2kExactHashKeywordServerAttemptBudget", "Exact-hash server attempts")}
              {renderField("ed2k.sourceServerAttemptBudget", "ed2kSourceServerAttemptBudget", "Source server attempts")}
            </div>
          </SettingsControlSection>
        )}
        {sectionVisible([
          "ed2k.uploadQueue.activeSlots",
          "ed2k.uploadQueue.elasticPercent",
          "ed2k.uploadQueue.uploadLimitBytesPerSec",
          "ed2k.uploadQueue.elasticUnderfillBytesPerSec",
          "ed2k.uploadQueue.elasticUnderfillSecs",
          "ed2k.uploadQueue.waitingCapacity",
          "ed2k.uploadQueue.waitingTimeoutSecs",
          "ed2k.uploadQueue.grantedTimeoutSecs",
          "ed2k.uploadQueue.uploadTimeoutSecs",
          "ed2k.uploadQueue.sessionTransferPercent",
          "ed2k.uploadQueue.sessionTimeLimitSecs"
        ]) && (
          <SettingsControlSection title="Uploads">
            <div class="settings-grid">
              {renderField("ed2k.uploadQueue.activeSlots", "ed2kUploadQueueActiveSlots", "Startup upload slots")}
              {renderField("ed2k.uploadQueue.elasticPercent", "ed2kUploadQueueElasticPercent", "Startup upload elasticity %")}
              {renderField("ed2k.uploadQueue.uploadLimitBytesPerSec", "ed2kUploadQueueUploadLimitBytesPerSec", "Upload limit B/s")}
              {renderField("ed2k.uploadQueue.elasticUnderfillBytesPerSec", "ed2kUploadQueueElasticUnderfillBytesPerSec", "Elastic underfill B/s")}
              {renderField("ed2k.uploadQueue.elasticUnderfillSecs", "ed2kUploadQueueElasticUnderfillSecs", "Elastic underfill seconds")}
              {renderField("ed2k.uploadQueue.waitingCapacity", "ed2kUploadQueueWaitingCapacity", "Waiting queue capacity")}
              {renderField("ed2k.uploadQueue.waitingTimeoutSecs", "ed2kUploadQueueWaitingTimeoutSecs", "Waiting timeout seconds")}
              {renderField("ed2k.uploadQueue.grantedTimeoutSecs", "ed2kUploadQueueGrantedTimeoutSecs", "Granted idle timeout seconds")}
              {renderField("ed2k.uploadQueue.uploadTimeoutSecs", "ed2kUploadQueueUploadTimeoutSecs", "Upload timeout seconds")}
              {renderField("ed2k.uploadQueue.sessionTransferPercent", "ed2kUploadQueueSessionTransferPercent", "Session transfer %")}
              {renderField("ed2k.uploadQueue.sessionTimeLimitSecs", "ed2kUploadQueueSessionTimeLimitSecs", "Session time limit seconds")}
            </div>
          </SettingsControlSection>
        )}
        {sectionVisible([
          "kad.bootstrapMinRoutingContacts",
          "kad.localStoreEnabled",
          "kad.publishSharedFilesEnabled",
          "kad.republishIntervalSecs",
          "kad.publishContactFanout",
          "kad.udpFirewallCheckEnabled",
          "kad.udpFirewallCheckIntervalSecs",
          "kad.tcpFirewallCheckEnabled",
          "kad.tcpFirewallCheckIntervalSecs",
          "kad.buddyEnabled",
          "kad.routingMaintenanceEnabled"
        ]) && (
          <SettingsControlSection title="Kad">
            <div class="settings-grid">
              {renderField("kad.bootstrapMinRoutingContacts", "kadBootstrapMinRoutingContacts", "Bootstrap contact floor")}
              {renderToggle("kad.localStoreEnabled", "kadLocalStoreEnabled", "Kad local store")}
              {renderToggle("kad.publishSharedFilesEnabled", "kadPublishSharedFilesEnabled", "Kad publish shared files")}
              {renderField("kad.republishIntervalSecs", "kadRepublishIntervalSecs", "Kad republish seconds")}
              {renderField("kad.publishContactFanout", "kadPublishContactFanout", "Publish contact fanout")}
              {renderToggle("kad.udpFirewallCheckEnabled", "udpFirewallCheckEnabled", "Kad UDP firewall checks")}
              {renderField("kad.udpFirewallCheckIntervalSecs", "kadUdpFirewallCheckIntervalSecs", "UDP firewall interval seconds")}
              {renderToggle("kad.tcpFirewallCheckEnabled", "tcpFirewallCheckEnabled", "Kad TCP firewall checks")}
              {renderField("kad.tcpFirewallCheckIntervalSecs", "kadTcpFirewallCheckIntervalSecs", "TCP firewall interval seconds")}
              {renderToggle("kad.buddyEnabled", "buddyEnabled", "Kad buddy")}
              {renderToggle("kad.routingMaintenanceEnabled", "routingMaintenanceEnabled", "Routing maintenance")}
            </div>
          </SettingsControlSection>
        )}
        {sectionVisible([
          "nat.enabled",
          "nat.requireInitialMapping",
          "nat.bindIp",
          "nat.backendOrder",
          "nat.igdIp",
          "nat.minissdpdSocket",
          "nat.ssdpLocalPort",
          "nat.discoveryTimeoutSecs",
          "nat.leaseDurationSecs",
          "nat.renewMarginSecs",
          "nat.externalIpOverride"
        ]) && (
          <SettingsControlSection title="NAT">
            <div class="settings-grid">
              {renderToggle("nat.enabled", "natEnabled", "NAT")}
              {renderToggle("nat.requireInitialMapping", "natRequireInitialMapping", "Require initial NAT mapping")}
              {renderField("nat.bindIp", "natBindIp", "NAT bind IP")}
              {renderField("nat.backendOrder", "natBackendOrder", "NAT backend order")}
              {renderField("nat.igdIp", "natIgdIp", "Pinned IGD IP")}
              {renderField("nat.minissdpdSocket", "natMinissdpdSocket", "miniSSDPd socket")}
              {renderField("nat.ssdpLocalPort", "natSsdpLocalPort", "SSDP local port")}
              {renderField("nat.discoveryTimeoutSecs", "natDiscoveryTimeoutSecs", "Discovery timeout seconds")}
              {renderField("nat.leaseDurationSecs", "natLeaseDurationSecs", "Lease duration seconds")}
              {renderField("nat.renewMarginSecs", "natRenewMarginSecs", "Renew margin seconds")}
              {renderField("nat.externalIpOverride", "natExternalIpOverride", "External IP override")}
            </div>
          </SettingsControlSection>
        )}
        {sectionVisible(["vpnGuard.enabled", "vpnGuard.mode", "vpnGuard.allowedPublicIpCidrs"]) && (
          <SettingsControlSection title="VPN Guard">
            <div class="settings-grid">
              {renderToggle("vpnGuard.enabled", "vpnGuardEnabled", "VPN Guard")}
              {renderField("vpnGuard.mode", "vpnGuardMode", "VPN Guard mode")}
              {renderField("vpnGuard.allowedPublicIpCidrs", "vpnGuardAllowedPublicIpCidrs", "Allowed public CIDRs")}
            </div>
          </SettingsControlSection>
        )}
        {sectionVisible(["ipFilter.enabled", "ipFilter.path", "ipFilter.level"]) && (
          <SettingsControlSection title="IP Filter">
            <div class="settings-grid">
              {renderToggle("ipFilter.enabled", "ipFilterEnabled", "IP filter")}
              {renderField("ipFilter.path", "ipFilterPath", "IP filter path")}
              {renderField("ipFilter.level", "ipFilterLevel", "IP filter level")}
            </div>
          </SettingsControlSection>
        )}
      </div>
      <SettingsSectionResources resources={props.surface?.sectionResources ?? []} openSection={props.openSection} />
    </section>
  );
}

function SettingsControlSection(props: { title: string; children: ComponentChildren }) {
  return (
    <div class="settings-control-section">
      <div class="subsection-title">
        <h3>{props.title}</h3>
      </div>
      {props.children}
    </div>
  );
}

function SettingsSectionResources(props: { resources: SettingsSectionResourceSpec[]; openSection: (name: string) => void }) {
  if (props.resources.length === 0) {
    return null;
  }
  return (
    <div class="settings-section-resources">
      <div class="subsection-title">
        <h3>Sections</h3>
      </div>
      <div class="settings-resource-list">
        {props.resources.map((resource) => (
          <div class="settings-resource-row" key={resource.name}>
            <div>
              <strong>{resource.uiSection}</strong>
              <span>{resource.description}</span>
              <code>{resource.route}</code>
            </div>
            <button class="btn" type="button" aria-label={`Open ${resource.uiSection}`} onClick={() => props.openSection(resource.name)}>
              <Link size={15} />
              Open
            </button>
          </div>
        ))}
      </div>
    </div>
  );
}

function Field(props: { label: string; value: string; surface?: SettingSurfaceSpec; error?: string; onInput: (value: string) => void }) {
  return (
    <label title={props.surface?.description}>
      <span class="setting-label">
        <span>{props.label}</span>
        <SettingBadges surface={props.surface} />
      </span>
      <input class="form-control" aria-invalid={props.error ? "true" : "false"} value={props.value} onInput={(event) => props.onInput(event.currentTarget.value)} />
      {props.error && <span class="field-error">{props.error}</span>}
    </label>
  );
}

function Toggle(props: { label: string; checked: boolean; surface?: SettingSurfaceSpec; onInput: (value: boolean) => void }) {
  return (
    <label class="check setting-check" title={props.surface?.description}>
      <input class="form-check-input" type="checkbox" checked={props.checked} onInput={(event) => props.onInput(event.currentTarget.checked)} />
      <span class="setting-label">
        <span>{props.label}</span>
        <SettingBadges surface={props.surface} />
      </span>
    </label>
  );
}

function SettingBadges(props: { surface?: SettingSurfaceSpec }) {
  if (!props.surface) {
    return null;
  }
  return (
    <span class="setting-badges">
      {props.surface.class === "advancedControl" && <span class="setting-badge">Advanced</span>}
      {props.surface.restartRequired && <span class="setting-badge">Restart</span>}
    </span>
  );
}

function validateSettingsForm(form: SettingsForm): Map<SettingsTextKey, string> {
  const errors = new Map<SettingsTextKey, string>();
  validateUnsigned(errors, form, "uploadLimitKiBps", "Upload limit KiB/s", { min: 1 });
  validateUnsigned(errors, form, "downloadLimitKiBps", "Download limit KiB/s", { min: 1 });
  validateUnsigned(errors, form, "maxConnections", "Max connections", { min: 1 });
  validateUnsigned(errors, form, "maxConnectionsPerFiveSeconds", "New connections / 5s", { min: 1 });
  validateUnsigned(errors, form, "maxSourcesPerFile", "Max sources / file", { min: 1 });
  validateUnsigned(errors, form, "uploadClientDataRate", "Upload client KiB/s", { min: 1 });
  validateUnsigned(errors, form, "maxUploadSlots", "Max upload slots", { min: 1, max: 64 });
  validateUnsigned(errors, form, "uploadSlotElasticPercent", "Upload elasticity %", { max: 100 });
  validateUnsigned(errors, form, "queueSize", "Queue size", { min: 2000, max: 10000 });
  validateUnsigned(errors, form, "hostnameLookupCacheTtlSecs", "DNS cache TTL seconds", { min: 1 });
  validateUnsigned(errors, form, "hostnameLookupMaxLookupsPerTick", "DNS lookups / tick", { min: 1 });
  validateUnsigned(errors, form, "hostnameLookupTickIntervalSecs", "DNS tick seconds", { min: 1 });
  validateUnsigned(errors, form, "ed2kListenPort", "eD2K listen port", { optional: true, min: 1, max: 65535 });
  validateUnsigned(errors, form, "ed2kConnectTimeoutSecs", "eD2K connect timeout seconds", { min: 1 });
  validateUnsigned(errors, form, "ed2kServerConnectTimeoutSecs", "Server connect timeout seconds", { min: 1 });
  validateUnsigned(errors, form, "ed2kCallbackTimeoutSecs", "Callback timeout seconds", { min: 1 });
  validateUnsigned(errors, form, "ed2kReconnectIntervalSecs", "Reconnect interval seconds", { min: 1 });
  validateUnsigned(errors, form, "ed2kKeepaliveSecs", "eD2K keepalive seconds", { min: 1 });
  validateUnsigned(errors, form, "ed2kDeadServerRetries", "Dead server retries", {});
  validateUnsigned(errors, form, "ed2kSessionRotationSecs", "Session rotation seconds", {});
  validateUnsigned(errors, form, "ed2kMaxConcurrentDownloads", "Concurrent downloads", { min: 1 });
  validateUnsigned(errors, form, "ed2kMaxNewConnectionsPerFiveSeconds", "eD2K new connections / 5s", { min: 1 });
  validateUnsigned(errors, form, "ed2kMaxHalfOpenConnections", "eD2K half-open connections", { min: 1 });
  validateUnsigned(errors, form, "ed2kMaxSourcesPerFile", "eD2K source cap", { min: 1 });
  validateUnsigned(errors, form, "ed2kMaxParallelDownloadPeers", "Parallel download peers", { min: 1 });
  validateUnsigned(errors, form, "ed2kDownloadLimitBytesPerSec", "Download limit B/s", {});
  validateUnsigned(errors, form, "ed2kKeywordServerAttemptBudget", "Keyword server attempts", { min: 1 });
  validateUnsigned(errors, form, "ed2kExactHashKeywordServerAttemptBudget", "Exact-hash server attempts", { min: 1 });
  validateUnsigned(errors, form, "ed2kSourceServerAttemptBudget", "Source server attempts", { min: 1 });
  validateUnsigned(errors, form, "ed2kUploadQueueActiveSlots", "Startup upload slots", { min: 1, max: 64 });
  validateUnsigned(errors, form, "ed2kUploadQueueElasticPercent", "Startup upload elasticity %", { max: 100 });
  validateUnsigned(errors, form, "ed2kUploadQueueUploadLimitBytesPerSec", "Upload limit B/s", {});
  validateUnsigned(errors, form, "ed2kUploadQueueElasticUnderfillBytesPerSec", "Elastic underfill B/s", {});
  validateUnsigned(errors, form, "ed2kUploadQueueElasticUnderfillSecs", "Elastic underfill seconds", { min: 1 });
  validateUnsigned(errors, form, "ed2kUploadQueueWaitingCapacity", "Waiting queue capacity", { min: 1 });
  validateUnsigned(errors, form, "ed2kUploadQueueWaitingTimeoutSecs", "Waiting timeout seconds", { min: 1 });
  validateUnsigned(errors, form, "ed2kUploadQueueGrantedTimeoutSecs", "Granted idle timeout seconds", { min: 1 });
  validateUnsigned(errors, form, "ed2kUploadQueueUploadTimeoutSecs", "Upload timeout seconds", { min: 1 });
  validateUnsigned(errors, form, "ed2kUploadQueueSessionTransferPercent", "Session transfer %", { min: 1, max: 100 });
  validateUnsigned(errors, form, "ed2kUploadQueueSessionTimeLimitSecs", "Session time limit seconds", { min: 1 });
  validateUnsigned(errors, form, "kadListenPort", "Kad listen port", { optional: true, min: 1, max: 65535 });
  validateUnsigned(errors, form, "kadBootstrapMinRoutingContacts", "Bootstrap contact floor", { min: 1 });
  validateUnsigned(errors, form, "kadRepublishIntervalSecs", "Kad republish seconds", { min: 1 });
  validateUnsigned(errors, form, "kadPublishContactFanout", "Publish contact fanout", { min: 1 });
  validateUnsigned(errors, form, "kadUdpFirewallCheckIntervalSecs", "UDP firewall interval seconds", { min: 1 });
  validateUnsigned(errors, form, "kadTcpFirewallCheckIntervalSecs", "TCP firewall interval seconds", { min: 1 });
  validateUnsigned(errors, form, "natSsdpLocalPort", "SSDP local port", { optional: true, min: 1, max: 65535 });
  validateUnsigned(errors, form, "natDiscoveryTimeoutSecs", "Discovery timeout seconds", { min: 1 });
  validateUnsigned(errors, form, "natLeaseDurationSecs", "Lease duration seconds", { min: 1 });
  validateUnsigned(errors, form, "natRenewMarginSecs", "Renew margin seconds", { min: 1 });
  validateUnsigned(errors, form, "ipFilterLevel", "IP filter level", {});
  return errors;
}

function validateUnsigned(
  errors: Map<SettingsTextKey, string>,
  form: SettingsForm,
  key: SettingsTextKey,
  label: string,
  options: { optional?: boolean; min?: number; max?: number }
) {
  const value = form[key].trim();
  if (!value && options.optional) {
    return;
  }
  if (!/^\d+$/.test(value)) {
    errors.set(key, `${label} must be a whole number.`);
    return;
  }
  const parsed = Number(value);
  const min = options.min ?? 0;
  const max = options.max ?? Number.MAX_SAFE_INTEGER;
  if (parsed < min || parsed > max) {
    errors.set(key, `${label} must be between ${min} and ${max}.`);
  }
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
    hostnameLookupEnabled: boolField(recordField(settings.daemon, "hostnameLookup"), "enabled"),
    hostnameLookupDnsServers: arrayField(recordField(settings.daemon, "hostnameLookup"), "dnsServers").join(", "),
    hostnameLookupCacheTtlSecs: String(numberField(recordField(settings.daemon, "hostnameLookup"), "cacheTtlSecs") ?? ""),
    hostnameLookupMaxLookupsPerTick: String(numberField(recordField(settings.daemon, "hostnameLookup"), "maxLookupsPerTick") ?? ""),
    hostnameLookupTickIntervalSecs: String(numberField(recordField(settings.daemon, "hostnameLookup"), "tickIntervalSecs") ?? ""),
    ed2kListenPort: String(numberField(settings.ed2k, "listenPort") ?? ""),
    ed2kConnectTimeoutSecs: String(numberField(settings.ed2k, "connectTimeoutSecs") ?? ""),
    ed2kServerConnectTimeoutSecs: String(numberField(settings.ed2k, "serverConnectTimeoutSecs") ?? ""),
    ed2kCallbackTimeoutSecs: String(numberField(settings.ed2k, "callbackTimeoutSecs") ?? ""),
    ed2kReconnectIntervalSecs: String(numberField(settings.ed2k, "reconnectIntervalSecs") ?? ""),
    ed2kKeepaliveSecs: String(numberField(settings.ed2k, "keepaliveSecs") ?? ""),
    ed2kDeadServerRetries: String(numberField(settings.ed2k, "deadServerRetries") ?? ""),
    ed2kSessionRotationSecs: String(numberField(settings.ed2k, "sessionRotationSecs") ?? ""),
    ed2kMaxConcurrentDownloads: String(numberField(settings.ed2k, "maxConcurrentDownloads") ?? ""),
    ed2kMaxNewConnectionsPerFiveSeconds: String(numberField(settings.ed2k, "maxNewConnectionsPerFiveSeconds") ?? ""),
    ed2kMaxHalfOpenConnections: String(numberField(settings.ed2k, "maxHalfOpenConnections") ?? ""),
    ed2kMaxSourcesPerFile: String(numberField(settings.ed2k, "maxSourcesPerFile") ?? ""),
    ed2kMaxParallelDownloadPeers: String(numberField(settings.ed2k, "maxParallelDownloadPeers") ?? ""),
    ed2kDownloadLimitBytesPerSec: String(numberField(settings.ed2k, "downloadLimitBytesPerSec") ?? ""),
    ed2kKeywordServerAttemptBudget: String(numberField(settings.ed2k, "keywordServerAttemptBudget") ?? ""),
    ed2kExactHashKeywordServerAttemptBudget: String(numberField(settings.ed2k, "exactHashKeywordServerAttemptBudget") ?? ""),
    ed2kSourceServerAttemptBudget: String(numberField(settings.ed2k, "sourceServerAttemptBudget") ?? ""),
    ed2kUploadQueueActiveSlots: String(numberField(recordField(settings.ed2k, "uploadQueue"), "activeSlots") ?? ""),
    ed2kUploadQueueElasticPercent: String(numberField(recordField(settings.ed2k, "uploadQueue"), "elasticPercent") ?? ""),
    ed2kUploadQueueUploadLimitBytesPerSec: String(numberField(recordField(settings.ed2k, "uploadQueue"), "uploadLimitBytesPerSec") ?? ""),
    ed2kUploadQueueElasticUnderfillBytesPerSec: String(numberField(recordField(settings.ed2k, "uploadQueue"), "elasticUnderfillBytesPerSec") ?? ""),
    ed2kUploadQueueElasticUnderfillSecs: String(numberField(recordField(settings.ed2k, "uploadQueue"), "elasticUnderfillSecs") ?? ""),
    ed2kUploadQueueWaitingCapacity: String(numberField(recordField(settings.ed2k, "uploadQueue"), "waitingCapacity") ?? ""),
    ed2kUploadQueueWaitingTimeoutSecs: String(numberField(recordField(settings.ed2k, "uploadQueue"), "waitingTimeoutSecs") ?? ""),
    ed2kUploadQueueGrantedTimeoutSecs: String(numberField(recordField(settings.ed2k, "uploadQueue"), "grantedTimeoutSecs") ?? ""),
    ed2kUploadQueueUploadTimeoutSecs: String(numberField(recordField(settings.ed2k, "uploadQueue"), "uploadTimeoutSecs") ?? ""),
    ed2kUploadQueueSessionTransferPercent: String(numberField(recordField(settings.ed2k, "uploadQueue"), "sessionTransferPercent") ?? ""),
    ed2kUploadQueueSessionTimeLimitSecs: String(numberField(recordField(settings.ed2k, "uploadQueue"), "sessionTimeLimitSecs") ?? ""),
    kadListenPort: String(numberField(settings.kad, "listenPort") ?? ""),
    obfuscationEnabled: boolField(settings.ed2k, "obfuscationEnabled"),
    ed2kReconnectEnabled: boolField(settings.ed2k, "reconnectEnabled"),
    enableUdpReask: boolField(settings.ed2k, "enableUdpReask"),
    publishEmuleRustIdentity: boolField(settings.ed2k, "publishEmuleRustIdentity"),
    kadBootstrapMinRoutingContacts: String(numberField(settings.kad, "bootstrapMinRoutingContacts") ?? ""),
    kadLocalStoreEnabled: boolField(settings.kad, "localStoreEnabled"),
    kadPublishSharedFilesEnabled: boolField(settings.kad, "publishSharedFilesEnabled"),
    kadRepublishIntervalSecs: String(numberField(settings.kad, "republishIntervalSecs") ?? ""),
    kadPublishContactFanout: String(numberField(settings.kad, "publishContactFanout") ?? ""),
    udpFirewallCheckEnabled: boolField(settings.kad, "udpFirewallCheckEnabled"),
    kadUdpFirewallCheckIntervalSecs: String(numberField(settings.kad, "udpFirewallCheckIntervalSecs") ?? ""),
    tcpFirewallCheckEnabled: boolField(settings.kad, "tcpFirewallCheckEnabled"),
    kadTcpFirewallCheckIntervalSecs: String(numberField(settings.kad, "tcpFirewallCheckIntervalSecs") ?? ""),
    buddyEnabled: boolField(settings.kad, "buddyEnabled"),
    routingMaintenanceEnabled: boolField(settings.kad, "routingMaintenanceEnabled"),
    natEnabled: boolField(settings.nat, "enabled"),
    natRequireInitialMapping: boolField(settings.nat, "requireInitialMapping"),
    natBindIp: stringField(settings.nat, "bindIp"),
    natBackendOrder: Array.isArray(settings.nat?.backendOrder) ? settings.nat.backendOrder.join(", ") : "",
    natIgdIp: stringField(settings.nat, "igdIp"),
    natMinissdpdSocket: stringField(settings.nat, "minissdpdSocket"),
    natSsdpLocalPort: String(numberField(settings.nat, "ssdpLocalPort") ?? ""),
    natDiscoveryTimeoutSecs: String(numberField(settings.nat, "discoveryTimeoutSecs") ?? ""),
    natLeaseDurationSecs: String(numberField(settings.nat, "leaseDurationSecs") ?? ""),
    natRenewMarginSecs: String(numberField(settings.nat, "renewMarginSecs") ?? ""),
    natExternalIpOverride: stringField(settings.nat, "externalIpOverride"),
    vpnGuardEnabled: boolField(settings.vpnGuard, "enabled"),
    vpnGuardMode: stringField(settings.vpnGuard, "mode"),
    vpnGuardAllowedPublicIpCidrs: stringField(settings.vpnGuard, "allowedPublicIpCidrs"),
    ipFilterEnabled: boolField(settings.ipFilter, "enabled"),
    ipFilterPath: stringField(settings.ipFilter, "path"),
    ipFilterLevel: String(numberField(settings.ipFilter, "level") ?? "")
  };
}

function recordField(object: Record<string, unknown> | undefined, key: string): Record<string, unknown> {
  const value = object?.[key];
  return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {};
}

function arrayField(object: Record<string, unknown> | undefined, key: string): string[] {
  const value = object?.[key];
  return Array.isArray(value) ? value.map((item) => String(item)) : [];
}

function optionalPort(value: string): number | null {
  const trimmed = value.trim();
  return trimmed ? Number(trimmed) : null;
}

function categoryPriorityValue(value: string): string | number {
  const trimmed = value.trim();
  return /^\d+$/.test(trimmed) ? Number(trimmed) : trimmed;
}

export function DiagnosticsView(props: { app: unknown; capabilities: unknown; runtimeDiagnostics: unknown; client: RestClient; run: RunFunction }) {
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
      <section class="panel card">
        <div class="section-title">
          <h2>Diagnostics</h2>
        </div>
        <div class="row-actions">
          <label class="check">
            <input class="form-check-input" type="checkbox" checked={fullMemory} onInput={(event) => setFullMemory(event.currentTarget.checked)} />
            Full memory dump
          </label>
          <button class="btn" type="button" onClick={() => void props.run(captureDump, "Diagnostic dump captured")}>
            <FileText size={15} />
            Capture dump
          </button>
        </div>
        {dumpPath && <p class="hint">Dump path: {dumpPath}</p>}
        <div class="form-row danger-row">
          <input class="form-control" value={crashConfirm} placeholder="Type CRASH" onInput={(event) => setCrashConfirm(event.currentTarget.value)} />
          <button class="btn"
            type="button"
            disabled={crashConfirm !== "CRASH"}
            onClick={() => void props.run(() => props.client.post("diagnostics/crash-tests", { confirmCrash: true }), "Crash test triggered")}
          >
            <Ban size={15} />
            Crash test
          </button>
          <input class="form-control" value={shutdownConfirm} placeholder="Type SHUTDOWN" onInput={(event) => setShutdownConfirm(event.currentTarget.value)} />
          <button class="btn"
            type="button"
            disabled={shutdownConfirm !== "SHUTDOWN"}
            onClick={() => void props.run(() => props.client.post("app/shutdown", { confirmShutdown: true }), "Shutdown requested")}
          >
            <Plug size={15} />
            Shutdown
          </button>
        </div>
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
