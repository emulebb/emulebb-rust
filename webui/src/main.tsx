import { render } from "preact";
import { useCallback, useEffect, useMemo, useState } from "preact/hooks";
import {
  Activity,
  Ban,
  Download,
  FileText,
  FolderPlus,
  FolderTree,
  KeyRound,
  Lock,
  Pause,
  Play,
  Plug,
  RefreshCw,
  Search,
  Server,
  Shield,
  Trash2,
  Unlock
} from "lucide-preact";
import {
  KadStatus,
  LogRecord,
  RestClient,
  SearchItem,
  SearchResult,
  ServerItem,
  SharedDirectories,
  Snapshot,
  Transfer
} from "./api";
import "./styles.css";

const API_KEY_STORAGE = "emulebb.webui.apiKey";
const SNAPSHOT_LIMIT = 250;
const LOG_LIMIT = 200;

type Tab = "overview" | "transfers" | "search" | "sharing" | "servers" | "kad" | "logs";

const client = new RestClient();

function App() {
  const [apiKey, setApiKey] = useState(() => localStorage.getItem(API_KEY_STORAGE) ?? "");
  const [apiKeyInput, setApiKeyInput] = useState(apiKey);
  const [tab, setTab] = useState<Tab>("overview");
  const [snapshot, setSnapshot] = useState<Snapshot | null>(null);
  const [sharedDirectories, setSharedDirectories] = useState<SharedDirectories | null>(null);
  const [logs, setLogs] = useState<LogRecord[]>([]);
  const [latestSearch, setLatestSearch] = useState<SearchItem | null>(null);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const [refreshing, setRefreshing] = useState(false);

  useEffect(() => {
    client.setApiKey(apiKey);
  }, [apiKey]);

  const refresh = useCallback(async () => {
    setRefreshing(true);
    setError("");
    try {
      const [nextSnapshot, nextLogs, nextSharedDirectories] = await Promise.all([
        client.get<Snapshot>(`snapshot?limit=${SNAPSHOT_LIMIT}`),
        client.get<{ items?: LogRecord[] } | LogRecord[]>(`logs?limit=${LOG_LIMIT}`),
        client.get<SharedDirectories>("shared-directories")
      ]);
      setSnapshot(nextSnapshot);
      setLogs(Array.isArray(nextLogs) ? nextLogs : nextLogs.items ?? []);
      setSharedDirectories(nextSharedDirectories);
      const searches = nextSnapshot.searches ?? [];
      const recent = searches[0];
      if (recent?.id !== undefined) {
        try {
          const search = await client.get<SearchItem>(
            `searches/${recent.id}?limit=250&includeEvidence=false&exactTotal=true`
          );
          setLatestSearch(search);
        } catch {
          setLatestSearch(recent);
        }
      } else {
        setLatestSearch(null);
      }
    } catch (caught) {
      setError(errorMessage(caught));
    } finally {
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    void refresh();
    const timer = window.setInterval(() => void refresh(), 3000);
    return () => window.clearInterval(timer);
  }, [refresh]);

  const saveApiKey = () => {
    const next = apiKeyInput.trim();
    localStorage.setItem(API_KEY_STORAGE, next);
    setApiKey(next);
    setMessage(next ? "API key saved" : "API key cleared");
  };

  const clearApiKey = () => {
    localStorage.removeItem(API_KEY_STORAGE);
    setApiKey("");
    setApiKeyInput("");
    setMessage("API key cleared");
  };

  const run = async (operation: () => Promise<unknown>, success: string) => {
    setError("");
    setMessage("");
    try {
      await operation();
      setMessage(success);
      await refresh();
    } catch (caught) {
      setError(errorMessage(caught));
    }
  };

  const stats = snapshot?.stats ?? snapshot?.status?.stats ?? {};
  const transfers = snapshot?.transfers ?? [];
  const servers = snapshot?.servers ?? [];
  const searches = snapshot?.searches ?? [];
  const kad = snapshot?.kad ?? {};

  return (
    <main class="shell">
      <header class="topbar">
        <div>
          <h1>eMuleBB WebUI</h1>
          <p>{snapshot?.app?.version ?? snapshot?.app?.apiVersion ?? "REST dashboard"}</p>
        </div>
        <div class="top-actions">
          <label class="api-key">
            <KeyRound size={16} />
            <input
              type="password"
              value={apiKeyInput}
              placeholder="X-API-Key"
              onInput={(event) => setApiKeyInput(event.currentTarget.value)}
            />
          </label>
          <button type="button" onClick={saveApiKey}>
            {apiKey ? <Unlock size={16} /> : <Lock size={16} />}
            Save
          </button>
          <button type="button" class="icon-button" title="Clear API key" onClick={clearApiKey}>
            <Trash2 size={16} />
          </button>
          <button type="button" class="icon-button" title="Refresh" onClick={() => void refresh()}>
            <RefreshCw size={16} class={refreshing ? "spin" : ""} />
          </button>
        </div>
      </header>

      <nav class="tabs" aria-label="Primary views">
        <TabButton tab="overview" active={tab} setTab={setTab} icon={<Activity size={16} />} label="Overview" />
        <TabButton tab="transfers" active={tab} setTab={setTab} icon={<Download size={16} />} label="Transfers" />
        <TabButton tab="search" active={tab} setTab={setTab} icon={<Search size={16} />} label="Search" />
        <TabButton tab="sharing" active={tab} setTab={setTab} icon={<FolderTree size={16} />} label="Sharing" />
        <TabButton tab="servers" active={tab} setTab={setTab} icon={<Server size={16} />} label="Servers" />
        <TabButton tab="kad" active={tab} setTab={setTab} icon={<Shield size={16} />} label="Kad" />
        <TabButton tab="logs" active={tab} setTab={setTab} icon={<FileText size={16} />} label="Logs" />
      </nav>

      {message && <div class="notice">{message}</div>}
      {error && <div class="notice error">{error}</div>}

      {tab === "overview" && (
        <Overview snapshot={snapshot} stats={stats} transfers={transfers} servers={servers} kad={kad} />
      )}
      {tab === "transfers" && <TransfersView transfers={transfers} run={run} />}
      {tab === "search" && (
        <SearchView
          searches={searches}
          latestSearch={latestSearch}
          run={run}
          refresh={refresh}
          setLatestSearch={setLatestSearch}
        />
      )}
      {tab === "sharing" && <SharingView directories={sharedDirectories} run={run} />}
      {tab === "servers" && <ServersView servers={servers} run={run} />}
      {tab === "kad" && <KadView kad={kad} run={run} />}
      {tab === "logs" && <LogsView logs={logs} run={run} />}
    </main>
  );
}

function SharingView(props: {
  directories: SharedDirectories | null;
  run: (operation: () => Promise<unknown>, success: string) => Promise<void>;
}) {
  const [path, setPath] = useState("");
  const roots = props.directories?.roots ?? [];
  const items = props.directories?.items ?? [];
  const reload = props.directories?.reload ?? {};

  const replaceRoots = (paths: string[]) =>
    client.patch("shared-directories", {
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

      <section class="panel wide sharing-panel">
        <div class="section-title">
          <h2>Shared Folders</h2>
          <button
            type="button"
            onClick={() => props.run(() => client.post("shared-directories/operations/reload"), "Reload queued")}
          >
            <RefreshCw size={15} />
            Reload
          </button>
        </div>
        <form class="form-row" onSubmit={(event) => {
          event.preventDefault();
          void props.run(addRoot, "Folder added");
        }}>
          <input
            value={path}
            placeholder="Folder path"
            onInput={(event) => setPath(event.currentTarget.value)}
          />
          <button type="submit">
            <FolderPlus size={16} />
            Add
          </button>
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
                  <td>
                    <StatusPill value={root.accessible === false || root.shareable === false ? "unavailable" : "monitored"} />
                  </td>
                  <td>
                    <Action
                      title="Remove"
                      icon={<Trash2 size={15} />}
                      onClick={() => {
                        if (window.confirm("Remove this shared folder tree?")) {
                          void props.run(() => removeRoot(root.path), "Folder removed");
                        }
                      }}
                    />
                  </td>
                </tr>
              ))}
              {roots.length === 0 && (
                <tr>
                  <td colSpan={4} class="empty-cell">No shared folders.</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </section>

      <section class="panel wide">
        <h2>Reload Status</h2>
        <div class="kv">
          <span>Running</span>
          <strong>{reload.running ? "yes" : "no"}</strong>
          <span>Pending</span>
          <strong>{reload.pending ? "yes" : "no"}</strong>
          <span>Scanned</span>
          <strong>{reload.scannedCount ?? 0}</strong>
          <span>Queued</span>
          <strong>{reload.plannedHashCount ?? 0}</strong>
          <span>Reused</span>
          <strong>{reload.reusedCount ?? 0}</strong>
          <span>Pruned</span>
          <strong>{reload.prunedCount ?? 0}</strong>
        </div>
      </section>
    </section>
  );
}

function TabButton(props: {
  tab: Tab;
  active: Tab;
  setTab: (tab: Tab) => void;
  icon: preact.ComponentChildren;
  label: string;
}) {
  return (
    <button
      type="button"
      class={props.active === props.tab ? "tab active" : "tab"}
      onClick={() => props.setTab(props.tab)}
    >
      {props.icon}
      {props.label}
    </button>
  );
}

function Overview(props: {
  snapshot: Snapshot | null;
  stats: Record<string, unknown>;
  transfers: Transfer[];
  servers: ServerItem[];
  kad: KadStatus;
}) {
  const activeTransfers = props.transfers.filter((item) => item.state !== "completed").length;
  const connectedServers = props.servers.filter((item) => item.connected).length;
  return (
    <section class="view-grid">
      <Metric label="Download" value={formatRate(numberField(props.stats, "downloadRateBytesPerSec"))} />
      <Metric label="Upload" value={formatRate(numberField(props.stats, "uploadRateBytesPerSec"))} />
      <Metric label="Transfers" value={`${activeTransfers}/${props.transfers.length}`} />
      <Metric label="Servers" value={`${connectedServers}/${props.servers.length}`} />
      <Metric label="Shared" value={String(numberField(props.stats, "sharedFiles") ?? props.snapshot?.sharedFiles?.length ?? 0)} />
      <Metric label="Kad" value={props.kad.connected ? "Connected" : "Idle"} />

      <section class="panel wide">
        <h2>Network</h2>
        <div class="kv">
          <span>Lifecycle</span>
          <strong>{String(props.snapshot?.status?.lifecycle ?? "unknown")}</strong>
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

function Metric(props: { label: string; value: string }) {
  return (
    <section class="metric">
      <span>{props.label}</span>
      <strong>{props.value}</strong>
    </section>
  );
}

function TransfersView(props: {
  transfers: Transfer[];
  run: (operation: () => Promise<unknown>, success: string) => Promise<void>;
}) {
  return (
    <section class="panel">
      <div class="section-title">
        <h2>Transfers</h2>
        <span>{props.transfers.length} total</span>
      </div>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>State</th>
              <th>Progress</th>
              <th>Down</th>
              <th>Up</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {props.transfers.map((transfer) => (
              <tr key={transfer.hash}>
                <td>{transfer.name ?? transfer.hash}</td>
                <td><StatusPill value={transfer.state ?? "unknown"} /></td>
                <td>{formatProgress(transfer)}</td>
                <td>{formatRate(transfer.downloadRateBytesPerSec)}</td>
                <td>{formatRate(transfer.uploadRateBytesPerSec)}</td>
                <td>
                  <div class="row-actions">
                    <Action title="Pause" icon={<Pause size={15} />} onClick={() => props.run(() => client.post(`transfers/${transfer.hash}/operations/pause`), "Transfer paused")} />
                    <Action title="Resume" icon={<Play size={15} />} onClick={() => props.run(() => client.post(`transfers/${transfer.hash}/operations/resume`), "Transfer resumed")} />
                    <Action title="Stop" icon={<Ban size={15} />} onClick={() => props.run(() => client.post(`transfers/${transfer.hash}/operations/stop`), "Transfer stopped")} />
                    <Action title="Recheck" icon={<RefreshCw size={15} />} onClick={() => props.run(() => client.post(`transfers/${transfer.hash}/operations/recheck`), "Recheck queued")} />
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

function SearchView(props: {
  searches: SearchItem[];
  latestSearch: SearchItem | null;
  run: (operation: () => Promise<unknown>, success: string) => Promise<void>;
  refresh: () => Promise<void>;
  setLatestSearch: (search: SearchItem | null) => void;
}) {
  const [query, setQuery] = useState("");
  const [method, setMethod] = useState("automatic");
  const [fileType, setFileType] = useState("any");
  const results = props.latestSearch?.results ?? [];

    const startSearch = async () => {
    const next = await client.post<SearchItem>("searches", { query, method, type: fileType });
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
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Size</th>
              <th>Sources</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            {results.map((result) => (
              <tr key={result.hash}>
                <td>{result.name ?? result.hash}</td>
                <td>{formatBytes(result.sizeBytes)}</td>
                <td>{result.sources ?? result.availability ?? 0}</td>
                <td>
                  <button
                    type="button"
                    onClick={() => props.run(
                      () => client.post(`searches/${props.latestSearch?.id}/results/${result.hash}/operations/download`, { paused: false }),
                      "Download queued"
                    )}
                  >
                    <Download size={15} />
                    Download
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

function ServersView(props: {
  servers: ServerItem[];
  run: (operation: () => Promise<unknown>, success: string) => Promise<void>;
}) {
  const [address, setAddress] = useState("");
  const [port, setPort] = useState("4661");
  const [name, setName] = useState("");
  const [importUrl, setImportUrl] = useState("");

  const createServer = () => client.post("servers", {
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
          <button type="button" onClick={() => props.run(() => client.post("servers/operations/connect"), "Server connect started")}><Plug size={15} />Connect</button>
          <button type="button" onClick={() => props.run(() => client.post("servers/operations/disconnect"), "Servers disconnected")}><Ban size={15} />Disconnect</button>
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
        void props.run(() => client.post("servers/operations/import-met-url", { url: importUrl }), "Server list import started");
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
              <th>Users</th>
              <th>Files</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {props.servers.map((server) => {
              const endpoint = server.endpoint ?? server.id ?? `${server.address}:${server.port}`;
              return (
                <tr key={endpoint}>
                  <td>{endpoint}</td>
                  <td>{server.name ?? ""}</td>
                  <td><StatusPill value={server.connected ? "connected" : server.connecting ? "connecting" : "idle"} /></td>
                  <td>{server.users ?? 0}</td>
                  <td>{server.files ?? 0}</td>
                  <td>
                    <div class="row-actions">
                      <Action title="Connect" icon={<Plug size={15} />} onClick={() => props.run(() => client.post(`servers/${endpoint}/operations/connect`), "Server connect started")} />
                      <Action title="Delete" icon={<Trash2 size={15} />} onClick={() => props.run(() => client.delete(`servers/${endpoint}`), "Server deleted")} />
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </section>
  );
}

function KadView(props: {
  kad: KadStatus;
  run: (operation: () => Promise<unknown>, success: string) => Promise<void>;
}) {
  const [bootstrap, setBootstrap] = useState("");
  return (
    <section class="panel">
      <div class="section-title">
        <h2>Kad</h2>
        <div class="row-actions">
          <button type="button" onClick={() => props.run(() => client.post("kad/operations/start"), "Kad started")}><Play size={15} />Start</button>
          <button type="button" onClick={() => props.run(() => client.post("kad/operations/stop"), "Kad stopped")}><Pause size={15} />Stop</button>
          <button type="button" onClick={() => props.run(() => client.post("kad/operations/recheck-firewall"), "Kad firewall recheck started")}><Shield size={15} />Recheck</button>
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
        void props.run(() => client.post("kad/operations/import-nodes-url", { url: bootstrap }), "Kad nodes import started");
      }}>
        <input value={bootstrap} placeholder="nodes.dat URL" onInput={(event) => setBootstrap(event.currentTarget.value)} />
        <button type="submit"><Download size={16} />Import</button>
      </form>
    </section>
  );
}

function LogsView(props: {
  logs: LogRecord[];
  run: (operation: () => Promise<unknown>, success: string) => Promise<void>;
}) {
  return (
    <section class="panel">
      <div class="section-title">
        <h2>Logs</h2>
        <button type="button" onClick={() => props.run(() => client.post("logs/operations/clear", { confirmClearLogs: true }), "Logs cleared")}>
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

function StatusPill(props: { value: string }) {
  const className = useMemo(() => {
    const value = props.value.toLowerCase();
    if (value.includes("connected") || value.includes("downloading")) {
      return "pill good";
    }
    if (value.includes("error") || value.includes("firewall")) {
      return "pill bad";
    }
    if (value.includes("paused") || value.includes("idle")) {
      return "pill idle";
    }
    return "pill";
  }, [props.value]);
  return <span class={className}>{props.value}</span>;
}

function Action(props: { title: string; icon: preact.ComponentChildren; onClick: () => void }) {
  return (
    <button type="button" class="icon-button" title={props.title} onClick={props.onClick}>
      {props.icon}
    </button>
  );
}

function formatProgress(transfer: Transfer): string {
  const size = transfer.sizeBytes ?? 0;
  if (!size) {
    return "0%";
  }
  const completed = transfer.completedBytes ?? 0;
  return `${Math.min(100, Math.round((completed / size) * 100))}%`;
}

function formatRate(value?: number): string {
  return `${formatBytes(value)}/s`;
}

function formatBytes(value?: number): string {
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

function firewallLabel(value: boolean | null | undefined): string {
  if (value === true) {
    return "firewalled";
  }
  if (value === false) {
    return "open";
  }
  return "unknown";
}

function numberField(object: Record<string, unknown>, key: string): number | undefined {
  const value = object[key];
  return typeof value === "number" ? value : undefined;
}

function errorMessage(caught: unknown): string {
  return caught instanceof Error ? caught.message : String(caught);
}

render(<App />, document.getElementById("app")!);
