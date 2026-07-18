import type { ComponentChildren } from "preact";
import { useCallback, useEffect, useState } from "preact/hooks";
import {
  Activity,
  FolderTree,
  Gauge,
  KeyRound,
  ListChecks,
  Lock,
  Network,
  RefreshCw,
  Search,
  Server,
  Settings,
  Share2,
  Shield,
  Trash2,
  Unlock,
  UploadCloud,
  Users,
  FileText,
  Download
} from "lucide-preact";
import {
  AppInfo,
  AppSettings,
  Category,
  Friend,
  IpFilterStatus,
  KadStatus,
  LogRecord,
  NatStatus,
  NetworkStatus,
  Page,
  RestClient,
  RuntimeDiagnostics,
  SearchItem,
  SharedDirectories,
  SharedFile,
  SettingsSurface,
  Snapshot,
  TransferEvent,
  TransferEventRuntimeDiagnostics,
  Upload,
  VpnGuardStatus
} from "./api";
import { errorMessage } from "./format";
import {
  CategoriesView,
  DiagnosticsView,
  FriendsView,
  KadView,
  LogsView,
  NetworkHealthView,
  Overview,
  SearchView,
  ServersView,
  SettingsView,
  SharedFilesView,
  SharingView,
  TransfersView,
  UploadsView,
  type EventStreamStatus
} from "./views";
import "@tabler/core/dist/css/tabler.min.css";
import "./styles.css";

const API_KEY_STORAGE = "emulebb.webui.apiKey";
const SNAPSHOT_LIMIT = 500;
const LOG_LIMIT = 300;
const REFRESH_INTERVAL_MS = 3000;
const EVENT_STREAM_RETRY_MS = 3000;

type Tab =
  | "overview"
  | "transfers"
  | "search"
  | "sharing"
  | "shared-files"
  | "uploads"
  | "network"
  | "servers"
  | "kad"
  | "categories"
  | "friends"
  | "settings"
  | "diagnostics"
  | "logs";

const client = new RestClient();

const settingsSectionTabs: Record<string, Tab> = {
  sharedDirectories: "sharing",
  categories: "categories",
  servers: "servers",
  kad: "kad",
  diagnostics: "diagnostics",
  logs: "logs",
  network: "network",
  nat: "settings",
  ipFilter: "settings",
  vpnGuard: "settings"
};

const pollingEventStreamStatus: EventStreamStatus = {
  mode: "polling",
  enabled: false,
  connected: false,
  reconnectAttempts: 0,
  pollIntervalMs: REFRESH_INTERVAL_MS,
  retryIntervalMs: EVENT_STREAM_RETRY_MS
};

export function App() {
  const [apiKey, setApiKey] = useState(() => localStorage.getItem(API_KEY_STORAGE) ?? "");
  const [apiKeyInput, setApiKeyInput] = useState(apiKey);
  const [tab, setTab] = useState<Tab>("overview");
  const [snapshot, setSnapshot] = useState<Snapshot | null>(null);
  const [appInfo, setAppInfo] = useState<AppInfo | null>(null);
  const [capabilities, setCapabilities] = useState<unknown>(null);
  const [runtimeDiagnostics, setRuntimeDiagnostics] = useState<RuntimeDiagnostics | null>(null);
  const [networkStatus, setNetworkStatus] = useState<NetworkStatus | null>(null);
  const [natStatus, setNatStatus] = useState<NatStatus | null>(null);
  const [ipFilterStatus, setIpFilterStatus] = useState<IpFilterStatus | null>(null);
  const [vpnGuardStatus, setVpnGuardStatus] = useState<VpnGuardStatus | null>(null);
  const [settings, setSettings] = useState<AppSettings | null>(null);
  const [settingsSurface, setSettingsSurface] = useState<SettingsSurface | null>(null);
  const [settingsSectionTarget, setSettingsSectionTarget] = useState<string | null>(null);
  const [categories, setCategories] = useState<Category[]>([]);
  const [friends, setFriends] = useState<Friend[]>([]);
  const [sharedDirectories, setSharedDirectories] = useState<SharedDirectories | null>(null);
  const [sharedFiles, setSharedFiles] = useState<SharedFile[]>([]);
  const [uploads, setUploads] = useState<Upload[]>([]);
  const [uploadQueue, setUploadQueue] = useState<Upload[]>([]);
  const [logs, setLogs] = useState<LogRecord[]>([]);
  const [latestSearch, setLatestSearch] = useState<SearchItem | null>(null);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const [refreshing, setRefreshing] = useState(false);
  const [eventStreamStatus, setEventStreamStatus] = useState<EventStreamStatus>(pollingEventStreamStatus);

  useEffect(() => {
    client.setApiKey(apiKey);
  }, [apiKey]);

  const refresh = useCallback(async () => {
    setRefreshing(true);
    setError("");
    try {
      const [
        nextSnapshot,
        nextLogs,
        nextSharedDirectories,
        nextSharedFiles,
        nextCategories,
        nextFriends,
        nextSettings,
        nextUploads,
        nextUploadQueue,
        nextAppInfo,
        nextCapabilities,
        nextRuntimeDiagnostics,
        nextTransferEventDiagnostics,
        nextNetworkStatus,
        nextNatStatus,
        nextIpFilterStatus,
        nextVpnGuardStatus,
        nextSettingsSurface
      ] = await Promise.all([
        client.get<Snapshot>(`snapshot?limit=${SNAPSHOT_LIMIT}`),
        client.get<Page<LogRecord> | LogRecord[]>(`logs?limit=${LOG_LIMIT}`),
        client.get<SharedDirectories>("shared-directories"),
        client.get<Page<SharedFile>>(`shared-files?limit=${SNAPSHOT_LIMIT}`),
        client.get<Page<Category>>("categories"),
        client.get<Page<Friend>>("friends"),
        client.get<AppSettings>("app/settings"),
        client.get<Page<Upload>>("uploads"),
        client.get<Page<Upload>>(`upload-queue?limit=${SNAPSHOT_LIMIT}&includeScoreBreakdown=true`),
        client.get<AppInfo>("app"),
        client.get<unknown>("capabilities"),
        client.get<RuntimeDiagnostics>("diagnostics"),
        client.get<TransferEventRuntimeDiagnostics>("events/status"),
        client.get<NetworkStatus>("network"),
        client.get<NatStatus>("nat"),
        client.get<IpFilterStatus>("ip-filter"),
        client.get<VpnGuardStatus>("vpn-guard"),
        client.get<SettingsSurface>("app/settings/surface")
      ]);
      setSnapshot(nextSnapshot);
      setAppInfo(nextAppInfo);
      setCapabilities(nextCapabilities);
      setRuntimeDiagnostics({
        ...nextRuntimeDiagnostics,
        transferEvents: nextTransferEventDiagnostics
      });
      setNetworkStatus(nextNetworkStatus);
      setNatStatus(nextNatStatus);
      setIpFilterStatus(nextIpFilterStatus);
      setVpnGuardStatus(nextVpnGuardStatus);
      setSettingsSurface(nextSettingsSurface);
      setLogs(Array.isArray(nextLogs) ? nextLogs : nextLogs.items ?? []);
      setSharedDirectories(nextSharedDirectories);
      setSharedFiles(nextSharedFiles.items ?? nextSnapshot.sharedFiles ?? []);
      setCategories(nextCategories.items ?? []);
      setFriends(nextFriends.items ?? []);
      setSettings(nextSettings);
      setUploads(nextUploads.items ?? nextSnapshot.uploads ?? []);
      setUploadQueue(nextUploadQueue.items ?? nextSnapshot.uploadQueue ?? []);

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
    const timer = window.setInterval(() => void refresh(), REFRESH_INTERVAL_MS);
    return () => window.clearInterval(timer);
  }, [refresh]);

  const transferSseEnabled = supportsTransferSse(appInfo) || supportsTransferSse(capabilities);

  useEffect(() => {
    if (!transferSseEnabled) {
      setEventStreamStatus(pollingEventStreamStatus);
      return;
    }
    const controller = new AbortController();
    let closed = false;
    let lastEventId: string | undefined;
    let reconnectAttempts = 0;
    let refreshTimer: number | undefined;
    let refreshInFlight = false;
    let refreshPending = false;
    setEventStreamStatus({
      mode: "connecting",
      enabled: true,
      connected: false,
      reconnectAttempts: 0,
      pollIntervalMs: REFRESH_INTERVAL_MS,
      retryIntervalMs: EVENT_STREAM_RETRY_MS
    });

    const runScheduledRefresh = async () => {
      if (refreshInFlight) {
        refreshPending = true;
        return;
      }
      refreshInFlight = true;
      try {
        await refresh();
      } finally {
        refreshInFlight = false;
        if (refreshPending && !closed) {
          refreshPending = false;
          scheduleRefresh();
        }
      }
    };

    const scheduleRefresh = () => {
      if (refreshTimer !== undefined) {
        return;
      }
      refreshTimer = window.setTimeout(() => {
        refreshTimer = undefined;
        void runScheduledRefresh();
      }, 100);
    };

    const runStream = async () => {
      while (!closed) {
        try {
          setEventStreamStatus((status) => ({
            ...status,
            mode: status.lastEventAt ? "reconnecting" : "connecting",
            enabled: true,
            connected: false,
            reconnectAttempts,
            pollIntervalMs: REFRESH_INTERVAL_MS,
            retryIntervalMs: EVENT_STREAM_RETRY_MS
          }));
          await client.streamTransferEvents((event: TransferEvent) => {
            lastEventId = String(event.id);
            setEventStreamStatus({
              mode: "streaming",
              enabled: true,
              connected: true,
              lastEventId,
              lastEventType: event.type,
              lastEventAt: new Date().toISOString(),
              reconnectAttempts,
              pollIntervalMs: REFRESH_INTERVAL_MS,
              retryIntervalMs: EVENT_STREAM_RETRY_MS
            });
            scheduleRefresh();
          }, { signal: controller.signal, lastEventId });
          if (!closed && !controller.signal.aborted) {
            setEventStreamStatus((status) => ({
              ...status,
              mode: "reconnecting",
              enabled: true,
              connected: false,
              reconnectAttempts,
              pollIntervalMs: REFRESH_INTERVAL_MS,
              retryIntervalMs: EVENT_STREAM_RETRY_MS
            }));
          }
        } catch (streamError) {
          if (closed || controller.signal.aborted) {
            return;
          }
          reconnectAttempts += 1;
          setEventStreamStatus((status) => ({
            ...status,
            mode: "reconnecting",
            enabled: true,
            connected: false,
            reconnectAttempts,
            lastError: errorMessage(streamError),
            pollIntervalMs: REFRESH_INTERVAL_MS,
            retryIntervalMs: EVENT_STREAM_RETRY_MS
          }));
        }
        await delayWithAbort(EVENT_STREAM_RETRY_MS, controller.signal);
      }
    };

    void runStream();
    return () => {
      closed = true;
      controller.abort();
      if (refreshTimer !== undefined) {
        window.clearTimeout(refreshTimer);
      }
    };
  }, [apiKey, refresh, transferSseEnabled]);

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
  const kad: KadStatus = snapshot?.kad ?? {};

  return (
    <div class="page">
      <header class="navbar navbar-expand-md d-print-none">
        <div class="container-xl topbar">
          <div class="navbar-brand app-brand">
            <span class="brand-mark">eM</span>
            <div>
              <h1>eMuleBB WebUI</h1>
              <p>{appInfo?.version ?? appInfo?.apiVersion ?? snapshot?.app?.version ?? "REST dashboard"}</p>
            </div>
          </div>
          <div class="top-actions navbar-nav flex-row order-md-last">
            <label class="api-key input-icon">
              <span class="input-icon-addon"><KeyRound size={16} /></span>
              <input
                class="form-control"
                type="password"
                value={apiKeyInput}
                placeholder="X-API-Key"
                onInput={(event) => setApiKeyInput(event.currentTarget.value)}
              />
            </label>
            <button type="button" class="btn btn-primary" onClick={saveApiKey}>
              {apiKey ? <Unlock size={16} /> : <Lock size={16} />}
              Save
            </button>
            <button type="button" class="btn btn-icon btn-outline-secondary icon-button" title="Clear API key" onClick={clearApiKey}>
              <Trash2 size={16} />
            </button>
            <button type="button" class="btn btn-icon btn-outline-secondary icon-button" title="Refresh" onClick={() => void refresh()}>
              <RefreshCw size={16} class={refreshing ? "spin" : ""} />
            </button>
          </div>
        </div>
      </header>

      <div class="page-wrapper">
        <div class="page-header d-print-none">
          <div class="container-xl">
            <nav class="tabs nav nav-pills card p-2" aria-label="Primary views">
              <TabButton tab="overview" active={tab} setTab={setTab} icon={<Activity size={16} />} label="Overview" />
              <TabButton tab="transfers" active={tab} setTab={setTab} icon={<Download size={16} />} label="Transfers" />
              <TabButton tab="search" active={tab} setTab={setTab} icon={<Search size={16} />} label="Search" />
              <TabButton tab="sharing" active={tab} setTab={setTab} icon={<FolderTree size={16} />} label="Sharing" />
              <TabButton tab="shared-files" active={tab} setTab={setTab} icon={<Share2 size={16} />} label="Shared Files" />
              <TabButton tab="uploads" active={tab} setTab={setTab} icon={<UploadCloud size={16} />} label="Uploads" />
              <TabButton tab="network" active={tab} setTab={setTab} icon={<Network size={16} />} label="Network" />
              <TabButton tab="servers" active={tab} setTab={setTab} icon={<Server size={16} />} label="Servers" />
              <TabButton tab="kad" active={tab} setTab={setTab} icon={<Shield size={16} />} label="Kad" />
              <TabButton tab="categories" active={tab} setTab={setTab} icon={<ListChecks size={16} />} label="Categories" />
              <TabButton tab="friends" active={tab} setTab={setTab} icon={<Users size={16} />} label="Friends" />
              <TabButton tab="settings" active={tab} setTab={setTab} icon={<Settings size={16} />} label="Settings" />
              <TabButton tab="diagnostics" active={tab} setTab={setTab} icon={<Gauge size={16} />} label="Diagnostics" />
              <TabButton tab="logs" active={tab} setTab={setTab} icon={<FileText size={16} />} label="Logs" />
            </nav>
          </div>
        </div>

        <div class="page-body">
          <div class="container-xl shell">
            {message && <div class="notice alert alert-success">{message}</div>}
            {error && <div class="notice alert alert-danger">{error}</div>}

            {tab === "overview" && (
              <Overview
                snapshot={snapshot}
                stats={stats}
                transfers={transfers}
                servers={servers}
                uploads={uploads}
                uploadQueue={uploadQueue}
                sharedFiles={sharedFiles}
                sharedDirectories={sharedDirectories}
                kad={kad}
              />
            )}
            {tab === "transfers" && <TransfersView transfers={transfers} categories={categories} client={client} run={run} />}
            {tab === "search" && (
              <SearchView
                searches={searches}
                latestSearch={latestSearch}
                categories={categories}
                client={client}
                run={run}
                refresh={refresh}
                setLatestSearch={setLatestSearch}
              />
            )}
            {tab === "sharing" && <SharingView directories={sharedDirectories} client={client} run={run} />}
            {tab === "shared-files" && <SharedFilesView files={sharedFiles} client={client} run={run} />}
            {tab === "uploads" && <UploadsView uploads={uploads} uploadQueue={uploadQueue} client={client} run={run} />}
            {tab === "network" && (
              <NetworkHealthView
                servers={servers}
                transfers={transfers}
                uploads={uploads}
                uploadQueue={uploadQueue}
                kad={kad}
                settings={settings}
                client={client}
              />
            )}
            {tab === "servers" && <ServersView servers={servers} client={client} run={run} />}
            {tab === "kad" && <KadView kad={kad} client={client} run={run} />}
            {tab === "categories" && <CategoriesView categories={categories} client={client} run={run} />}
            {tab === "friends" && <FriendsView friends={friends} client={client} run={run} />}
            {tab === "settings" && (
              <SettingsView
                settings={settings}
                surface={settingsSurface}
                networkStatus={networkStatus}
                natStatus={natStatus}
                ipFilterStatus={ipFilterStatus}
                vpnGuardStatus={vpnGuardStatus}
                focusedSection={settingsSectionTarget}
                client={client}
                run={run}
                openSection={(name) => {
                  setSettingsSectionTarget(name);
                  setTab(settingsSectionTabs[name] ?? "settings");
                }}
              />
            )}
            {tab === "diagnostics" && <DiagnosticsView app={appInfo} capabilities={capabilities} runtimeDiagnostics={runtimeDiagnostics} eventStreamStatus={eventStreamStatus} client={client} run={run} />}
            {tab === "logs" && <LogsView logs={logs} client={client} run={run} />}
          </div>
        </div>
      </div>
    </div>
  );
}

function supportsTransferSse(value: unknown): boolean {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const capabilities = (value as Record<string, unknown>).capabilities;
  if (Array.isArray(capabilities)) {
    return capabilities.includes("transfers.sse");
  }
  if (typeof capabilities === "object" && capabilities !== null) {
    return (capabilities as Record<string, unknown>)["transfers.sse"] === true;
  }
  return false;
}

function delayWithAbort(ms: number, signal: AbortSignal): Promise<void> {
  if (signal.aborted) {
    return Promise.resolve();
  }
  return new Promise((resolve) => {
    const done = () => {
      window.clearTimeout(timer);
      signal.removeEventListener("abort", done);
      resolve();
    };
    const timer = window.setTimeout(done, ms);
    signal.addEventListener("abort", done, { once: true });
  });
}

function TabButton(props: {
  tab: Tab;
  active: Tab;
  setTab: (tab: Tab) => void;
  icon: ComponentChildren;
  label: string;
}) {
  return (
    <button
      type="button"
      class={props.active === props.tab ? "tab nav-link active" : "tab nav-link"}
      onClick={() => props.setTab(props.tab)}
    >
      {props.icon}
      {props.label}
    </button>
  );
}
