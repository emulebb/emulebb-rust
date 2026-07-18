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
  KadStatus,
  LogRecord,
  Page,
  RestClient,
  SearchItem,
  SharedDirectories,
  SharedFile,
  Snapshot,
  Upload
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
  UploadsView
} from "./views";
import "@tabler/core/dist/css/tabler.min.css";
import "./styles.css";

const API_KEY_STORAGE = "emulebb.webui.apiKey";
const SNAPSHOT_LIMIT = 500;
const LOG_LIMIT = 300;

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

export function App() {
  const [apiKey, setApiKey] = useState(() => localStorage.getItem(API_KEY_STORAGE) ?? "");
  const [apiKeyInput, setApiKeyInput] = useState(apiKey);
  const [tab, setTab] = useState<Tab>("overview");
  const [snapshot, setSnapshot] = useState<Snapshot | null>(null);
  const [appInfo, setAppInfo] = useState<AppInfo | null>(null);
  const [capabilities, setCapabilities] = useState<unknown>(null);
  const [settings, setSettings] = useState<AppSettings | null>(null);
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
        nextCapabilities
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
        client.get<unknown>("capabilities")
      ]);
      setSnapshot(nextSnapshot);
      setAppInfo(nextAppInfo);
      setCapabilities(nextCapabilities);
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
            {tab === "settings" && <SettingsView settings={settings} client={client} run={run} />}
            {tab === "diagnostics" && <DiagnosticsView app={appInfo} capabilities={capabilities} client={client} run={run} />}
            {tab === "logs" && <LogsView logs={logs} client={client} run={run} />}
          </div>
        </div>
      </div>
    </div>
  );
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
