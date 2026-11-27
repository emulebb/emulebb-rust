import { LibraryView } from "./libraryFiles";
import type { ComponentChildren } from "preact";
import { AppIdentity } from "./AppIdentity";
import { useCallback, useEffect, useLayoutEffect, useRef, useState } from "preact/hooks";
import { type Appearance, type AppearancePreference } from "./appearance";
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
  Unlock,
  UploadCloud,
  Users,
  FileText,
  Download
} from "lucide-preact";
import {
  AppInfo,
  SettingsSnapshot,
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
  SearchResult,
  CursorPage,
  LibraryScan,
  SharedFileIgnores,
  SettingsSurface,
  Snapshot,
  DownloadSummary,
  DownloadEvent,
  DownloadEventRuntimeDiagnostics,
  Upload,
  VpnGuardStatus
} from "./api";
import { errorMessage, formatRate, numberField } from "./format";
import {
  type AppRoute,
  type Tab,
  pathForRoute,
  routeFromPathname
} from "./routes";
import {
  CategoriesView,
  DiagnosticsView,
  FriendsView,
  KadView,
  LogsView,
  NetworkHealthView,
  OperationCancelledError,
  Overview,
  SearchView,
  ServersView,
  SharingView,
  TransfersView,
  UploadsView,
  type EventStreamStatus
} from "./views";
import "@tabler/core/dist/css/tabler.min.css";
import "./styles.css";
import { SettingsView } from "./settings";
import { useRefreshRead } from "./useRefreshRead";

const API_KEY_STORAGE = "emulebb.webui.apiKey";
const SNAPSHOT_LIMIT = 500;
const LOG_LIMIT = 300;
const SEARCH_RESULT_PAGE_SIZE = 100;
const REFRESH_INTERVAL_MS = 10_000;
const EVENT_STREAM_RETRY_MS = 3000;

type AuthenticationState = "checking" | "authenticated" | "unauthenticated";

const client = new RestClient();

const settingsSectionTabs: Record<string, Tab> = {
  libraryRoots: "sharing",
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

function currentRoute(): AppRoute {
  const route = routeFromPathname(window.location.pathname);
  if (route) {
    const canonicalPath = pathForRoute(route);
    if (window.location.pathname !== canonicalPath) {
      window.history.replaceState(null, "", canonicalPath + window.location.search + window.location.hash);
    }
    return route;
  }
  const fallback: AppRoute = { tab: "overview" };
  window.history.replaceState(null, "", pathForRoute(fallback));
  return fallback;
}

export function App({ appearance }: { appearance: Appearance }) {
  const [appearancePreference, setAppearancePreference] = useState(appearance.getPreference);
  const [mobileMenuExpanded, setMobileMenuExpanded] = useState(false);
  const menuButton = useRef<HTMLButtonElement>(null);
  useEffect(() => appearance.subscribe(setAppearancePreference), [appearance]);
  useLayoutEffect(() => {
    if (!mobileMenuExpanded) return;
    const ownerDocument = menuButton.current?.ownerDocument;
    if (!ownerDocument) return;
    // WHY: Capture Escape immediately, including body focus and controls that consume bubbling key events.
    const close = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        setMobileMenuExpanded(false);
        menuButton.current?.focus();
      }
    };
    ownerDocument.addEventListener("keydown", close, true);
    return () => ownerDocument.removeEventListener("keydown", close, true);
  }, [mobileMenuExpanded]);
  useEffect(() => {
    const mobile = window.matchMedia("(max-width: 639px)");
    const reset = () => { if (!mobile.matches) setMobileMenuExpanded(false); };
    mobile.addEventListener("change", reset);
    return () => mobile.removeEventListener("change", reset);
  }, []);
  const [apiKey, setApiKey] = useState(readStoredApiKey);
  const [apiKeyInput, setApiKeyInput] = useState(apiKey);
  const [authState, setAuthState] = useState<AuthenticationState>("checking");
  const [authError, setAuthError] = useState("");
  const [authAttempt, setAuthAttempt] = useState(0);
  const [storageWarning, setStorageWarning] = useState("");
  const [route, setRoute] = useState<AppRoute>(currentRoute);
  const [snapshot, setSnapshot] = useState<Snapshot | null>(null);
  const [downloadPreview, setDownloadPreview] = useState<DownloadSummary[]>([]);
  const [appInfo, setAppInfo] = useState<AppInfo | null>(null);
  const [capabilities, setCapabilities] = useState<unknown>(null);
  const [runtimeDiagnostics, setRuntimeDiagnostics] = useState<RuntimeDiagnostics | null>(null);
  const [networkStatus, setNetworkStatus] = useState<NetworkStatus | null>(null);
  const [natStatus, setNatStatus] = useState<NatStatus | null>(null);
  const [ipFilterStatus, setIpFilterStatus] = useState<IpFilterStatus | null>(null);
  const [vpnGuardStatus, setVpnGuardStatus] = useState<VpnGuardStatus | null>(null);
  const [settings, setSettings] = useState<SettingsSnapshot | null>(null);
  const [settingsSurface, setSettingsSurface] = useState<SettingsSurface | null>(null);
  const [settingsSectionTarget, setSettingsSectionTarget] = useState<string | null>(null);
  const [categories, setCategories] = useState<Category[]>([]);
  const [friends, setFriends] = useState<Friend[]>([]);
  const [libraryScan, setLibraryScan] = useState<LibraryScan | null>(null);
  const [sharedFileIgnores, setSharedFileIgnores] = useState<SharedFileIgnores | null>(null);
  const [uploads, setUploads] = useState<Upload[]>([]);
  const [uploadQueue, setUploadQueue] = useState<Upload[]>([]);
  const [logs, setLogs] = useState<LogRecord[]>([]);
  const [searches, setSearches] = useState<SearchItem[]>([]);
  const [selectedSearch, setSelectedSearch] = useState<SearchItem | null>(null);
  const [searchPage, setSearchPage] = useState<{ searchId: string; cursor: string | null }>({ searchId: "", cursor: null });
  const [searchResults, setSearchResults] = useState<{ key: string; page: CursorPage<SearchResult> } | null>(null);
  const [searchError, setSearchError] = useState<{ key: string; message: string } | null>(null);
  const [searchSessionsError, setSearchSessionsError] = useState("");
  const [searchSessionCursor, setSearchSessionCursor] = useState<string | null>(null);
  const [searchSessionNextCursor, setSearchSessionNextCursor] = useState<string | null>(null);
  const [searchSort, setSearchSort] = useState("sources");
  const [searchOrder, setSearchOrder] = useState("desc");
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const [refreshing, setRefreshing] = useState(false);
  const [refreshError, setRefreshError] = useState("");
  const [supportingReadError, setSupportingReadError] = useState("");
  const [refreshGeneration, setRefreshGeneration] = useState(0);
  const [manualRefreshGeneration, setManualRefreshGeneration] = useState(0);
  const [eventStreamStatus, setEventStreamStatus] = useState<EventStreamStatus>(pollingEventStreamStatus);
  const session = useRef(new AbortController());
  const downloadRequests = useRef(new Map<string, string | symbol>());
  const [downloadStatus, setDownloadStatus] = useState<ReadonlyMap<string, string | symbol>>(downloadRequests.current);

  const updateDownloadStatus = useCallback((hash: string, status?: string | symbol) => {
    const next = new Map(downloadRequests.current);
    if (status === undefined) next.delete(hash);
    else next.set(hash, status);
    downloadRequests.current = next;
    setDownloadStatus(next);
  }, []);

  const queueSearchDownload = useCallback(async (
    hash: string, create: (signal: AbortSignal) => Promise<DownloadSummary>
  ) => {
    const key = hash.toLowerCase();
    if (downloadRequests.current.has(key)) throw new OperationCancelledError();
    const pending = Symbol();
    const signal = session.current.signal;
    updateDownloadStatus(key, pending);
    try {
      const job = await create(signal);
      if (!signal.aborted) updateDownloadStatus(key, job.id);
    } finally {
      if (downloadRequests.current.get(key) === pending) updateDownloadStatus(key);
    }
  }, [updateDownloadStatus]);

  const forgetDownload = useCallback((job: DownloadSummary) => {
    const key = job.hash.toLowerCase();
    if (downloadRequests.current.get(key) === job.id) updateDownloadStatus(key);
  }, [updateDownloadStatus]);

  const resetProtectedState = useCallback(() => {
    setSnapshot(null);
    setDownloadPreview([]);
    setAppInfo(null);
    setCapabilities(null);
    setRuntimeDiagnostics(null);
    setNetworkStatus(null);
    setNatStatus(null);
    setIpFilterStatus(null);
    setVpnGuardStatus(null);
    setSettings(null);
    setSettingsSurface(null);
    setCategories([]);
    setFriends([]);
    setLibraryScan(null);
    setSharedFileIgnores(null);
    setUploads([]);
    setUploadQueue([]);
    setLogs([]);
    setSearches([]);
    setSearchResults(null);
    setSearchError(null);
    setSearchSessionsError("");
    setRefreshError("");
    setSupportingReadError("");
    setRefreshing(false);
    setSearchSessionCursor(null);
    setSearchSessionNextCursor(null);
    setSelectedSearch(null);
    setSearchPage({ searchId: "", cursor: null });
    setSearchSort("sources");
    setSearchOrder("desc");
  }, []);

  const navigate = useCallback((nextRoute: AppRoute, replace = false) => {
    setMobileMenuExpanded(false);
    const path = pathForRoute(nextRoute);
    if (window.location.pathname !== path) {
      window.history[replace ? "replaceState" : "pushState"](null, "", path);
    }
    setRoute(nextRoute);
  }, []);

  const navigateToTab = useCallback((nextTab: Tab) => {
    navigate({ tab: nextTab });
  }, [navigate]);

  const navigateToSearch = useCallback((searchId: string, replace = false) => {
    navigate({ tab: "search", searchId }, replace);
  }, [navigate]);

  useEffect(() => {
    const syncRoute = () => {
      setMobileMenuExpanded(false);
      setRoute(currentRoute());
    };
    window.addEventListener("popstate", syncRoute);
    return () => window.removeEventListener("popstate", syncRoute);
  }, []);

  const tab = route.tab;
  const needsRecentSearch = !route.searchId;
  const selectedSearchCursor = route.searchId === searchPage.searchId ? searchPage.cursor : null;
  const searchResultKey = JSON.stringify([route.searchId, selectedSearchCursor, searchSort, searchOrder]);

  useEffect(() => {
    let cancelled = false;
    const authenticate = async () => {
      client.setApiKey(apiKey);
      setError("");
      if (!apiKey) {
        resetProtectedState();
        setAuthState("unauthenticated");
        setAuthError("Enter the API key printed by emulebb-rust when the daemon starts.");
        return;
      }

      setAuthState("checking");
      setAuthError("");
      try {
        const [nextAppInfo, nextCapabilities] = await Promise.all([
          client.get<AppInfo>("app"),
          client.get<unknown>("capabilities")
        ]);
        if (!cancelled) {
          setAppInfo(nextAppInfo);
          setCapabilities(nextCapabilities);
          setAuthState("authenticated");
          setMessage(authAttempt > 0 ? "API key verified" : "");
        }
      } catch (caught) {
        if (!cancelled) {
          resetProtectedState();
          setAuthState("unauthenticated");
          setAuthError(`Could not authenticate with the local daemon: ${errorMessage(caught)}`);
        }
      }
    };
    void authenticate();
    return () => {
      cancelled = true;
    };
  }, [apiKey, authAttempt, resetProtectedState]);

  const refresh = useCallback((manual = false) => {
    setSupportingReadError("");
    setRefreshGeneration((value) => value + 1);
    if (manual) setManualRefreshGeneration((value) => value + 1);
  }, []);

  const readSnapshot = useCallback(async (signal: AbortSignal) => {
    setRefreshing(true);
    const [snapshotResult, previewResult] = await Promise.allSettled([
      client.get<Snapshot>(`snapshot?limit=${SNAPSHOT_LIMIT}`, signal),
      client.getPage<DownloadSummary>("downloads?view=all&limit=12", signal)
    ]);
    if (signal.aborted) return;
    if (snapshotResult.status === "fulfilled") {
      const next = snapshotResult.value;
      setSnapshot(next);
      setAppInfo((current) => current ?? next.app ?? null);
      setUploads(next.uploads ?? []);
      setUploadQueue(next.uploadQueue ?? []);
    }
    if (previewResult.status === "fulfilled") setDownloadPreview(previewResult.value.data);
    const failure = [snapshotResult, previewResult].find((result) => result.status === "rejected");
    setRefreshError(failure ? errorMessage(failure.reason) : "");
    setRefreshing(false);
  }, []);
  useRefreshRead(authState === "authenticated" ? readSnapshot : null, refreshGeneration);

  useEffect(() => {
    if (authState !== "authenticated") return;
    // WHY: The periodic read picks up download events too, so event bursts cannot
    // start extra reads or reorder rows between scheduled updates.
    const timer = window.setInterval(refresh, REFRESH_INTERVAL_MS);
    return () => window.clearInterval(timer);
  }, [authState, refresh]);

  useEffect(() => {
    if (authState !== "authenticated" || !["transfers", "search", "categories"].includes(tab)) {
      return;
    }
    let cancelled = false;
    const loadCategories = async () => {
      try {
        const nextCategories = await client.get<Page<Category>>("categories");
        if (!cancelled) {
          setCategories(nextCategories.items ?? []);
        }
      } catch (caught) {
        if (!cancelled) {
          setSupportingReadError(errorMessage(caught));
        }
      }
    };
    void loadCategories();
    return () => {
      cancelled = true;
    };
  }, [tab, refreshGeneration, authState]);

  useEffect(() => {
    if (authState !== "authenticated" || tab !== "friends") {
      return;
    }
    let cancelled = false;
    const loadFriends = async () => {
      try {
        const nextFriends = await client.get<Page<Friend>>("friends");
        if (!cancelled) {
          setFriends(nextFriends.items ?? []);
        }
      } catch (caught) {
        if (!cancelled) {
          setSupportingReadError(errorMessage(caught));
        }
      }
    };
    void loadFriends();
    return () => {
      cancelled = true;
    };
  }, [tab, refreshGeneration, authState]);

  useEffect(() => {
    if (authState !== "authenticated" || tab !== "sharing") {
      return;
    }
    let cancelled = false;
    const loadSharing = async () => {
      try {
        const [nextLibraryScan, nextSharedFileIgnores] = await Promise.all([
          client.get<LibraryScan>("library/scan"),
          client.get<SharedFileIgnores>("library/ignores")
        ]);
        if (!cancelled) {
          setLibraryScan(nextLibraryScan);
          setSharedFileIgnores(nextSharedFileIgnores);
        }
      } catch (caught) {
        if (!cancelled) {
          setSupportingReadError(errorMessage(caught));
        }
      }
    };
    void loadSharing();
    return () => {
      cancelled = true;
    };
  }, [tab, refreshGeneration, authState]);

  useEffect(() => {
    if (authState !== "authenticated" || !["settings", "network"].includes(tab)) {
      return;
    }
    let cancelled = false;
    const loadSettings = async () => {
      try {
        const [nextSettings, nextNetworkStatus, nextNatStatus, nextIpFilterStatus, nextVpnGuardStatus, nextSettingsSurface] = await Promise.all([
          client.getSettings(),
          client.get<NetworkStatus>("network"),
          client.get<NatStatus>("nat"),
          client.get<IpFilterStatus>("ip-filter"),
          client.get<VpnGuardStatus>("vpn-guard"),
          client.get<SettingsSurface>("settings/surface")
        ]);
        if (!cancelled) {
          setSettings(nextSettings);
          setNetworkStatus(nextNetworkStatus);
          setNatStatus(nextNatStatus);
          setIpFilterStatus(nextIpFilterStatus);
          setVpnGuardStatus(nextVpnGuardStatus);
          setSettingsSurface(nextSettingsSurface);
        }
      } catch (caught) {
        if (!cancelled) {
          setSupportingReadError(errorMessage(caught));
        }
      }
    };
    void loadSettings();
    return () => {
      cancelled = true;
    };
  }, [tab, authState]);

  useEffect(() => {
    if (authState !== "authenticated" || tab !== "diagnostics") {
      return;
    }
    let cancelled = false;
    const loadDiagnostics = async () => {
      try {
        const [nextRuntimeDiagnostics, nextDownloadEventDiagnostics] = await Promise.all([
          client.get<RuntimeDiagnostics>("diagnostics"),
          client.get<DownloadEventRuntimeDiagnostics>("events/status")
        ]);
        if (!cancelled) {
          setRuntimeDiagnostics({
            ...nextRuntimeDiagnostics,
            downloadEvents: nextDownloadEventDiagnostics
          });
        }
      } catch (caught) {
        if (!cancelled) {
          setSupportingReadError(errorMessage(caught));
        }
      }
    };
    void loadDiagnostics();
    return () => {
      cancelled = true;
    };
  }, [tab, refreshGeneration, authState]);

  useEffect(() => {
    if (authState !== "authenticated" || tab !== "logs") {
      return;
    }
    let cancelled = false;
    const loadLogs = async () => {
      try {
        const nextLogs = await client.get<Page<LogRecord> | LogRecord[]>(`logs?limit=${LOG_LIMIT}`);
        if (!cancelled) {
          setLogs(Array.isArray(nextLogs) ? nextLogs : nextLogs.items ?? []);
        }
      } catch (caught) {
        if (!cancelled) {
          setSupportingReadError(errorMessage(caught));
        }
      }
    };
    void loadLogs();
    return () => {
      cancelled = true;
    };
  }, [tab, refreshGeneration, authState]);

  const readSearchSessions = useCallback(async (signal: AbortSignal) => {
    const query = new URLSearchParams({ limit: "100" });
    if (searchSessionCursor) query.set("cursor", searchSessionCursor);
    try {
      const collection = await client.getPage<SearchItem>(`searches?${query}`, signal);
      if (signal.aborted) return;
      setSearches(collection.data);
      setSearchSessionNextCursor(collection.meta.nextCursor);
      setSearchSessionsError("");
      if (needsRecentSearch && collection.data[0]) navigateToSearch(collection.data[0].id, true);
    } catch (caught) {
      if (!signal.aborted) setSearchSessionsError(errorMessage(caught));
    }
  }, [needsRecentSearch, searchSessionCursor, navigateToSearch]);

  const readSearchResults = useCallback(async (signal: AbortSignal) => {
    if (!route.searchId) return;
    const path = `searches/${route.searchId}`;
    const query = new URLSearchParams({ limit: String(SEARCH_RESULT_PAGE_SIZE), sort: searchSort, order: searchOrder });
    if (selectedSearchCursor) query.set("cursor", selectedSearchCursor);
    const [search, results] = await Promise.allSettled([
      client.get<SearchItem>(path, signal),
      client.getPage<SearchResult>(`${path}/results?${query}`, signal)
    ]);
    if (signal.aborted) return;
    if (search.status === "fulfilled") setSelectedSearch(search.value);
    if (results.status === "fulfilled") setSearchResults({ key: searchResultKey, page: results.value });
    const failure = [search, results].find((result) => result.status === "rejected");
    setSearchError(failure ? { key: searchResultKey, message: errorMessage(failure.reason) } : null);
  }, [route.searchId, searchSort, searchOrder, selectedSearchCursor, searchResultKey]);

  const searchActive = authState === "authenticated" && tab === "search";
  useRefreshRead(searchActive ? readSearchSessions : null, refreshGeneration);
  useRefreshRead(searchActive ? readSearchResults : null, refreshGeneration);

  const downloadSseEnabled = supportsDownloadSse(appInfo) || supportsDownloadSse(capabilities);

  useEffect(() => {
    if (authState !== "authenticated" || !downloadSseEnabled) {
      setEventStreamStatus(pollingEventStreamStatus);
      return;
    }
    const controller = new AbortController();
    let closed = false;
    let lastEventId: string | undefined;
    let reconnectAttempts = 0;
    setEventStreamStatus({
      mode: "connecting",
      enabled: true,
      connected: false,
      reconnectAttempts: 0,
      pollIntervalMs: REFRESH_INTERVAL_MS,
      retryIntervalMs: EVENT_STREAM_RETRY_MS
    });

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
          await client.streamDownloadEvents((event: DownloadEvent, cursor?: string) => {
            lastEventId = cursor;
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
    };
  }, [apiKey, authState, downloadSseEnabled]);

  const resetSession = () => {
    session.current.abort();
    session.current = new AbortController();
    downloadRequests.current = new Map();
    setDownloadStatus(downloadRequests.current);
    setAuthState("checking");
    resetProtectedState();
  };

  const saveApiKey = () => {
    const next = apiKeyInput.trim();
    resetSession();
    setMessage("");
    setError("");
    setStorageWarning(storeApiKey(next) ? "" : "Browser storage is unavailable; this key will only last for the current page.");
    setApiKey(next);
    setAuthAttempt((value) => value + 1);
  };

  const clearApiKey = () => {
    resetSession();
    removeStoredApiKey();
    setApiKey("");
    setApiKeyInput("");
    setStorageWarning("");
    setMessage("");
    setAuthAttempt((value) => value + 1);
  };

  const run = async (
    operation: () => Promise<unknown>,
    success: string,
    options: { refresh?: boolean } = {}
  ) => {
    const signal = session.current.signal;
    setError("");
    setMessage("");
    try {
      await operation();
      if (signal.aborted) return;
      setMessage(success);
      if (options.refresh !== false) {
        refresh();
      }
    } catch (caught) {
      if (signal.aborted || caught instanceof OperationCancelledError) {
        return;
      }
      setError(errorMessage(caught));
    }
  };

  const stats = snapshot?.stats ?? snapshot?.status?.stats ?? {};
  const transfers = downloadPreview;
  const kad: KadStatus = snapshot?.kad ?? {};
  const serverStatus = snapshot?.status?.servers;
  const serverConnected = Boolean(serverStatus?.connected);
  const serverConnecting = Boolean(serverStatus?.connecting);
  const serverIdState = serverConnected ? serverStatus?.ed2kIdState ?? "unknown" : "unknown";
  const serverConnectionLabel = serverConnected
    ? serverIdState === "high"
      ? "HighID"
      : serverIdState === "low"
        ? "LowID"
        : "Connected"
    : serverConnecting
      ? "Connecting"
      : "Disconnected";
  const serverConnectionStyle = serverIdState === "high"
    ? "connected"
    : serverIdState === "low" || serverConnecting
      ? "warning"
      : serverConnected
        ? undefined
        : "disconnected";
  const activeTransfers = snapshot?.downloads?.unfinished ?? 0;
  const downloadRate = formatRate(
    numberField(stats, "downloadRateBytesPerSec") ?? (numberField(stats, "downloadSpeedKiBps") ?? 0) * 1024
  );
  const uploadRate = formatRate(
    numberField(stats, "uploadRateBytesPerSec") ?? (numberField(stats, "uploadSpeedKiBps") ?? 0) * 1024
  );
  const kadStatus = kad.connected ? "Connected" : kad.running ? "Starting" : "Stopped";
  const sessionSignal = session.current.signal;

  return (
    <div class="page">
      <header class="navbar navbar-expand-md d-print-none">
        <div class="container-fluid topbar">
          <div class="topbar-main">
            <div class="navbar-brand app-brand">
              <img class="brand-mark" src="/favicon.ico" width="32" height="32" alt="" />
              <AppIdentity app={appInfo ?? snapshot?.app ?? null} />
            </div>
            <label class="appearance-control">
              <span>Appearance</span>
              <select class="form-select" value={appearancePreference}
                onChange={(event) => appearance.setPreference(event.currentTarget.value as AppearancePreference)}>
                <option value="system">System</option>
                <option value="light">Light</option>
                <option value="dark">Dark</option>
              </select>
            </label>
            {authState === "authenticated" && (
              <>
                <div class="status-toolbar" role="toolbar" aria-label="Connection and transfer status">
                  <ToolbarButton
                    label="Server"
                    value={serverConnectionLabel}
                    icon={<Server size={17} />}
                    state={serverConnectionStyle}
                    onClick={() => navigateToTab("servers")}
                  />
                  <ToolbarButton
                    label="Kad"
                    value={kadStatus}
                    icon={<Shield size={17} />}
                    state={kad.connected ? "connected" : "disconnected"}
                    onClick={() => navigateToTab("kad")}
                  />
                  <ToolbarButton
                    label="Download"
                    value={downloadRate}
                    icon={<Download size={17} />}
                    onClick={() => navigateToTab("transfers")}
                  />
                  <ToolbarButton
                    label="Upload"
                    value={uploadRate}
                    icon={<UploadCloud size={17} />}
                    onClick={() => navigateToTab("uploads")}
                  />
                  <ToolbarButton
                    label="Transfers"
                    value={`${activeTransfers} unfinished`}
                    icon={<Activity size={17} />}
                    onClick={() => navigateToTab("transfers")}
                  />
                </div>
                <div class="top-actions navbar-nav flex-row">
                  <span class="badge bg-success-lt api-status"><Unlock size={14} /> API connected</span>
                  <button type="button" class="btn btn-outline-secondary" title="Change API key" onClick={clearApiKey}>
                    <KeyRound size={16} />
                    Change key
                  </button>
                  <button type="button" class="btn btn-outline-secondary" title="Refresh" onClick={() => refresh(true)}>
                    <RefreshCw size={16} class={refreshing ? "spin" : ""} />
                    Refresh
                  </button>
                </div>
              </>
            )}
          </div>
          {authState === "authenticated" && (
            <div class="primary-navigation">
            <div class="mobile-menu-bar">
              <button class="btn btn-outline-secondary" type="button" ref={menuButton}
                aria-expanded={mobileMenuExpanded} aria-controls="primary-views"
                onClick={() => setMobileMenuExpanded((expanded) => !expanded)}>Menu</button>
              <strong>{tab === "library" ? "Library" : tab === "network" ? "Network" : tab[0].toUpperCase() + tab.slice(1)}</strong>
            </div>
            <nav id="primary-views" class={`tabs topbar-tabs nav nav-pills${mobileMenuExpanded ? " mobile-expanded" : ""}`} aria-label="Primary views">
              <TabButton tab="overview" active={tab} navigate={navigateToTab} icon={<Activity size={16} />} label="Overview" />
              <TabButton tab="transfers" active={tab} navigate={navigateToTab} icon={<Download size={16} />} label="Transfers" />
              <TabButton tab="search" active={tab} navigate={navigateToTab} icon={<Search size={16} />} label="Search" />
              <TabButton tab="sharing" active={tab} navigate={navigateToTab} icon={<FolderTree size={16} />} label="Sharing" />
              <TabButton tab="library" active={tab} navigate={navigateToTab} icon={<Share2 size={16} />} label="Library" />
              <TabButton tab="uploads" active={tab} navigate={navigateToTab} icon={<UploadCloud size={16} />} label="Uploads" />
              <TabButton tab="network" active={tab} navigate={navigateToTab} icon={<Network size={16} />} label="Network" />
              <TabButton tab="servers" active={tab} navigate={navigateToTab} icon={<Server size={16} />} label="Servers" />
              <TabButton tab="kad" active={tab} navigate={navigateToTab} icon={<Shield size={16} />} label="Kad" />
              <TabButton tab="categories" active={tab} navigate={navigateToTab} icon={<ListChecks size={16} />} label="Categories" />
              <TabButton tab="friends" active={tab} navigate={navigateToTab} icon={<Users size={16} />} label="Friends" />
              <TabButton tab="settings" active={tab} navigate={navigateToTab} icon={<Settings size={16} />} label="Settings" />
              <TabButton tab="diagnostics" active={tab} navigate={navigateToTab} icon={<Gauge size={16} />} label="Diagnostics" />
              <TabButton tab="logs" active={tab} navigate={navigateToTab} icon={<FileText size={16} />} label="Logs" />
            </nav>
            </div>
          )}
        </div>
      </header>

      <div class="page-wrapper">
        <div class="page-body">
          <div class="container-xl shell">
            {authState !== "authenticated" && (
              <section class="auth-card card" aria-labelledby="auth-title">
                <div class="card-body">
                  <div class="auth-heading">
                    <span class="brand-mark"><Lock size={18} /></span>
                    <div>
                      <h2 id="auth-title">Connect to the local daemon</h2>
                      <p>The WebUI stays locked until the API key is verified.</p>
                    </div>
                  </div>
                  {authError && <div class="notice alert alert-danger">{authError}</div>}
                  {storageWarning && <div class="notice alert alert-warning">{storageWarning}</div>}
                  <form
                    class="auth-form"
                    onSubmit={(event) => {
                      event.preventDefault();
                      saveApiKey();
                    }}
                  >
                    <label for="webui-api-key">API key</label>
                    <div class="auth-controls">
                      <div class="api-key input-icon">
                        <span class="input-icon-addon"><KeyRound size={16} /></span>
                        <input
                          id="webui-api-key"
                          class="form-control"
                          type="password"
                          value={apiKeyInput}
                          placeholder="X-API-Key"
                          autoComplete="off"
                          autofocus
                          onInput={(event) => setApiKeyInput(event.currentTarget.value)}
                        />
                      </div>
                      <button type="submit" class="btn btn-primary" disabled={authState === "checking" || !apiKeyInput.trim()}>
                        {authState === "checking" ? <RefreshCw size={16} class="spin" /> : <Unlock size={16} />}
                        {authState === "checking" ? "Checking…" : "Connect"}
                      </button>
                    </div>
                  </form>
                  <p class="auth-help">Use the API key printed beside the WebUI address when emulebb-rust starts.</p>
                </div>
              </section>
            )}

            {authState === "authenticated" && (
              <>
                {message && <div class="notice alert alert-success" role="status">{message}</div>}
                {error && <div class="notice alert alert-danger">{error}</div>}
                {(refreshError || supportingReadError) && <div class="notice alert alert-danger">{refreshError || supportingReadError}</div>}

                {tab === "overview" && (
              <Overview
                snapshot={snapshot}
                stats={stats}
                transfers={transfers}
                uploads={uploads}
                uploadQueue={uploadQueue}
                libraryScan={libraryScan}
                kad={kad}
              />
            )}
            {tab === "transfers" && <TransfersView categories={categories} client={client} run={run} refreshGeneration={refreshGeneration}
              onDownloadRemoved={(job) => { if (!sessionSignal.aborted) forgetDownload(job); }} />}
            {tab === "search" && (
              <SearchView
                searches={searches}
                selectedSearch={selectedSearch}
                resultPage={searchResults?.key === searchResultKey ? searchResults.page : null}
                readError={(searchError?.key === searchResultKey ? searchError.message : "") || searchSessionsError}
                downloadStatus={downloadStatus}
                queueDownload={queueSearchDownload}
                resultCursor={selectedSearchCursor}
                sessionCursor={searchSessionCursor}
                sessionNextCursor={searchSessionNextCursor}
                selectSearchSessionsPage={setSearchSessionCursor}
                selectedSearchId={route.searchId}
                categories={categories}
                client={client}
                run={run}
                selectSearch={navigateToSearch}
                searchSort={searchSort}
                searchOrder={searchOrder}
                selectSearchSort={(sort, order) => {
                  setSearchSort(sort);
                  setSearchOrder(order);
                  setSearchPage({ searchId: route.searchId ?? "", cursor: null });
                }}
                selectSearchPage={(cursor) => {
                  if (route.searchId) setSearchPage({ searchId: route.searchId, cursor });
                }}
                onSearchCreated={(search) => {
                  setSearchSessionCursor(null);
                  setSelectedSearch(search);
                  setSearchPage({ searchId: search.id, cursor: null });
                  navigateToSearch(search.id);
                }}
                onSearchDeleted={() => {
                  setSelectedSearch(null);
                  setSearchResults(null);
                  setSearchPage({ searchId: "", cursor: null });
                  navigateToTab("search");
                }}
                onSearchesCleared={() => {
                  setSearches([]);
                  setSearchSessionCursor(null);
                  setSearchSessionNextCursor(null);
                  setSearchResults(null);
                  setSelectedSearch(null);
                  setSearchPage({ searchId: "", cursor: null });
                  navigateToTab("search");
                }}
              />
            )}
            {tab === "sharing" && (
              <SharingView
                refreshGeneration={refreshGeneration}
                directories={libraryScan}
                ignores={sharedFileIgnores}
                stats={stats}
                sharedFileCount={snapshot?.status?.runtimeDiagnostics?.sharedFileCount}
                uploads={uploads}
                uploadQueue={uploadQueue}
                client={client}
                run={run}
              />
            )}
            {tab === "library" && (
              <LibraryView
                client={client}
                run={run}
                refreshGeneration={manualRefreshGeneration}
              />
            )}
            {tab === "uploads" && <UploadsView refreshGeneration={refreshGeneration} client={client} run={run} />}
            {tab === "network" && (
              <NetworkHealthView
                serverStatus={serverStatus}
                transfers={transfers}
                uploads={uploads}
                uploadQueue={uploadQueue}
                kad={kad}
                settings={settings}
                client={client}
              />
            )}
            {tab === "servers" && <ServersView status={snapshot?.status ?? {}} client={client} run={run} />}
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
                onSettingsSaved={(nextSettings) => setSettings(nextSettings)}
                openSection={(name) => {
                  setSettingsSectionTarget(name);
                  navigateToTab(settingsSectionTabs[name] ?? "settings");
                }}
              />
            )}
            {tab === "diagnostics" && <DiagnosticsView app={appInfo} capabilities={capabilities} runtimeDiagnostics={runtimeDiagnostics} eventStreamStatus={eventStreamStatus} client={client} run={run} />}
                {tab === "logs" && <LogsView logs={logs} client={client} run={run} />}
              </>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

function readStoredApiKey(): string {
  removeLegacyApiKey();
  try {
    return window.sessionStorage.getItem(API_KEY_STORAGE) ?? "";
  } catch {
    return "";
  }
}

function storeApiKey(apiKey: string): boolean {
  removeLegacyApiKey();
  try {
    if (apiKey) {
      window.sessionStorage.setItem(API_KEY_STORAGE, apiKey);
    } else {
      window.sessionStorage.removeItem(API_KEY_STORAGE);
    }
    return true;
  } catch {
    return false;
  }
}

function removeStoredApiKey(): void {
  removeLegacyApiKey();
  try {
    window.sessionStorage.removeItem(API_KEY_STORAGE);
  } catch {
    // The in-memory key is still cleared when browser storage is unavailable.
  }
}

function removeLegacyApiKey(): void {
  try {
    window.localStorage.removeItem(API_KEY_STORAGE);
  } catch {
    // Ignore unavailable persistent storage; it is never read for credentials.
  }
}

function supportsDownloadSse(value: unknown): boolean {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const capabilities = (value as Record<string, unknown>).capabilities;
  if (Array.isArray(capabilities)) {
    return capabilities.includes("downloads.sse");
  }
  if (typeof capabilities === "object" && capabilities !== null) {
    return (capabilities as Record<string, unknown>)["downloads.sse"] === true;
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
  navigate: (tab: Tab) => void;
  icon: ComponentChildren;
  label: string;
}) {
  return (
    <a
      href={pathForRoute({ tab: props.tab })}
      class={props.active === props.tab ? "tab nav-link active" : "tab nav-link"}
      aria-current={props.active === props.tab ? "page" : undefined}
      onClick={(event) => {
        if (
          event.button === 0
          && !event.altKey
          && !event.ctrlKey
          && !event.metaKey
          && !event.shiftKey
        ) {
          event.preventDefault();
          props.navigate(props.tab);
        }
      }}
    >
      {props.icon}
      {props.label}
    </a>
  );
}

function ToolbarButton(props: {
  label: string;
  value: string;
  icon: ComponentChildren;
  state?: "connected" | "disconnected" | "warning";
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      class={`toolbar-item${props.state ? ` is-${props.state}` : ""}`}
      aria-label={`${props.label}: ${props.value}`}
      onClick={props.onClick}
    >
      <span class="toolbar-icon">{props.icon}</span>
      <span class="toolbar-copy">
        <span class="toolbar-label">{props.label}</span>
        <strong>{props.value}</strong>
      </span>
    </button>
  );
}
