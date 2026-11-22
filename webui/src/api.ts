import type { SettingsPatch, SettingsSnapshot } from "./settingsModel";
export type { SettingsValue, SettingsValues, SavedSetting, SavedSettings, SettingsReadData, SettingsSnapshot, SettingsPatch, SettingRule, SettingField, BootstrapSettingSpec, SettingsSectionResourceSpec, SettingsSurface } from "./settingsModel";

export type ApiEnvelope<T> = {
  data: T;
  meta?: Record<string, unknown>;
};

export type ApiError = {
  error?: {
    code?: string;
    message?: string;
    details?: unknown;
  };
};

export class RestError extends Error {
  constructor(
    message: string,
    public readonly status: number,
    public readonly code?: string,
    public readonly details?: unknown
  ) {
    super(message);
    this.name = "RestError";
  }
}

export type Page<T> = {
  items: T[];
  total?: number;
  offset?: number;
  limit?: number;
  nextCursor?: string | null;
  nextAfterHash?: string | null;
};

export type AppInfo = {
  build?: string;
  platform?: string;
  channel?: string;
  sourceRevision?: string;
  appName?: string;
  apiVersion?: string;
  contractVersion?: string;
  name?: string;
  version?: string;
  [key: string]: unknown;
};

export type DownloadResources = {
  active: number;
  preparing: number;
  waiting: number;
  concurrency: {
    mode: "automatic" | "fixed";
    configuredLimit: number | null;
    target: number;
    burstActive: number;
  };
  residentMemory: { usedBytes: number; softTargetBytes: number; limitBytes: number };
};

export type Stats = {
  downloadRateBytesPerSec?: number;
  uploadRateBytesPerSec?: number;
  downloadSpeedKiBps?: number;
  uploadSpeedKiBps?: number;
  downloadResources: DownloadResources;
  activeUploads?: number;
  waitingUploads?: number;
  totalTransfers?: number;
  sharedFiles?: number;
  sharedBytes?: number;
  [key: string]: unknown;
};

export type Status = {
  lifecycle?: string | { state?: string; [key: string]: unknown };
  connected?: boolean;
  servers?: ServerStatus;
  stats?: Stats;
  sharedStartupCache?: {
    hashingCount?: number;
    deferredHashingActive?: boolean;
    reloadProgress?: SharedDirectoryReloadProgress;
    [key: string]: unknown;
  };
  runtimeDiagnostics?: RuntimeDiagnostics;
  [key: string]: unknown;
};

export type Ed2kIdState = "unknown" | "low" | "high";

export type ServerStatus = {
  connected?: boolean;
  connecting?: boolean;
  currentServer?: ServerItem | null;
  ed2kIdState?: Ed2kIdState;
  serverCount?: number;
  [key: string]: unknown;
};

export type RuntimeDiagnostics = {
  processId?: number;
  processResources?: ProcessResources;
  knownFileCount?: number;
  sharedFileCount?: number;
  sharedHashingCount?: number;
  sharedDirectoryReloadProgress?: SharedDirectoryReloadProgress;
  ed2kPublish?: Record<string, unknown>;
  kadPublish?: Record<string, unknown>;
  downloadEvents?: DownloadEventRuntimeDiagnostics;
  downloadFileCount?: number;
  activeUploads?: number;
  waitingUploads?: number;
  geolocation?: Record<string, unknown> | null;
  [key: string]: unknown;
};

export type ProcessResources = {
  sampledAtMs: number | null;
  residentMemoryBytes: number | null;
  cpuUsagePercent: number | null;
  cpuSampleIntervalMs: number | null;
};

export type DownloadEventRuntimeDiagnostics = {
  enabled?: boolean;
  stream?: string;
  epoch?: string;
  channelCapacity?: number;
  queuedEventCount?: number;
  subscriberCount?: number;
  latestEventId?: number;
  nextEventId?: number;
  resumeBehavior?: string;
  [key: string]: unknown;
};

export type DownloadWaitingReason = "network" | "sources" | "resources";
export type DownloadState = "queued" | "waiting-metadata" | "downloading" | "stopping" | "stopped" | "verifying" | "delivering" | "completed" | "removing" | "failed";
export type DownloadSummary = {
  id: string;
  hash: string;
  name: string;
  sizeBytes: number | null;
  progress: number | null;
  intent: "started" | "stopped";
  category: string | null;
  createdAt: number;
  updatedAt: number;
  completedAt: number | null;
} & ({ state: "queued"; waitingReason: DownloadWaitingReason }
  | { state: Exclude<DownloadState, "queued">; waitingReason: null });

export type DownloadDetail = DownloadSummary & {
  payloadVerified: boolean;
  delivery: { path: string | null; state: "pending" | "delivered"; ownership: "none" | "owned" | "unowned" } | null;
  failure: { code: string; message: string; failedAt: number } | null;
};

export type CursorPage<T> = {
  data: T[];
  meta: { apiVersion: string; nextCursor: string | null; hasMore: boolean; total?: number };
};

export type LibraryTag = { name: string };

export type DownloadBatchItem = {
  id: string;
  status: "accepted" | "unchanged" | "failed";
  httpStatus: number;
  error?: { code: string; message: string; details: unknown };
};

export type HashBatchItem = Omit<DownloadBatchItem, "id"> & { hash: string };

export type DownloadEvent = {
  id: number;
  epoch: string;
} & (
  | { type: "download.changed" | "download.removed"; downloadId: string }
  | { type: "sync.reset"; reason: "initial" | "reconnect" | "lagged" | "epoch-changed"; missed?: number }
);

export type DownloadSource = {
  clientId?: string;
  userName?: string;
  userHash?: string | null;
  downloadState?: string;
  address?: string;
  port?: number;
  downloadRateBytesPerSecond?: number;
  requestedFileName?: string | null;
  clientSoftware?: string;
  reportedFileNames?: Array<{
    rawName: string;
    normalizedName: string;
    origin: string;
    reporterEndpoint: string | null;
    observedAt: number;
  }>;
  reportedFileNamesHasMore?: boolean;
  banned?: boolean;
  friend?: boolean;
  lowId?: boolean;
  [key: string]: unknown;
};

export type SearchResultMedia = {
  artist: string;
  album: string;
  title: string;
  lengthSeconds: number;
  bitrateKbps: number;
  codec: string;
};

export type SearchResult = {
  id: string;
  searchId?: string;
  hash: string;
  displayName: string;
  sizeBytes: number | null;
  sources?: number;
  completeSources?: number;
  fileType?: string;
  media?: SearchResultMedia;
  extension?: string;
  directory?: string;
  rating?: number;
  aichHash?: string | null;
  complete?: boolean;
};

export type SearchObservation = {
  id: string;
  origin: "server" | "global" | "kad";
  reporterEndpoint: string | null;
  rawName: string | null;
  normalizedName: string | null;
  sizeBytes: number | null;
  sources: number | null;
  completeSources: number | null;
  sourceClientId: number | null;
  sourceClientPort: number | null;
  fileType: string | null;
  media: { artist: string | null; album: string | null; title: string | null;
    lengthSeconds: number | null; bitrateKbps: number | null; codec: string | null };
  rating: number | null;
  aichHash: string | null;
  complete: boolean | null;
  directory: string | null;
  firstSeenAt: number;
  lastSeenAt: number;
  observationCount: number;
};

export type SearchCriteria = {
  extension?: string;
  minSizeBytes?: number | null;
  maxSizeBytes?: number | null;
  minAvailability?: number | null;
  minCompleteSources?: number | null;
  minBitrateKbps?: number | null;
  minLengthSeconds?: number | null;
  codec?: string;
  title?: string;
  album?: string;
  artist?: string;
};

export type SearchProgress = {
  phase: string;
  completedUnits: number;
  totalUnits?: number | null;
  unit: string;
};

export type SearchItem = {
  id: string;
  parentSearchId?: string | null;
  query?: string;
  status?: "queued" | "running" | "completed" | "error" | "stopped";
  statusReason?: string | null;
  requestedMethod?: string;
  resolvedMethod?: string | null;
  type?: string;
  criteria?: SearchCriteria;
  progress?: SearchProgress | null;
  resultCount: number;
  createdAt?: number;
  updatedAt?: number;
  completedAt?: number | null;
};

export type ServerItem = {
  endpoint?: string;
  id?: string;
  address?: string;
  port?: number;
  name?: string;
  priority?: string;
  connected?: boolean;
  connecting?: boolean;
  enabled?: boolean;
  static?: boolean;
  users?: number;
  files?: number;
  current?: boolean;
  description?: string;
  dynIp?: string;
  auxiliaryPorts?: number[];
  failedCount?: number;
  hardFiles?: number;
  ip?: string;
  ping?: number;
  softFiles?: number;
  offerFilesMode?: string;
  offerFilesBatchMax?: number;
  offerFilesMinIntervalMs?: number;
  offerFilesFallbackReason?: string;
  offerFilesPublishedEntries?: number;
  offerFilesPendingEntries?: number;
  version?: string;
  obfuscationTcpPort?: number | null;
  udpFlags?: number | null;
  hostName?: string | null;
  hostNameStatus?: string | null;
  hostNameResolvedAt?: string | null;
  hostNameError?: string | null;
  [key: string]: unknown;
};

export type KadNode = {
  nodeId?: string;
  ip?: string;
  hostName?: string | null;
  hostNameStatus?: string | null;
  hostNameResolvedAt?: string | null;
  hostNameError?: string | null;
  udpPort?: number;
  tcpPort?: number;
  kadVersion?: number;
  verified?: boolean;
  contactType?: string;
  probeType?: number;
  udpKeyKnown?: boolean;
  helloSourceUdpPort?: number | null;
  udpFirewalled?: boolean;
  tcpFirewalled?: boolean;
  receivedHelloPacket?: boolean;
  bootstrap?: boolean;
  createdAt?: string;
  lastSeen?: string;
  [key: string]: unknown;
};

export type KadStatus = {
  enabled?: boolean;
  running?: boolean;
  connected?: boolean;
  firewalled?: boolean | null;
  bootstrapping?: boolean;
  bootstrapProgress?: number;
  contactCount?: number;
  users?: number;
  files?: number;
  nodes?: number;
  indexedKeywordCount?: number;
  indexedSourceCount?: number;
  blockedByVpnGuard?: boolean;
  [key: string]: unknown;
};

export type LogRecord = {
  ts?: string;
  timestamp?: string;
  level?: string;
  message?: string;
  target?: string;
  [key: string]: unknown;
};

export type Category = {
  name: string;
  tempDir: string | null;
  destinationDir: string | null;
  comment: string;
};

export type Friend = {
  userHash?: string;
  name?: string;
  lastSeen?: number | null;
  address?: string | null;
  port?: number;
  [key: string]: unknown;
};

export type UploadScoreBreakdown = {
  score: number;
  creditRatio: number;
  filePriorityScore: number;
  lowRatioApplied: boolean;
  lowRatioBonus: number;
  lowIdPenaltyApplied: boolean;
  lowIdDivisor: number;
  oldClientPenaltyApplied: boolean;
};

export type Upload = {
  id: string;
  userHash: string | null;
  clientSoftware: string | null;
  uploadState: "queued" | "connecting" | "uploading";
  uploadRateBytesPerSec: number;
  sessionUploadedBytes: number;
  waitTimeSeconds: number;
  uploadDurationSeconds: number | null;
  address: string;
  port: number;
  lowId: boolean | null;
  friendSlot: boolean;
  connected: boolean;
  requestedFileHash: string;
  requestedFileName: string | null;
  requestedFileSizeBytes: number | null;
  filePartsAvailable: number | null;
  filePartsTotal: number | null;
  queueRank: number | null;
  scoreBreakdown?: UploadScoreBreakdown;
};

export type LibraryLocation = { path: string; present: boolean };

export type SharedFile = {
  hash: string;
  name?: string;
  sizeBytes?: number;
  path: string;
  priority?: string;
  autoUploadPriority?: boolean;
  allTimeUploadedBytes?: number;
  allTimeUploadRequests?: number;
  allTimeUploadAccepts?: number;
  requests?: number;
  acceptedRequests?: number;
  transferredBytes?: number;
  comment?: string;
  rating?: number;
  ed2kLink?: string;
  publication?: SharedFilePublication | null;
  [key: string]: unknown;
};

export type SharedFilePublishState =
  | "unavailable"
  | "waiting"
  | "queued"
  | "publishing"
  | "partial"
  | "published"
  | "failed";

export type SharedFilePublishLane = {
  state: SharedFilePublishState;
  lastSuccessAtMs?: number | null;
};

export type SharedFileKadKeywordPublish = SharedFilePublishLane & {
  publishedKeywords: number;
  totalKeywords: number;
};

export type SharedFilePublication = {
  ed2k: SharedFilePublishLane;
  kadKeyword: SharedFileKadKeywordPublish;
  kadSource: SharedFilePublishLane;
};

export type LibraryRoot = {
  id: string;
  path: string;
  watchEnabled: boolean;
  scanRequired: boolean;
  managed: boolean;
  shareable: boolean;
  accessible: boolean;
  lastScannedAt: number | null;
};

export type SharedDirectoryReloadProgress = {
  phase?: string;
  running?: boolean;
  pending?: boolean;
  scannedCount?: number;
  plannedHashCount?: number;
  activeHashCount?: number;
  hashedCount?: number;
  failedHashCount?: number;
  reusedCount?: number;
  newCount?: number;
  changedCount?: number;
  escapedDisplayPathCount?: number;
  missingFingerprintCount?: number;
  statFailedCount?: number;
  skippedFailedCount?: number;
  skippedIntakeCount?: number;
  prunedCount?: number;
  staleHashCount?: number;
  diskCount?: number;
  plannedHashBytes?: number;
  completedHashBytes?: number;
  plannedReadBytes?: number;
  completedReadBytes?: number;
  readRateBytesPerSec?: number;
  startedAtMs?: number | null;
  updatedAtMs?: number | null;
  active?: SharedDirectoryHashActiveFile[];
  recent?: SharedDirectoryHashRecentFile[];
  upcoming?: SharedDirectoryHashQueuedFile[];
  disks?: SharedDirectoryHashDiskProgress[];
  [key: string]: unknown;
};

export type SharedDirectoryHashActiveFile = {
  id?: string;
  diskKey?: string;
  path?: string;
  name?: string;
  sizeBytes?: number;
  reason?: string;
  stage?: string;
  stageReadBytes?: number;
  stageTotalBytes?: number;
  readBytes?: number;
  readBytesTotal?: number;
  readRateBytesPerSec?: number;
  startedAtMs?: number;
  updatedAtMs?: number;
  [key: string]: unknown;
};

export type SharedDirectoryHashRecentFile = {
  id?: string;
  diskKey?: string;
  path?: string;
  name?: string;
  sizeBytes?: number;
  reason?: string;
  result?: string;
  error?: string | null;
  hash?: string | null;
  readBytes?: number;
  readBytesTotal?: number;
  durationMs?: number;
  averageReadRateBytesPerSec?: number;
  finishedAtMs?: number;
  [key: string]: unknown;
};

export type SharedDirectoryHashQueuedFile = {
  id?: string;
  diskKey?: string;
  path?: string;
  name?: string;
  sizeBytes?: number;
  reason?: string;
  order?: number;
  [key: string]: unknown;
};

export type SharedDirectoryHashDiskProgress = {
  diskKey?: string;
  plannedCount?: number;
  activeCount?: number;
  completedCount?: number;
  failedCount?: number;
  queuedCount?: number;
  plannedReadBytes?: number;
  completedReadBytes?: number;
  readRateBytesPerSec?: number;
  currentPath?: string | null;
  currentName?: string | null;
  currentStage?: string | null;
  [key: string]: unknown;
};

export type LibraryScan = {
  hashingCount?: number;
  reloadProgress?: SharedDirectoryReloadProgress;
  [key: string]: unknown;
};

export type SharedFileIgnorePattern = {
  pattern: string;
  [key: string]: unknown;
};

export type SharedFileIgnoreRule = {
  key: string;
  matchKind: string;
  pattern: string;
  enabled: boolean;
  [key: string]: unknown;
};

export type SharedFileIgnores = {
  custom?: SharedFileIgnorePattern[];
  defaults?: SharedFileIgnoreRule[];
  [key: string]: unknown;
};

export type VpnGuardMode = "off" | "block";

export type VpnGuardProbeStatus = {
  attempted?: boolean;
  succeeded?: boolean;
  publicIp?: string | null;
  provider?: string;
  error?: string | null;
  [key: string]: unknown;
};

export type VpnGuardStatus = {
  enabled?: boolean;
  mode?: VpnGuardMode;
  allowedPublicIpCidrs?: string;
  startupBlocked?: boolean;
  startupBlockReason?: string;
  publicIp?: string | null;
  egressVerified?: boolean;
  egressBlockReason?: string;
  stunProbe?: VpnGuardProbeStatus;
  httpProbe?: VpnGuardProbeStatus;
  [key: string]: unknown;
};

export type NetworkPorts = {
  tcp?: number;
  udp?: number;
  serverUdp?: number | null;
  [key: string]: unknown;
};

export type NetworkBinding = {
  configuredAddress?: string | null;
  configuredInterfaceId?: string | null;
  configuredInterfaceName?: string | null;
  activeConfiguredAddress?: string | null;
  activeInterfaceId?: string | null;
  activeInterfaceName?: string | null;
  activeInterfaceIndex?: number | null;
  resolveResult?: string;
  [key: string]: unknown;
};

export type NetworkStatus = {
  ports?: NetworkPorts;
  binding?: NetworkBinding;
  vpnGuard?: VpnGuardStatus;
  [key: string]: unknown;
};

export type NatMapping = {
  name?: string;
  protocol?: string;
  localAddr?: string;
  externalAddr?: string;
  leaseExpiresInSecs?: number;
  backend?: string;
  [key: string]: unknown;
};

export type NatGateway = {
  backend?: string;
  controlUrl?: string;
  localIp?: string | null;
  gatewayIp?: string | null;
  externalIp?: string | null;
  [key: string]: unknown;
};

export type NatStatus = {
  enabled?: boolean;
  gatewayDiscovered?: boolean;
  backend?: string | null;
  protocol?: string | null;
  bindIp?: string | null;
  pcpServerIp?: string | null;
  igdIp?: string | null;
  minissdpdSocket?: string | null;
  ssdpLocalPort?: number | null;
  externalIpOverride?: string | null;
  gateway?: NatGateway | null;
  mappings?: NatMapping[];
  observedExternalAddresses?: string[];
  lastRefreshUnixSecs?: number | null;
  lastError?: string | null;
  [key: string]: unknown;
};

export type IpFilterStatus = {
  configured?: boolean;
  reloadable?: boolean;
  path?: string;
  level?: number;
  rangeCount?: number;
  [key: string]: unknown;
};

export type Snapshot = {
  app?: AppInfo;
  status?: Status;
  stats?: Stats;
  downloads?: { unfinished: number; completed: number };
  servers?: ServerItem[];
  kad?: KadStatus;
  uploads?: Upload[];
  uploadQueue?: Upload[];
  sharedFiles?: SharedFile[];
  network?: NetworkStatus;
  logs?: LogRecord[];
  [key: string]: unknown;
};

export type RestClientOptions = {
  basePath?: string;
  fetch?: typeof fetch;
};

export type StreamDownloadEventsOptions = {
  signal?: AbortSignal;
  lastEventId?: string;
};

export function encodeSegment(value: string): string {
  return encodeURIComponent(value);
}

export class RestClient {
  private apiKey = "";
  private readonly basePath: string;
  private readonly fetchImpl: typeof fetch;

  constructor(options: RestClientOptions = {}) {
    this.basePath = normalizeBasePath(options.basePath ?? "/api/v1");
    this.fetchImpl = options.fetch ?? globalThis.fetch.bind(globalThis);
  }

  setApiKey(apiKey: string): void {
    this.apiKey = apiKey.trim();
  }

  /** Preserve the opaque saved revision alongside coherent settings data. */
  async getSettings(): Promise<SettingsSnapshot> {
    return checkedSettingsSnapshot(await this.request<SettingsSnapshot>("GET", "settings", undefined, "json"));
  }

  /** Submit one CAS write without retry or revision conversion. */
  async patchSettings(patch: SettingsPatch): Promise<SettingsSnapshot> {
    return checkedSettingsSnapshot(await this.request<SettingsSnapshot>("PATCH", "settings", patch, "json"));
  }

  async get<T>(path: string): Promise<T> {
    return this.request<T>("GET", path);
  }

  /** Read the current bounded data array together with its opaque continuation. */
  async getPage<T>(path: string): Promise<CursorPage<T>> {
    return this.request<CursorPage<T>>("GET", path, undefined, "json");
  }

  async controlDownloads(action: "start" | "stop" | "verify", ids: string[]): Promise<DownloadBatchItem[]>;
  async controlDownloads(action: "remove", ids: string[], deleteData: boolean): Promise<DownloadBatchItem[]>;
  async controlDownloads(action: "start" | "stop" | "verify" | "remove", ids: string[], deleteData?: boolean): Promise<DownloadBatchItem[]> {
    const items = await this.post<DownloadBatchItem[]>(`downloads/${action}`,
      action === "remove" ? { ids, deleteData } : { ids });
    const failed = items.filter((item) => item.status === "failed");
    if (failed.length) {
      const first = failed[0];
      throw new RestError(failed.map((item) => `${item.id}: ${item.error?.message ?? "Operation failed"}`).join("; "),
        first.httpStatus, first.error?.code, items);
    }
    return items;
  }

  /** Apply an explicit hash selection and surface per-item failures from HTTP 207. */
  async controlLibraryTags(action: "add" | "remove", tag: string, hashes: string[]): Promise<HashBatchItem[]> {
    const items = await this.post<HashBatchItem[]>(`library/files/tags/${action}`, { tag, hashes });
    const failed = items.filter((item) => item.status === "failed");
    if (failed.length) {
      const first = failed[0];
      throw new RestError(failed.map((item) => `${item.hash}: ${item.error?.message ?? "Operation failed"}`).join("; "),
        first.httpStatus, first.error?.code, items);
    }
    return items;
  }

  async post<T>(path: string, body: unknown = {}): Promise<T> {
    return this.request<T>("POST", path, body);
  }

  async captureDiagnosticBundle(maxBytes: number): Promise<Record<string, unknown>> {
    // This endpoint deliberately returns the bundle itself, not a data envelope.
    const bundle = await this.request<Record<string, unknown>>(
      "POST", "diagnostics/bundles", { confirmCapture: true, maxBytes }, "json"
    );
    if (!isRecord(bundle) || bundle.schema !== "emulebb.diagnostic-bundle.v7" || typeof bundle.capturedAt !== "string") {
      throw new Error("Diagnostic bundle returned an unexpected response");
    }
    return bundle;
  }

  async patch<T>(path: string, body: unknown): Promise<T> {
    return this.request<T>("PATCH", path, body);
  }

  async delete<T>(path: string, body?: unknown): Promise<T> {
    return this.request<T>("DELETE", path, body);
  }

  async streamDownloadEvents(
    onEvent: (event: DownloadEvent, cursor?: string) => void,
    options: StreamDownloadEventsOptions = {}
  ): Promise<void> {
    const headers: Record<string, string> = { Accept: "text/event-stream" };
    if (this.apiKey) {
      headers["X-API-Key"] = this.apiKey;
    }
    if (options.lastEventId) {
      headers["Last-Event-ID"] = options.lastEventId;
    }
    const requestPath = `${this.basePath}/events`;
    const response = await this.fetchImpl(requestPath, {
      method: "GET",
      headers,
      signal: options.signal
    });
    if (!response.ok) {
      const text = await response.text();
      const value = parseApiEnvelope<unknown>("GET", requestPath, response, text);
      const message = value?.error?.message ?? `GET ${requestPath} failed`;
      throw new RestError(message, response.status, value?.error?.code, value?.error?.details);
    }
    if (!isEventStreamResponse(response)) {
      throw new Error(`GET ${requestPath} returned ${describeContentType(response)}; expected text/event-stream`);
    }
    if (!response.body) {
      throw new Error(`GET ${requestPath} returned no stream body`);
    }
    await readDownloadEventStream(response.body, onEvent, options.signal);
  }

  private async request<T>(method: string, path: string, body?: unknown, responseKind: "envelope" | "json" = "envelope"): Promise<T> {
    const headers: Record<string, string> = {};
    if (this.apiKey) {
      headers["X-API-Key"] = this.apiKey;
    }
    const init: RequestInit = { method, headers };
    if (body !== undefined) {
      headers["Content-Type"] = "application/json";
      init.body = JSON.stringify(body);
    }
    const response = await this.fetchImpl(`${this.basePath}/${path}`, init);
    const text = await response.text();
    const requestPath = `${this.basePath}/${path}`;
    const value = parseApiEnvelope<T>(method, requestPath, response, text);
    if (!response.ok) {
      const message = value?.error?.message ?? `${method} ${requestPath} failed`;
      throw new RestError(message, response.status, value?.error?.code, value?.error?.details);
    }
    return (responseKind === "json" ? value : value?.data) as T;
  }
}

function checkedSettingsSnapshot(value: SettingsSnapshot): SettingsSnapshot {
  const revision = value?.meta?.settingsRevision;
  if (typeof revision !== "string" || !/^[1-9][0-9]{0,18}$/.test(revision) || BigInt(revision) > 9223372036854775807n
      || !isRecord(value.data?.saved) || !isRecord(value.data?.effective)
      || !Array.isArray(value.data?.application?.pendingRestart) || !Array.isArray(value.data?.application?.failed)) {
    throw new Error("Settings response is missing a valid saved revision or settings data.");
  }
  return value;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function normalizeBasePath(basePath: string): string {
  return basePath.replace(/\/+$/, "");
}

async function readDownloadEventStream(
  body: ReadableStream<Uint8Array>,
  onEvent: (event: DownloadEvent, cursor?: string) => void,
  signal?: AbortSignal
): Promise<void> {
  const reader = body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  try {
    for (;;) {
      if (signal?.aborted) {
        return;
      }
      const { done, value } = await reader.read();
      if (done) {
        break;
      }
      buffer += decoder.decode(value, { stream: true });
      buffer = drainSseFrames(buffer, onEvent);
      if (buffer.length > 65_536) {
        throw new Error("Download event frame exceeds the stream buffer limit");
      }
    }
    buffer += decoder.decode();
    drainSseFrames(`${buffer}\n\n`, onEvent);
  } finally {
    reader.releaseLock();
  }
}

function drainSseFrames(buffer: string, onEvent: (event: DownloadEvent, cursor?: string) => void): string {
  for (;;) {
    const separator = sseFrameSeparator(buffer);
    if (separator === undefined) {
      return buffer;
    }
    const frame = buffer.slice(0, separator.index);
    buffer = buffer.slice(separator.index + separator.length);
    const event = parseDownloadEventFrame(frame);
    if (event) {
      onEvent(event.event, event.cursor);
    }
  }
}

function sseFrameSeparator(buffer: string): { index: number; length: number } | undefined {
  const lf = buffer.indexOf("\n\n");
  const crlf = buffer.indexOf("\r\n\r\n");
  if (lf < 0) {
    return crlf < 0 ? undefined : { index: crlf, length: 4 };
  }
  if (crlf < 0 || lf < crlf) {
    return { index: lf, length: 2 };
  }
  return { index: crlf, length: 4 };
}

function parseDownloadEventFrame(frame: string): { event: DownloadEvent; cursor?: string } | undefined {
  const data = frame
    .split(/\r?\n/)
    .filter((line) => line.startsWith("data:"))
    .map((line) => line.slice(5).trimStart())
    .join("\n");
  if (!data) {
    return undefined;
  }
  // Preserve the server's opaque SSE cursor verbatim. Rebuilding it from the
  // JSON numeric revision loses precision above JavaScript's safe integer range.
  const cursor = frame.split(/\r?\n/)
    .filter((line) => line.startsWith("id:"))
    .map((line) => line.slice(3).replace(/^ /, ""))
    .at(-1);
  return { event: JSON.parse(data) as DownloadEvent, cursor };
}

function parseApiEnvelope<T>(
  method: string,
  path: string,
  response: Response,
  text: string
): (ApiEnvelope<T> & ApiError) | undefined {
  if (!text) {
    return undefined;
  }
  if (!isJsonResponse(response, text)) {
    throw new Error(`${method} ${path} returned ${response.status} ${response.statusText || "response"} with ${describeContentType(response)}; expected a REST JSON envelope`);
  }
  try {
    return JSON.parse(text) as ApiEnvelope<T> & ApiError;
  } catch (caught) {
    const message = caught instanceof Error ? caught.message : String(caught);
    throw new Error(`${method} ${path} returned invalid JSON: ${message}`);
  }
}

function isJsonResponse(response: Response, text: string): boolean {
  const contentType = response.headers.get("Content-Type") ?? "";
  return /\bapplication\/json\b|\+json\b/i.test(contentType) || /^[\s]*[{[]/.test(text);
}

function isEventStreamResponse(response: Response): boolean {
  return (response.headers.get("Content-Type") ?? "").toLowerCase().startsWith("text/event-stream");
}

function describeContentType(response: Response): string {
  return response.headers.get("Content-Type") || "a non-JSON body";
}
