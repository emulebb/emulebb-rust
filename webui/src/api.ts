export type ApiEnvelope<T> = {
  data: T;
  meta?: Record<string, unknown>;
};

export type ApiError = {
  error?: {
    code?: string;
    message?: string;
  };
};

export type Page<T> = {
  items: T[];
  total?: number;
  offset?: number;
  limit?: number;
};

export type AppInfo = {
  appName?: string;
  apiVersion?: string;
  contractVersion?: string;
  name?: string;
  version?: string;
  [key: string]: unknown;
};

export type Stats = {
  downloadRateBytesPerSec?: number;
  uploadRateBytesPerSec?: number;
  downloadSpeedKiBps?: number;
  uploadSpeedKiBps?: number;
  activeDownloads?: number;
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
  serverConnected?: boolean;
  firewalled?: boolean | null;
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

export type RuntimeDiagnostics = {
  processId?: number;
  knownFileCount?: number;
  sharedFileCount?: number;
  sharedHashingCount?: number;
  sharedDirectoryReloadProgress?: SharedDirectoryReloadProgress;
  ed2kPublish?: Record<string, unknown>;
  kadPublish?: Record<string, unknown>;
  transferEvents?: TransferEventRuntimeDiagnostics;
  downloadFileCount?: number;
  activeUploads?: number;
  waitingUploads?: number;
  geolocation?: Record<string, unknown> | null;
  [key: string]: unknown;
};

export type TransferEventRuntimeDiagnostics = {
  enabled?: boolean;
  stream?: string;
  channelCapacity?: number;
  queuedEventCount?: number;
  subscriberCount?: number;
  latestEventId?: number;
  nextEventId?: number;
  resumeBehavior?: string;
  [key: string]: unknown;
};

export type Transfer = {
  hash: string;
  name?: string;
  path?: string;
  deliveredPath?: string | null;
  state?: string;
  sizeBytes?: number;
  completedBytes?: number;
  progress?: number;
  downloadRateBytesPerSec?: number;
  uploadRateBytesPerSec?: number;
  downloadSpeedKiBps?: number;
  uploadSpeedKiBps?: number;
  priority?: string;
  categoryId?: number | null;
  categoryName?: string | null;
  sources?: number;
  sourcesTransferring?: number;
  stopped?: boolean;
  ed2kLink?: string;
  [key: string]: unknown;
};

export type TransferAddedEvent = {
  id: number;
  type: "transfer.added";
  transfer: Transfer;
  [key: string]: unknown;
};

export type TransferUpdatedEvent = {
  id: number;
  type: "transfer.updated";
  transfer: Transfer;
  [key: string]: unknown;
};

export type TransferRemovedEvent = {
  id: number;
  type: "transfer.removed";
  hash: string;
  [key: string]: unknown;
};

export type SyncResetEvent = {
  id: number;
  type: "sync.reset";
  reason: "lagged" | "last-event-id";
  missed?: number;
  lastEventId?: string;
  [key: string]: unknown;
};

export type TransferEvent = TransferAddedEvent | TransferUpdatedEvent | TransferRemovedEvent | SyncResetEvent;

export type TransferSource = {
  clientId?: string;
  userName?: string;
  userHash?: string | null;
  state?: string;
  address?: string;
  port?: number;
  downloadRateBytesPerSec?: number;
  downloadSpeedKiBps?: number;
  requestedFileName?: string | null;
  banned?: boolean;
  friend?: boolean;
  lowId?: boolean;
  [key: string]: unknown;
};

export type SearchResult = {
  hash: string;
  name?: string;
  sizeBytes?: number;
  sources?: number;
  completeSources?: number;
  availability?: number;
  fileType?: string;
  knownType?: string;
  directory?: string;
  evidence?: Record<string, unknown>;
  [key: string]: unknown;
};

export type SearchItem = {
  id: string;
  query?: string;
  state?: string;
  status?: string;
  statusReason?: string | null;
  method?: string;
  type?: string;
  results?: SearchResult[];
  resultCount?: number;
  [key: string]: unknown;
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
  failedCount?: number;
  hardFiles?: number;
  ip?: string;
  ping?: number;
  softFiles?: number;
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
  id: number;
  name: string;
  path?: string | null;
  comment?: string;
  priority?: number | string;
  color?: number | null;
  [key: string]: unknown;
};

export type Friend = {
  userHash?: string;
  name?: string;
  lastSeen?: string | null;
  address?: string | null;
  port?: number;
  [key: string]: unknown;
};

export type Upload = {
  clientId?: string;
  userName?: string;
  userHash?: string | null;
  clientSoftware?: string;
  clientMod?: string;
  uploadState?: string;
  uploadSpeedKiBps?: number;
  uploadedBytes?: number;
  queueSessionUploaded?: number;
  waitTimeMs?: number;
  score?: number;
  address?: string;
  port?: number;
  lowId?: boolean;
  friendSlot?: boolean;
  uploading?: boolean;
  waitingQueue?: boolean;
  requestedFileHash?: string | null;
  requestedFileName?: string | null;
  requestedFileSizeBytes?: number | null;
  requestedPartsProgressText?: string;
  queueRank?: number;
  scoreBreakdown?: Record<string, unknown> | null;
  [key: string]: unknown;
};

export type SharedFile = {
  hash: string;
  name?: string;
  sizeBytes?: number;
  sourcePath?: string | null;
  path?: string;
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
  [key: string]: unknown;
};

export type SharedDirectoryRoot = {
  path: string;
  monitorOwned?: boolean;
  shareable?: boolean;
  accessible?: boolean;
  [key: string]: unknown;
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
  missingMtimeCount?: number;
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

export type SharedDirectories = {
  roots?: SharedDirectoryRoot[];
  items?: SharedDirectoryRoot[];
  monitorOwned?: string[];
  hashingCount?: number;
  reloadProgress?: SharedDirectoryReloadProgress;
  [key: string]: unknown;
};

export type CoreSettings = {
  uploadLimitKiBps?: number;
  downloadLimitKiBps?: number;
  maxConnections?: number;
  maxConnectionsPerFiveSeconds?: number;
  maxSourcesPerFile?: number;
  uploadClientDataRate?: number;
  maxUploadSlots?: number;
  uploadSlotElasticPercent?: number;
  queueSize?: number;
  autoConnect?: boolean;
  reconnect?: boolean;
  creditSystem?: boolean;
  safeServerConnect?: boolean;
  addServersFromServer?: boolean;
  networkKademlia?: boolean;
  networkEd2k?: boolean;
  [key: string]: unknown;
};

export type HostnameLookupSettings = {
  enabled?: boolean;
  dnsServers?: string[];
  cacheTtlSecs?: number;
  maxLookupsPerTick?: number;
  tickIntervalSecs?: number;
  [key: string]: unknown;
};

export type DaemonSettings = {
  incomingDir?: string | null;
  p2pBindIp?: string | null;
  p2pBindInterface?: string | null;
  ed2kUserHash?: string | null;
  hostnameLookup?: HostnameLookupSettings;
  [key: string]: unknown;
};

export type Ed2kUploadQueueSettings = {
  activeSlots?: number;
  elasticPercent?: number;
  uploadLimitBytesPerSec?: number;
  elasticUnderfillBytesPerSec?: number;
  elasticUnderfillSecs?: number;
  waitingCapacity?: number;
  waitingTimeoutSecs?: number;
  grantedTimeoutSecs?: number;
  uploadTimeoutSecs?: number;
  sessionTransferPercent?: number;
  sessionTimeLimitSecs?: number;
  [key: string]: unknown;
};

export type Ed2kSettings = {
  listenPort?: number | null;
  obfuscationEnabled?: boolean;
  probeSearchTerm?: string | null;
  connectTimeoutSecs?: number;
  serverConnectTimeoutSecs?: number;
  callbackTimeoutSecs?: number;
  reconnectIntervalSecs?: number;
  reconnectEnabled?: boolean;
  safeServerConnect?: boolean;
  keepaliveSecs?: number;
  sessionRotationSecs?: number;
  maxConcurrentDownloads?: number;
  maxNewConnectionsPerFiveSeconds?: number;
  maxHalfOpenConnections?: number;
  maxSourcesPerFile?: number;
  maxParallelDownloadPeers?: number;
  keywordServerAttemptBudget?: number;
  exactHashKeywordServerAttemptBudget?: number;
  sourceServerAttemptBudget?: number;
  uploadQueue?: Ed2kUploadQueueSettings;
  downloadLimitBytesPerSec?: number;
  enableUdpReask?: boolean;
  publishEmuleRustIdentity?: boolean;
  addServersFromServer?: boolean;
  deadServerRetries?: number;
  [key: string]: unknown;
};

export type KadSettings = {
  listenPort?: number | null;
  bootstrapMinRoutingContacts?: number;
  localStoreEnabled?: boolean;
  localStoreKeywordTtlSecs?: number;
  localStoreSourceTtlSecs?: number;
  localStoreNotesTtlSecs?: number;
  localStoreKeywordCapacity?: number;
  localStoreSourceCapacity?: number;
  localStoreNotesCapacity?: number;
  localStoreSourcePerFileCapacity?: number;
  localStoreNotesPerFileCapacity?: number;
  publishSharedFilesEnabled?: boolean;
  republishIntervalSecs?: number;
  publishContactFanout?: number;
  udpFirewallCheckEnabled?: boolean;
  udpFirewallCheckIntervalSecs?: number;
  tcpFirewallCheckEnabled?: boolean;
  tcpFirewallCheckIntervalSecs?: number;
  buddyEnabled?: boolean;
  routingMaintenanceEnabled?: boolean;
  snoopQueueDedupWindowSecs?: number;
  snoopQueueGeneralMaxQueriesPer600s?: number;
  snoopQueueGeneralDrainCooldownSecs?: number;
  snoopQueueSourceMaxQueriesPer600s?: number;
  snoopQueueSourceDrainCooldownSecs?: number;
  snoopQueueSourceStopAfterResults?: number;
  [key: string]: unknown;
};

export type NatSettings = {
  enabled?: boolean;
  requireInitialMapping?: boolean;
  backendOrder?: string[];
  bindIp?: string | null;
  igdIp?: string | null;
  minissdpdSocket?: string | null;
  ssdpLocalPort?: number | null;
  discoveryTimeoutSecs?: number;
  leaseDurationSecs?: number;
  renewMarginSecs?: number;
  externalIpOverride?: string | null;
  [key: string]: unknown;
};

export type VpnGuardSettings = {
  enabled?: boolean;
  mode?: string;
  allowedPublicIpCidrs?: string;
  [key: string]: unknown;
};

export type IpFilterSettings = {
  enabled?: boolean;
  path?: string | null;
  level?: number;
  [key: string]: unknown;
};

export type AppSettings = {
  core?: CoreSettings;
  daemon?: DaemonSettings;
  ed2k?: Ed2kSettings;
  kad?: KadSettings;
  nat?: NatSettings;
  vpnGuard?: VpnGuardSettings;
  ipFilter?: IpFilterSettings;
  [key: string]: unknown;
};

export type SettingSurfaceClass = "normalControl" | "advancedControl" | "existingSectionResource" | "bootstrapOnly" | "notUserFacing";

export type SettingSurfaceSpec = {
  path: string;
  class: SettingSurfaceClass;
  restartRequired: boolean;
  uiSection: string;
  route: string;
  description: string;
};

export type SettingsSectionResourceSpec = {
  name: string;
  class: "existingSectionResource";
  route: string;
  uiSection: string;
  description: string;
};

export type SettingsSurface = {
  settings: SettingSurfaceSpec[];
  sectionResources: SettingsSectionResourceSpec[];
};

export type Snapshot = {
  app?: AppInfo;
  status?: Status;
  stats?: Stats;
  transfers?: Transfer[];
  searches?: SearchItem[];
  servers?: ServerItem[];
  kad?: KadStatus;
  uploads?: Upload[];
  uploadQueue?: Upload[];
  sharedFiles?: SharedFile[];
  network?: Record<string, unknown>;
  logs?: LogRecord[];
  [key: string]: unknown;
};

export type RestClientOptions = {
  basePath?: string;
  fetch?: typeof fetch;
};

export type StreamTransferEventsOptions = {
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

  async get<T>(path: string): Promise<T> {
    return this.request<T>("GET", path);
  }

  async post<T>(path: string, body: unknown = {}): Promise<T> {
    return this.request<T>("POST", path, body);
  }

  async patch<T>(path: string, body: unknown): Promise<T> {
    return this.request<T>("PATCH", path, body);
  }

  async delete<T>(path: string): Promise<T> {
    return this.request<T>("DELETE", path);
  }

  async streamTransferEvents(
    onEvent: (event: TransferEvent) => void,
    options: StreamTransferEventsOptions = {}
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
      throw new Error(message);
    }
    if (!isEventStreamResponse(response)) {
      throw new Error(`GET ${requestPath} returned ${describeContentType(response)}; expected text/event-stream`);
    }
    if (!response.body) {
      throw new Error(`GET ${requestPath} returned no stream body`);
    }
    await readTransferEventStream(response.body, onEvent, options.signal);
  }

  private async request<T>(method: string, path: string, body?: unknown): Promise<T> {
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
      throw new Error(message);
    }
    return value?.data as T;
  }
}

function normalizeBasePath(basePath: string): string {
  return basePath.replace(/\/+$/, "");
}

async function readTransferEventStream(
  body: ReadableStream<Uint8Array>,
  onEvent: (event: TransferEvent) => void,
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
    }
    buffer += decoder.decode();
    drainSseFrames(`${buffer}\n\n`, onEvent);
  } finally {
    reader.releaseLock();
  }
}

function drainSseFrames(buffer: string, onEvent: (event: TransferEvent) => void): string {
  for (;;) {
    const separator = sseFrameSeparator(buffer);
    if (separator === undefined) {
      return buffer;
    }
    const frame = buffer.slice(0, separator.index);
    buffer = buffer.slice(separator.index + separator.length);
    const event = parseTransferEventFrame(frame);
    if (event) {
      onEvent(event);
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

function parseTransferEventFrame(frame: string): TransferEvent | undefined {
  const data = frame
    .split(/\r?\n/)
    .filter((line) => line.startsWith("data:"))
    .map((line) => line.slice(5).trimStart())
    .join("\n");
  if (!data) {
    return undefined;
  }
  return JSON.parse(data) as TransferEvent;
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
