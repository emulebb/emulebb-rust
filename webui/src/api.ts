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
  runtimeDiagnostics?: {
    sharedHashingCount?: number;
    sharedDirectoryReloadProgress?: SharedDirectoryReloadProgress;
    ed2kPublish?: Record<string, unknown>;
    kadPublish?: Record<string, unknown>;
    [key: string]: unknown;
  };
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

export type AppSettings = {
  core?: Record<string, unknown>;
  daemon?: Record<string, unknown>;
  ed2k?: Record<string, unknown>;
  kad?: Record<string, unknown>;
  nat?: Record<string, unknown>;
  vpnGuard?: Record<string, unknown>;
  ipFilter?: Record<string, unknown>;
  [key: string]: unknown;
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

function describeContentType(response: Response): string {
  return response.headers.get("Content-Type") || "a non-JSON body";
}
