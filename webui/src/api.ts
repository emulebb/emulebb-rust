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
  directory?: string;
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
  [key: string]: unknown;
};

export type KadStatus = {
  enabled?: boolean;
  connected?: boolean;
  firewalled?: boolean | null;
  indexedKeywordCount?: number;
  indexedSourceCount?: number;
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

export type SharedReloadDiagnostics = {
  phase?: string;
  running?: boolean;
  pending?: boolean;
  scannedCount?: number;
  plannedHashCount?: number;
  reusedCount?: number;
  newCount?: number;
  changedCount?: number;
  skippedIntakeCount?: number;
  prunedCount?: number;
  [key: string]: unknown;
};

export type SharedDirectories = {
  roots?: SharedDirectoryRoot[];
  items?: SharedDirectoryRoot[];
  monitorOwned?: string[];
  hashingCount?: number;
  reload?: SharedReloadDiagnostics;
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

export function encodeSegment(value: string): string {
  return encodeURIComponent(value);
}

export class RestClient {
  private apiKey = "";

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
    const response = await fetch(`/api/v1/${path}`, init);
    const text = await response.text();
    const value = text ? (JSON.parse(text) as ApiEnvelope<T> & ApiError) : undefined;
    if (!response.ok) {
      const message = value?.error?.message ?? `${method} /api/v1/${path} failed`;
      throw new Error(message);
    }
    return value?.data as T;
  }
}
