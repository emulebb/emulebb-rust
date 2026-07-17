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

export type AppInfo = {
  appName?: string;
  apiVersion?: string;
  contractVersion?: string;
  version?: string;
};

export type Stats = {
  downloadRateBytesPerSec?: number;
  uploadRateBytesPerSec?: number;
  activeDownloads?: number;
  totalTransfers?: number;
  sharedFiles?: number;
  sharedBytes?: number;
};

export type Status = {
  lifecycle?: string;
  connected?: boolean;
  serverConnected?: boolean;
  firewalled?: boolean | null;
  stats?: Stats;
  [key: string]: unknown;
};

export type Transfer = {
  hash: string;
  name?: string;
  state?: string;
  sizeBytes?: number;
  completedBytes?: number;
  downloadRateBytesPerSec?: number;
  uploadRateBytesPerSec?: number;
  priority?: string;
  categoryId?: number | null;
  sources?: number;
  [key: string]: unknown;
};

export type SearchResult = {
  hash: string;
  name?: string;
  sizeBytes?: number;
  sources?: number;
  availability?: number;
  [key: string]: unknown;
};

export type SearchItem = {
  id: string;
  query?: string;
  state?: string;
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

export type Snapshot = {
  app?: AppInfo;
  status?: Status;
  stats?: Stats;
  transfers?: Transfer[];
  searches?: SearchItem[];
  servers?: ServerItem[];
  kad?: KadStatus;
  uploads?: unknown[];
  uploadQueue?: unknown[];
  sharedFiles?: unknown[];
  [key: string]: unknown;
};

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
