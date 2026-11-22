import type { Upload } from "../../src/api";
import { settingsFixture, settingsSurfaceFixture, applySettingsFixture } from "./settings";
import type { Route } from "@playwright/test";

export type RecordedApiRequest = {
  method: string;
  path: string;
  query: string;
  headers: Record<string, string>;
  body: string | null;
};

const transferHash = "00112233445566778899AABBCCDDEEFF";
const sharedFileHash = "ffeeddccbbaa99887766554433221100";
const secondSharedFileHash = "0123456789abcdeffedcba9876543210";
const longSharedRoot =
  "\\\\?\\F:\\Sample\\Shared\\Deep Library Root With Long Name\\Album Archive Segment With A Very Long Folder Name\\Leaf Collection";

export function uploadFixture(overrides: Partial<Upload> = {}): Upload {
  return { id: "12345678-1234-4234-8234-123456789abc", userHash: null,
    clientSoftware: "Sample Client", uploadState: "uploading", uploadRateBytesPerSec: 8192,
    sessionUploadedBytes: 4096, waitTimeSeconds: 12, uploadDurationSeconds: 3,
    address: "192.0.2.10", port: 4662, lowId: null, friendSlot: false, connected: true,
    requestedFileHash: sharedFileHash, requestedFileName: "Shared Sample.bin", requestedFileSizeBytes: 4096,
    filePartsAvailable: 1, filePartsTotal: 1, queueRank: null, ...overrides };
}

const snapshot = {
  app: { version: "0.1.0-beta.2" },
  status: {
    lifecycle: "running",
    sharedStartupCache: {
      hashingCount: 1,
      deferredHashingActive: true,
      reloadProgress: {
        phase: "hashing",
        running: true,
        plannedHashCount: 3,
        activeHashCount: 1,
        hashedCount: 1,
        plannedReadBytes: 24576,
        completedReadBytes: 12288,
        readRateBytesPerSec: 4096
      }
    },
    runtimeDiagnostics: {
      sharedFileCount: 1,
      sharedHashingCount: 1,
      sharedDirectoryReloadProgress: {
        phase: "hashing",
        running: true,
        plannedHashCount: 3,
        activeHashCount: 1,
        hashedCount: 1,
        plannedReadBytes: 24576,
        completedReadBytes: 12288,
        readRateBytesPerSec: 4096
      },
      ed2kPublish: { phase: "published" },
      kadPublish: { phase: "waiting" },
      downloadEvents: {
        enabled: true,
        stream: "sse",
        epoch: "00000000-0000-4000-8000-000000000001",
        channelCapacity: 1024,
        queuedEventCount: 0,
        subscriberCount: 1,
        latestEventId: 0,
        nextEventId: 1,
        resumeBehavior: "reset"
      }
    },
    stats: {
      activeUploads: 2,
      waitingUploads: 3,
      downloadSpeedKiBps: 2,
      uploadSpeedKiBps: 1
    },
    servers: {
      connected: true,
      connecting: false,
      currentServer: { endpoint: "192.0.2.10:4661", name: "Sample Server", connected: true, current: true },
      ed2kIdState: "high",
      serverCount: 1
    }
  },
  downloads: { unfinished: 1, completed: 0 },
  searches: [],
  servers: [{ endpoint: "192.0.2.10:4661", name: "Sample Server", connected: true, auxiliaryPorts: [4662, 4663] }],
  kad: { enabled: true, connected: true, firewalled: false },
  uploads: [uploadFixture()],
  uploadQueue: [uploadFixture({ id: "12345678-1234-4234-8234-123456789abd", address: "192.0.2.11",
    uploadState: "queued", uploadRateBytesPerSec: 0, sessionUploadedBytes: 0,
    uploadDurationSeconds: null, connected: false, queueRank: 1 })],
  sharedFiles: [{
    hash: sharedFileHash,
    name: "Shared Sample.bin",
    path: "F:\\Sample\\Shared Sample.bin",
    sizeBytes: 4096,
    priority: "normal",
    publication: {
      ed2k: { state: "published", lastSuccessAtMs: 1_700_000_000_000 },
      kadKeyword: { state: "partial", publishedKeywords: 1, totalKeywords: 2, lastSuccessAtMs: 1_700_000_000_000 },
      kadSource: { state: "publishing", lastSuccessAtMs: null }
    }
  }]
};

const secondSharedFile = {
  ...snapshot.sharedFiles[0],
  hash: secondSharedFileHash,
  name: "Second Shared Sample.bin",
  path: "F:\\Sample\\Second Shared Sample.bin"
};

export function mockDownloadFixture() {
  return [{ id: "1", hash: transferHash.toLowerCase(), name: "Sample Transfer.bin", state: "downloading" as const, waitingReason: null,
    intent: "started" as const, progress: 0.25, sizeBytes: 4096, category: "Sample-Category", createdAt: 1, updatedAt: 1, completedAt: null }];
}

/** Fresh mutable dashboard state for stateful browser workflow tests. */
export function mockSnapshotFixture(): typeof snapshot {
  return structuredClone(snapshot);
}

export function installMockApi(requests: RecordedApiRequest[]) {
  let currentSettings = settingsFixture();
  let nextRootId = 3;
  let roots = [
    { id: "1", path: "C:\\Sample\\Shared", watchEnabled: false, managed: false, shareable: true, accessible: true, scanRequired: false, lastScannedAt: null },
    { id: "2", path: longSharedRoot, watchEnabled: false, managed: true, shareable: true, accessible: true, scanRequired: false, lastScannedAt: null }
  ];
  return async (route: Route): Promise<void> => {
    const request = route.request();
    const url = new URL(request.url());
    const path = url.pathname.replace(/^\/api\/v1\/?/, "");
    requests.push({
      method: request.method(),
      path,
      query: url.search,
      headers: request.headers(),
      body: request.postData()
    });

    if (request.method() === "POST" && path === "diagnostics/bundles") {
      const body = request.postDataJSON();
      const valid = body.confirmCapture === true && Number.isInteger(body.maxBytes)
        && body.maxBytes >= 65_536 && body.maxBytes <= 67_108_864;
      await route.fulfill({ status: valid ? 200 : 400, contentType: "application/json", body: JSON.stringify(valid
        ? { schema: "emulebb.diagnostic-bundle.v7", capturedAt: 1794657600, summary: { issueCount: 0 } }
        : { error: { code: "BAD_REQUEST", message: "A bounded maxBytes value is required" } }) });
      return;
    }
    if (request.method() === "GET" && path === "library/roots") {
      await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({
        data: roots, meta: { apiVersion: "v1", nextCursor: null, hasMore: false }
      }) });
      return;
    }
    if (request.method() === "GET" && /^library\/files\/[0-9a-f]{32}\/locations$/.test(path)) {
      const next = url.searchParams.has("cursor");
      await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({
        data: [{ path: next ? "/library/Cached-Second.bin" : "/library/Cached-First.bin", present: !next }],
        meta: { apiVersion: "v1", nextCursor: next ? null : "location-next", hasMore: !next }
      }) });
      return;
    }
    if (request.method() === "GET" && (path === "upload-queue" || path === "uploads")) {
      const waiting = path === "uploads" ? snapshot.uploads : snapshot.uploadQueue;
      await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({
        data: waiting, meta: { apiVersion: "v1", nextCursor: null, hasMore: false, total: waiting.length }
      }) });
      return;
    }
    if (request.method() === "POST" && path === "library/roots") {
      const body = request.postDataJSON();
      const root = { id: String(nextRootId++), path: body.path, watchEnabled: body.watchEnabled ?? false,
        managed: false, shareable: true, accessible: true, scanRequired: false, lastScannedAt: null };
      roots.push(root);
      await route.fulfill({ status: 201, contentType: "application/json",
        headers: { Location: `/api/v1/library/roots/${root.id}` }, body: JSON.stringify({ data: root }) });
      return;
    }
    if (/^library\/roots\/[1-9][0-9]*$/.test(path)) {
      const root = roots.find(value => value.id === path.split("/").at(-1));
      if (!root) {
        await route.fulfill({ status: 404, contentType: "application/json",
          body: JSON.stringify({ error: { code: "NOT_FOUND", message: "Library root not found" } }) });
      } else if (request.method() === "DELETE") {
        roots = roots.filter(value => value.id !== root.id);
        await route.fulfill({ status: 204, body: "" });
      } else {
        if (request.method() === "PATCH") root.watchEnabled = request.postDataJSON().watchEnabled;
        await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ data: root }) });
      }
      return;
    }

    if (request.method() === "GET" && (path === "library/tags" || /^library\/files\/[0-9a-f]{32}\/tags$/.test(path))) {
      await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({
        data: [{ name: "Alpha" }], meta: { apiVersion: "v1", nextCursor: null, hasMore: false }
      }) });
      return;
    }
    if (request.method() === "GET" && (path === "downloads" || /^downloads\/1\/(sources|parts|comments)$/.test(path))) {
      const data = path === "downloads"
        ? url.searchParams.get("view") === "completed" ? [] : mockDownloadFixture()
        : path.endsWith("sources") ? [{ clientId: "192.0.2.40:4662", userName: "Sample Peer", downloadState: "downloading", downloadRateBytesPerSecond: 2048, reportedFileNames: [], reportedFileNamesHasMore: false }] : [];
      await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ data, meta: { apiVersion: "2.0.0", nextCursor: null, hasMore: false } }) });
      return;
    }
    if (request.method() === "POST" && /^downloads\/(start|stop|verify|remove)$/.test(path)) {
      await route.fulfill({ status: 207, contentType: "application/json", body: JSON.stringify({ data: request.postDataJSON().ids.map((id: string) => ({ id, status: "accepted", httpStatus: 202 })) }) });
      return;
    }
    if (path === "settings") {
      if (request.method() === "PATCH") {
        const patch = request.postDataJSON();
        if (patch.expectedRevision !== currentSettings.meta.settingsRevision) {
          await route.fulfill({ status: 409, contentType: "application/json", body: JSON.stringify({ error: { code: "SETTINGS_CONFLICT", message: "Saved settings changed; read the latest revision." } }) });
          return;
        }
        currentSettings = applySettingsFixture(currentSettings, patch);
      }
      await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(currentSettings) });
      return;
    }
    const data = request.method() === "GET" && path === "shared-files"
      ? url.searchParams.has("cursor")
        ? { items: [secondSharedFile], total: 2, nextCursor: null }
        : { items: snapshot.sharedFiles, total: 2, nextCursor: "second-page" }
      : dataFor(request.method(), path);
    if (data === eventStream) {
      await route.fulfill({
        status: 200,
        contentType: "text/event-stream",
        body: [
          "event: sync.reset",
          "id: 00000000-0000-4000-8000-000000000001:0",
          'data: {"id":0,"epoch":"00000000-0000-4000-8000-000000000001","type":"sync.reset","reason":"initial"}',
          "",
          ""
        ].join("\n")
      });
      return;
    }
    if (data === undefined) {
      await route.fulfill({
        status: 404,
        contentType: "application/json",
        body: JSON.stringify({ error: { code: "NOT_FOUND", message: `No fixture for ${path}` } })
      });
      return;
    }

    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ data, ...(path === "searches" ? { meta: { apiVersion: "v1", nextCursor: null, hasMore: false } } : {}) })
    });
  };
}

const eventStream = Symbol("eventStream");

function dataFor(method: string, path: string): unknown {
  if (method !== "GET") {
    return {};
  }
  switch (path) {
    case "events":
      return eventStream;
    case "events/status":
      return snapshot.status.runtimeDiagnostics.downloadEvents;
    case "snapshot":
      return snapshot;
    case "searches":
      return snapshot.searches;
    case "kad/nodes":
      return { items: [] };
    case "logs":
      return { items: [{ timestamp: 1_767_225_600, level: "INFO", message: "Sample log entry" }] };
    case "library/scan":
      return {
        hashingCount: 1,
        reloadProgress: {
          phase: "hashing",
          running: true,
          pending: false,
          scannedCount: 12,
          plannedHashCount: 3,
          activeHashCount: 1,
          hashedCount: 1,
          failedHashCount: 0,
          reusedCount: 8,
          newCount: 2,
          changedCount: 1,
          skippedIntakeCount: 0,
          prunedCount: 0,
          diskCount: 1,
          plannedHashBytes: 12288,
          completedHashBytes: 4096,
          plannedReadBytes: 24576,
          completedReadBytes: 12288,
          readRateBytesPerSec: 4096,
          active: [
            {
              id: "hash-000002",
              diskKey: "C:",
              path: "\\\\?\\C:\\Sample\\Shared\\Hashing Now.bin",
              name: "Hashing Now.bin",
              sizeBytes: 4096,
              reason: "new",
              stage: "aich",
              stageReadBytes: 2048,
              stageTotalBytes: 4096,
              readBytes: 6144,
              readBytesTotal: 8192,
              readRateBytesPerSec: 4096
            }
          ],
          recent: [
            {
              id: "hash-000001",
              diskKey: "C:",
              path: "C:\\Sample\\Shared\\Recently Hashed.bin",
              name: "Recently Hashed.bin",
              sizeBytes: 4096,
              reason: "new",
              result: "ok",
              hash: "11223344556677889900AABBCCDDEEFF",
              readBytes: 8192,
              readBytesTotal: 8192,
              durationMs: 2000,
              averageReadRateBytesPerSec: 4096
            }
          ],
          upcoming: [
            {
              id: "hash-000003",
              diskKey: "C:",
              path: "\\\\?\\C:\\Sample\\Shared\\Queued Next.bin",
              name: "Queued Next.bin",
              sizeBytes: 4096,
              reason: "changed",
              order: 2
            }
          ],
          disks: [
            {
              diskKey: "C:",
              plannedCount: 3,
              activeCount: 1,
              completedCount: 1,
              failedCount: 0,
              queuedCount: 1,
              plannedReadBytes: 24576,
              completedReadBytes: 12288,
              readRateBytesPerSec: 4096,
              currentPath: "\\\\?\\C:\\Sample\\Shared\\Hashing Now.bin",
              currentName: "Hashing Now.bin",
              currentStage: "aich"
            }
          ]
        }
      };
    case "library/ignores":
      return {
        custom: [{ pattern: "*.private.bin" }],
        defaults: [
          {
            key: "mfc-runtime-database",
            matchKind: "file-name",
            pattern: "downloads.met",
            enabled: true
          },
          {
            key: "operating-system-noise",
            matchKind: "file-name",
            pattern: "Thumbs.db",
            enabled: false
          }
        ]
      };
    case "shared-files":
      return { items: snapshot.sharedFiles, total: snapshot.sharedFiles.length, nextCursor: null };
    case `shared-files/${sharedFileHash}/ed2k-link`:
      return { hash: sharedFileHash, link: "ed2k://|file|Shared%20Sample.bin|4096|ffeeddccbbaa99887766554433221100|/" };
    case `shared-files/${sharedFileHash}/comments`:
      return { items: [] };
    case `shared-files/${secondSharedFileHash}/ed2k-link`:
      return { hash: secondSharedFileHash, link: "ed2k://|file|Second%20Shared%20Sample.bin|4096|0123456789abcdeffedcba9876543210|/" };
    case `shared-files/${secondSharedFileHash}/comments`:
      return { items: [] };
    case "categories":
      return { items: [{ name: "Sample-Category", tempDir: null, destinationDir: null, comment: "" }] };
    case "friends":
      return { items: [] };
    case "ip-filter":
      return {
        configured: true,
        reloadable: true,
        path: "C:\\Sample\\ipfilter.dat",
        level: 127,
        rangeCount: 3
      };
    case "network":
      return {
        ports: {
          tcp: 20019,
          udp: 20020,
          serverUdp: null
        },
        binding: {
          configuredAddress: "192.0.2.10",
          configuredInterfaceId: "test-adapter",
          configuredInterfaceName: "Test Adapter",
          activeConfiguredAddress: "192.0.2.10",
          activeInterfaceId: "test-adapter",
          activeInterfaceName: "Test Adapter",
          activeInterfaceIndex: 12,
          resolveResult: "resolved"
        },
        vpnGuard: {
          enabled: true,
          mode: "block",
          allowedPublicIpCidrs: "203.0.113.0/24",
          startupBlocked: false,
          startupBlockReason: "",
          publicIp: "203.0.113.10",
          egressVerified: true,
          egressBlockReason: "",
          stunProbe: { attempted: true, succeeded: true, publicIp: "203.0.113.10", provider: "stun", error: null },
          httpProbe: { attempted: true, succeeded: true, publicIp: "203.0.113.10", provider: "http", error: null }
        }
      };
    case "nat":
      return {
        enabled: true,
        gatewayDiscovered: true,
        backend: "upnp_miniupnpc",
        protocol: "upnp_igd",
        bindIp: "192.0.2.10",
        pcpServerIp: null,
        igdIp: "192.0.2.1",
        minissdpdSocket: null,
        ssdpLocalPort: null,
        externalIpOverride: null,
        gateway: {
          backend: "upnp_miniupnpc",
          controlUrl: "http://192.0.2.1:5000/rootDesc.xml",
          localIp: "192.0.2.10",
          gatewayIp: "192.0.2.1",
          externalIp: "203.0.113.10"
        },
        mappings: [
          {
            name: "ed2k_tcp",
            protocol: "tcp",
            localAddr: "192.0.2.10:20019",
            externalAddr: "203.0.113.10:20019",
            leaseExpiresInSecs: 1800,
            backend: "miniupnpc"
          },
          {
            name: "kad_udp",
            protocol: "udp",
            localAddr: "192.0.2.10:20020",
            externalAddr: "203.0.113.10:20020",
            leaseExpiresInSecs: 1800,
            backend: "miniupnpc"
          }
        ],
        observedExternalAddresses: ["203.0.113.10"],
        lastRefreshUnixSecs: 1784390000,
        lastError: null
      };
    case "vpn-guard":
      return {
        enabled: true,
        mode: "block",
        allowedPublicIpCidrs: "203.0.113.0/24",
        startupBlocked: false,
        startupBlockReason: "",
        publicIp: "203.0.113.10",
        egressVerified: true,
        egressBlockReason: "",
        stunProbe: {
          attempted: true,
          succeeded: true,
          publicIp: "203.0.113.10",
          provider: "stun",
          error: null
        },
        httpProbe: {
          attempted: true,
          succeeded: true,
          publicIp: "203.0.113.10",
          provider: "http",
          error: null
        }
      };
    case "settings/surface":
      return settingsSurfaceFixture;
    case "uploads/12345678-1234-4234-8234-123456789abc":
      return { ...snapshot.uploads[0], scoreBreakdown: uploadScore(100) };
    case "upload-queue/12345678-1234-4234-8234-123456789abd":
      return { ...snapshot.uploadQueue[0], scoreBreakdown: uploadScore(50) };
    case "app":
      return {
        name: "eMuleBB",
        version: "0.1.0-beta.2",
        apiVersion: "v1",
        capabilities: { downloads: true, "downloads.sse": true, "downloads.sse.status": true }
      };
    case "capabilities":
      return { contractVersion: "2.0.0", apiVersion: "v1", capabilities: ["downloads", "downloads.sse", "downloads.sse.status"] };
    case "diagnostics":
      return snapshot.status.runtimeDiagnostics;
    case "downloads/1":
      return { ...mockDownloadFixture()[0], payloadVerified: false, delivery: { path: null, state: "pending", ownership: "none" }, failure: null };
    default:
      return undefined;
  }
}

export function uploadScore(score: number) {
  return { score, creditRatio: 2, filePriorityScore: 1, lowRatioApplied: false,
    lowRatioBonus: 0, lowIdPenaltyApplied: false, lowIdDivisor: 1, oldClientPenaltyApplied: false };
}
