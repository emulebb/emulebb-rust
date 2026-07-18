import type { Route } from "@playwright/test";

export type RecordedApiRequest = {
  method: string;
  path: string;
  headers: Record<string, string>;
  body: string | null;
};

const transferHash = "00112233445566778899AABBCCDDEEFF";

const snapshot = {
  app: { version: "0.1.0-beta.1" },
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
      kadPublish: { phase: "waiting" }
    },
    stats: {
      downloadRateBytesPerSec: 2048,
      uploadRateBytesPerSec: 1024,
      sharedFiles: 1,
      sharedBytes: 4096
    }
  },
  stats: {
    downloadRateBytesPerSec: 2048,
    uploadRateBytesPerSec: 1024,
    sharedFiles: 1,
    sharedBytes: 4096
  },
  transfers: [
    {
      hash: transferHash,
      name: "Sample Transfer.bin",
      state: "downloading",
      sizeBytes: 4096,
      completedBytes: 1024,
      downloadRateBytesPerSec: 2048,
      categoryId: 1
    }
  ],
  searches: [],
  servers: [{ endpoint: "192.0.2.10:4661", name: "Sample Server", connected: true }],
  kad: { enabled: true, connected: true, firewalled: false },
  uploads: [],
  uploadQueue: [],
  sharedFiles: [{ hash: "FFEEDDCCBBAA99887766554433221100", name: "Shared Sample.bin", sizeBytes: 4096 }]
};

export function installMockApi(requests: RecordedApiRequest[]) {
  return async (route: Route): Promise<void> => {
    const request = route.request();
    const url = new URL(request.url());
    const path = url.pathname.replace(/^\/api\/v1\/?/, "");
    requests.push({
      method: request.method(),
      path,
      headers: request.headers(),
      body: request.postData()
    });

    const data = dataFor(request.method(), path);
    if (data === eventStream) {
      await route.fulfill({
        status: 200,
        contentType: "text/event-stream",
        body: [
          "event: sync.reset",
          "id: 1",
          'data: {"id":1,"type":"sync.reset","reason":"last-event-id","lastEventId":"0"}',
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
      body: JSON.stringify({ data })
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
    case "snapshot":
      return snapshot;
    case "logs":
      return { items: [{ timestamp: "2026-01-01T00:00:00Z", level: "INFO", message: "Sample log entry" }] };
    case "shared-directories":
      return {
        roots: [{ path: "C:\\Sample\\Shared", monitorOwned: true, shareable: true, accessible: true }],
        items: [],
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
              path: "C:\\Sample\\Shared\\Hashing Now.bin",
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
              path: "C:\\Sample\\Shared\\Queued Next.bin",
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
              currentPath: "C:\\Sample\\Shared\\Hashing Now.bin",
              currentName: "Hashing Now.bin",
              currentStage: "aich"
            }
          ]
        }
      };
    case "shared-files":
      return { items: snapshot.sharedFiles };
    case "categories":
      return { items: [{ id: 1, name: "Sample Category", priority: 0 }] };
    case "friends":
      return { items: [] };
    case "app/settings/surface":
      return {
        settings: [
          setting("core.uploadLimitKiBps", "normalControl", false),
          setting("core.downloadLimitKiBps", "normalControl", false),
          setting("core.maxConnections", "advancedControl", false),
          setting("core.maxConnectionsPerFiveSeconds", "advancedControl", false),
          setting("core.maxSourcesPerFile", "advancedControl", false),
          setting("core.uploadClientDataRate", "advancedControl", false),
          setting("core.maxUploadSlots", "normalControl", false),
          setting("core.uploadSlotElasticPercent", "advancedControl", false),
          setting("core.queueSize", "advancedControl", false),
          setting("core.autoConnect", "normalControl", true),
          setting("core.reconnect", "normalControl", true),
          setting("core.creditSystem", "normalControl", false),
          setting("core.safeServerConnect", "normalControl", false),
          setting("core.addServersFromServer", "normalControl", false),
          setting("core.networkKademlia", "normalControl", true),
          setting("core.networkEd2k", "normalControl", true),
          setting("daemon.incomingDir", "normalControl", false),
          setting("daemon.p2pBindIp", "normalControl", true),
          setting("daemon.p2pBindInterface", "normalControl", true),
          setting("daemon.ed2kUserHash", "notUserFacing", true),
          setting("daemon.hostnameLookup.enabled", "advancedControl", false),
          setting("daemon.hostnameLookup.dnsServers", "advancedControl", false),
          setting("daemon.hostnameLookup.cacheTtlSecs", "advancedControl", false),
          setting("daemon.hostnameLookup.maxLookupsPerTick", "advancedControl", false),
          setting("daemon.hostnameLookup.tickIntervalSecs", "advancedControl", false),
          setting("ed2k.listenPort", "normalControl", true),
          setting("ed2k.obfuscationEnabled", "normalControl", true),
          setting("ed2k.reconnectEnabled", "normalControl", true),
          setting("ed2k.enableUdpReask", "normalControl", true),
          setting("ed2k.publishEmuleRustIdentity", "advancedControl", true),
          setting("kad.listenPort", "normalControl", true),
          setting("kad.publishSharedFilesEnabled", "normalControl", true),
          setting("kad.republishIntervalSecs", "advancedControl", true),
          setting("kad.udpFirewallCheckEnabled", "normalControl", true),
          setting("kad.tcpFirewallCheckEnabled", "normalControl", true),
          setting("kad.buddyEnabled", "normalControl", true),
          setting("kad.routingMaintenanceEnabled", "normalControl", true),
          setting("nat.enabled", "normalControl", true),
          setting("nat.requireInitialMapping", "advancedControl", true),
          setting("nat.backendOrder", "advancedControl", true),
          setting("nat.bindIp", "advancedControl", true),
          setting("vpnGuard.enabled", "normalControl", true),
          setting("vpnGuard.mode", "normalControl", true),
          setting("vpnGuard.allowedPublicIpCidrs", "normalControl", true),
          setting("ipFilter.enabled", "normalControl", true),
          setting("ipFilter.path", "normalControl", true),
          setting("ipFilter.level", "normalControl", true)
        ],
        sectionResources: [
          { name: "diagnostics", class: "existingSectionResource", route: "/api/v1/diagnostics", uiSection: "Diagnostics", description: "Runtime diagnostics." }
        ]
      };
    case "app/settings":
      return {
        core: { autoConnect: true, networkEd2k: true, networkKademlia: true },
        daemon: { incomingDir: "C:\\Sample\\Incoming" },
        ed2k: { listenPort: 4662 },
        kad: { listenPort: 4672 },
        nat: { enabled: false, backendOrder: [] },
        vpnGuard: { enabled: false, mode: "block", allowedPublicIpCidrs: "" },
        ipFilter: { enabled: false }
      };
    case "uploads":
    case "upload-queue":
      return { items: [] };
    case "app":
      return {
        name: "eMuleBB",
        version: "0.1.0-beta.1",
        apiVersion: "v1",
        capabilities: { transfers: true, "transfers.sse": true }
      };
    case "capabilities":
      return { contractVersion: "1.2.0", apiVersion: "v1", capabilities: ["transfers", "transfers.sse"] };
    case "diagnostics":
      return snapshot.status.runtimeDiagnostics;
    case `transfers/${transferHash}/details`:
      return { hash: transferHash, name: "Sample Transfer.bin" };
    case `transfers/${transferHash}/sources`:
      return { items: [{ clientId: "sample-peer", userName: "Sample Peer", state: "downloading" }] };
    default:
      return undefined;
  }
}

function setting(path: string, classification: "normalControl" | "advancedControl" | "notUserFacing", restartRequired: boolean) {
  return {
    path,
    class: classification,
    restartRequired,
    uiSection: "Settings",
    route: "/api/v1/app/settings",
    description: path
  };
}
