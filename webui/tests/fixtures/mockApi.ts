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
      kadPublish: { phase: "waiting" },
      transferEvents: {
        enabled: true,
        stream: "sse",
        channelCapacity: 1024,
        queuedEventCount: 1,
        subscriberCount: 1,
        latestEventId: 1,
        nextEventId: 2,
        resumeBehavior: "reset"
      }
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
    case "ip-filter":
      return {
        configured: true,
        reloadable: true,
        path: "C:\\Sample\\ipfilter.dat",
        level: 127,
        rangeCount: 3
      };
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
          setting("ed2k.connectTimeoutSecs", "advancedControl", true),
          setting("ed2k.serverConnectTimeoutSecs", "advancedControl", true),
          setting("ed2k.callbackTimeoutSecs", "advancedControl", true),
          setting("ed2k.reconnectIntervalSecs", "advancedControl", true),
          setting("ed2k.keepaliveSecs", "advancedControl", true),
          setting("ed2k.sessionRotationSecs", "advancedControl", true),
          setting("ed2k.maxConcurrentDownloads", "advancedControl", true),
          setting("ed2k.maxNewConnectionsPerFiveSeconds", "advancedControl", true),
          setting("ed2k.maxHalfOpenConnections", "advancedControl", true),
          setting("ed2k.maxSourcesPerFile", "advancedControl", true),
          setting("ed2k.maxParallelDownloadPeers", "advancedControl", true),
          setting("ed2k.downloadLimitBytesPerSec", "advancedControl", true),
          setting("ed2k.keywordServerAttemptBudget", "advancedControl", true),
          setting("ed2k.exactHashKeywordServerAttemptBudget", "advancedControl", true),
          setting("ed2k.sourceServerAttemptBudget", "advancedControl", true),
          setting("ed2k.obfuscationEnabled", "normalControl", true),
          setting("ed2k.reconnectEnabled", "normalControl", true),
          setting("ed2k.enableUdpReask", "normalControl", true),
          setting("ed2k.publishEmuleRustIdentity", "advancedControl", true),
          setting("ed2k.deadServerRetries", "advancedControl", true),
          setting("ed2k.uploadQueue.activeSlots", "advancedControl", true),
          setting("ed2k.uploadQueue.elasticPercent", "advancedControl", true),
          setting("ed2k.uploadQueue.uploadLimitBytesPerSec", "advancedControl", true),
          setting("ed2k.uploadQueue.elasticUnderfillBytesPerSec", "advancedControl", true),
          setting("ed2k.uploadQueue.elasticUnderfillSecs", "advancedControl", true),
          setting("ed2k.uploadQueue.waitingCapacity", "advancedControl", true),
          setting("ed2k.uploadQueue.waitingTimeoutSecs", "advancedControl", true),
          setting("ed2k.uploadQueue.grantedTimeoutSecs", "advancedControl", true),
          setting("ed2k.uploadQueue.uploadTimeoutSecs", "advancedControl", true),
          setting("ed2k.uploadQueue.sessionTransferPercent", "advancedControl", true),
          setting("ed2k.uploadQueue.sessionTimeLimitSecs", "advancedControl", true),
          setting("kad.listenPort", "normalControl", true),
          setting("kad.bootstrapMinRoutingContacts", "advancedControl", true),
          setting("kad.localStoreEnabled", "advancedControl", true),
          setting("kad.publishSharedFilesEnabled", "normalControl", true),
          setting("kad.republishIntervalSecs", "advancedControl", true),
          setting("kad.publishContactFanout", "advancedControl", true),
          setting("kad.udpFirewallCheckEnabled", "normalControl", true),
          setting("kad.udpFirewallCheckIntervalSecs", "advancedControl", true),
          setting("kad.tcpFirewallCheckEnabled", "normalControl", true),
          setting("kad.tcpFirewallCheckIntervalSecs", "advancedControl", true),
          setting("kad.buddyEnabled", "normalControl", true),
          setting("kad.routingMaintenanceEnabled", "normalControl", true),
          setting("nat.enabled", "normalControl", true),
          setting("nat.requireInitialMapping", "advancedControl", true),
          setting("nat.backendOrder", "advancedControl", true),
          setting("nat.bindIp", "advancedControl", true),
          setting("nat.igdIp", "advancedControl", true),
          setting("nat.minissdpdSocket", "advancedControl", true),
          setting("nat.ssdpLocalPort", "advancedControl", true),
          setting("nat.discoveryTimeoutSecs", "advancedControl", true),
          setting("nat.leaseDurationSecs", "advancedControl", true),
          setting("nat.renewMarginSecs", "advancedControl", true),
          setting("nat.externalIpOverride", "advancedControl", true),
          setting("vpnGuard.enabled", "normalControl", true),
          setting("vpnGuard.mode", "normalControl", true),
          setting("vpnGuard.allowedPublicIpCidrs", "normalControl", true),
          setting("ipFilter.enabled", "normalControl", true),
          setting("ipFilter.path", "normalControl", true),
          setting("ipFilter.level", "normalControl", true)
        ],
        sectionResources: [
          sectionResource("sharedDirectories", "/api/v1/shared-directories", "Sharing", "Shared root ownership and reload operations."),
          sectionResource("categories", "/api/v1/categories", "Categories", "Transfer category paths and priorities."),
          sectionResource("servers", "/api/v1/servers", "Servers", "eD2K server repository, import, and connect operations."),
          sectionResource("kad", "/api/v1/kad", "Kad", "Kad status, bootstrap, import, and control operations."),
          sectionResource("ipFilter", "/api/v1/ip-filter", "IP Filter", "IP filter status and live reload operation."),
          sectionResource("diagnostics", "/api/v1/diagnostics", "Diagnostics", "Runtime diagnostics.")
        ]
      };
    case "app/settings":
      return {
        core: {
          uploadLimitKiBps: 6200,
          downloadLimitKiBps: 12207,
          maxConnections: 500,
          maxConnectionsPerFiveSeconds: 50,
          maxSourcesPerFile: 600,
          uploadClientDataRate: 32,
          maxUploadSlots: 12,
          uploadSlotElasticPercent: 80,
          queueSize: 10000,
          autoConnect: true,
          reconnect: true,
          creditSystem: true,
          safeServerConnect: true,
          addServersFromServer: true,
          networkEd2k: true,
          networkKademlia: true
        },
        daemon: {
          incomingDir: "C:\\Sample\\Incoming",
          hostnameLookup: {
            enabled: false,
            dnsServers: [],
            cacheTtlSecs: 86400,
            maxLookupsPerTick: 32,
            tickIntervalSecs: 30
          }
        },
        ed2k: {
          listenPort: 4662,
          connectTimeoutSecs: 30,
          serverConnectTimeoutSecs: 25,
          callbackTimeoutSecs: 45,
          reconnectIntervalSecs: 30,
          keepaliveSecs: 1200,
          sessionRotationSecs: 0,
          maxConcurrentDownloads: 500,
          maxNewConnectionsPerFiveSeconds: 50,
          maxHalfOpenConnections: 50,
          maxSourcesPerFile: 600,
          maxParallelDownloadPeers: 2,
          downloadLimitBytesPerSec: 0,
          keywordServerAttemptBudget: 3,
          exactHashKeywordServerAttemptBudget: 4,
          sourceServerAttemptBudget: 3,
          obfuscationEnabled: true,
          reconnectEnabled: true,
          enableUdpReask: true,
          publishEmuleRustIdentity: false,
          deadServerRetries: 1,
          uploadQueue: {
            activeSlots: 3,
            elasticPercent: 0,
            uploadLimitBytesPerSec: 0,
            elasticUnderfillBytesPerSec: 0,
            elasticUnderfillSecs: 10,
            waitingCapacity: 512,
            waitingTimeoutSecs: 3600,
            grantedTimeoutSecs: 30,
            uploadTimeoutSecs: 90,
            sessionTransferPercent: 90,
            sessionTimeLimitSecs: 7200
          }
        },
        kad: {
          listenPort: 4672,
          bootstrapMinRoutingContacts: 10,
          localStoreEnabled: true,
          publishSharedFilesEnabled: true,
          republishIntervalSecs: 1800,
          publishContactFanout: 12,
          udpFirewallCheckEnabled: true,
          udpFirewallCheckIntervalSecs: 3600,
          tcpFirewallCheckEnabled: true,
          tcpFirewallCheckIntervalSecs: 3600,
          buddyEnabled: true,
          routingMaintenanceEnabled: true
        },
        nat: {
          enabled: false,
          requireInitialMapping: true,
          bindIp: "",
          backendOrder: [],
          igdIp: "",
          minissdpdSocket: "",
          ssdpLocalPort: 1900,
          discoveryTimeoutSecs: 5,
          leaseDurationSecs: 3600,
          renewMarginSecs: 300,
          externalIpOverride: ""
        },
        vpnGuard: { enabled: false, mode: "block", allowedPublicIpCidrs: "" },
        ipFilter: { enabled: false, level: 127 }
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

function sectionResource(name: string, route: string, uiSection: string, description: string) {
  return {
    name,
    class: "existingSectionResource",
    route,
    uiSection,
    description
  };
}
