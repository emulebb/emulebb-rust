import { fireEvent, render, screen, waitFor } from "@testing-library/preact";
import { afterEach, describe, expect, it, vi } from "vitest";

import { type AppSettings, RestClient, type SettingsSurface } from "../../src/api";
import { SettingsView } from "../../src/views";

afterEach(() => {
  vi.restoreAllMocks();
});

describe("SettingsView ED2K server policy", () => {
  it("writes only ED2K-owned server controls and validates keepalive minutes", async () => {
    const client = new RestClient();
    const patch = vi.spyOn(client, "patch").mockResolvedValue(settings);

    render(
      <SettingsView
        settings={settings}
        surface={surface}
        networkStatus={null}
        natStatus={null}
        ipFilterStatus={null}
        vpnGuardStatus={null}
        focusedSection={null}
        client={client}
        run={async (operation) => { await operation(); }}
        onSettingsSaved={() => undefined}
        openSection={() => undefined}
      />
    );

    expect(screen.getByRole("checkbox", { name: /^Reconnect after disconnect/ })).toBeChecked();
    expect(screen.getByRole("checkbox", { name: /^Safe server connect/ })).not.toBeChecked();
    expect(screen.getByRole("checkbox", { name: /^Add servers from server/ })).not.toBeChecked();
    expect(screen.queryByRole("checkbox", { name: /^Reconnect$/ })).not.toBeInTheDocument();

    fireEvent.click(screen.getByLabelText(/Advanced/));
    const keepalive = screen.getByLabelText(/^Server keepalive minutes/);
    expect(keepalive).toHaveValue("0");
    fireEvent.input(keepalive, { target: { value: "1441" } });
    expect(screen.getByText("Server keepalive minutes must be between 0 and 1440.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Save" })).toBeDisabled();

    fireEvent.input(keepalive, { target: { value: "20" } });
    fireEvent.click(screen.getByRole("checkbox", { name: /^Reconnect after disconnect/ }));
    fireEvent.click(screen.getByRole("checkbox", { name: /^Safe server connect/ }));
    fireEvent.click(screen.getByRole("checkbox", { name: /^Add servers from server/ }));
    fireEvent.click(screen.getByRole("button", { name: "Save" }));

    await waitFor(() => {
      expect(patch).toHaveBeenCalledWith("app/settings", {
        ed2k: {
          reconnectEnabled: false,
          safeServerConnect: true,
          addServersFromServer: true,
          serverKeepaliveMinutes: 20
        }
      });
    });
  });
});

const settings: AppSettings = {
  core: {
    uploadLimitKiBps: 6200,
    downloadLimitKiBps: 12207,
    maxConnections: 500,
    maxConnectionsPerFiveSeconds: 50,
    maxSourcesPerFile: 600,
    uploadClientDataRate: 32,
    baseUploadSlots: 12,
    uploadSlotElasticPercent: 80,
    queueSize: 10000,
    autoConnect: true,
    creditSystem: true,
    networkKademlia: true,
    networkEd2k: true
  },
  daemon: {
    hostnameLookup: {
      cacheTtlSecs: 86400,
      maxLookupsPerTick: 32,
      tickIntervalSecs: 30
    }
  },
  ed2k: {
    nickname: "Sample Mule",
    connectTimeoutSecs: 30,
    serverConnectTimeoutSecs: 25,
    callbackTimeoutSecs: 45,
    reconnectIntervalSecs: 30,
    reconnectEnabled: true,
    safeServerConnect: false,
    addServersFromServer: false,
    serverKeepaliveMinutes: 0,
    sessionRotationSecs: 0,
    maxConcurrentDownloads: 500,
    maxNewConnectionsPerFiveSeconds: 50,
    maxHalfOpenConnections: 50,
    maxSourcesPerFile: 600,
    maxParallelDownloadPeers: 2,
    keywordServerAttemptBudget: 3,
    exactHashKeywordServerAttemptBudget: 4,
    sourceServerAttemptBudget: 3,
    downloadLimitBytesPerSec: 0,
    minFreeConfigSpaceBytes: 1073741824,
    minFreeTransferSpaceBytes: 5368709120,
    minFreeIncomingSpaceBytes: 5368709120,
    deadServerRetries: 1,
    uploadQueue: {
      elasticUnderfillSecs: 10,
      waitingTimeoutSecs: 3600,
      grantedTimeoutSecs: 5,
      uploadTimeoutSecs: 30,
      sessionTransferPercent: 90,
      sessionTimeLimitSecs: 7200
    }
  },
  kad: {
    bootstrapMinRoutingContacts: 10,
    republishIntervalSecs: 1800,
    publishContactFanout: 12,
    udpFirewallCheckIntervalSecs: 3600,
    tcpFirewallCheckIntervalSecs: 3600
  },
  nat: {
    backendOrder: ["pcp_natpmp", "upnp_miniupnpc"],
    discoveryTimeoutSecs: 5,
    leaseDurationSecs: 3600,
    renewMarginSecs: 300
  },
  vpnGuard: {
    allowedPublicIpCidrs: ""
  },
  ipFilter: {
    level: 127
  }
};

const surface: SettingsSurface = {
  settings: [
    setting("core.autoConnect", "normalControl"),
    setting("ed2k.reconnectEnabled", "normalControl"),
    setting("ed2k.safeServerConnect", "normalControl"),
    setting("ed2k.addServersFromServer", "normalControl"),
    setting("ed2k.serverKeepaliveMinutes", "advancedControl")
  ],
  bootstrapSettings: [],
  sectionResources: []
};

function setting(path: string, fieldClass: "normalControl" | "advancedControl") {
  return {
    path,
    class: fieldClass,
    restartRequired: true,
    uiSection: "Servers",
    route: "/api/v1/app/settings",
    description: "Synthetic settings test field."
  } as const;
}
