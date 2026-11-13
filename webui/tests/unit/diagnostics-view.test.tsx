import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/preact";
import { afterEach, describe, expect, it, vi } from "vitest";

import { RestClient } from "../../src/api";
import { DiagnosticsView } from "../../src/views";

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("DiagnosticsView", () => {
  it.each([
    { memory: 67_108_864, cpu: 125.5, interval: 2_000, memoryText: "64 MiB", cpuText: "125.5%" },
    { memory: 0, cpu: 0, interval: 1_000, memoryText: "0 B", cpuText: "0.0%" },
    { memory: null, cpu: null, interval: null, memoryText: "n/a", cpuText: "n/a" }
  ])("shows process memory and CPU without inventing unavailable values ($cpuText)", ({ memory, cpu, interval, memoryText, cpuText }) => {
    render(
      <DiagnosticsView
        app={{}}
        capabilities={{}}
        runtimeDiagnostics={{ processResources: {
          sampledAtMs: 1_000,
          residentMemoryBytes: memory,
          cpuUsagePercent: cpu,
          cpuSampleIntervalMs: interval
        } }}
        eventStreamStatus={{
          mode: "polling", enabled: true, connected: false, reconnectAttempts: 0,
          pollIntervalMs: 1_000, retryIntervalMs: 1_000
        }}
        client={new RestClient()}
        run={async (operation) => { await operation(); }}
      />
    );
    expect(screen.getByText("Resident memory").parentElement).toHaveTextContent(memoryText);
    expect(screen.getByText("CPU usage").parentElement).toHaveTextContent(cpuText);
    expect(screen.getByText(/100% means one fully occupied core/)).toBeInTheDocument();
    if (interval === null) {
      expect(screen.getByText(/CPU usage needs two samples/)).toBeInTheDocument();
    } else {
      expect(screen.getByText(new RegExp(`CPU average over ${(interval / 1_000).toFixed(1)} s`))).toBeInTheDocument();
    }
  });

  it("downloads caller-owned inline diagnostic bundles", async () => {
    const bundle = {
      schema: "emulebb.diagnostic-bundle.v5",
      capturedAt: "2026-10-25T12:34:56Z",
      summary: { artifactFileCount: 1, missingArtifactFamilies: [], issueCount: 0 }
    };
    const client = new RestClient();
    const post = vi.spyOn(client, "post").mockResolvedValue(bundle);
    const createObjectURL = vi.fn(() => "blob:diagnostic-bundle");
    const revokeObjectURL = vi.fn();
    vi.stubGlobal("URL", class extends URL {
      static createObjectURL = createObjectURL;
      static revokeObjectURL = revokeObjectURL;
    });
    let downloadedFileName = "";
    vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(function (this: HTMLAnchorElement) {
      downloadedFileName = this.download;
    });

    render(
      <DiagnosticsView
        app={{}}
        capabilities={{}}
        runtimeDiagnostics={null}
        eventStreamStatus={{
          mode: "polling",
          enabled: true,
          connected: false,
          reconnectAttempts: 0,
          pollIntervalMs: 1_000,
          retryIntervalMs: 1_000
        }}
        client={client}
        run={async (operation) => { await operation(); }}
      />
    );

    expect(screen.getByText("CPU usage").parentElement).toHaveTextContent("n/a");
    expect(screen.getByText("Resident memory").parentElement).toHaveTextContent("n/a");
    fireEvent.click(screen.getByRole("button", { name: "Capture bundle" }));

    await waitFor(() => expect(post).toHaveBeenCalledOnce());
    expect(post).toHaveBeenCalledWith("diagnostics/bundles", { confirmCapture: true });
    expect(createObjectURL).toHaveBeenCalledOnce();
    expect(revokeObjectURL).toHaveBeenCalledWith("blob:diagnostic-bundle");
    expect(downloadedFileName).toBe("emulebb-rust-diagnostic-bundle-20261025T123456Z.json");
    expect(screen.getByText(`Downloaded: ${downloadedFileName}`)).toBeInTheDocument();
  });
});
