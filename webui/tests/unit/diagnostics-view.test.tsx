import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/preact";
import { afterEach, describe, expect, it, vi } from "vitest";

import { RestClient } from "../../src/api";
import { DiagnosticsView } from "../../src/views";

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

const bundle = {
  schema: "emulebb.diagnostic-bundle.v5",
  capturedAt: "2026-10-25T12:34:56Z",
  summary: { artifactFileCount: 1, missingArtifactFamilies: [], issueCount: 0 }
};

function renderView() {
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
  const run = vi.fn(async (operation: () => Promise<unknown>) => { await operation(); });

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
      run={run}
    />
  );

  return {
    post,
    createObjectURL,
    revokeObjectURL,
    run,
    downloadedFileName: () => downloadedFileName,
    captureButton: () => screen.getByRole("button", { name: "Capture bundle" }),
    acknowledgementInput: () => screen.getByPlaceholderText("Type PRIVATE")
  };
}

describe("DiagnosticsView", () => {
  it("discloses bundle privacy before any capture", () => {
    const { captureButton } = renderView();

    expect(screen.getByText(/Private bundle:/)).toBeInTheDocument();
    expect(screen.getByText(/API key/)).toBeInTheDocument();
    expect(screen.getByText(/not for sharing/)).toBeInTheDocument();
    expect(captureButton()).toBeDisabled();
  });

  it("blocks capture until the acknowledgement phrase is typed", () => {
    const { post, createObjectURL, run, captureButton, acknowledgementInput } = renderView();

    fireEvent.input(acknowledgementInput(), { target: { value: "private" } });

    expect(captureButton()).toBeDisabled();
    expect(post).not.toHaveBeenCalled();
    expect(createObjectURL).not.toHaveBeenCalled();
    expect(run).not.toHaveBeenCalled();
    expect(screen.queryByText(/Downloaded:/)).not.toBeInTheDocument();
  });

  it("downloads caller-owned inline diagnostic bundles after acknowledgement", async () => {
    const { post, createObjectURL, revokeObjectURL, run, downloadedFileName, captureButton, acknowledgementInput } = renderView();

    fireEvent.input(acknowledgementInput(), { target: { value: "PRIVATE" } });
    expect(captureButton()).toBeEnabled();

    fireEvent.click(captureButton());

    await waitFor(() => expect(post).toHaveBeenCalledOnce());
    expect(post).toHaveBeenCalledWith("diagnostics/bundles", { confirmCapture: true });
    expect(createObjectURL).toHaveBeenCalledOnce();
    expect(revokeObjectURL).toHaveBeenCalledWith("blob:diagnostic-bundle");
    expect(downloadedFileName()).toBe("emulebb-rust-diagnostic-bundle-20261025T123456Z.json");
    expect(screen.getByText(`Downloaded: ${downloadedFileName()}`)).toBeInTheDocument();
    expect(run).toHaveBeenCalledWith(expect.any(Function), "Diagnostic bundle downloaded");
  });

  it("performs no capture and reports no success when not acknowledged", () => {
    const { post, createObjectURL, run, captureButton, acknowledgementInput } = renderView();

    expect(acknowledgementInput()).toHaveValue("");
    expect(captureButton()).toBeDisabled();
    expect(post).not.toHaveBeenCalled();
    expect(createObjectURL).not.toHaveBeenCalled();
    expect(run).not.toHaveBeenCalled();
    expect(screen.queryByText(/Downloaded:/)).not.toBeInTheDocument();
  });
});
