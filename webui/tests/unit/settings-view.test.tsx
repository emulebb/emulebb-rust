import { fireEvent, render, screen, waitFor } from "@testing-library/preact";
import { useState } from "preact/hooks";
import { afterEach, describe, expect, it, vi } from "vitest";
import { RestClient, RestError, type SettingsSnapshot } from "../../src/api";
import { SettingsView } from "../../src/settings";
import { savedSetting, setSetting } from "../../src/settingsModel";
import { applySettingsFixture, settingsFixture, settingsSurfaceFixture } from "../fixtures/settings";

afterEach(() => vi.restoreAllMocks());

function mount(initial = settingsFixture()) {
  const client = new RestClient();
  let current = initial;
  const patch = vi.spyOn(client, "patchSettings").mockImplementation(async (edit) => {
    current = applySettingsFixture(current, edit);
    return current;
  });
  const read = vi.spyOn(client, "getSettings").mockResolvedValue(initial);
  const saved = vi.fn();
  function Host() {
    const [snapshot, setSnapshot] = useState(initial);
    return <SettingsView settings={snapshot} surface={settingsSurfaceFixture}
      networkStatus={null} natStatus={null} ipFilterStatus={null} vpnGuardStatus={null} focusedSection={null}
      client={client} run={async (operation) => { try { await operation(); } catch { /* Parent displays the same error. */ } }}
      onSettingsSaved={(next) => { saved(next); setSnapshot(next); }} openSection={() => undefined} />;
  }
  render(<Host />);
  return { patch, read, saved };
}
const useCustom = (label: string) => fireEvent.click(screen.getByLabelText(`Use default for ${label}`));
const fill = (label: string, value: string) => fireEvent.input(screen.getByLabelText(label, { exact: true }), { target: { value } });
const save = () => fireEvent.click(screen.getByRole("button", { name: /^Save$/ }));

describe("canonical settings", () => {
  it("resets a custom leaf and shows saved versus running state", async () => {
    const snapshot = settingsFixture();
    Object.assign(savedSetting(snapshot.data.saved, "storage.incomingDirectory"), { mode: "custom", value: "custom-incoming" });
    setSetting(snapshot.data.effective, "storage.incomingDirectory", "custom-incoming");
    const { patch } = mount(snapshot);
    useCustom("Incoming directory");
    save();
    await waitFor(() => expect(patch).toHaveBeenCalledWith({ expectedRevision: "9007199254740993", reset: ["storage.incomingDirectory"] }));
    await waitFor(() => expect(screen.getByText("Saved changes require a daemon restart.")).toBeInTheDocument());
    expect(screen.getByText("Running: custom-incoming")).toBeInTheDocument();
    expect(screen.getByLabelText("Incoming directory", { exact: true })).toHaveValue("incoming");
    expect(screen.getByRole("button", { name: /^Save$/ })).toBeDisabled();
  });

  it("keeps nullable automatic selection distinct from a custom integer", async () => {
    const { patch } = mount();
    useCustom("Max concurrent downloads");
    expect(screen.getByLabelText("Not set for Max concurrent downloads")).toBeChecked();
    fireEvent.click(screen.getByLabelText("Not set for Max concurrent downloads"));
    fill("Max concurrent downloads", "16");
    save();
    await waitFor(() => expect(patch).toHaveBeenCalledWith({ expectedRevision: "9007199254740993", set: { transfers: { maxConcurrentDownloads: 16 } } }));
    await waitFor(() => expect(screen.getByLabelText("Use default for Max concurrent downloads")).toBeEnabled());
    useCustom("Max concurrent downloads");
    await waitFor(() => expect(screen.getByRole("button", { name: /^Save$/ })).toBeEnabled());
    save();
    await waitFor(() => expect(patch).toHaveBeenLastCalledWith({ expectedRevision: "9007199254740994", reset: ["transfers.maxConcurrentDownloads"] }));
  });

  it("validates metadata bounds and sends only the edited nested keys", async () => {
    const { patch } = mount();
    useCustom("Servers · Keepalive minutes");
    fill("Servers · Keepalive minutes", "1441");
    expect(screen.getByRole("button", { name: /^Save$/ })).toBeDisabled();
    expect(patch).not.toHaveBeenCalled();
    fill("Servers · Keepalive minutes", "20");
    useCustom("Servers · Safe connect");
    fireEvent.click(screen.getByLabelText("Servers · Safe connect", { exact: true }));
    save();
    await waitFor(() => expect(patch).toHaveBeenCalledWith({ expectedRevision: "9007199254740993",
      set: { network: { servers: { keepaliveMinutes: 20, safeConnect: true } } } }));
  });

  it("retains edits on conflict and reloads only after an explicit discard", async () => {
    const { patch, read } = mount();
    patch.mockRejectedValueOnce(new RestError("Saved settings changed.", 409, "SETTINGS_CONFLICT"));
    useCustom("Nickname"); fill("Nickname", "Sample Client"); save();
    await waitFor(() => expect(screen.getByText(/Your edits are kept/)).toBeInTheDocument());
    expect(screen.getByLabelText("Nickname", { exact: true })).toHaveValue("Sample Client");
    expect(screen.getByRole("button", { name: /^Save$/ })).toBeDisabled();
    expect(read).not.toHaveBeenCalled();
    expect(patch).toHaveBeenCalledTimes(1);
    fireEvent.click(screen.getByRole("button", { name: "Discard and reload" }));
    await waitFor(() => expect(read).toHaveBeenCalledTimes(1));
    await waitFor(() => expect(screen.getByLabelText("Nickname", { exact: true })).toHaveValue("eMule"));
    expect(patch).toHaveBeenCalledTimes(1);
  });

  it("does not retry an unknown save outcome", async () => {
    const { patch, read } = mount();
    patch.mockRejectedValueOnce(new TypeError("Connection lost"));
    useCustom("Temp directory"); fill("Temp directory", "custom-temp"); save();
    await waitFor(() => expect(screen.getByText(/Read the current settings before another save/)).toBeInTheDocument());
    expect(screen.getByLabelText("Temp directory", { exact: true })).toHaveValue("custom-temp");
    expect(read).not.toHaveBeenCalled();
    expect(patch).toHaveBeenCalledTimes(1);
  });

  it("admits at most one save while its response is pending", async () => {
    const { patch } = mount();
    let complete!: (value: SettingsSnapshot) => void;
    patch.mockImplementationOnce(() => new Promise((resolve) => { complete = resolve; }));
    useCustom("Nickname"); fill("Nickname", "Sample Client"); save(); save();
    await waitFor(() => expect(patch).toHaveBeenCalledTimes(1));
    complete(applySettingsFixture(settingsFixture(), { expectedRevision: "9007199254740993", set: { network: { nickname: "Sample Client" } } }));
    await waitFor(() => expect(screen.getByRole("button", { name: /^Save$/ })).toBeDisabled());
  });

  it("reports live application failure without claiming that saved values are running", () => {
    const snapshot = settingsFixture();
    Object.assign(savedSetting(snapshot.data.saved, "transfers.uploadLimitBytesPerSecond"), { mode: "custom", value: 4000 });
    snapshot.data.application.failed = [{ key: "transfers.uploadLimitBytesPerSecond", code: "APPLY_FAILED", message: "Runtime application failed", truncated: false }];
    mount(snapshot);
    expect(screen.getByText(/Runtime application failed/)).toBeInTheDocument();
    expect(screen.getByText("Running: 6348800")).toBeInTheDocument();
    expect(screen.getByText("rest.api_key")).toBeInTheDocument();
  });
});
