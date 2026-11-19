import defaults from "./settings-defaults.json" with { type: "json" };
import {
  savedSetting, settingAt, setSetting,
  type SavedSettings, type SettingField, type SettingRule, type SettingsPatch, type SettingsSnapshot, type SettingsSurface, type SettingsValue, type SettingsValues
} from "../../src/settingsModel";

function values(saved: SavedSettings): SettingsValues {
  return Object.fromEntries(Object.entries(saved).map(([key, item]) => [key,
    item.mode === "default" || item.mode === "custom" ? item.value : values(item as SavedSettings)]));
}

export function settingsFixture(): SettingsSnapshot {
  const saved = structuredClone(defaults) as SavedSettings;
  return { data: { saved, effective: values(saved), application: { pendingRestart: [], failed: [] } }, meta: { settingsRevision: "9007199254740993" } };
}

function field(key: string, rule: SettingRule, application: "live" | "restart" = "restart", unit = "none", nullable = false): SettingField {
  return { key, rule, application, unit, nullable, defaultValue: savedSetting(defaults as SavedSettings, key).value };
}
const integer = (min: number, max: number, step = 1): SettingRule => ({ kind: "integer", min, max, step });
export const settingsSurfaceFixture: SettingsSurface = {
  fields: [
    field("network.autoConnect", { kind: "boolean" }),
    field("network.nickname", { kind: "text", minBytes: 1, maxBytes: 128, forbidControls: true }),
    field("network.p2p.bindIp", { kind: "ipv4" }, "restart", "none", true),
    field("network.p2p.bindInterface", { kind: "text", minBytes: 1, maxBytes: 256, forbidControls: false }, "restart", "none", true),
    field("network.p2p.tcpPort", integer(1, 65535), "restart", "port"),
    field("network.connections.maxConnections", integer(1, 2147483647), "live", "connections"),
    field("network.servers.keepaliveMinutes", integer(0, 1440), "restart", "whole minutes"),
    field("network.servers.safeConnect", { kind: "boolean" }),
    field("network.servers.acceptServerListUpdates", { kind: "boolean" }),
    field("network.hostnameLookup.enabled", { kind: "boolean" }, "live"),
    field("network.hostnameLookup.dnsServers", { kind: "dnsServers" }, "live", "endpoints"),
    field("network.nat.backendOrder", { kind: "natBackends" }, "restart", "ordered backends"),
    field("transfers.uploadLimitBytesPerSecond", integer(1, 4398046509056), "live", "bytes per second"),
    field("transfers.maxConcurrentDownloads", integer(1, 2147483647), "live", "downloads", true),
    field("transfers.upload.queueCapacity", integer(2000, 10000), "live", "waiting peers"),
    field("storage.incomingDirectory", { kind: "path" }),
    field("storage.tempDirectory", { kind: "path" }),
    field("sharing.scanOnStartup", { kind: "boolean" }),
    field("security.vpnGuard.mode", { kind: "vpnMode" }),
    field("security.vpnGuard.allowedPublicIpCidrs", { kind: "ipv4Cidrs" }, "restart", "networks"),
    field("security.ipFilter.filePath", { kind: "path" }, "restart", "none", true)
  ],
  schemas: { SettingsValues: { type: "object", properties: { security: { properties: { vpnGuard: { properties: { mode: { enum: ["off", "block"] } } } } } } } },
  bootstrap: ["bind_addr", "api_key", "web_root_dir"].map((key) => ({ path: `rest.${key}`, class: "bootstrapOnly", restartRequired: true,
    uiSection: "Bootstrap REST", route: "emulebb-rust-settings.toml", description: "Configure the control service in the profile TOML." })),
  resources: [
    { name: "libraryRoots", class: "existingSectionResource", route: "/api/v1/library/roots", uiSection: "Sharing", description: "Library roots and watch policy." },
    { name: "categories", class: "existingSectionResource", route: "/api/v1/categories", uiSection: "Categories", description: "Category paths." },
    { name: "servers", class: "existingSectionResource", route: "/api/v1/servers", uiSection: "Servers", description: "Server repository." },
    { name: "nat", class: "existingSectionResource", route: "/api/v1/nat", uiSection: "NAT", description: "NAT state and refresh." },
    { name: "ipFilter", class: "existingSectionResource", route: "/api/v1/ip-filter", uiSection: "IP Filter", description: "Filter state and reload." },
    { name: "vpnGuard", class: "existingSectionResource", route: "/api/v1/vpn-guard", uiSection: "VPN Guard", description: "VPN guard state and probe." },
    { name: "diagnostics", class: "existingSectionResource", route: "/api/v1/diagnostics", uiSection: "Diagnostics", description: "Runtime diagnostics." },
    { name: "logs", class: "existingSectionResource", route: "/api/v1/logs", uiSection: "Logs", description: "Recent logs." }
  ]
};

/** Only fixture state is changed here; the daemon owns actual candidate validation. */
export function applySettingsFixture(snapshot: SettingsSnapshot, patch: SettingsPatch): SettingsSnapshot {
  const next = structuredClone(snapshot);
  for (const spec of settingsSurfaceFixture.fields) {
    let value: SettingsValue;
    if (patch.reset?.includes(spec.key)) value = spec.defaultValue;
    else {
      try { value = settingAt(patch.set ?? {}, spec.key) as SettingsValue; }
      catch { continue; }
    }
    const leaf = savedSetting(next.data.saved, spec.key);
    leaf.mode = JSON.stringify(value) === JSON.stringify(spec.defaultValue) ? "default" : "custom";
    leaf.value = value;
    next.data.application.pendingRestart = next.data.application.pendingRestart.filter((key) => key !== spec.key);
    if (spec.application === "live") setSetting(next.data.effective, spec.key, value);
    else if (JSON.stringify(value) !== JSON.stringify(settingAt(next.data.effective, spec.key))) next.data.application.pendingRestart.push(spec.key);
  }
  next.meta.settingsRevision = String(BigInt(snapshot.meta.settingsRevision) + 1n);
  return next;
}
