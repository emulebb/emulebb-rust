/** Current native settings wire model. Values and defaults come from the daemon. */
export type SettingsValue = boolean | number | string | string[] | null;
export type SettingsValues = { [key: string]: SettingsValue | SettingsValues };
export type SavedSetting = { mode: "default" | "custom"; value: SettingsValue };
export type SavedSettings = { [key: string]: SavedSetting | SavedSettings };
export type SettingsReadData = {
  saved: SavedSettings;
  effective: SettingsValues;
  application: { pendingRestart: string[]; failed: { key: string; code: string; message: string; truncated: boolean }[] };
};
export type SettingsSnapshot = { data: SettingsReadData; meta: { settingsRevision: string; [key: string]: unknown } };
export type SettingsPatch = { expectedRevision: string; set?: SettingsValues; reset?: string[] };
export type SettingRule =
  | { kind: "boolean" | "path" | "ipv4" | "dnsServers" | "natBackends" | "ipv4Cidrs" | "vpnMode" | "sharedFilesVisibility" }
  | { kind: "integer"; min: number; max: number; step: number }
  | { kind: "text"; minBytes: number; maxBytes: number; forbidControls: boolean };
export type SettingField = { key: string; nullable: boolean; defaultValue: SettingsValue; application: "live" | "restart"; unit: string; rule: SettingRule };
export type BootstrapSettingSpec = { path: string; class: "bootstrapOnly"; restartRequired: boolean; uiSection: string; route: string; description: string };
export type SettingsSectionResourceSpec = { name: string; class: "existingSectionResource"; route: string; uiSection: string; description: string };
export type SettingsSurface = { fields: SettingField[]; schemas: Record<string, unknown>; bootstrap: BootstrapSettingSpec[]; resources: SettingsSectionResourceSpec[] };

export type SettingDraft = { mode: "default" | "custom"; text: string; unset: boolean };
export type SettingsDraft = Record<string, SettingDraft>;

/** Traverse current canonical keys without aliases or value conversion. */
export function settingAt(root: SavedSettings | SettingsValues, key: string): unknown {
  let value: unknown = root;
  for (const part of key.split(".")) {
    if (typeof value !== "object" || value === null || Array.isArray(value) || !Object.hasOwn(value, part)) {
      throw new Error(`Settings response is missing ${key}.`);
    }
    value = (value as Record<string, unknown>)[part];
  }
  return value;
}

export function savedSetting(root: SavedSettings, key: string): SavedSetting {
  const leaf = settingAt(root, key) as SavedSetting;
  if (!leaf || (leaf.mode !== "default" && leaf.mode !== "custom") || leaf.value === undefined) {
    throw new Error(`Settings response has an invalid saved value for ${key}.`);
  }
  return leaf;
}

export function settingText(value: SettingsValue): string {
  return value === null ? "" : Array.isArray(value) ? value.join("\n") : String(value);
}

export function settingsDraft(snapshot: SettingsSnapshot, fields: SettingField[]): SettingsDraft {
  return Object.fromEntries(fields.map((field) => {
    const leaf = savedSetting(snapshot.data.saved, field.key);
    return [field.key, { mode: leaf.mode, text: settingText(leaf.value), unset: leaf.value === null }];
  }));
}

/** Build nested current-model fields; prototype names cannot alter object prototypes. */
export function setSetting(root: SettingsValues, key: string, value: SettingsValue): void {
  const parts = key.split(".");
  let group = root;
  for (const part of parts.slice(0, -1)) {
    if (!Object.hasOwn(group, part)) group[part] = Object.create(null) as SettingsValues;
    group = group[part] as SettingsValues;
  }
  group[parts.at(-1)!] = value;
}

export function parseSetting(field: SettingField, draft: SettingDraft): SettingsValue {
  if (draft.mode === "default") return field.defaultValue;
  if (draft.unset && field.nullable) return null;
  const rule = field.rule;
  switch (rule.kind) {
    case "boolean": return draft.text === "true";
    case "integer": {
      const value = Number(draft.text);
      if (!/^[0-9]+$/.test(draft.text) || !Number.isSafeInteger(value)
          || value < rule.min || value > rule.max || value % rule.step !== 0) {
        throw new Error(`Enter a whole number from ${rule.min} to ${rule.max}, in steps of ${rule.step}.`);
      }
      return value;
    }
    case "text": {
      const bytes = new TextEncoder().encode(draft.text).length;
      if (bytes < rule.minBytes || bytes > rule.maxBytes) throw new Error(`Enter ${rule.minBytes}–${rule.maxBytes} UTF-8 bytes.`);
      if (rule.forbidControls && /[\u0000-\u001f\u007f-\u009f]/u.test(draft.text)) throw new Error("Control characters are not allowed.");
      return draft.text;
    }
    case "path":
    case "ipv4":
      if (!draft.text) throw new Error(field.nullable ? "Enter a value or select Not set." : "Enter a value.");
      return draft.text;
    case "dnsServers":
    case "natBackends":
    case "ipv4Cidrs": return draft.text.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
    case "vpnMode":
    case "sharedFilesVisibility": return draft.text;
    default: throw new Error("This setting requires an updated WebUI.");
  }
}

export function settingsPatch(snapshot: SettingsSnapshot, fields: SettingField[], draft: SettingsDraft): SettingsPatch | null {
  const baseline = settingsDraft(snapshot, fields);
  const set: SettingsValues = Object.create(null) as SettingsValues;
  const reset: string[] = [];
  let changed = false;
  for (const field of fields) {
    const item = draft[field.key];
    if (JSON.stringify(item) === JSON.stringify(baseline[field.key])) continue;
    changed = true;
    if (item.mode === "default") reset.push(field.key);
    else setSetting(set, field.key, parseSetting(field, item));
  }
  return changed ? { expectedRevision: snapshot.meta.settingsRevision,
    ...(Object.keys(set).length ? { set } : {}), ...(reset.length ? { reset } : {}) } : null;
}

export function settingLabel(key: string): string {
  return key.split(".").slice(1).map((part) => {
    const words = part.replace(/([a-z0-9])([A-Z])/g, "$1 $2").toLowerCase();
    return (words[0].toUpperCase() + words.slice(1)).replace(/\bip\b/gi, "IP").replace(/\bdns\b/gi, "DNS")
      .replace(/\bvpn\b/gi, "VPN").replace(/\bnat\b/gi, "NAT").replace(/\bp2p\b/gi, "P2P");
  }).join(" · ");
}
