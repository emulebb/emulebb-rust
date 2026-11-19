import { useEffect, useLayoutEffect, useMemo, useRef, useState } from "preact/hooks";
import { RefreshCw, Save } from "lucide-preact";
import { RestClient, RestError, type IpFilterStatus, type NatStatus, type NetworkStatus, type VpnGuardStatus } from "./api";
import type { RunFunction } from "./views";
import { errorMessage } from "./format";
import { Metric } from "./components";
import {
  parseSetting, savedSetting, settingAt, settingLabel, settingsDraft, settingsPatch, settingText,
  type SettingDraft, type SettingField, type SettingsDraft, type SettingsSnapshot, type SettingsSurface, type SettingsValue
} from "./settingsModel";

export function SettingsView(props: {
  settings: SettingsSnapshot | null;
  surface: SettingsSurface | null;
  networkStatus: NetworkStatus | null;
  natStatus: NatStatus | null;
  ipFilterStatus: IpFilterStatus | null;
  vpnGuardStatus: VpnGuardStatus | null;
  focusedSection: string | null;
  client: RestClient;
  run: RunFunction;
  onSettingsSaved: (settings: SettingsSnapshot) => void;
  openSection: (name: string) => void;
}) {
  const fields = props.surface?.fields;
  const baseline = useMemo(() => props.settings && fields ? settingsDraft(props.settings, fields) : {}, [props.settings, fields]);
  const [draft, setDraft] = useState<SettingsDraft>(baseline);
  const [busy, setBusy] = useState(false);
  const admission = useRef(false);
  const [needsReload, setNeedsReload] = useState(false);
  const [saveError, setSaveError] = useState("");
  const [issues, setIssues] = useState<Record<string, string>>({});
  // WHY: adopt the response before controls become interactive. A deferred reset
  // could otherwise overwrite the user's first edit after a completed save.
  useLayoutEffect(() => { setDraft(baseline); setNeedsReload(false); setSaveError(""); setIssues({}); }, [baseline]);
  useEffect(() => {
    if (!props.focusedSection) return;
    const element = Array.from(document.querySelectorAll<HTMLElement>("[data-settings-section]"))
      .find((item) => item.dataset.settingsSection === props.focusedSection);
    element?.scrollIntoView({ block: "start", behavior: "smooth" });
    element?.focus({ preventScroll: true });
  }, [props.focusedSection]);

  if (!props.settings || !props.surface || !fields) return <section class="panel card"><p class="empty">Settings are not loaded.</p></section>;
  const snapshot = props.settings;
  const ready = fields.every((field) => draft[field.key]);
  const dirty = ready && JSON.stringify(draft) !== JSON.stringify(baseline);
  const errors = new Map<string, string>();
  if (ready) for (const field of fields) {
    try { parseSetting(field, draft[field.key]); }
    catch (caught) { errors.set(field.key, errorMessage(caught)); }
  }
  const groups = [...new Set(fields.map((field) => field.key.split(".")[0]))];
  const update = (key: string, item: SettingDraft) => {
    setDraft((current) => ({ ...current, [key]: item }));
    setIssues((current) => { const next = { ...current }; delete next[key]; return next; });
  };
  const save = async () => {
    if (admission.current || !ready || !dirty || errors.size || needsReload) return;
    const patch = settingsPatch(snapshot, fields, draft);
    if (!patch) return;
    admission.current = true; setBusy(true); setSaveError(""); setIssues({});
    try { props.onSettingsSaved(await props.client.patchSettings(patch)); }
    catch (caught) {
      const reload = !(caught instanceof RestError) || caught.status === 409 || caught.status >= 500;
      setNeedsReload(reload);
      setSaveError(reload ? `${errorMessage(caught)} Your edits are kept. Read the current settings before another save.` : errorMessage(caught));
      if (caught instanceof RestError && caught.details && typeof caught.details === "object") {
        const items = (caught.details as { issues?: unknown }).issues;
        if (Array.isArray(items)) setIssues(Object.fromEntries(items.filter((item) => item && typeof item.key === "string"
          && typeof item.message === "string" && fields.some((field) => field.key === item.key)).map((item) => [item.key, item.message])));
      }
      throw caught;
    } finally { admission.current = false; setBusy(false); }
  };
  const reload = async () => {
    if (admission.current) return;
    admission.current = true; setBusy(true);
    try {
      const next = await props.client.getSettings();
      setDraft(settingsDraft(next, fields)); setNeedsReload(false); setSaveError(""); setIssues({});
      props.onSettingsSaved(next);
    }
    finally { admission.current = false; setBusy(false); }
  };

  return <section class="panel card">
    <div class="section-title"><h2>Settings</h2><div class="settings-actions">
      <button class="btn" type="button" disabled={busy} onClick={() => void props.run(reload, "Settings reloaded")}><RefreshCw size={15} />{dirty || needsReload ? "Discard and reload" : "Reload"}</button>
      <button class="btn" type="button" disabled={busy || !dirty} onClick={() => { setDraft(baseline); setIssues({}); }}>Revert</button>
      <button class="btn" type="button" disabled={busy || !dirty || errors.size > 0 || needsReload}
        onClick={() => void props.run(save, "Settings saved")}><Save size={15} />Save</button>
    </div></div>
    {saveError && <p role="alert" class="field-error">{saveError}</p>}
    {snapshot.data.application.pendingRestart.length > 0 && <div role="status" class="settings-application">
      <strong>Saved changes require a daemon restart.</strong>
      <ul>{snapshot.data.application.pendingRestart.map((key) => <li key={key}>{settingLabel(key)}</li>)}</ul>
    </div>}
    {snapshot.data.application.failed.length > 0 && <div role="alert" class="field-error">
      <strong>Some saved settings could not be applied.</strong>
      <ul>{snapshot.data.application.failed.map((item) => <li key={item.key}>{settingLabel(item.key)}: {item.message}</li>)}</ul>
      <p>Apply an explicit settings update or restart the daemon to try again.</p>
    </div>}
    {ready && groups.map((group) => <div class="settings-control-section" key={group} data-settings-section={group} tabIndex={-1}>
      <h3>{group[0].toUpperCase() + group.slice(1)}</h3><div class="settings-grid">
        {fields.filter((field) => field.key.startsWith(group + ".")).map((field) => <SettingEditor key={field.key} field={field}
          draft={draft[field.key]} busy={busy} error={errors.get(field.key) ?? issues[field.key]}
          running={settingAt(snapshot.data.effective, field.key) as SettingsValue}
          saved={savedSetting(snapshot.data.saved, field.key).value}
          schema={fieldSchema(props.surface!, field.key)} onChange={(item) => update(field.key, item)} />)}
      </div>
    </div>)}
    <div class="settings-control-section" data-settings-section="network" tabIndex={-1}><h3>Network status</h3>
      <div class="view-grid compact-grid"><Metric label="Bind" value={props.networkStatus?.binding?.resolveResult ?? "Unknown"} />
        <Metric label="Interface" value={props.networkStatus?.binding?.activeInterfaceName ?? "Default"} /></div>
    </div>
    <div class="settings-control-section" data-settings-section="nat" tabIndex={-1}><h3>NAT status</h3>
      <div class="view-grid compact-grid"><Metric label="NAT" value={props.natStatus?.enabled ? "Enabled" : "Off"} />
        <Metric label="Gateway" value={props.natStatus?.gatewayDiscovered ? "Discovered" : "Not discovered"} />
        <Metric label="Mappings" value={String(props.natStatus?.mappings?.length ?? 0)} /></div>
        <button class="btn" type="button" onClick={() => void props.run(() => props.client.post("nat/operations/refresh"), "NAT refresh completed")}>Refresh NAT</button>
    </div>
    <div class="settings-control-section" data-settings-section="vpnGuard" tabIndex={-1}><h3>VPN Guard</h3>
      <div class="view-grid compact-grid"><Metric label="Guard" value={props.vpnGuardStatus?.enabled ? "Enabled" : "Off"} />
        <Metric label="Egress" value={!props.vpnGuardStatus?.enabled ? "Off" : props.vpnGuardStatus.egressVerified ? (props.vpnGuardStatus.publicIp ? `Verified ${props.vpnGuardStatus.publicIp}` : "Verified") : props.vpnGuardStatus.egressBlockReason || "Not verified"} /></div>
        <button class="btn" type="button" onClick={() => void props.run(() => props.client.post("vpn-guard/operations/probe"), "VPN Guard probe completed")}>Probe VPN Guard</button>
    </div>
    <div class="settings-control-section" data-settings-section="ipFilter" tabIndex={-1}><h3>IP Filter</h3>
      <div class="view-grid compact-grid"><Metric label="Configured" value={props.ipFilterStatus?.configured ? "Yes" : "No"} />
        <Metric label="Reloadable" value={props.ipFilterStatus?.reloadable ? "Yes" : "No"} />
        <Metric label="Ranges" value={String(props.ipFilterStatus?.rangeCount ?? 0)} />
        <Metric label="Level" value={String(props.ipFilterStatus?.level ?? "n/a")} /></div>
        <button class="btn" type="button" onClick={() => void props.run(() => props.client.post("ip-filter/operations/reload"), "IP filter reloaded")}>Reload IP filter</button>
    </div>
    <div class="settings-control-section"><h3>Bootstrap REST</h3><div class="settings-resource-list">
      {props.surface.bootstrap.map((item) => <div class="settings-resource-row" key={item.path}><div><strong>{item.path}</strong><span>{item.description}</span><code>{item.route}</code></div><span class="setting-badge">Restart</span></div>)}
    </div></div>
    <div class="settings-section-resources"><h3>Sections</h3><div class="settings-resource-list">
      {props.surface.resources.map((item) => <div class="settings-resource-row" key={item.name}><div><strong>{item.uiSection}</strong><span>{item.description}</span></div>
        <button class="btn" type="button" aria-label={`Open ${item.uiSection}`} onClick={() => props.openSection(item.name)}>Open</button></div>)}
    </div></div>
  </section>;
}

function fieldSchema(surface: SettingsSurface, key: string): Record<string, unknown> {
  let schema = surface.schemas.SettingsValues as Record<string, unknown>;
  for (const part of key.split(".")) schema = (schema.properties as Record<string, Record<string, unknown>>)?.[part] ?? {};
  return schema;
}

function SettingEditor(props: { field: SettingField; draft: SettingDraft; busy: boolean; error?: string; running: SettingsValue;
  saved: SettingsValue; schema: Record<string, unknown>; onChange: (draft: SettingDraft) => void }) {
  const { field, draft } = props;
  const label = settingLabel(field.key);
  const disabled = props.busy || draft.mode === "default" || draft.unset;
  const list = ["dnsServers", "natBackends", "ipv4Cidrs"].includes(field.rule.kind);
  const values = Array.isArray(props.schema.enum) ? props.schema.enum.filter((item): item is string => typeof item === "string") : [];
  const change = (text: string) => props.onChange({ ...draft, text });
  return <fieldset class="setting-editor" disabled={props.busy}>
    <legend>{label} {field.application === "restart" && <span class="setting-badge">Restart</span>}</legend>
    <code class="setting-key">{field.key}</code>
    <label class="check"><input class="form-check-input" type="checkbox" checked={draft.mode === "default"}
      aria-label={`Use default for ${label}`} onInput={(event) => props.onChange(event.currentTarget.checked
        ? { mode: "default", text: settingText(field.defaultValue), unset: field.defaultValue === null }
        : { ...draft, mode: "custom" })} />Use default</label>
    {field.nullable && draft.mode === "custom" && <label class="check"><input class="form-check-input" type="checkbox" checked={draft.unset}
      aria-label={`Not set for ${label}`} onInput={(event) => props.onChange({ ...draft, unset: event.currentTarget.checked })} />{field.rule.kind === "integer" ? "Automatic" : "Not set"}</label>}
    {field.rule.kind === "boolean" ? <label class="check"><input class="form-check-input" type="checkbox" aria-label={label}
      disabled={disabled} checked={draft.text === "true"} onInput={(event) => change(String(event.currentTarget.checked))} />Enabled</label>
      : list ? <label><span>{label}</span><textarea class="form-control" aria-label={label} disabled={disabled} value={draft.text}
        onInput={(event) => change(event.currentTarget.value)} /><small>One value per line, in order.</small></label>
      : values.length ? <label><span>{label}</span><select class="form-select" aria-label={label} disabled={disabled} value={draft.text}
        onChange={(event) => change(event.currentTarget.value)}>{values.map((value) => <option value={value} key={value}>{value}</option>)}</select></label>
      : <label><span>{label}</span><input class="form-control" aria-label={label} aria-invalid={props.error ? "true" : "false"}
        inputMode={field.rule.kind === "integer" ? "numeric" : "text"} disabled={disabled} value={draft.text} onInput={(event) => change(event.currentTarget.value)} /></label>}
    <small>Default: {displayValue(field.defaultValue)}{field.unit !== "none" && ` · ${field.unit}`}</small>
    {JSON.stringify(props.running) !== JSON.stringify(props.saved) && <small>Running: {displayValue(props.running)}</small>}
    {props.error && <span class="field-error" role="alert">{props.error}</span>}
  </fieldset>;
}

function displayValue(value: SettingsValue): string {
  return value === null ? "Not set" : Array.isArray(value) ? value.join(", ") || "Empty list" : String(value) || "Empty";
}
