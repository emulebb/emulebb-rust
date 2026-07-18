import type { ComponentChildren } from "preact";
import { useMemo } from "preact/hooks";

export function Metric(props: { label: string; value: string }) {
  return (
    <section class="metric card">
      <div class="card-body">
        <span class="text-secondary">{props.label}</span>
        <strong>{props.value}</strong>
      </div>
    </section>
  );
}

export function StatusPill(props: { value: string }) {
  const className = useMemo(() => {
    const value = props.value.toLowerCase();
    if (
      value.includes("connected") ||
      value.includes("downloading") ||
      value.includes("uploading") ||
      value.includes("monitored") ||
      value.includes("open") ||
      value.includes("complete") ||
      value === "ok" ||
      value.includes("published")
    ) {
      return "status-pill badge bg-success-lt";
    }
    if (value.includes("error") || value.includes("firewall") || value.includes("banned") || value.includes("failed") || value.includes("blocked")) {
      return "status-pill badge bg-danger-lt";
    }
    if (value.includes("paused") || value.includes("idle") || value.includes("queued") || value.includes("active")) {
      return "status-pill badge bg-warning-lt";
    }
    return "status-pill badge bg-secondary-lt";
  }, [props.value]);
  return <span class={className}>{props.value}</span>;
}

export function Action(props: { title: string; icon: ComponentChildren; onClick: () => void; disabled?: boolean }) {
  return (
    <button type="button" class="btn btn-icon btn-outline-secondary icon-button" title={props.title} disabled={props.disabled} onClick={props.onClick}>
      {props.icon}
    </button>
  );
}

export function EmptyRow(props: { colSpan: number; text: string }) {
  return (
    <tr>
      <td colSpan={props.colSpan} class="empty-cell">
        {props.text}
      </td>
    </tr>
  );
}

export function JsonPanel(props: { value: unknown }) {
  return <pre class="json-panel">{JSON.stringify(props.value ?? {}, null, 2)}</pre>;
}
