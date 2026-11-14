import type { ComponentChildren } from "preact";
import { useEffect, useId, useMemo, useRef, useState } from "preact/hooks";

/** Retain every table column while keeping overflow local and keyboard reachable. */
export function TableScroll(props: { children: ComponentChildren; label?: string }) {
  const container = useRef<HTMLDivElement>(null);
  const hintId = useId();
  const [overflow, setOverflow] = useState(false);
  useEffect(() => {
    const element = container.current!;
    const measure = () => setOverflow(element.scrollWidth > element.clientWidth + 1);
    measure();
    const observer = typeof ResizeObserver === "undefined" ? undefined : new ResizeObserver(measure);
    observer?.observe(element);
    if (element.firstElementChild) observer?.observe(element.firstElementChild);
    window.addEventListener("resize", measure);
    return () => {
      observer?.disconnect();
      window.removeEventListener("resize", measure);
    };
  }, []);
  return (
    <div class="table-region">
      <div class="table-wrap" ref={container} tabIndex={overflow ? 0 : undefined}
        role={overflow ? "region" : undefined} aria-label={overflow ? props.label ?? "Table columns" : undefined}
        aria-describedby={overflow ? hintId : undefined}>
        {props.children}
      </div>
      <p id={hintId} class="table-scroll-hint hint" hidden={!overflow}>Swipe horizontally for more columns</p>
    </div>
  );
}

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
      value === "highid" ||
      value.includes("published")
    ) {
      return "status-pill badge bg-success-lt";
    }
    if (value.includes("error") || value.includes("firewall") || value.includes("banned") || value.includes("failed") || value.includes("blocked")) {
      return "status-pill badge bg-danger-lt";
    }
    if (value === "lowid" || value.includes("connecting") || value.includes("paused") || value.includes("insufficient") || value.includes("idle") || value.includes("queued") || value.includes("active")) {
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
