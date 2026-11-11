import type { AppInfo } from "./api";

/** Keep the existing application heading and its build details on one identity. */
export function AppIdentity({ app }: { app: AppInfo | null }) {
  const version = app?.version ?? app?.apiVersion ?? "REST dashboard";
  return (
    <div>
      <h1>eMuleBB WebUI</h1>
      <details class="brand-identity" aria-label="About this build">
        <summary class="brand-version">{version}</summary>
        <dl class="build-details">
          <dt>Version</dt><dd>{version}</dd>
          <dt>Channel</dt><dd>{app?.channel ?? "unknown"}</dd>
          <dt>Architecture</dt><dd>{app?.platform ?? "unknown"}</dd>
          <dt>Build</dt><dd>{app?.build ?? "unknown"}</dd>
          <dt>Source commit</dt><dd>{app?.sourceRevision ?? "unknown"}</dd>
        </dl>
      </details>
    </div>
  );
}
