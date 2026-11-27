import type { ComponentChildren } from "preact";
import { useEffect, useLayoutEffect, useRef, useState } from "preact/hooks";
import { Download, Ellipsis, Search } from "lucide-preact";
import type { SearchItem } from "./api";
import type { Appearance, AppearancePreference } from "./appearance";
import { UpdateWarning } from "./components";
import { formatBytes, formatProgress } from "./format";
import { pathForRoute, type AppRoute, type Tab } from "./routes";
import {
  DownloadStateLabel,
  normalizeSearchQuery,
  queueSearchResult,
  searchQueryValidationError,
  useDownloads,
  type DownloadsViewProps,
  type SearchViewProps
} from "./views";
import "./mobile.css";

function follow(event: MouseEvent, navigate: () => void) {
  if (event.button !== 0 || event.altKey || event.ctrlKey || event.metaKey || event.shiftKey) return;
  event.preventDefault();
  navigate();
}

const mobileTabs = [
  { label: "Downloads", tab: "downloads", icon: Download },
  { label: "Search", tab: "search", icon: Search },
  { label: "More", tab: "overview", icon: Ellipsis }
] as const;

export function MobileShell(props: {
  route: AppRoute;
  authenticated: boolean;
  navigate: (route: AppRoute) => void;
  desktopRoute: AppRoute;
  switchToDesktop: () => void;
  refreshError: string;
  message: string;
  error: string;
  children: ComponentChildren;
}) {
  const [visibleMessage, setVisibleMessage] = useState("");
  useEffect(() => {
    setVisibleMessage(props.message);
    if (!props.message) return;
    const timeout = window.setTimeout(() => setVisibleMessage(""), 4000);
    return () => window.clearTimeout(timeout);
  }, [props.message]);
  return <div class="mobile-ui">
    <header class="phone-header">
      <strong>eMuleBB</strong>
      {props.authenticated
        ? <UpdateWarning message={props.refreshError} />
        : <a href={pathForRoute(props.desktopRoute)} onClick={(event) => follow(event, props.switchToDesktop)}>Desktop view</a>}
    </header>
    <main class="phone-content">{props.children}</main>
    {props.authenticated && <>
      <div class="phone-feedback" aria-live="polite">
        {props.error ? <span class="phone-error">{props.error}</span> : visibleMessage && <span>{visibleMessage}</span>}
      </div>
      <nav class="phone-navigation" aria-label="Mobile views">
        {mobileTabs.map(({ label, tab, icon: Icon }) => {
          const route = { tab, mobile: true } as const;
          return <a key={tab} href={pathForRoute(route)} aria-current={tab === props.route.tab ? "page" : undefined}
            onClick={(event) => follow(event, () => {
              if (tab !== props.route.tab) props.navigate(route);
            })}>
            <Icon size={21} aria-hidden="true" />{label}
          </a>;
        })}
      </nav>
    </>}
  </div>;
}

export function MobileMore(props: {
  appearance: Appearance;
  preference: AppearancePreference;
  logOut: () => void;
  desktopRoute: AppRoute;
  switchToDesktop: () => void;
  tools: { tab: Tab; label: string }[];
  navigate: (route: AppRoute) => void;
}) {
  return <section class="phone-list">
    <h1>More</h1>
    <div class="phone-card phone-list">
      <label class="phone-field">Appearance
        <select value={props.preference} onChange={(event) => props.appearance.setPreference(event.currentTarget.value as AppearancePreference)}>
          <option value="system">System</option><option value="light">Light</option><option value="dark">Dark</option>
        </select>
      </label>
      <a class="phone-button" href={pathForRoute(props.desktopRoute)}
        onClick={(event) => follow(event, props.switchToDesktop)}>Desktop view</a>
      <button type="button" onClick={props.logOut}>Log out</button>
    </div>
    <h2>Desktop tools</h2>
    <ul class="phone-tools">
      {props.tools.map(({ tab, label }) => <li key={tab}>
        <a href={pathForRoute({ tab })} onClick={(event) => follow(event, () => props.navigate({ tab }))}>{label}</a>
      </li>)}
    </ul>
  </section>;
}

function PhonePages(props: { cursor: string | null; next: string | null | undefined; change: (cursor: string | null) => void; label: string }) {
  if (!props.cursor && !props.next) return null;
  return <div class="phone-actions" role="group" aria-label={props.label}>
    <button type="button" disabled={!props.cursor} onClick={() => props.change(null)}>First page</button>
    <button type="button" disabled={!props.next} onClick={() => props.change(props.next ?? null)}>Next page</button>
  </div>;
}

export function MobileDownloads(props: DownloadsViewProps) {
  const downloads = useDownloads(props);
  const [adding, setAdding] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const detailDialog = useRef<HTMLDialogElement>(null);
  const selectedId = downloads.selectedId;
  useLayoutEffect(() => {
    if (selectedId) detailDialog.current?.showModal();
  }, [selectedId]);

  const closeAdd = () => {
    downloads.consumeHandoff();
    downloads.setEd2kLinks("");
    setAdding(false);
  };
  return <section class="phone-list">
    <div class="phone-heading"><h1>Downloads</h1>
      <UpdateWarning message={downloads.page ? downloads.listError : ""} />
      <button class="phone-primary" type="button" aria-expanded={Boolean(adding || downloads.handoff)}
        onClick={() => adding || downloads.handoff ? closeAdd() : setAdding(true)}>Add links</button>
    </div>
    {(adding || downloads.handoff) && <form class="phone-card phone-list" onSubmit={(event) => {
      event.preventDefault();
      if (submitting) return;
      setAdding(true);
      setSubmitting(true);
      void props.run(async () => {
        await downloads.createDownloads();
        setAdding(false);
      }, "Downloads queued").finally(() => setSubmitting(false));
    }}>
      {downloads.handoff && <p role={downloads.handoff.error ? "alert" : undefined}>
        {downloads.handoff.error ?? "Review the eD2K link before queueing."}
      </p>}
      <label class="phone-field">eD2K links
        <textarea value={downloads.ed2kLinks} rows={3} placeholder="One eD2K link per line"
          aria-invalid={Boolean(downloads.linksError)} onInput={(event) => downloads.setEd2kLinks(event.currentTarget.value)} />
      </label>
      {downloads.linksError && <p role="alert">{downloads.linksError}</p>}
      <label class="phone-check"><input type="checkbox" checked={downloads.stoppedCreate}
        onChange={(event) => downloads.setStoppedCreate(event.currentTarget.checked)} /> Add stopped</label>
      <div class="phone-actions">
        <button type="submit" class="phone-primary" disabled={submitting || !downloads.ed2kLinks.trim() || Boolean(downloads.linksError)}>Queue links</button>
        <button type="button" onClick={closeAdd} disabled={submitting}>Cancel</button>
      </div>
    </form>}
    <div class="phone-filters">
      <label class="phone-field">Status
        <select value={downloads.view} onChange={(event) => { downloads.setView(event.currentTarget.value); downloads.changePage(null); }}>
          <option value="unfinished">Unfinished</option><option value="completed">Completed</option><option value="all">All downloads</option>
        </select>
      </label>
      <label class="phone-field">Category
        <select value={downloads.category} onChange={(event) => { downloads.setCategory(event.currentTarget.value); downloads.changePage(null); }}>
          <option value="">All categories</option>
          {props.categories.map((item) => <option key={item.name} value={item.name}>{item.name}</option>)}
        </select>
      </label>
    </div>
    {!downloads.page && (downloads.listError ? <p role="alert">{downloads.listError}</p> : <p>Loading downloads…</p>)}
    {downloads.page?.data.length === 0 && <p>No downloads.</p>}
    {downloads.page?.data.map((job) => <article class="phone-card phone-list" key={job.id}>
      <div class="phone-card-heading">
        <button class="phone-file" type="button" aria-haspopup="dialog" onClick={() => downloads.selectDownload(job.id)}><span>{job.name}</span></button>
        {job.state !== "completed" && (job.intent === "stopped"
          ? <button type="button" onClick={() => void props.run(() => props.client.controlDownloads("start", [job.id]), "Download started")}>Start</button>
          : <button type="button" onClick={() => void props.run(() => props.client.controlDownloads("stop", [job.id]), "Download stopped")}>Stop</button>)}
      </div>
      <div class="phone-card-meta"><DownloadStateLabel download={job} /><span>{formatProgress(job)}</span></div>
      {job.progress !== null && <progress value={job.progress} max={1} aria-label={`Progress for ${job.name}`} />}
    </article>)}
    <PhonePages cursor={downloads.cursor} next={downloads.page?.meta.nextCursor} change={downloads.changePage} label="Download pages" />
    {selectedId && <dialog class="phone-dialog" ref={detailDialog} aria-labelledby="phone-download-details"
      onClose={() => downloads.selectDownload("")}>
      <div class="phone-heading"><h2 id="phone-download-details">Download details</h2>
        <UpdateWarning message={downloads.details ? downloads.detailError : ""} />
        <button type="button" autofocus onClick={() => detailDialog.current?.close()}>Close</button>
      </div>
      {downloads.details ? <div class="phone-list">
        <strong>{downloads.details.name}</strong>
        <DownloadStateLabel download={downloads.details} />
        <span>{formatProgress(downloads.details)} · {downloads.details.sizeBytes === null ? "Unknown size" : formatBytes(downloads.details.sizeBytes)}</span>
        {downloads.details.category && <span>Category: {downloads.details.category}</span>}
        {downloads.details.delivery?.path && <span>File: {downloads.details.delivery.path}</span>}
        {downloads.details.failure && <span>{downloads.details.failure.message}</span>}
        <button type="button" onClick={() => {
          if (downloads.details) downloads.remove(downloads.details, false);
        }}>Remove from list</button>
      </div> : downloads.detailError ? <p role="alert">{downloads.detailError}</p> : <p>Loading details…</p>}
    </dialog>}
  </section>;
}

export function MobileSearch(props: SearchViewProps) {
  const [query, setQuery] = useState("");
  const [method, setMethod] = useState("automatic");
  const [fileType, setFileType] = useState("");
  const [starting, setStarting] = useState(false);
  const error = searchQueryValidationError(query);
  const selected = props.selectedSearch?.id === props.selectedSearchId ? props.selectedSearch : null;
  const results = props.resultPage?.data;
  return <section class="phone-list">
    <div class="phone-heading"><h1>Search</h1><UpdateWarning message={props.resultPage ? props.readError : ""} /></div>
    <form class="phone-list" onSubmit={(event) => {
      event.preventDefault();
      if (starting || !normalizeSearchQuery(query) || error) return;
      setStarting(true);
      void props.run(async () => {
        const next = await props.client.post<SearchItem>("searches", {
          query: normalizeSearchQuery(query), method, type: fileType
        });
        props.onSearchCreated(next);
      }, "Search started", { refresh: false }).finally(() => setStarting(false));
    }}>
      <div class="phone-query">
        <input type="search" aria-label="Search query" placeholder="Search query" value={query}
          aria-invalid={Boolean(error)} onInput={(event) => setQuery(event.currentTarget.value)} />
        <button class="phone-primary" type="submit" disabled={starting || !normalizeSearchQuery(query) || Boolean(error)}>Search</button>
      </div>
      {error && <p role="alert">{error}</p>}
      <details class="phone-card">
        <summary>Search options</summary>
        <div class="phone-filters">
          <label class="phone-field">Method<select value={method} onChange={(event) => setMethod(event.currentTarget.value)}>
            <option value="automatic">Automatic</option><option value="server">Server</option>
            <option value="global">Global</option><option value="kad">Kad</option>
          </select></label>
          <label class="phone-field">File type<select value={fileType} onChange={(event) => setFileType(event.currentTarget.value)}>
            <option value="">Any</option><option value="audio">Audio</option><option value="video">Video</option>
            <option value="image">Image</option><option value="doc">Document</option><option value="arc">Archive</option>
            <option value="iso">ISO</option><option value="pro">Program</option><option value="emulecollection">eMule collection</option>
          </select></label>
        </div>
      </details>
    </form>
    {(props.searches.length > 0 || selected) && <label class="phone-field">Search session
      <select value={props.selectedSearchId ?? ""} onChange={(event) => props.selectSearch(event.currentTarget.value)}>
        {!props.selectedSearchId && <option value="" disabled>Select a search session</option>}
        {selected && !props.searches.some((session) => session.id === selected.id) &&
          <option value={selected.id}>{selected.query || `Search #${selected.id}`}</option>}
        {props.searches.map((session) => <option key={session.id} value={session.id}>{session.query || `Search #${session.id}`} · {session.resultCount} results</option>)}
      </select>
    </label>}
    <PhonePages cursor={props.sessionCursor} next={props.sessionNextCursor} change={props.selectSearchSessionsPage} label="Search session pages" />
    {selected && <p class="phone-muted">{selected.resultCount} results · {selected.status ?? "Unknown status"}</p>}
    {!results && (props.readError ? <p role="alert">{props.readError}</p> : props.selectedSearchId && <p>Loading results…</p>)}
    {results?.length === 0 && <p>No results.</p>}
    {results?.map((result) => {
      const status = props.downloadStatus.get(result.hash.toLowerCase());
      return <article class="phone-card phone-list" key={result.id}>
        <strong>{result.displayName ?? result.hash}</strong>
        <div class="phone-card-meta">
          <span>{result.sizeBytes === null ? "Unknown size" : formatBytes(result.sizeBytes)} · {result.sources ?? 0} sources</span>
          {typeof status === "string" ? <span class="phone-queued">Queued</span>
            : <button type="button" class="phone-primary" disabled={typeof status === "symbol" || !props.selectedSearchId}
              onClick={() => void queueSearchResult(props, result)}>{typeof status === "symbol" ? "Queuing…" : "Download"}</button>}
        </div>
      </article>;
    })}
    <PhonePages cursor={props.resultCursor} next={props.resultPage?.meta.nextCursor} change={props.selectSearchPage} label="Search result pages" />
  </section>;
}
