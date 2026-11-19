import { useEffect, useRef, useState } from "preact/hooks";
import { type CursorPage, type LibraryTag, type RestClient } from "./api";
import { CursorControls, EmptyRow, TableScroll } from "./components";
import { errorMessage, identityNameError } from "./format";

/** Shared bounded tag-page loading with cancellation at the resource boundary. */
function useTagPage(client: RestClient, path: string, generation: number) {
  const [cursor, setCursor] = useState<string | null>(null);
  const [page, setPage] = useState<CursorPage<LibraryTag> | null>(null);
  const [loading, setLoading] = useState(false);
  const [readError, setReadError] = useState("");
  useEffect(() => {
    let current = true;
    setLoading(true);
    setPage(null);
    setReadError("");
    const query = new URLSearchParams({ limit: "100" });
    if (cursor) query.set("cursor", cursor);
    void client.getPage<LibraryTag>(`${path}?${query}`).then((value) => {
      if (current) setPage(value);
    }).catch((error) => { if (current) setReadError(errorMessage(error)); })
      .finally(() => { if (current) setLoading(false); });
    return () => { current = false; };
  }, [client, path, cursor, generation]);
  return { cursor, setCursor, page, loading, readError };
}

/** Manage immutable tag names while retaining only the current bounded page. */
export function LibraryTags(props: { client: RestClient }) {
  const [generation, setGeneration] = useState(0);
  const { cursor, setCursor, page, loading, readError } = useTagPage(props.client, "library/tags", generation);
  const [mutating, setMutating] = useState(false);
  const mutationActive = useRef(false);
  const [name, setName] = useState("");
  const [mutationError, setMutationError] = useState("");
  const [notice, setNotice] = useState("");
  const nameError = identityNameError(name);

  const mutate = async (operation: () => Promise<unknown>, message: string) => {
    if (mutationActive.current) return;
    mutationActive.current = true;
    setMutating(true);
    setMutationError("");
    setNotice("");
    try {
      await operation();
      setCursor(null);
      setGeneration((value) => value + 1);
      setNotice(message);
    } catch (error) {
      setMutationError(errorMessage(error));
    } finally {
      mutationActive.current = false;
      setMutating(false);
    }
  };

  return <section class="panel card wide" aria-label="Library tags">
    <div class="section-title"><h2>Library Tags</h2><div class="row-actions">
      <CursorControls cursor={cursor} nextCursor={page?.meta.nextCursor ?? null}
        loading={loading || mutating} change={setCursor} />
      <button class="btn" type="button" disabled={loading || mutating}
        onClick={() => setGeneration((value) => value + 1)}>Refresh tags</button>
    </div></div>
    <form class="form-row" onSubmit={(event) => {
      event.preventDefault();
      if (!name || nameError || mutating) return;
      void mutate(async () => {
        await props.client.post("library/tags", { name });
        setName("");
      }, "Tag created.");
    }}>
      <label>Tag name<input class="form-control" value={name} maxLength={64}
        aria-invalid={Boolean(nameError)} disabled={mutating}
        onInput={(event) => setName(event.currentTarget.value)} /></label>
      <button class="btn" type="submit" disabled={!name || Boolean(nameError) || mutating}>Create tag</button>
    </form>
    <p class="hint">Names are permanent and case-insensitive. Create a new tag to use a different name.</p>
    {nameError && <p class="field-error">{nameError}</p>}
    {(readError || mutationError) && <div class="notice alert alert-danger" role="alert">{readError || mutationError}</div>}
    {notice && <p role="status">{notice}</p>}
    {loading && <p role="status">Loading tags…</p>}
    <TableScroll label="Library tags"><table class="table table-vcenter card-table">
      <thead><tr><th>Name</th><th>Actions</th></tr></thead>
      <tbody>{page?.data.map((tag) => <tr key={tag.name}><td>{tag.name}</td><td>
        <button class="btn" type="button" disabled={mutating} aria-label={`Delete tag ${tag.name}`}
          onClick={() => {
            if (window.confirm(`Delete tag ${tag.name} and its file assignments?`)) {
              void mutate(() => props.client.delete(`library/tags/${encodeURIComponent(tag.name)}`), "Tag deleted.");
            }
          }}>Delete</button>
      </td></tr>)}
      {page?.data.length === 0 && <EmptyRow colSpan={2} text="No tags." />}</tbody>
    </table></TableScroll>
  </section>;
}

/** A content change resets assignment editing and cursor scope together. */
export function FileTags(props: { client: RestClient; hash: string }) {
  return <FileTagEditor key={props.hash} {...props} />;
}

function FileTagEditor(props: { client: RestClient; hash: string }) {
  const [generation, setGeneration] = useState(0);
  const { cursor, setCursor, page, loading, readError } = useTagPage(
    props.client, `library/files/${encodeURIComponent(props.hash)}/tags`, generation);
  const [name, setName] = useState("");
  const [mutating, setMutating] = useState(false);
  const mutationActive = useRef(false);
  const [mutationError, setMutationError] = useState("");
  const [notice, setNotice] = useState("");
  const nameError = identityNameError(name);

  const change = async (action: "add" | "remove", tag: string) => {
    if (mutationActive.current) return;
    mutationActive.current = true;
    setMutating(true);
    setMutationError("");
    setNotice("");
    try {
      const items = await props.client.controlLibraryTags(action, tag, [props.hash]);
      if (action === "add") setName("");
      setCursor(null);
      setGeneration((value) => value + 1);
      setNotice(items[0].status === "unchanged"
        ? action === "add" ? "Tag already assigned." : "Tag was not assigned."
        : action === "add" ? "Tag assigned." : "Tag removed.");
    } catch (error) {
      setMutationError(errorMessage(error));
    } finally {
      mutationActive.current = false;
      setMutating(false);
    }
  };

  return <section aria-label="File tags">
    <div class="section-title"><h3>Tags</h3><div class="row-actions">
      <CursorControls cursor={cursor} nextCursor={page?.meta.nextCursor ?? null}
        loading={loading || mutating} change={setCursor} />
      <button class="btn" type="button" disabled={loading || mutating}
        onClick={() => setGeneration((value) => value + 1)}>Refresh assigned tags</button>
    </div></div>
    <p class="hint">Tags apply to all library copies of this content. Create tag names under Sharing.</p>
    <form class="form-row" onSubmit={(event) => {
      event.preventDefault();
      if (name && !nameError) void change("add", name);
    }}>
      <label>Existing tag name<input class="form-control" value={name} maxLength={64}
        aria-invalid={Boolean(nameError)} disabled={mutating}
        onInput={(event) => setName(event.currentTarget.value)} /></label>
      <button class="btn" type="submit" disabled={!name || Boolean(nameError) || mutating}>Assign tag</button>
    </form>
    {nameError && <p class="field-error">{nameError}</p>}
    {readError && <p role="alert" class="field-error">{readError}</p>}
    {mutationError && <p role="alert" class="field-error">{mutationError}</p>}
    {notice && <p role="status">{notice}</p>}
    {loading && <p role="status">Loading assigned tags…</p>}
    <TableScroll label="Assigned tags"><table class="table table-vcenter card-table">
      <thead><tr><th>Name</th><th>Actions</th></tr></thead>
      <tbody>{page?.data.map((tag) => <tr key={tag.name}><td>{tag.name}</td><td>
        <button class="btn" type="button" disabled={mutating}
          aria-label={`Remove tag ${tag.name} from this content`}
          onClick={() => void change("remove", tag.name)}>Remove</button>
      </td></tr>)}
      {page?.data.length === 0 && <EmptyRow colSpan={2} text="No assigned tags." />}</tbody>
    </table></TableScroll>
  </section>;
}
