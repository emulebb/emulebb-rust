import { useEffect, useRef, useState } from "preact/hooks";
import { type CursorPage, type LibraryTag, type RestClient } from "./api";
import { CursorControls, EmptyRow, TableScroll } from "./components";
import { errorMessage, identityNameError } from "./format";

/** Manage immutable tag names while retaining only the current bounded page. */
export function LibraryTags(props: { client: RestClient }) {
  const [cursor, setCursor] = useState<string | null>(null);
  const [page, setPage] = useState<CursorPage<LibraryTag> | null>(null);
  const [generation, setGeneration] = useState(0);
  const [loading, setLoading] = useState(false);
  const [mutating, setMutating] = useState(false);
  const mutationActive = useRef(false);
  const [name, setName] = useState("");
  const [readError, setReadError] = useState("");
  const [mutationError, setMutationError] = useState("");
  const [notice, setNotice] = useState("");
  const nameError = identityNameError(name);

  useEffect(() => {
    let current = true;
    setLoading(true);
    setPage(null);
    setReadError("");
    const query = new URLSearchParams({ limit: "100" });
    if (cursor) query.set("cursor", cursor);
    void props.client.getPage<LibraryTag>(`library/tags?${query}`).then((value) => {
      if (current) setPage(value);
    }).catch((error) => { if (current) setReadError(errorMessage(error)); })
      .finally(() => { if (current) setLoading(false); });
    return () => { current = false; };
  }, [props.client, cursor, generation]);

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
