import { act, fireEvent, render, screen, waitFor } from "@testing-library/preact";
import { describe, expect, it, vi } from "vitest";
import { RestClient, type CursorPage, type LibraryTag } from "../../src/api";
import { FileTags, LibraryTags } from "../../src/libraryTags";

const page = (name: string, nextCursor: string | null = null): CursorPage<LibraryTag> => ({
  data: [{ name }], meta: { apiVersion: "v1", nextCursor, hasMore: nextCursor !== null }
});

const emptyPage: CursorPage<LibraryTag> = {
  data: [], meta: { apiVersion: "v1", nextCursor: null, hasMore: false }
};
const hash = "a".repeat(32);

describe("content tag assignments", () => {
  it("assigns an existing name to the selected hash and refreshes its bounded tag page", async () => {
    const client = new RestClient();
    const get = vi.spyOn(client, "getPage").mockResolvedValueOnce(emptyPage).mockResolvedValue(page("Alpha"));
    const control = vi.spyOn(client, "controlLibraryTags").mockResolvedValue([{ hash, status: "accepted", httpStatus: 200 }]);
    render(<FileTags client={client} hash={hash} />);
    await screen.findByText("No assigned tags.");
    fireEvent.input(screen.getByRole("textbox", { name: "Existing tag name" }), { target: { value: "Alpha" } });
    fireEvent.click(screen.getByRole("button", { name: "Assign tag" }));
    await screen.findByText("Tag assigned.");
    await screen.findByText("Alpha");
    expect(control).toHaveBeenCalledExactlyOnceWith("add", "Alpha", [hash]);
    expect(get).toHaveBeenLastCalledWith(`library/files/${hash}/tags?limit=100`);
    expect(screen.getByRole("textbox", { name: "Existing tag name" })).toHaveValue("");
  });

  it("removes an assignment through the bulk action without deleting the global tag", async () => {
    const client = new RestClient();
    vi.spyOn(client, "getPage").mockResolvedValueOnce(page("Alpha")).mockResolvedValue(emptyPage);
    const control = vi.spyOn(client, "controlLibraryTags").mockResolvedValue([{ hash, status: "accepted", httpStatus: 200 }]);
    const removeTag = vi.spyOn(client, "delete");
    render(<FileTags client={client} hash={hash} />);
    await screen.findByText("Alpha");
    fireEvent.click(screen.getByRole("button", { name: "Remove tag Alpha from this content" }));
    await screen.findByText("Tag removed.");
    await screen.findByText("No assigned tags.");
    expect(control).toHaveBeenCalledExactlyOnceWith("remove", "Alpha", [hash]);
    expect(removeTag).not.toHaveBeenCalled();
  });

  it("retains the input and current assignments when the bulk action fails", async () => {
    const client = new RestClient();
    const get = vi.spyOn(client, "getPage").mockResolvedValue(page("Alpha"));
    vi.spyOn(client, "controlLibraryTags").mockRejectedValue(new Error("Tag not found"));
    render(<FileTags client={client} hash={hash} />);
    await screen.findByText("Alpha");
    fireEvent.input(screen.getByRole("textbox", { name: "Existing tag name" }), { target: { value: "Missing" } });
    fireEvent.click(screen.getByRole("button", { name: "Assign tag" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Tag not found");
    expect(screen.getByRole("textbox", { name: "Existing tag name" })).toHaveValue("Missing");
    expect(screen.getByText("Alpha")).toBeInTheDocument();
    expect(screen.queryByText("Tag assigned.")).not.toBeInTheDocument();
    expect(get).toHaveBeenCalledOnce();
  });

  it("resets cursor and input on content selection and ignores the previous content's late page", async () => {
    const client = new RestClient();
    let resolve!: (value: CursorPage<LibraryTag>) => void;
    const get = vi.spyOn(client, "getPage").mockResolvedValueOnce(page("Alpha", "older-scope"))
      .mockReturnValueOnce(new Promise<CursorPage<LibraryTag>>((done) => { resolve = done; }))
      .mockResolvedValue(page("Gamma"));
    const { rerender } = render(<FileTags client={client} hash={hash} />);
    await screen.findByText("Alpha");
    fireEvent.input(screen.getByRole("textbox", { name: "Existing tag name" }), { target: { value: "Draft" } });
    fireEvent.click(screen.getByRole("button", { name: "Next page" }));
    await waitFor(() => expect(get).toHaveBeenCalledTimes(2));
    const nextHash = "b".repeat(32);
    rerender(<FileTags client={client} hash={nextHash} />);
    await screen.findByText("Gamma");
    await act(async () => { resolve(page("Beta")); });
    expect(screen.getByText("Gamma")).toBeInTheDocument();
    expect(screen.queryByText("Beta")).not.toBeInTheDocument();
    expect(get).toHaveBeenLastCalledWith(`library/files/${nextHash}/tags?limit=100`);
    expect(screen.getByRole("textbox", { name: "Existing tag name" })).toHaveValue("");
  });
});

describe("library tag management", () => {
  it("replaces pages and passes the opaque cursor without accumulating rows", async () => {
    const client = new RestClient();
    const get = vi.spyOn(client, "getPage").mockResolvedValueOnce(page("Alpha", "next/+"))
      .mockResolvedValueOnce(page("Beta")).mockResolvedValueOnce(page("Alpha", "next/+"));
    render(<LibraryTags client={client} />);
    await screen.findByText("Alpha");
    expect(get).toHaveBeenNthCalledWith(1, "library/tags?limit=100");
    fireEvent.click(screen.getByRole("button", { name: "Next page" }));
    await screen.findByText("Beta");
    expect(screen.queryByText("Alpha")).not.toBeInTheDocument();
    expect(get).toHaveBeenNthCalledWith(2, "library/tags?limit=100&cursor=next%2F%2B");
    fireEvent.click(screen.getByRole("button", { name: "First page" }));
    await screen.findByText("Alpha");
    expect(screen.queryByText("Beta")).not.toBeInTheDocument();
  });

  it("creates a tag from a later page and refreshes only the first tag page", async () => {
    const client = new RestClient();
    const get = vi.spyOn(client, "getPage").mockResolvedValueOnce(page("Alpha", "later"))
      .mockResolvedValueOnce(page("Beta")).mockResolvedValue(page("Rare-Files"));
    const post = vi.spyOn(client, "post").mockResolvedValue({ name: "Rare-Files" });
    render(<LibraryTags client={client} />);
    await screen.findByText("Alpha");
    fireEvent.click(screen.getByRole("button", { name: "Next page" }));
    await screen.findByText("Beta");
    fireEvent.input(screen.getByRole("textbox", { name: "Tag name" }), { target: { value: "Rare-Files" } });
    fireEvent.click(screen.getByRole("button", { name: "Create tag" }));
    await screen.findByText("Tag created.");
    await screen.findByText("Rare-Files");
    expect(post).toHaveBeenCalledExactlyOnceWith("library/tags", { name: "Rare-Files" });
    expect(get).toHaveBeenLastCalledWith("library/tags?limit=100");
    expect(screen.queryByText("Beta")).not.toBeInTheDocument();
    expect(screen.getByRole("textbox", { name: "Tag name" })).toHaveValue("");
  });

  it("preserves the proposed name and current page when creation fails", async () => {
    const client = new RestClient();
    const get = vi.spyOn(client, "getPage").mockResolvedValue(page("Alpha"));
    vi.spyOn(client, "post").mockRejectedValue(new Error("Tag name already exists"));
    render(<LibraryTags client={client} />);
    await screen.findByText("Alpha");
    fireEvent.input(screen.getByRole("textbox", { name: "Tag name" }), { target: { value: "ALPHA" } });
    fireEvent.click(screen.getByRole("button", { name: "Create tag" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Tag name already exists");
    expect(screen.getByRole("textbox", { name: "Tag name" })).toHaveValue("ALPHA");
    await waitFor(() => expect(screen.getByRole("button", { name: "Create tag" })).not.toBeDisabled());
    expect(get).toHaveBeenCalledOnce();
    expect(screen.getByText("Alpha")).toBeInTheDocument();
  });

  it("requires deletion confirmation and refreshes after a successful deletion", async () => {
    const client = new RestClient();
    const get = vi.spyOn(client, "getPage").mockResolvedValueOnce(page("Alpha"))
      .mockResolvedValue({ data: [], meta: { apiVersion: "v1", nextCursor: null, hasMore: false } });
    const remove = vi.spyOn(client, "delete").mockResolvedValue(undefined);
    const confirm = vi.spyOn(window, "confirm").mockReturnValueOnce(false).mockReturnValueOnce(true);
    render(<LibraryTags client={client} />);
    await screen.findByText("Alpha");
    fireEvent.click(screen.getByRole("button", { name: "Delete tag Alpha" }));
    expect(remove).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: "Delete tag Alpha" }));
    await screen.findByText("Tag deleted.");
    await screen.findByText("No tags.");
    expect(confirm).toHaveBeenCalledWith("Delete tag Alpha and its file assignments?");
    expect(remove).toHaveBeenCalledExactlyOnceWith("library/tags/Alpha");
    expect(get).toHaveBeenCalledTimes(2);
  });

  it("does not publish a late page from a replaced client", async () => {
    const first = new RestClient();
    const second = new RestClient();
    let resolve!: (value: CursorPage<LibraryTag>) => void;
    const firstGet = vi.spyOn(first, "getPage").mockReturnValue(new Promise<CursorPage<LibraryTag>>((done) => { resolve = done; }));
    vi.spyOn(second, "getPage").mockResolvedValue(page("Beta"));
    const { rerender } = render(<LibraryTags client={first} />);
    await waitFor(() => expect(firstGet).toHaveBeenCalledOnce());
    rerender(<LibraryTags client={second} />);
    await screen.findByText("Beta");
    await act(async () => { resolve(page("Alpha")); });
    expect(screen.queryByText("Alpha")).not.toBeInTheDocument();
    expect(screen.getByText("Beta")).toBeInTheDocument();
  });

  it("keeps invalid names out of create requests and permits retrying a failed read", async () => {
    const client = new RestClient();
    vi.spyOn(client, "getPage").mockRejectedValueOnce(new Error("Tag list unavailable"))
      .mockResolvedValue(page("Alpha"));
    const post = vi.spyOn(client, "post");
    render(<LibraryTags client={client} />);
    expect(await screen.findByRole("alert")).toHaveTextContent("Tag list unavailable");
    await waitFor(() => expect(screen.getByRole("button", { name: "Refresh tags" })).not.toBeDisabled());
    fireEvent.click(screen.getByRole("button", { name: "Refresh tags" }));
    await screen.findByText("Alpha");
    fireEvent.input(screen.getByRole("textbox", { name: "Tag name" }), { target: { value: "bad tag" } });
    expect(screen.getByRole("button", { name: "Create tag" })).toBeDisabled();
    expect(post).not.toHaveBeenCalled();
  });
});
