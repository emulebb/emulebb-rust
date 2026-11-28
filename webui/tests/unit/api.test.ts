import { describe, expect, it, vi } from "vitest";

import { RestClient, RestError } from "../../src/api";
import { settingsFixture } from "../fixtures/settings";

describe("RestClient", () => {
  it("keeps full-width saved revisions on settings reads and atomic writes", async () => {
    const snapshot = settingsFixture();
    const fetchMock = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) => jsonResponse(snapshot));
    const client = new RestClient({ fetch: fetchMock as unknown as typeof fetch });
    await expect(client.getSettings()).resolves.toEqual(snapshot);
    const patch = { expectedRevision: snapshot.meta.settingsRevision, set: { network: { nickname: "Sample Client" } }, reset: ["storage.tempDirectory"] };
    await expect(client.patchSettings(patch)).resolves.toEqual(snapshot);
    expect(fetchMock.mock.calls[0][0]).toBe("/api/v1/settings");
    expect(fetchMock.mock.calls[1]).toEqual(["/api/v1/settings", { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify(patch) }]);
  });

  it.each([0, "0", "01", "1e6", "9223372036854775808"])("refuses an invalid saved revision %s", async (revision) => {
    const fetchMock = vi.fn(async () => jsonResponse({ ...settingsFixture(), meta: { settingsRevision: revision } }));
    const client = new RestClient({ fetch: fetchMock as unknown as typeof fetch });
    await expect(client.getSettings()).rejects.toThrow("valid saved revision");
    expect(fetchMock).toHaveBeenCalledOnce();
  });

  it("exposes a settings conflict without another read or write", async () => {
    const fetchMock = vi.fn(async () => jsonResponse({ error: { code: "SETTINGS_CONFLICT", message: "Saved settings changed." } }, { status: 409 }));
    const client = new RestClient({ fetch: fetchMock as unknown as typeof fetch });
    await expect(client.patchSettings({ expectedRevision: "9007199254740993", reset: ["storage.tempDirectory"] }))
      .rejects.toMatchObject({ status: 409, code: "SETTINGS_CONFLICT" });
    expect(fetchMock).toHaveBeenCalledOnce();
  });

  it("preserves ordered hash outcomes and sends tag changes through the bulk endpoint", async () => {
    const hashes = ["a".repeat(32), "b".repeat(32)];
    const data = [{ hash: hashes[0], status: "accepted", httpStatus: 200 },
      { hash: hashes[1], status: "unchanged", httpStatus: 200 }];
    const fetchMock = vi.fn(async () => jsonResponse({ data }, { status: 207 })) as unknown as typeof fetch;
    const client = new RestClient({ fetch: fetchMock });
    await expect(client.controlLibraryTags("add", "Alpha", hashes)).resolves.toEqual(data);
    expect(fetchMock).toHaveBeenCalledExactlyOnceWith("/api/v1/library/files/tags/add", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ tag: "Alpha", hashes })
    });
  });

  it("surfaces failed hash outcomes from HTTP 207 without retrying accepted tag changes", async () => {
    const hashes = ["a".repeat(32), "b".repeat(32)];
    const data = [{ hash: hashes[0], status: "accepted", httpStatus: 200 },
      { hash: hashes[1], status: "failed", httpStatus: 404,
        error: { code: "NOT_FOUND", message: "Library file not found", details: {} } }];
    const fetchMock = vi.fn(async () => jsonResponse({ data }, { status: 207 })) as unknown as typeof fetch;
    const client = new RestClient({ fetch: fetchMock });
    await expect(client.controlLibraryTags("remove", "Alpha", hashes)).rejects.toMatchObject({
      status: 404, code: "NOT_FOUND", details: data
    });
    expect(fetchMock).toHaveBeenCalledOnce();
  });

  it("captures the exact raw diagnostic bundle with its required bounded request", async () => {
    const bundle = { schema: "emulebb.diagnostic-bundle.v8" as const, capturedAt: 1794657600,
      settingsProvenance: { apiKeyIncluded: true, sensitiveValues: "exact", apiKey: "synthetic-private-key" } };
    const fetchMock = vi.fn(async () => jsonResponse(bundle)) as unknown as typeof fetch;
    const client = new RestClient({ fetch: fetchMock });
    client.setApiKey("synthetic-request-key");
    await expect(client.captureDiagnosticBundle(16_777_216)).resolves.toEqual(bundle);
    expect(fetchMock).toHaveBeenCalledWith("/api/v1/diagnostics/bundles", {
      method: "POST", headers: { "Content-Type": "application/json", "X-API-Key": "synthetic-request-key" },
      body: JSON.stringify({ confirmCapture: true, maxBytes: 16_777_216 })
    });
  });

  it("rejects an envelope substituted for the raw diagnostic bundle", async () => {
    const fetchMock = vi.fn(async () => jsonResponse({ data: { schema: "emulebb.diagnostic-bundle.v8" as const, capturedAt: 0 } })) as unknown as typeof fetch;
    await expect(new RestClient({ fetch: fetchMock }).captureDiagnosticBundle(16_777_216)).rejects.toThrow("unexpected response");
  });

  it("unwraps successful API envelopes", async () => {
    const fetchMock = vi.fn(async () => jsonResponse({ data: { version: "0.1.0-beta.2" } })) as unknown as typeof fetch;
    const client = new RestClient({ basePath: "/test-api", fetch: fetchMock });

    await expect(client.get<{ version: string }>("app")).resolves.toEqual({ version: "0.1.0-beta.2" });
    expect(fetchMock).toHaveBeenCalledWith("/test-api/app", {
      method: "GET",
      headers: {}
    });
  });

  it("sends API keys and JSON request bodies", async () => {
    const fetchMock = vi.fn(async () => jsonResponse({ data: { queued: true } })) as unknown as typeof fetch;
    const client = new RestClient({ basePath: "/api/v1/", fetch: fetchMock });
    client.setApiKey("  secret-key  ");

    const body = { source: { type: "ed2k-link", link: "ed2k://|file|Sample.bin|1|00112233445566778899aabbccddeeff|/" }, intent: "stopped" };
    await client.post("downloads", body);

    expect(fetchMock).toHaveBeenCalledWith("/api/v1/downloads", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-API-Key": "secret-key"
      },
      body: JSON.stringify(body)
    });
  });

  it("throws server error messages from error envelopes", async () => {
    const fetchMock = vi.fn(async () =>
      jsonResponse({ error: { code: "BAD_REQUEST", message: "Path is required" } }, { status: 400 })
    ) as unknown as typeof fetch;
    const client = new RestClient({ fetch: fetchMock });

    await expect(client.post("library/roots", {})).rejects.toThrow("Path is required");
  });

  it("surfaces a failed item in a successful HTTP 207 batch without retrying accepted work", async () => {
    const data = [{ id: "1", status: "accepted", httpStatus: 202 },
      { id: "2", status: "failed", httpStatus: 409, error: { code: "OUTPUT_MISSING", message: "Output is missing", details: {} } }];
    const fetchMock = vi.fn(async () => jsonResponse({ data }, { status: 207 })) as unknown as typeof fetch;
    const client = new RestClient({ fetch: fetchMock });
    await expect(client.controlDownloads("verify", ["1", "2"])).rejects.toMatchObject({
      status: 409, code: "OUTPUT_MISSING", details: data,
    });
    expect(fetchMock).toHaveBeenCalledOnce();
  });

  it("retains cursor page metadata without accumulating rows", async () => {
    const page = { data: [{ id: "1" }], meta: { apiVersion: "2.0.0", nextCursor: "opaque", hasMore: true } };
    const client = new RestClient({ fetch: vi.fn(async () => jsonResponse(page)) as unknown as typeof fetch });
    expect(await client.getPage("downloads?limit=100")).toEqual(page);
  });

  it("falls back to a method and path error when no envelope message exists", async () => {
    const fetchMock = vi.fn(async () => new Response("", { status: 500 })) as unknown as typeof fetch;
    const client = new RestClient({ fetch: fetchMock });

    await expect(client.get("downloads/1")).rejects.toThrow("GET /api/v1/downloads/1 failed");
  });

  it("reports HTML fallback responses as a REST routing problem", async () => {
    const fetchMock = vi.fn(async () =>
      new Response("<!doctype html><html></html>", {
        headers: { "Content-Type": "text/html" },
        status: 200,
        statusText: "OK"
      })
    ) as unknown as typeof fetch;
    const client = new RestClient({ fetch: fetchMock });

    await expect(client.get("snapshot")).rejects.toThrow(
      "GET /api/v1/snapshot returned 200 OK with text/html; expected a REST JSON envelope"
    );
  });

  it("reports malformed JSON with request context", async () => {
    const fetchMock = vi.fn(async () =>
      new Response("{", {
        headers: { "Content-Type": "application/json" },
        status: 200
      })
    ) as unknown as typeof fetch;
    const client = new RestClient({ fetch: fetchMock });

    await expect(client.get("snapshot")).rejects.toThrow("GET /api/v1/snapshot returned invalid JSON");
  });

  it("streams download identity events with API key and resume headers", async () => {
    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(
          new TextEncoder().encode(
            [
              ": heartbeat",
              "",
              "event: download.changed",
              "id: 00000000-0000-4000-8000-000000000001:18446744073709551615",
              'data: {"id":18446744073709551615,"epoch":"00000000-0000-4000-8000-000000000001","type":"download.changed","downloadId":"1"}',
              "",
              ""
            ].join("\n")
          )
        );
        controller.close();
      }
    });
    const fetchMock = vi.fn(async () =>
      new Response(body, {
        headers: { "Content-Type": "text/event-stream" },
        status: 200
      })
    ) as unknown as typeof fetch;
    const client = new RestClient({ fetch: fetchMock });
    client.setApiKey("secret-key");
    const events: unknown[] = [];

    const cursors: Array<string | undefined> = [];
    await client.streamDownloadEvents((event, cursor) => {
      events.push(event);
      cursors.push(cursor);
    }, { lastEventId: "00000000-0000-4000-8000-000000000001:6" });

    expect(fetchMock).toHaveBeenCalledWith("/api/v1/events", {
      method: "GET",
      headers: {
        Accept: "text/event-stream",
        "Last-Event-ID": "00000000-0000-4000-8000-000000000001:6",
        "X-API-Key": "secret-key"
      },
      signal: undefined
    });
    expect(events).toEqual([
      {
        id: Number("18446744073709551615"),
        epoch: "00000000-0000-4000-8000-000000000001",
        type: "download.changed",
        downloadId: "1"
      }
    ]);
    expect(cursors).toEqual(["00000000-0000-4000-8000-000000000001:18446744073709551615"]);
  });

  it("surfaces event stream error envelopes", async () => {
    const fetchMock = vi.fn(async () =>
      jsonResponse(
        { error: { code: "UNAUTHORIZED", message: "missing API key" } },
        { status: 401 }
      )
    ) as unknown as typeof fetch;
    const client = new RestClient({ fetch: fetchMock });

    await expect(client.streamDownloadEvents(() => undefined)).rejects.toThrow("missing API key");
  });

  it("streams split UTF-8 and line endings at the frame byte limit", async () => {
    const encoder = new TextEncoder();
    const payload = 'id: epoch:7\r\ndata: {"id":7,"epoch":"epoch","type":"download.changed","downloadId":"é"}';
    const comment = ":" + "x".repeat(65_536 - encoder.encode(payload).length - 3) + "\r\n";
    const bytes = encoder.encode(comment + payload + "\r\n\r\n");
    const unicode = bytes.indexOf(0xc3);
    const { body } = downloadEventBody([
      bytes.slice(0, unicode + 1), bytes.slice(unicode + 1, -1), bytes.slice(-1)
    ], true);
    const receive = vi.fn();

    await eventClient(body).streamDownloadEvents(receive);

    expect(receive).toHaveBeenCalledExactlyOnceWith(
      { id: 7, epoch: "epoch", type: "download.changed", downloadId: "é" }, "epoch:7"
    );
  });

  it.each([
    ["a complete oversized frame", new TextEncoder().encode("é".repeat(32_769) + "\n\n"), /buffer limit/],
    ["an incomplete oversized frame", new TextEncoder().encode("x".repeat(65_537)), /buffer limit/],
    ["invalid UTF-8", new Uint8Array([0xc3, 10, 10]), /invalid UTF-8/],
    ["invalid JSON", new TextEncoder().encode("id: epoch:8\ndata: {\n\n"), /invalid JSON/],
    ["an invalid payload", new TextEncoder().encode('id: epoch:8\ndata: {"type":"download.changed"}\n\n'), /invalid payload/]
  ] as const)("cancels on %s and retains the last valid cursor in a shared read", async (_name, malformed, error) => {
    const valid = new TextEncoder().encode("id: epoch:7\r\ndata: " + downloadEventJson + "\r\n\n");
    const chunk = new Uint8Array(valid.length + malformed.length);
    chunk.set(valid);
    chunk.set(malformed, valid.length);
    const { body, cancel } = downloadEventBody([chunk]);
    const receive = vi.fn();

    await expect(eventClient(body).streamDownloadEvents(receive)).rejects.toThrow(error);

    expect(receive).toHaveBeenCalledExactlyOnceWith(JSON.parse(downloadEventJson), "epoch:7");
    expect(cancel).toHaveBeenCalledTimes(1);
    expect(body.locked).toBe(false);
  });

  it("does not dispatch an unterminated event or forward an invalid header cursor", async () => {
    const encoder = new TextEncoder();
    const valid = "id: epoch:7\nid: broken\0cursor\ndata: " + downloadEventJson + "\n\n";
    const partial = "id: epoch:8\ndata: " + downloadEventJson;
    const { body } = downloadEventBody([encoder.encode(valid + partial)], true);
    const receive = vi.fn();

    await expect(eventClient(body).streamDownloadEvents(receive)).rejects.toThrow(/incomplete frame/);

    expect(receive).toHaveBeenCalledExactlyOnceWith(JSON.parse(downloadEventJson), "epoch:7");
    expect(body.locked).toBe(false);
  });

  it("cancels a pending read when the caller aborts", async () => {
    const { body, cancel } = downloadEventBody([]);
    const controller = new AbortController();
    const receive = vi.fn();
    const result = eventClient(body).streamDownloadEvents(receive, { signal: controller.signal });
    await vi.waitFor(() => expect(body.locked).toBe(true));

    controller.abort();
    await result;

    expect(cancel).toHaveBeenCalledTimes(1);
    expect(body.locked).toBe(false);
    expect(receive).not.toHaveBeenCalled();
  });
});

const downloadEventJson = '{"id":7,"epoch":"epoch","type":"download.changed","downloadId":"1"}';

function downloadEventBody(chunks: Uint8Array[], close = false) {
  const cancel = vi.fn();
  const body = new ReadableStream<Uint8Array>({
    start(controller) {
      for (const chunk of chunks) controller.enqueue(chunk);
      if (close) controller.close();
    },
    cancel
  });
  return { body, cancel };
}

function eventClient(body: ReadableStream<Uint8Array>): RestClient {
  return new RestClient({
    fetch: async () => new Response(body, { headers: { "Content-Type": "text/event-stream" } })
  });
}

function jsonResponse(value: unknown, init: ResponseInit = {}): Response {
  return new Response(JSON.stringify(value), {
    headers: { "Content-Type": "application/json" },
    status: 200,
    ...init
  });
}
