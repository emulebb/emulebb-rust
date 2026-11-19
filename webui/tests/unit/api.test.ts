import { describe, expect, it, vi } from "vitest";

import { RestClient, RestError } from "../../src/api";

describe("RestClient", () => {
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
    const bundle = { schema: "emulebb.diagnostic-bundle.v7", capturedAt: "2026-11-14T12:00:00Z",
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
    const fetchMock = vi.fn(async () => jsonResponse({ data: { schema: "emulebb.diagnostic-bundle.v7", capturedAt: "synthetic" } })) as unknown as typeof fetch;
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

    await client.post("transfers", { links: ["ed2k://|file|Sample.bin|1|ABCDEF|/"], paused: true });

    expect(fetchMock).toHaveBeenCalledWith("/api/v1/transfers", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-API-Key": "secret-key"
      },
      body: JSON.stringify({ links: ["ed2k://|file|Sample.bin|1|ABCDEF|/"], paused: true })
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
});

function jsonResponse(value: unknown, init: ResponseInit = {}): Response {
  return new Response(JSON.stringify(value), {
    headers: { "Content-Type": "application/json" },
    status: 200,
    ...init
  });
}
