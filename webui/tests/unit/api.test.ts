import { describe, expect, it, vi } from "vitest";

import { RestClient } from "../../src/api";

describe("RestClient", () => {
  it("unwraps successful API envelopes", async () => {
    const fetchMock = vi.fn(async () => jsonResponse({ data: { version: "0.1.0-beta.1" } })) as unknown as typeof fetch;
    const client = new RestClient({ basePath: "/test-api", fetch: fetchMock });

    await expect(client.get<{ version: string }>("app")).resolves.toEqual({ version: "0.1.0-beta.1" });
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

    await expect(client.patch("shared-directories", {})).rejects.toThrow("Path is required");
  });

  it("falls back to a method and path error when no envelope message exists", async () => {
    const fetchMock = vi.fn(async () => new Response("", { status: 500 })) as unknown as typeof fetch;
    const client = new RestClient({ fetch: fetchMock });

    await expect(client.delete("transfers/hash")).rejects.toThrow("DELETE /api/v1/transfers/hash failed");
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
});

function jsonResponse(value: unknown, init: ResponseInit = {}): Response {
  return new Response(JSON.stringify(value), {
    headers: { "Content-Type": "application/json" },
    status: 200,
    ...init
  });
}
