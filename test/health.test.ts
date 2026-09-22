import http from "node:http";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import worker, {
  buildRequestContext,
  computeClientId,
  safeRequestLog,
} from "../src/index";

describe("GET /health", () => {
  it("returns a JSON health response", async () => {
    const response = await worker.fetch(new Request("http://localhost/health"));

    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toContain("application/json");
    await expect(response.json()).resolves.toEqual({
      status: "ok",
      service: "edgeguard",
    });
  });
});

describe("bootstrap routing", () => {
  it("returns 404 for routes outside M0", async () => {
    const response = await worker.fetch(new Request("http://localhost/"));

    expect(response.status).toBe(404);
  });
});

describe("M1 proxy forwarding", () => {
  let server: http.Server;
  let port: number;

  beforeAll(async () => {
    server = http.createServer((req, res) => {
      let body = "";

      req.on("data", (chunk) => {
        body += chunk.toString();
      });

      req.on("end", () => {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(
          JSON.stringify({
            method: req.method,
            url: req.url,
            header: req.headers["x-test"],
            body,
          }),
        );
      });
    });

    await new Promise<void>((resolve) => {
      server.listen(0, "127.0.0.1", () => resolve());
    });

    port = (server.address() as { port: number }).port;
  });

  afterAll(async () => {
    await new Promise<void>((resolve, reject) => {
      server.close((error) => {
        if (error) {
          reject(error);
          return;
        }

        resolve();
      });
    });
  });

  it("forwards the request and response to the configured origin", async () => {
    const response = await worker.fetch(
      new Request("http://localhost/api/v1/users?active=true", {
        method: "POST",
        headers: {
          "x-test": "edgeguard",
        },
        body: JSON.stringify({ ok: true }),
      }),
      {
        ORIGIN_URL: `http://127.0.0.1:${port}`,
      },
    );

    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toEqual({
      method: "POST",
      url: "/api/v1/users?active=true",
      header: "edgeguard",
      body: '{"ok":true}',
    });
  });
});

describe("M2 request metadata and client identity", () => {
  it("builds a normalized request context with a stable client id", async () => {
    const request = new Request("https://example.com/api/items?expand=true", {
      method: "GET",
      headers: {
        authorization: "Bearer secret-token",
        cookie: "session=abc; other=123",
        "cf-connecting-ip": "203.0.113.42",
        "user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
        "accept-language": "en-US,en;q=0.9",
      },
    });

    const first = await buildRequestContext(request, "req-1", {
      FINGERPRINT_SECRET: "test-secret",
      ORIGIN_URL: "https://example.com",
    });

    const second = await buildRequestContext(request, "req-2", {
      FINGERPRINT_SECRET: "test-secret",
      ORIGIN_URL: "https://example.com",
    });

    expect(first.requestId).toBe("req-1");
    expect(first.method).toBe("GET");
    expect(first.path).toBe("/api/items");
    expect(first.country).toBeNull();
    expect(first.colo).toBeNull();
    expect(first.asn).toBeNull();
    expect(first.userAgentPresent).toBe(true);
    expect(first.acceptLanguage).toBe("en-US");
    expect(first.clientId).toBe(second.clientId);
    expect(first.clientId).toMatch(/^[a-f0-9]+$/i);
    expect(first.clientId).not.toContain("secret-token");
    expect(first.clientId).not.toContain("203.0.113.42");
    expect(first.clientId).not.toContain("session");
  });

  it("separates identities by secret and identity inputs", async () => {
    const requestA = new Request("https://example.com/api/items", {
      headers: {
        "cf-connecting-ip": "203.0.113.42",
        "user-agent": "Mozilla/5.0",
        "accept-language": "en-US",
      },
    });

    const requestB = new Request("https://example.com/api/items", {
      headers: {
        "cf-connecting-ip": "203.0.113.43",
        "user-agent": "Mozilla/5.0",
        "accept-language": "en-US",
      },
    });

    const contextA = await buildRequestContext(requestA, "req-a", {
      FINGERPRINT_SECRET: "secret-a",
      ORIGIN_URL: "https://example.com",
    });
    const contextB = await buildRequestContext(requestB, "req-b", {
      FINGERPRINT_SECRET: "secret-a",
      ORIGIN_URL: "https://example.com",
    });
    const contextC = await buildRequestContext(requestA, "req-c", {
      FINGERPRINT_SECRET: "secret-b",
      ORIGIN_URL: "https://example.com",
    });

    expect(contextA.clientId).not.toBe(contextB.clientId);
    expect(contextA.clientId).not.toBe(contextC.clientId);
    expect(contextA.requestId).not.toBe(contextB.requestId);
    expect(contextA.clientId).toBe(
      await computeClientId({
        ipAddress: "203.0.113.42",
        userAgent: "Mozilla/5.0",
        acceptLanguage: "en-US",
        secret: "secret-a",
      }),
    );
  });

  it("omits secrets and raw metadata from safe logs", async () => {
    const request = new Request("https://example.com/secure", {
      headers: {
        authorization: "Bearer secret-token",
        cookie: "session=abc",
        "cf-connecting-ip": "203.0.113.42",
      },
    });

    const context = await buildRequestContext(request, "req-safe", {
      FINGERPRINT_SECRET: "test-secret",
      ORIGIN_URL: "https://example.com",
    });
    const log = safeRequestLog(context, 200, 14);

    expect(log.requestId).toBe("req-safe");
    expect(log.clientId).toBe(context.clientId);
    expect(JSON.stringify(log)).not.toContain("secret-token");
    expect(JSON.stringify(log)).not.toContain("session=abc");
    expect(JSON.stringify(log)).not.toContain("203.0.113.42");
    expect(JSON.stringify(log)).not.toContain("test-secret");
  });
});
