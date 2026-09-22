import http from "node:http";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import worker, {
  buildRequestContext,
  computeClientId,
  evaluateRateLimit,
  evaluateSecurityDecision,
  safeRequestLog,
  validateOriginUrl,
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

  it("rejects origin credentials and invalid protocols", async () => {
    expect(validateOriginUrl("https://user:pass@example.com")).toBeNull();
    expect(validateOriginUrl("ftp://example.com")).toBeNull();

    const response = await worker.fetch(new Request("http://localhost/api"), {
      ORIGIN_URL: "https://user:pass@example.com",
    });
    expect(response.status).toBe(500);
    await expect(response.json()).resolves.toEqual({
      error: { code: "EDGEGUARD_INVALID_CONFIGURATION" },
    });
  });

  it("returns a sanitized 502 when the origin is unavailable", async () => {
    const response = await worker.fetch(new Request("http://localhost/api"), {
      ORIGIN_URL: "http://127.0.0.1:1",
    });

    expect(response.status).toBe(502);
    await expect(response.json()).resolves.toEqual({
      error: { code: "EDGEGUARD_ORIGIN_UNAVAILABLE" },
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

describe("M3 deterministic risk engine", () => {
  it("allows clean requests with no risk signals", async () => {
    const request = new Request("https://example.com/api/items", {
      method: "GET",
      headers: {
        "user-agent": "Mozilla/5.0",
      },
    });

    const context = await buildRequestContext(request, "req-clean", {
      FINGERPRINT_SECRET: "test-secret",
      ORIGIN_URL: "https://example.com",
    });

    const decision = evaluateSecurityDecision(request, context);

    expect(decision.action).toBe("allow");
    expect(decision.score).toBe(0);
    expect(decision.signals).toEqual([]);
  });

  it("treats missing user-agent as a weak signal and does not block alone", async () => {
    const request = new Request("https://example.com/api/items", {
      method: "GET",
    });

    const context = await buildRequestContext(request, "req-weak", {
      FINGERPRINT_SECRET: "test-secret",
      ORIGIN_URL: "https://example.com",
    });

    const decision = evaluateSecurityDecision(request, context);

    expect(decision.score).toBe(15);
    expect(decision.action).toBe("allow");
    expect(decision.signals.map((signal) => signal.id)).toContain(
      "missing_user_agent",
    );
  });

  it("blocks sensitive path probes and returns a sanitized 403", async () => {
    const request = new Request("https://example.com/.env", {
      method: "GET",
      headers: {
        "user-agent": "Mozilla/5.0",
        "x-edgeguard-request-id": "req-block",
      },
    });

    const context = await buildRequestContext(request, "req-block", {
      FINGERPRINT_SECRET: "test-secret",
      ORIGIN_URL: "https://example.com",
    });

    const decision = evaluateSecurityDecision(request, context);

    expect(decision.score).toBeGreaterThanOrEqual(70);
    expect(decision.action).toBe("block");
    expect(decision.signals.map((signal) => signal.id)).toContain(
      "sensitive_path_probe",
    );

    const response = await worker.fetch(request, {
      FINGERPRINT_SECRET: "test-secret",
      ORIGIN_URL: "http://127.0.0.1:1",
    });

    expect(response.status).toBe(403);
    await expect(response.json()).resolves.toMatchObject({
      error: {
        code: "EDGEGUARD_BLOCKED",
        message: "Request blocked by EdgeGuard.",
        requestId: "req-block",
      },
    });
  });

  it("aggregates multiple signals into a monitor decision", async () => {
    const request = new Request("https://example.com/..%2F..%2Fadmin", {
      method: "PROPFIND",
      headers: {
        "user-agent": "Mozilla/5.0",
      },
    });

    const context = await buildRequestContext(request, "req-monitor", {
      FINGERPRINT_SECRET: "test-secret",
      ORIGIN_URL: "https://example.com",
    });

    const decision = evaluateSecurityDecision(request, context);

    expect(decision.action).toBe("monitor");
    expect(decision.score).toBeGreaterThanOrEqual(40);
    expect(decision.score).toBeLessThan(70);
    expect(decision.signals.map((signal) => signal.id)).toEqual(
      expect.arrayContaining(["path_traversal_pattern", "uncommon_method"]),
    );
  });

  it("clamps risk scores to 100 and does not change the final decision with rule order", async () => {
    const request = new Request("https://example.com/.env?x=1", {
      method: "PROPFIND",
      headers: {
        "user-agent": "Mozilla/5.0",
      },
    });

    const context = await buildRequestContext(request, "req-order", {
      FINGERPRINT_SECRET: "test-secret",
      ORIGIN_URL: "https://example.com",
    });

    const first = evaluateSecurityDecision(request, context);
    const duplicate = evaluateSecurityDecision(
      new Request(request.url, request),
      context,
    );

    expect(first.score).toBe(100);
    expect(first.action).toBe("block");
    expect(first.score).toBe(duplicate.score);
    expect(first.action).toBe(duplicate.action);
  });
});

describe("M4 rate limiting", () => {
  it("allows traffic within the fixed window and limits the next request", () => {
    const policy = { limit: 2, windowMs: 1_000 };

    const first = evaluateRateLimit(
      { windowStartMs: 0, count: 0 },
      100,
      policy,
    );
    const second = evaluateRateLimit(
      { windowStartMs: 0, count: 1 },
      200,
      policy,
    );
    const third = evaluateRateLimit(
      { windowStartMs: 0, count: 2 },
      300,
      policy,
    );

    expect(first.allowed).toBe(true);
    expect(second.allowed).toBe(true);
    expect(third.allowed).toBe(false);
    expect(third.remaining).toBe(0);
    expect(third.retryAfterSeconds).toBeGreaterThan(0);
  });

  it("returns HTTP 429 with request metadata when a client is rate-limited", async () => {
    const request = new Request("https://example.com/api/items", {
      method: "GET",
      headers: {
        "user-agent": "Mozilla/5.0",
        "x-edgeguard-request-id": "req-rate-limited",
      },
    });

    const context = await buildRequestContext(request, "req-rate-limited", {
      FINGERPRINT_SECRET: "test-secret",
      ORIGIN_URL: "https://example.com",
    });

    const response = await worker.fetch(request, {
      FINGERPRINT_SECRET: "test-secret",
      ORIGIN_URL: "http://127.0.0.1:1",
      RATE_LIMITER: {
        idFromName: () => ({ name: context.clientId }),
        get: () => ({
          check: async () => ({
            allowed: false,
            limit: 2,
            remaining: 0,
            resetAt: Date.now() + 1000,
            retryAfterSeconds: 1,
          }),
        }),
      },
    });

    expect(response.status).toBe(429);
    expect(response.headers.get("x-edgeguard-request-id")).toBe(
      "req-rate-limited",
    );
    expect(response.headers.get("retry-after")).toBe("1");
    await expect(response.json()).resolves.toMatchObject({
      error: {
        code: "EDGEGUARD_RATE_LIMITED",
        message: "Too many requests.",
        requestId: "req-rate-limited",
        retryAfterSeconds: 1,
      },
    });
  });
});
