import { describe, expect, it, vi } from "vitest";
import worker, {
  buildRequestContext,
  evaluateSecurityDecision,
} from "../src/index";
import { mapSecurityEvent } from "../src/events/mapper";
import {
  analyzeSecurityEvent,
  buildThreatAnalysisPrompt,
  parseThreatAnalysisDraft,
} from "../src/events/analyst";
import {
  getSecurityEventByRequestId,
  insertSecurityEvent,
  listRecentSecurityEvents,
} from "../src/events/repository";
import type { SecurityEvent } from "../src/events/types";

const context = await buildRequestContext(
  new Request("https://example.com/api/items?token=do-not-store", {
    method: "POST",
    headers: {
      authorization: "Bearer private-token",
      cookie: "session=private-cookie",
      "cf-connecting-ip": "203.0.113.42",
      "user-agent": "Mozilla/5.0",
    },
  }),
  "req-event",
  { FINGERPRINT_SECRET: "private-fingerprint-secret" },
);

const decision = evaluateSecurityDecision(
  new Request("https://example.com/api/items", {
    method: "POST",
    headers: { "user-agent": "Mozilla/5.0" },
  }),
  context,
);

const event: SecurityEvent = mapSecurityEvent({
  context,
  decision,
  rateLimit: {
    allowed: false,
    limit: 60,
    remaining: 0,
    resetAt: Date.now() + 1000,
    retryAfterSeconds: 1,
  },
  upstreamStatus: null,
  durationMs: null,
});

describe("M5 security event mapping", () => {
  it("maps only normalized privacy-safe fields", () => {
    expect(event.path).toBe("/api/items");
    expect(event.action).toBe("rate_limited");
    expect(event.signalIds).toEqual(
      decision.signals.map((signal) => signal.id),
    );
    expect(JSON.stringify(event)).not.toContain("203.0.113.42");
    expect(JSON.stringify(event)).not.toContain("private-token");
    expect(JSON.stringify(event)).not.toContain("private-cookie");
    expect(JSON.stringify(event)).not.toContain("private-fingerprint-secret");
    expect(JSON.stringify(event)).not.toContain("do-not-store");
  });
});

describe("M5 security event repository", () => {
  it("uses parameterized insert values and round-trips signal IDs", async () => {
    const calls: { sql: string; values: unknown[] }[] = [];
    const row = {
      ...event,
      created_at: event.createdAt,
      request_id: event.requestId,
      client_id: event.clientId,
      risk_score: event.riskScore,
      signal_ids: JSON.stringify(event.signalIds),
      upstream_status: event.upstreamStatus,
      duration_ms: event.durationMs,
      rate_limit_remaining: event.rateLimitRemaining,
      retry_after_seconds: event.retryAfterSeconds,
    };
    const db = {
      prepare: (sql: string) => ({
        bind: (...values: unknown[]) => {
          calls.push({ sql, values });
          return {
            run: async () => ({}),
            first: async <T>() => row as T,
            all: async <T>() => ({ results: [row as T] }),
          };
        },
      }),
    } as unknown as D1Database;

    await insertSecurityEvent(db, event);
    const found = await getSecurityEventByRequestId(db, event.requestId);
    const recent = await listRecentSecurityEvents(db, 1000);

    expect(calls[0]?.sql).toContain(
      "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    );
    expect(calls[0]?.sql).not.toContain(event.requestId);
    expect(found?.signalIds).toEqual(event.signalIds);
    expect(recent).toHaveLength(1);
  });
});

describe("M5 persistence failure isolation", () => {
  it("does not create an event for /health", async () => {
    const prepare = vi.fn();
    const response = await worker.fetch(
      new Request("https://example.com/health"),
      {
        DB: { prepare } as unknown as D1Database,
      },
    );

    expect(response.status).toBe(200);
    expect(prepare).not.toHaveBeenCalled();
  });

  it("does not change a successful proxied response when D1 fails", async () => {
    const fetchSpy = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValue(new Response("origin-ok", { status: 201 }));

    const response = await worker.fetch(
      new Request("https://example.com/api/items", {
        headers: { "user-agent": "Mozilla/5.0" },
      }),
      {
        ORIGIN_URL: "https://origin.example.com",
        DB: {
          prepare: () => {
            throw new Error("D1 unavailable");
          },
        } as unknown as D1Database,
      },
    );

    expect(response.status).toBe(201);
    expect(await response.text()).toBe("origin-ok");
    expect(fetchSpy).toHaveBeenCalledOnce();
    fetchSpy.mockRestore();
  });

  it("does not prevent block or rate-limit enforcement when D1 fails", async () => {
    const failingDb = {
      prepare: () => {
        throw new Error("D1 unavailable");
      },
    } as unknown as D1Database;

    const blocked = await worker.fetch(
      new Request("https://example.com/.env"),
      {
        DB: failingDb,
      },
    );
    const limited = await worker.fetch(new Request("https://example.com/api"), {
      DB: failingDb,
      RATE_LIMITER: {
        idFromName: () => ({ name: "client" }),
        get: () => ({
          check: async () => ({
            allowed: false,
            limit: 1,
            remaining: 0,
            resetAt: Date.now() + 1000,
            retryAfterSeconds: 1,
          }),
        }),
      },
    });

    expect(blocked.status).toBe(403);
    expect(limited.status).toBe(429);
  });
});

describe("M6 asynchronous security event processing", () => {
  it("queues events without touching D1 during request handling", async () => {
    const send = vi.fn().mockResolvedValue(undefined);
    const prepare = vi.fn();
    const response = await worker.fetch(
      new Request("https://example.com/api/items", {
        headers: { "user-agent": "Mozilla/5.0" },
      }),
      {
        DB: { prepare } as unknown as D1Database,
        SECURITY_EVENTS_QUEUE: { send } as unknown as Queue<SecurityEvent>,
      },
    );

    expect(response.status).toBe(404);
    expect(send).toHaveBeenCalledOnce();
    expect(send.mock.calls[0]?.[0]).toMatchObject({
      requestId: expect.any(String),
      action: "allow",
      path: "/api/items",
    });
    expect(prepare).not.toHaveBeenCalled();
  });

  it("acks successfully persisted messages and retries failed messages", async () => {
    const ack = vi.fn();
    const retry = vi.fn();
    const run = vi.fn().mockResolvedValue({});
    const db = {
      prepare: () => ({
        bind: () => ({ run }),
      }),
    } as unknown as D1Database;

    await worker.queue?.(
      {
        messages: [{ body: event, ack, retry }],
      } as unknown as MessageBatch<SecurityEvent>,
      { DB: db },
    );

    expect(run).toHaveBeenCalledOnce();
    expect(ack).toHaveBeenCalledOnce();
    expect(retry).not.toHaveBeenCalled();

    const failingBatch = {
      messages: [{ body: event, ack, retry }],
    } as unknown as MessageBatch<SecurityEvent>;
    const failingDb = {
      prepare: () => {
        throw new Error("D1 unavailable");
      },
    } as unknown as D1Database;

    await worker.queue?.(failingBatch, { DB: failingDb });

    expect(retry).toHaveBeenCalledOnce();
  });
});

describe("M7 read-only analytics API", () => {
  const analyticsRow = {
    id: event.id,
    created_at: event.createdAt,
    request_id: event.requestId,
    client_id: event.clientId,
    method: event.method,
    path: event.path,
    country: event.country,
    colo: event.colo,
    asn: event.asn,
    risk_score: event.riskScore,
    action: event.action,
    signal_ids: JSON.stringify(event.signalIds),
    upstream_status: event.upstreamStatus,
    duration_ms: event.durationMs,
    rate_limit_remaining: event.rateLimitRemaining,
    retry_after_seconds: event.retryAfterSeconds,
  };

  const db = {
    prepare: (sql: string) => ({
      bind: () => ({
        first: async <T>() =>
          (sql.includes("COUNT(*)")
            ? {
                total_events: 2,
                average_risk_score: 62.5,
                allow_count: 1,
                monitor_count: 0,
                block_count: 0,
                rate_limited_count: 1,
              }
            : analyticsRow) as T,
        all: async <T>() =>
          (sql.includes("GROUP BY path")
            ? { results: [{ path: "/api/items", count: 2 }] }
            : { results: [analyticsRow] }) as { results: T[] },
      }),
    }),
  } as unknown as D1Database;

  it("requires the analytics API key without touching D1", async () => {
    const prepare = vi.fn();
    const response = await worker.fetch(
      new Request("https://example.com/api/analytics/events"),
      {
        ANALYTICS_API_KEY: "dashboard-secret",
        DB: { prepare } as unknown as D1Database,
      },
    );

    expect(response.status).toBe(401);
    expect(prepare).not.toHaveBeenCalled();
  });

  it("lists filtered events and returns aggregate summaries", async () => {
    const eventsResponse = await worker.fetch(
      new Request(
        "https://example.com/api/security/events?action=rate_limited&limit=10",
        { headers: { authorization: "Bearer dashboard-secret" } },
      ),
      { ANALYTICS_API_KEY: "dashboard-secret", DB: db },
    );
    const eventsBody = (await eventsResponse.json()) as {
      events: SecurityEvent[];
    };

    expect(eventsResponse.status).toBe(200);
    expect(eventsBody.events[0]?.path).toBe("/api/items");
    expect(eventsResponse.headers.get("cache-control")).toBe("no-store");

    const summaryResponse = await worker.fetch(
      new Request("https://example.com/api/analytics/summary?hours=48", {
        headers: { "x-api-key": "dashboard-secret" },
      }),
      { ANALYTICS_API_KEY: "dashboard-secret", DB: db },
    );
    const summaryBody = (await summaryResponse.json()) as {
      summary: {
        totalEvents: number;
        averageRiskScore: number;
        actionCounts: Record<string, number>;
        topPaths: Array<{ path: string; count: number }>;
      };
    };

    expect(summaryResponse.status).toBe(200);
    expect(summaryBody.summary.totalEvents).toBe(2);
    expect(summaryBody.summary.averageRiskScore).toBe(62.5);
    expect(summaryBody.summary.actionCounts.rate_limited).toBe(1);
    expect(summaryBody.summary.topPaths).toEqual([
      { path: "/api/items", count: 2 },
    ]);
  });

  it("rejects invalid filters", async () => {
    const response = await worker.fetch(
      new Request("https://example.com/api/analytics/events?action=unknown", {
        headers: { "x-api-key": "dashboard-secret" },
      }),
      { ANALYTICS_API_KEY: "dashboard-secret", DB: db },
    );

    expect(response.status).toBe(400);
  });
});

describe("M8 Workers AI threat analyst", () => {
  const validModelOutput = {
    summary: "Sensitive path probe matches a configuration discovery attempt.",
    category: "reconnaissance",
    evidenceSignalIds: ["sensitive_path_probe"],
    recommendedAction: "Review the request pattern and monitor similar probes.",
    proposedRule: {
      title: "Configuration path probe",
      rationale:
        "Repeated probes for sensitive files may indicate reconnaissance.",
      pattern: "/.env",
    },
    confidence: "high",
    caveats: ["A single event is not proof of malicious intent."],
  };

  it("builds a minimized prompt without prohibited request data", () => {
    const prompt = buildThreatAnalysisPrompt(event);

    expect(prompt).toContain('"signalIds":[]');
    expect(prompt).not.toContain("203.0.113.42");
    expect(prompt).not.toContain("private-token");
    expect(prompt).not.toContain("private-cookie");
    expect(prompt).not.toContain("private-fingerprint-secret");
    expect(prompt).not.toContain("do-not-store");
  });

  it("validates structured model output and creates separate analysis metadata", async () => {
    const run = vi
      .fn()
      .mockResolvedValue({ response: JSON.stringify(validModelOutput) });
    const analysis = await analyzeSecurityEvent({ run }, event, "test-model");

    expect(run).toHaveBeenCalledOnce();
    expect(analysis).toMatchObject({
      eventId: event.id,
      model: "test-model",
      category: "reconnaissance",
      confidence: "high",
    });
    expect(analysis?.analysisId).toEqual(expect.any(String));
    expect(parseThreatAnalysisDraft("not-json")).toBeNull();
    expect(
      parseThreatAnalysisDraft({ ...validModelOutput, confidence: "certain" }),
    ).toBeNull();
    expect(
      parseThreatAnalysisDraft({ ...validModelOutput, extra: true }),
    ).toBeNull();
  });

  it("keeps AI failures out of request enforcement and exposes no-analysis state", async () => {
    const run = vi.fn().mockRejectedValue(new Error("model unavailable"));
    await expect(
      analyzeSecurityEvent({ run }, event, "test-model"),
    ).rejects.toThrow("model unavailable");

    const response = await worker.fetch(
      new Request("https://example.com/api/security/analysis?eventId=missing", {
        headers: { "x-api-key": "dashboard-secret" },
      }),
      {
        ANALYTICS_API_KEY: "dashboard-secret",
        DB: {
          prepare: () => ({
            bind: () => ({ first: async () => null }),
          }),
        } as unknown as D1Database,
      },
    );
    await expect(response.json()).resolves.toEqual({
      aiGenerated: true,
      analysis: null,
    });
  });

  it("invokes AI only from queue processing and persists analysis separately", async () => {
    const run = vi
      .fn()
      .mockResolvedValue({ response: JSON.stringify(validModelOutput) });
    const prepare = vi.fn((sql: string) => ({
      bind: vi.fn(() => ({ run: vi.fn().mockResolvedValue({}) })),
      sql,
    }));
    const ack = vi.fn();
    const retry = vi.fn();

    await worker.queue?.(
      {
        messages: [{ body: event, ack, retry }],
      } as unknown as MessageBatch<SecurityEvent>,
      { DB: { prepare } as unknown as D1Database, AI: { run } },
    );

    expect(run).toHaveBeenCalledOnce();
    expect(prepare).toHaveBeenCalledTimes(2);
    expect(prepare.mock.calls[1]?.[0]).toContain("threat_analyses");
    expect(ack).toHaveBeenCalledOnce();
    expect(retry).not.toHaveBeenCalled();

    const requestAi = vi.fn();
    const response = await worker.fetch(
      new Request("https://example.com/api/items", {
        headers: { "user-agent": "Mozilla/5.0" },
      }),
      {
        AI: { run: requestAi },
        SECURITY_EVENTS_QUEUE: {
          send: vi.fn().mockResolvedValue(undefined),
        } as unknown as Queue<SecurityEvent>,
      },
    );
    expect(response.status).toBe(404);
    expect(requestAi).not.toHaveBeenCalled();
  });

  it("retries malformed queue messages without persisting them", async () => {
    const prepare = vi.fn();
    const ack = vi.fn();
    const retry = vi.fn();

    await worker.queue?.(
      {
        messages: [{ body: {} as SecurityEvent, ack, retry }],
      } as unknown as MessageBatch<SecurityEvent>,
      { DB: { prepare } as unknown as D1Database },
    );

    expect(prepare).not.toHaveBeenCalled();
    expect(ack).not.toHaveBeenCalled();
    expect(retry).toHaveBeenCalledOnce();
  });
});
