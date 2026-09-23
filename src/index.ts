import { mapSecurityEvent } from "./events/mapper";
import { enqueueSecurityEventBestEffort } from "./events/persistence";
import {
  getThreatAnalysisByEventId,
  insertSecurityEvent,
  insertThreatAnalysis,
} from "./events/repository";
import type { SecurityEvent } from "./events/types";
import { analyzeSecurityEvent, type WorkersAiBinding } from "./events/analyst";
import {
  getSecurityAnalyticsSummary,
  isSecurityEventAction,
  listAnalyticsEvents,
  parseSecurityEventQuery,
} from "./events/analytics";
import { dashboardResponse } from "./dashboard";

export interface Env {
  ORIGIN_URL?: string;
  FINGERPRINT_SECRET?: string;
  DB?: D1Database;
  ANALYTICS_API_KEY?: string;
  AI?: WorkersAiBinding;
  AI_MODEL?: string;
  SECURITY_EVENTS_QUEUE?: Queue<SecurityEvent>;
  RATE_LIMITER?: {
    idFromName: (name: string) => { name: string };
    get: (id: { name: string }) => {
      check: (policy?: RateLimitPolicy) => Promise<RateLimitResult>;
    };
  };
}

export interface RequestContext {
  requestId: string;
  clientId: string;
  method: string;
  path: string;
  country: string | null;
  colo: string | null;
  asn: number | null;
  userAgentPresent: boolean;
  acceptLanguage: string | null;
  receivedAt: string;
}

export interface SafeRequestLog {
  event: "request";
  requestId: string;
  clientId: string;
  method: string;
  path: string;
  country: string | null;
  colo: string | null;
  asn: number | null;
  upstreamStatus: number;
  durationMs: number;
}

export interface ClientIdentityInput {
  ipAddress: string | null;
  userAgent: string | null;
  acceptLanguage: string | null;
  secret: string;
}

export type SecurityAction = "allow" | "monitor" | "block";

export interface RiskSignal {
  id: string;
  weight: number;
  reason: string;
}

export interface SecurityDecision {
  action: SecurityAction;
  score: number;
  signals: RiskSignal[];
  requestId: string;
  clientId: string;
}

export interface RateLimitPolicy {
  limit: number;
  windowMs: number;
}

export interface RateLimitState {
  windowStartMs: number;
  count: number;
}

export interface RateLimitResult {
  allowed: boolean;
  limit: number;
  remaining: number;
  resetAt: number;
  retryAfterSeconds: number;
}

export const DEFAULT_RATE_LIMIT_POLICY: RateLimitPolicy = {
  limit: 60,
  windowMs: 60_000,
};

const healthResponse = (): Response =>
  Response.json({
    status: "ok",
    service: "edgeguard",
  });

export const validateOriginUrl = (originUrl: string): URL | null => {
  try {
    const origin = new URL(originUrl);
    if (
      !["http:", "https:"].includes(origin.protocol) ||
      !origin.hostname ||
      origin.username ||
      origin.password ||
      origin.search ||
      origin.hash
    ) {
      return null;
    }

    return origin;
  } catch {
    return null;
  }
};

const configurationErrorResponse = (): Response =>
  Response.json(
    { error: { code: "EDGEGUARD_INVALID_CONFIGURATION" } },
    { status: 500 },
  );

const analyticsResponse = (body: unknown, status = 200): Response =>
  Response.json(body, {
    status,
    headers: { "cache-control": "no-store" },
  });

const isAnalyticsAuthorized = (request: Request, env?: Env): boolean => {
  const configuredKey = env?.ANALYTICS_API_KEY;
  if (!configuredKey) {
    return false;
  }

  const authorization = request.headers.get("authorization");
  const bearerKey = authorization?.startsWith("Bearer ")
    ? authorization.slice("Bearer ".length)
    : null;
  const presentedKey = bearerKey ?? request.headers.get("x-api-key");
  return presentedKey === configuredKey;
};

const handleAnalyticsRequest = async (
  request: Request,
  env?: Env,
): Promise<Response> => {
  if (!isAnalyticsAuthorized(request, env)) {
    return analyticsResponse(
      { error: { code: "EDGEGUARD_ANALYTICS_UNAUTHORIZED" } },
      401,
    );
  }

  if (!env?.DB) {
    return analyticsResponse(
      { error: { code: "EDGEGUARD_ANALYTICS_UNAVAILABLE" } },
      503,
    );
  }

  try {
    const url = new URL(request.url);
    const action = url.searchParams.get("action");
    if (action && !isSecurityEventAction(action)) {
      return analyticsResponse(
        { error: { code: "EDGEGUARD_ANALYTICS_INVALID_FILTER" } },
        400,
      );
    }

    if (
      url.pathname === "/api/analytics/analysis" ||
      url.pathname === "/api/security/analysis"
    ) {
      const eventId = url.searchParams.get("eventId")?.trim();
      if (!eventId || eventId.length > 128) {
        return analyticsResponse(
          { error: { code: "EDGEGUARD_ANALYTICS_INVALID_EVENT_ID" } },
          400,
        );
      }

      return analyticsResponse({
        aiGenerated: true,
        analysis: await getThreatAnalysisByEventId(env.DB, eventId),
      });
    }

    if (
      url.pathname === "/api/analytics/events" ||
      url.pathname === "/api/security/events"
    ) {
      return analyticsResponse({
        events: await listAnalyticsEvents(
          env.DB,
          parseSecurityEventQuery(url.searchParams),
        ),
      });
    }

    const requestedHours = Number(url.searchParams.get("hours"));
    const hours = Number.isFinite(requestedHours) ? requestedHours : 24;
    return analyticsResponse({
      summary: await getSecurityAnalyticsSummary(env.DB, new Date(), hours),
    });
  } catch (error) {
    console.error(
      JSON.stringify({
        event: "security_analytics_failure",
        message: "Analytics query failed.",
        error: error instanceof Error ? error.message : String(error),
      }),
    );
    return analyticsResponse(
      { error: { code: "EDGEGUARD_ANALYTICS_UNAVAILABLE" } },
      503,
    );
  }
};

const normalizeText = (
  value: string | null | undefined,
  maxLength = 256,
): string | null => {
  if (!value) {
    return null;
  }

  const trimmed = value.trim().replace(/\s+/g, " ").slice(0, maxLength);
  return trimmed || null;
};

const deriveClientIp = (request: Request): string | null => {
  const headers = request.headers;
  const forwarded = headers.get("x-forwarded-for");
  if (forwarded) {
    return forwarded.split(",")[0]?.trim() ?? null;
  }

  const realIp = headers.get("x-real-ip");
  if (realIp) {
    return realIp.trim();
  }

  const cfIp = headers.get("cf-connecting-ip");
  return cfIp?.trim() ?? null;
};

const normalizeAcceptLanguage = (request: Request): string | null => {
  const raw = request.headers.get("accept-language");
  if (!raw) {
    return null;
  }

  const first = raw.split(",")[0]?.split(";")[0]?.trim();
  return first || null;
};

const clampScore = (value: number): number => Math.max(0, Math.min(100, value));

const securityThresholds = {
  allowMax: 39,
  monitorMax: 69,
  blockMin: 70,
};

export const computeClientId = async ({
  ipAddress,
  userAgent,
  acceptLanguage,
  secret,
}: ClientIdentityInput): Promise<string> => {
  const fingerprint = [
    ipAddress ?? "unknown",
    normalizeText(userAgent, 128) ?? "unknown",
    normalizeText(acceptLanguage, 64) ?? "unknown",
  ].join("|");

  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );

  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(fingerprint),
  );
  return Array.from(new Uint8Array(signature))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
};

export const buildRequestContext = async (
  request: Request,
  requestId: string,
  env?: Env,
): Promise<RequestContext> => {
  const url = new URL(request.url);
  const requestWithCf = request as Request & {
    cf?: {
      country?: string;
      colo?: string;
      asn?: number;
    };
  };

  const secret = env?.FINGERPRINT_SECRET ?? "local-development-secret";
  const ipAddress = deriveClientIp(request);
  const userAgent = request.headers.get("user-agent");
  const acceptLanguage = normalizeAcceptLanguage(request);
  const country = requestWithCf.cf?.country ?? null;
  const colo = requestWithCf.cf?.colo ?? null;
  const asn =
    typeof requestWithCf.cf?.asn === "number" ? requestWithCf.cf.asn : null;

  const clientId = await computeClientId({
    ipAddress,
    userAgent,
    acceptLanguage,
    secret,
  });

  return {
    requestId,
    clientId,
    method: request.method.toUpperCase(),
    path: url.pathname,
    country,
    colo,
    asn,
    userAgentPresent: !!userAgent,
    acceptLanguage,
    receivedAt: new Date().toISOString(),
  };
};

export const safeRequestLog = (
  context: RequestContext,
  upstreamStatus: number,
  durationMs: number,
): SafeRequestLog => ({
  event: "request",
  requestId: context.requestId,
  clientId: context.clientId,
  method: context.method,
  path: context.path,
  country: context.country,
  colo: context.colo,
  asn: context.asn,
  upstreamStatus,
  durationMs,
});

const evaluateRuleSignals = (
  request: Request,
  context: RequestContext,
): RiskSignal[] => {
  const path = context.path.toLowerCase();
  const method = context.method.toUpperCase();
  const signals: RiskSignal[] = [];

  if (!context.userAgentPresent) {
    signals.push({
      id: "missing_user_agent",
      weight: 15,
      reason: "Request is missing a User-Agent header.",
    });
  }

  const commonMethods = new Set([
    "GET",
    "POST",
    "PUT",
    "PATCH",
    "DELETE",
    "HEAD",
    "OPTIONS",
  ]);
  if (!commonMethods.has(method)) {
    signals.push({
      id: "uncommon_method",
      weight: 10,
      reason: `HTTP method ${method} is outside the standard allowlist.`,
    });
  }

  if (
    /\.(env|git|gitignore|pem|key|ini|cfg|conf|aws|json|yaml|yml)$/.test(
      path,
    ) ||
    path.includes("/.git") ||
    path.includes("/.env")
  ) {
    signals.push({
      id: "sensitive_path_probe",
      weight: 100,
      reason: "Sensitive configuration path detected.",
    });
  }

  const decodedUrl = decodeURIComponent(request.url).toLowerCase();
  const rawUrl = request.url.toLowerCase();
  const traversalPattern =
    /(?:\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e%5c|\.\.%2f|\.\.%5c)/i;
  if (traversalPattern.test(rawUrl) || traversalPattern.test(decodedUrl)) {
    signals.push({
      id: "path_traversal_pattern",
      weight: 50,
      reason: "Traversal sequence detected in the request path.",
    });
  }

  const oversizedPathLength = path.length > 128 || request.url.length > 2048;
  if (oversizedPathLength) {
    signals.push({
      id: "oversized_path",
      weight: 20,
      reason: "Request path exceeds the expected safe length.",
    });
  }

  return signals;
};

export const evaluateSecurityDecision = (
  request: Request,
  context: RequestContext,
): SecurityDecision => {
  const signals = evaluateRuleSignals(request, context);
  const score = clampScore(
    signals.reduce((total, signal) => total + signal.weight, 0),
  );

  let action: SecurityAction = "allow";
  if (score >= securityThresholds.blockMin) {
    action = "block";
  } else if (score >= securityThresholds.allowMax + 1) {
    action = "monitor";
  }

  return {
    action,
    score,
    signals,
    requestId: context.requestId,
    clientId: context.clientId,
  };
};

export const safeSecurityLog = (
  decision: SecurityDecision,
): Record<string, unknown> => ({
  event: "security_decision",
  requestId: decision.requestId,
  clientId: decision.clientId,
  riskScore: decision.score,
  action: decision.action,
  signals: decision.signals.map((signal) => signal.id),
});

export const evaluateRateLimit = (
  state: RateLimitState,
  nowMs: number,
  policy: RateLimitPolicy = DEFAULT_RATE_LIMIT_POLICY,
): RateLimitResult => {
  const windowStartMs = state.windowStartMs ?? nowMs;
  const isExpired = nowMs >= windowStartMs + policy.windowMs;
  const activeWindowStart = isExpired ? nowMs : windowStartMs;
  const activeCount = isExpired ? 0 : state.count;
  const allowed = activeCount < policy.limit;
  const nextCount = allowed ? activeCount + 1 : activeCount;
  const resetAt = activeWindowStart + policy.windowMs;
  const remaining = allowed ? Math.max(0, policy.limit - nextCount) : 0;

  return {
    allowed,
    limit: policy.limit,
    remaining,
    resetAt,
    retryAfterSeconds: allowed
      ? 0
      : Math.max(1, Math.ceil((resetAt - nowMs) / 1000)),
  };
};

export class RateLimiter {
  constructor(private readonly state: DurableObjectState) {}

  async check(
    policy: RateLimitPolicy = DEFAULT_RATE_LIMIT_POLICY,
  ): Promise<RateLimitResult> {
    const nowMs = Date.now();
    const savedState = ((await this.state.storage.get(
      "rate_limit",
    )) as RateLimitState | null) ?? {
      windowStartMs: nowMs,
      count: 0,
    };

    const windowStartMs = savedState.windowStartMs ?? nowMs;
    const count = savedState.count ?? 0;
    const isExpired = nowMs >= windowStartMs + policy.windowMs;
    const activeWindowStart = isExpired ? nowMs : windowStartMs;
    const activeCount = isExpired ? 0 : count;
    const result = evaluateRateLimit(
      { windowStartMs: activeWindowStart, count: activeCount },
      nowMs,
      policy,
    );

    if (result.allowed) {
      await this.state.storage.put("rate_limit", {
        windowStartMs: activeWindowStart,
        count: activeCount + 1,
      });
    }

    return result;
  }
}

const applyRateLimitSignal = (
  decision: SecurityDecision,
  result: RateLimitResult,
): SecurityDecision => {
  if (result.allowed) {
    return decision;
  }

  return {
    ...decision,
    action: "block",
    score: clampScore(decision.score + 100),
    signals: [
      ...decision.signals,
      {
        id: "rate_limit_exceeded",
        weight: 100,
        reason: "Client exceeded the configured rate limit.",
      },
    ],
  };
};

const enforceRateLimit = async (
  request: Request,
  context: RequestContext,
  env?: Env,
): Promise<RateLimitResult | null> => {
  const limiter = env?.RATE_LIMITER as
    | undefined
    | {
        idFromName: (name: string) => { name: string };
        get: (id: { name: string }) => {
          check: (policy?: RateLimitPolicy) => Promise<RateLimitResult>;
        };
      };

  if (!limiter) {
    return null;
  }

  try {
    const objectId = limiter.idFromName(context.clientId);
    const stub = limiter.get(objectId);
    return await stub.check(DEFAULT_RATE_LIMIT_POLICY);
  } catch (error) {
    console.error(
      JSON.stringify({
        event: "rate_limit_failure",
        requestId: context.requestId,
        clientId: context.clientId,
        message: "Limiter infrastructure failure; fail-open policy applied.",
        error: error instanceof Error ? error.message : String(error),
      }),
    );
    return null;
  }
};

const proxyRequest = async (
  request: Request,
  env?: Env,
  requestId?: string,
): Promise<Response | null> => {
  if (!env?.ORIGIN_URL) {
    return null;
  }

  const origin = validateOriginUrl(env.ORIGIN_URL);
  if (!origin) {
    throw new Error("ORIGIN_URL is invalid");
  }
  const target = new URL(request.url);

  target.protocol = origin.protocol;
  target.username = origin.username;
  target.password = origin.password;
  target.host = origin.host;

  const proxiedRequest = new Request(target.toString(), request);
  const headers = new Headers(proxiedRequest.headers);
  headers.set("host", origin.host);
  if (requestId) {
    headers.set("x-edgeguard-request-id", requestId);
  }

  return fetch(new Request(proxiedRequest, { headers }));
};

const recordSecurityEvent = async (
  env: Env | undefined,
  event: SecurityEvent,
): Promise<void> => {
  await enqueueSecurityEventBestEffort(env?.SECURITY_EVENTS_QUEUE, event);
};

const consumeSecurityEvents = async (
  batch: MessageBatch<SecurityEvent>,
  env: Env,
): Promise<void> => {
  for (const message of batch.messages) {
    try {
      if (
        !message.body ||
        typeof message.body.id !== "string" ||
        typeof message.body.requestId !== "string" ||
        typeof message.body.clientId !== "string"
      ) {
        throw new Error("Malformed security event message");
      }

      if (!env.DB) {
        throw new Error("D1 binding is not configured");
      }

      await insertSecurityEvent(env.DB, message.body);
      if (env.AI) {
        try {
          const analysis = await analyzeSecurityEvent(
            env.AI,
            message.body,
            env.AI_MODEL,
          );
          if (analysis) {
            await insertThreatAnalysis(env.DB, analysis);
          }
        } catch (error) {
          console.error(
            JSON.stringify({
              event: "threat_analysis_failure",
              eventId: message.body.id,
              message: "Workers AI analysis failed; base event was preserved.",
              error: error instanceof Error ? error.message : String(error),
            }),
          );
        }
      }
      message.ack();
    } catch (error) {
      console.error(
        JSON.stringify({
          event: "security_event_consumer_failure",
          requestId: message.body.requestId,
          clientId: message.body.clientId,
          message:
            "Security event persistence failed; queue message will retry.",
          error: error instanceof Error ? error.message : String(error),
        }),
      );
      message.retry();
    }
  }
};

export default {
  async fetch(request: Request, env?: Env): Promise<Response> {
    const url = new URL(request.url);

    if (request.method === "GET" && url.pathname === "/health") {
      return healthResponse();
    }

    if (request.method === "GET" && url.pathname === "/dashboard") {
      return dashboardResponse();
    }

    if (env?.ORIGIN_URL && !validateOriginUrl(env.ORIGIN_URL)) {
      return configurationErrorResponse();
    }

    if (
      request.method === "GET" &&
      (url.pathname === "/api/analytics/events" ||
        url.pathname === "/api/analytics/summary" ||
        url.pathname === "/api/analytics/analysis" ||
        url.pathname === "/api/security/events" ||
        url.pathname === "/api/security/summary" ||
        url.pathname === "/api/security/analysis")
    ) {
      return handleAnalyticsRequest(request, env);
    }

    const requestId =
      request.headers.get("x-edgeguard-request-id") ?? crypto.randomUUID();
    const context = await buildRequestContext(request, requestId, env);
    const rateLimitResult = await enforceRateLimit(request, context, env);
    let decision = evaluateSecurityDecision(request, context);

    if (rateLimitResult && !rateLimitResult.allowed) {
      decision = applyRateLimitSignal(decision, rateLimitResult);
    }

    if (rateLimitResult && !rateLimitResult.allowed) {
      console.log(
        JSON.stringify({
          event: "rate_limit",
          requestId: context.requestId,
          clientId: context.clientId,
          allowed: false,
          limit: rateLimitResult.limit,
          remaining: rateLimitResult.remaining,
          retryAfterSeconds: rateLimitResult.retryAfterSeconds,
        }),
      );
      console.log(JSON.stringify(safeSecurityLog(decision)));
      await recordSecurityEvent(
        env,
        mapSecurityEvent({
          context,
          decision,
          rateLimit: rateLimitResult,
          upstreamStatus: null,
          durationMs: null,
        }),
      );
      return Response.json(
        {
          error: {
            code: "EDGEGUARD_RATE_LIMITED",
            message: "Too many requests.",
            requestId: context.requestId,
            retryAfterSeconds: rateLimitResult.retryAfterSeconds,
          },
        },
        {
          status: 429,
          headers: {
            "x-edgeguard-request-id": context.requestId,
            "retry-after": String(rateLimitResult.retryAfterSeconds),
          },
        },
      );
    }

    if (decision.action === "block") {
      console.log(JSON.stringify(safeSecurityLog(decision)));
      await recordSecurityEvent(
        env,
        mapSecurityEvent({
          context,
          decision,
          rateLimit: rateLimitResult,
          upstreamStatus: null,
          durationMs: null,
        }),
      );
      return Response.json(
        {
          error: {
            code: "EDGEGUARD_BLOCKED",
            message: "Request blocked by EdgeGuard.",
            requestId: context.requestId,
          },
        },
        { status: 403 },
      );
    }

    const startedAt = Date.now();
    let proxiedResponse: Response | null = null;
    try {
      proxiedResponse = await proxyRequest(request, env, requestId);
    } catch (error) {
      console.error(
        JSON.stringify({
          event: "origin_failure",
          requestId: context.requestId,
          clientId: context.clientId,
          message: "Origin request failed; gateway returned 502.",
          error: error instanceof Error ? error.message : String(error),
        }),
      );
      await recordSecurityEvent(
        env,
        mapSecurityEvent({
          context,
          decision,
          rateLimit: rateLimitResult,
          upstreamStatus: null,
          durationMs: Date.now() - startedAt,
        }),
      );
      return Response.json(
        { error: { code: "EDGEGUARD_ORIGIN_UNAVAILABLE" } },
        { status: 502 },
      );
    }
    const durationMs = Date.now() - startedAt;

    if (proxiedResponse !== null) {
      console.log(
        JSON.stringify(
          safeRequestLog(context, proxiedResponse.status, durationMs),
        ),
      );
      console.log(JSON.stringify(safeSecurityLog(decision)));
      await recordSecurityEvent(
        env,
        mapSecurityEvent({
          context,
          decision,
          rateLimit: rateLimitResult,
          upstreamStatus: proxiedResponse.status,
          durationMs,
        }),
      );
      return proxiedResponse;
    }

    console.log(JSON.stringify(safeRequestLog(context, 404, durationMs)));
    console.log(JSON.stringify(safeSecurityLog(decision)));
    await recordSecurityEvent(
      env,
      mapSecurityEvent({
        context,
        decision,
        rateLimit: rateLimitResult,
        upstreamStatus: null,
        durationMs: null,
      }),
    );
    return Response.json({ error: "not_found" }, { status: 404 });
  },
  async queue(batch: MessageBatch<SecurityEvent>, env: Env): Promise<void> {
    await consumeSecurityEvents(batch, env);
  },
} satisfies ExportedHandler<Env, SecurityEvent>;
