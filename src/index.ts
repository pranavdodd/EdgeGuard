export interface Env {
  ORIGIN_URL?: string;
  FINGERPRINT_SECRET?: string;
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

const healthResponse = (): Response =>
  Response.json({
    status: "ok",
    service: "edgeguard",
  });

const canonicalizeText = (value: string | null | undefined, maxLength = 256): string | null => {
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

export const computeClientId = async ({
  ipAddress,
  userAgent,
  acceptLanguage,
  secret,
}: ClientIdentityInput): Promise<string> => {
  const fingerprint = [
    ipAddress ?? "unknown",
    canonicalizeText(userAgent, 128) ?? "unknown",
    canonicalizeText(acceptLanguage, 64) ?? "unknown",
  ].join("|");

  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );

  const signature = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(fingerprint));
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
  const asn = typeof requestWithCf.cf?.asn === "number" ? requestWithCf.cf.asn : null;

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

const proxyRequest = async (
  request: Request,
  env?: Env,
  requestId?: string,
): Promise<Response | null> => {
  if (!env?.ORIGIN_URL) {
    return null;
  }

  const origin = new URL(env.ORIGIN_URL);
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

export default {
  async fetch(request: Request, env?: Env): Promise<Response> {
    const url = new URL(request.url);

    if (request.method === "GET" && url.pathname === "/health") {
      return healthResponse();
    }

    const requestId = request.headers.get("x-edgeguard-request-id") ?? crypto.randomUUID();
    const context = await buildRequestContext(request, requestId, env);
    const startedAt = Date.now();

    const proxiedResponse = await proxyRequest(request, env, requestId);
    const durationMs = Date.now() - startedAt;

    if (proxiedResponse !== null) {
      console.log(JSON.stringify(safeRequestLog(context, proxiedResponse.status, durationMs)));
      return proxiedResponse;
    }

    console.log(JSON.stringify(safeRequestLog(context, 404, durationMs)));
    return Response.json({ error: "not_found" }, { status: 404 });
  },
} satisfies ExportedHandler<Env>;
