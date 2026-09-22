import type {
  RequestContext,
  RateLimitResult,
  SecurityDecision,
} from "../index";
import type { SecurityEvent } from "./types";

export interface SecurityEventOutcome {
  context: RequestContext;
  decision: SecurityDecision;
  rateLimit: RateLimitResult | null;
  upstreamStatus: number | null;
  durationMs: number | null;
}

export const mapSecurityEvent = ({
  context,
  decision,
  rateLimit,
  upstreamStatus,
  durationMs,
}: SecurityEventOutcome): SecurityEvent => ({
  id: crypto.randomUUID(),
  createdAt: new Date().toISOString(),
  requestId: context.requestId,
  clientId: context.clientId,
  method: context.method,
  path: context.path,
  country: context.country,
  colo: context.colo,
  asn: context.asn,
  riskScore: decision.score,
  action: rateLimit && !rateLimit.allowed ? "rate_limited" : decision.action,
  signalIds: decision.signals.map((signal) => signal.id),
  upstreamStatus,
  durationMs,
  rateLimitRemaining: rateLimit?.remaining ?? null,
  retryAfterSeconds:
    rateLimit && !rateLimit.allowed ? rateLimit.retryAfterSeconds : null,
});
