export type PersistedSecurityAction =
  "allow" | "monitor" | "block" | "rate_limited";

export interface SecurityEvent {
  id: string;
  createdAt: string;
  requestId: string;
  clientId: string;
  method: string;
  path: string;
  country: string | null;
  colo: string | null;
  asn: number | null;
  riskScore: number;
  action: PersistedSecurityAction;
  signalIds: string[];
  upstreamStatus: number | null;
  durationMs: number | null;
  rateLimitRemaining: number | null;
  retryAfterSeconds: number | null;
}

export interface SecurityEventRow {
  id: string;
  created_at: string;
  request_id: string;
  client_id: string;
  method: string;
  path: string;
  country: string | null;
  colo: string | null;
  asn: number | null;
  risk_score: number;
  action: string;
  signal_ids: string;
  upstream_status: number | null;
  duration_ms: number | null;
  rate_limit_remaining: number | null;
  retry_after_seconds: number | null;
}
