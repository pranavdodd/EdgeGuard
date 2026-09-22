import type { SecurityEvent, SecurityEventRow } from "./types";

const MAX_QUERY_LIMIT = 100;

const normalizeLimit = (limit: number): number => {
  if (!Number.isFinite(limit)) {
    return 1;
  }

  return Math.min(MAX_QUERY_LIMIT, Math.max(1, Math.floor(limit)));
};

const eventFromRow = (row: SecurityEventRow): SecurityEvent => {
  let signalIds: string[] = [];
  try {
    const parsed: unknown = JSON.parse(row.signal_ids);
    if (
      Array.isArray(parsed) &&
      parsed.every((value) => typeof value === "string")
    ) {
      signalIds = parsed;
    }
  } catch {
    signalIds = [];
  }

  return {
    id: row.id,
    createdAt: row.created_at,
    requestId: row.request_id,
    clientId: row.client_id,
    method: row.method,
    path: row.path,
    country: row.country,
    colo: row.colo,
    asn: row.asn,
    riskScore: row.risk_score,
    action: row.action as SecurityEvent["action"],
    signalIds,
    upstreamStatus: row.upstream_status,
    durationMs: row.duration_ms,
    rateLimitRemaining: row.rate_limit_remaining,
    retryAfterSeconds: row.retry_after_seconds,
  };
};

export const insertSecurityEvent = async (
  db: D1Database,
  event: SecurityEvent,
): Promise<void> => {
  await db
    .prepare(
      `INSERT OR IGNORE INTO security_events (
        id, created_at, request_id, client_id, method, path, country, colo, asn,
        risk_score, action, signal_ids, upstream_status, duration_ms,
        rate_limit_remaining, retry_after_seconds
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      event.id,
      event.createdAt,
      event.requestId,
      event.clientId,
      event.method,
      event.path,
      event.country,
      event.colo,
      event.asn,
      event.riskScore,
      event.action,
      JSON.stringify(event.signalIds),
      event.upstreamStatus,
      event.durationMs,
      event.rateLimitRemaining,
      event.retryAfterSeconds,
    )
    .run();
};

export const getSecurityEventByRequestId = async (
  db: D1Database,
  requestId: string,
): Promise<SecurityEvent | null> => {
  const result = await db
    .prepare(
      "SELECT * FROM security_events WHERE request_id = ? ORDER BY created_at DESC LIMIT 1",
    )
    .bind(requestId)
    .first<SecurityEventRow>();

  return result ? eventFromRow(result) : null;
};

const listEvents = async (
  statement: D1PreparedStatement,
): Promise<SecurityEvent[]> => {
  const result = await statement.all<SecurityEventRow>();
  return result.results.map(eventFromRow);
};

export const listRecentSecurityEvents = async (
  db: D1Database,
  limit = 50,
): Promise<SecurityEvent[]> =>
  listEvents(
    db
      .prepare(
        "SELECT * FROM security_events ORDER BY created_at DESC, id DESC LIMIT ?",
      )
      .bind(normalizeLimit(limit)),
  );

export const listSecurityEventsByClient = async (
  db: D1Database,
  clientId: string,
  limit = 50,
): Promise<SecurityEvent[]> =>
  listEvents(
    db
      .prepare(
        "SELECT * FROM security_events WHERE client_id = ? ORDER BY created_at DESC, id DESC LIMIT ?",
      )
      .bind(clientId, normalizeLimit(limit)),
  );

export const listSecurityEventsByAction = async (
  db: D1Database,
  action: SecurityEvent["action"],
  limit = 50,
): Promise<SecurityEvent[]> =>
  listEvents(
    db
      .prepare(
        "SELECT * FROM security_events WHERE action = ? ORDER BY created_at DESC, id DESC LIMIT ?",
      )
      .bind(action, normalizeLimit(limit)),
  );
