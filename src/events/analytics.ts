import type { SecurityEvent } from "./types";
import {
  listRecentSecurityEvents,
  listSecurityEventsByAction,
  listSecurityEventsByClient,
} from "./repository";

export interface SecurityAnalyticsSummary {
  windowStart: string;
  windowEnd: string;
  totalEvents: number;
  averageRiskScore: number;
  actionCounts: Record<SecurityEvent["action"], number>;
  topPaths: Array<{ path: string; count: number }>;
}

export interface SecurityEventQuery {
  limit: number;
  action: SecurityEvent["action"] | null;
  clientId: string | null;
}

const ACTIONS: SecurityEvent["action"][] = [
  "allow",
  "monitor",
  "block",
  "rate_limited",
];

const DEFAULT_LIMIT = 50;
const MAX_LIMIT = 100;
const DEFAULT_WINDOW_HOURS = 24;
const MAX_WINDOW_HOURS = 24 * 30;

const emptyActionCounts = (): Record<SecurityEvent["action"], number> => ({
  allow: 0,
  monitor: 0,
  block: 0,
  rate_limited: 0,
});

export const parseSecurityEventQuery = (
  searchParams: URLSearchParams,
): SecurityEventQuery => {
  const requestedLimit = Number(searchParams.get("limit"));
  const limit = Number.isFinite(requestedLimit)
    ? Math.min(MAX_LIMIT, Math.max(1, Math.floor(requestedLimit)))
    : DEFAULT_LIMIT;
  const action = searchParams.get("action");
  const clientId = searchParams.get("clientId")?.trim() || null;

  return {
    limit,
    action: ACTIONS.includes(action as SecurityEvent["action"])
      ? (action as SecurityEvent["action"])
      : null,
    clientId,
  };
};

export const isSecurityEventAction = (
  value: string,
): value is SecurityEvent["action"] =>
  ACTIONS.includes(value as SecurityEvent["action"]);

export const listAnalyticsEvents = async (
  db: D1Database,
  query: SecurityEventQuery,
): Promise<SecurityEvent[]> => {
  if (query.clientId) {
    return listSecurityEventsByClient(db, query.clientId, query.limit);
  }

  if (query.action) {
    return listSecurityEventsByAction(db, query.action, query.limit);
  }

  return listRecentSecurityEvents(db, query.limit);
};

export const getSecurityAnalyticsSummary = async (
  db: D1Database,
  now = new Date(),
  windowHours = DEFAULT_WINDOW_HOURS,
): Promise<SecurityAnalyticsSummary> => {
  const boundedWindowHours = Math.min(
    MAX_WINDOW_HOURS,
    Math.max(1, Math.floor(windowHours)),
  );
  const windowEnd = now.toISOString();
  const windowStart = new Date(
    now.getTime() - boundedWindowHours * 60 * 60 * 1000,
  ).toISOString();
  const summary = await db
    .prepare(
      `SELECT
        COUNT(*) AS total_events,
        COALESCE(AVG(risk_score), 0) AS average_risk_score,
        SUM(CASE WHEN action = 'allow' THEN 1 ELSE 0 END) AS allow_count,
        SUM(CASE WHEN action = 'monitor' THEN 1 ELSE 0 END) AS monitor_count,
        SUM(CASE WHEN action = 'block' THEN 1 ELSE 0 END) AS block_count,
        SUM(CASE WHEN action = 'rate_limited' THEN 1 ELSE 0 END) AS rate_limited_count
      FROM security_events
      WHERE created_at >= ? AND created_at <= ?`,
    )
    .bind(windowStart, windowEnd)
    .first<{
      total_events: number | null;
      average_risk_score: number | null;
      allow_count: number | null;
      monitor_count: number | null;
      block_count: number | null;
      rate_limited_count: number | null;
    }>();
  const topPaths = await db
    .prepare(
      `SELECT path, COUNT(*) AS count
      FROM security_events
      WHERE created_at >= ? AND created_at <= ?
      GROUP BY path
      ORDER BY count DESC, path ASC
      LIMIT 10`,
    )
    .bind(windowStart, windowEnd)
    .all<{ path: string; count: number }>();
  const actionCounts = emptyActionCounts();
  actionCounts.allow = summary?.allow_count ?? 0;
  actionCounts.monitor = summary?.monitor_count ?? 0;
  actionCounts.block = summary?.block_count ?? 0;
  actionCounts.rate_limited = summary?.rate_limited_count ?? 0;

  return {
    windowStart,
    windowEnd,
    totalEvents: summary?.total_events ?? 0,
    averageRiskScore: Number(summary?.average_risk_score ?? 0),
    actionCounts,
    topPaths: topPaths.results,
  };
};
