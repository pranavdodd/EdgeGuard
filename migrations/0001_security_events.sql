CREATE TABLE security_events (
  id TEXT PRIMARY KEY,
  created_at TEXT NOT NULL,
  request_id TEXT NOT NULL,
  client_id TEXT NOT NULL,
  method TEXT NOT NULL,
  path TEXT NOT NULL,
  country TEXT,
  colo TEXT,
  asn INTEGER,
  risk_score INTEGER NOT NULL,
  action TEXT NOT NULL CHECK (action IN ('allow', 'monitor', 'block', 'rate_limited')),
  signal_ids TEXT NOT NULL,
  upstream_status INTEGER,
  duration_ms INTEGER,
  rate_limit_remaining INTEGER,
  retry_after_seconds INTEGER
);

CREATE INDEX idx_security_events_created_at
  ON security_events(created_at DESC);

CREATE INDEX idx_security_events_client_created
  ON security_events(client_id, created_at DESC);

CREATE INDEX idx_security_events_action_created
  ON security_events(action, created_at DESC);

CREATE INDEX idx_security_events_request_id
  ON security_events(request_id);