CREATE TABLE threat_analyses (
  analysis_id TEXT PRIMARY KEY,
  event_id TEXT NOT NULL UNIQUE,
  model TEXT NOT NULL,
  created_at TEXT NOT NULL,
  summary TEXT NOT NULL,
  category TEXT NOT NULL,
  evidence_signal_ids TEXT NOT NULL,
  recommended_action TEXT NOT NULL,
  proposed_rule TEXT,
  confidence TEXT NOT NULL CHECK (confidence IN ('low', 'medium', 'high')),
  caveats TEXT NOT NULL,
  FOREIGN KEY (event_id) REFERENCES security_events(id)
);

CREATE INDEX idx_threat_analyses_event_id
  ON threat_analyses(event_id);

CREATE INDEX idx_threat_analyses_created_at
  ON threat_analyses(created_at DESC);