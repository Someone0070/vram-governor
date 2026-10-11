CREATE TABLE IF NOT EXISTS node_enrollments (
  node_id TEXT PRIMARY KEY,
  node_name TEXT NOT NULL,
  token_hash CHAR(64) NOT NULL UNIQUE,
  status TEXT NOT NULL CHECK (status IN ('active', 'revoked')),
  created_at TIMESTAMPTZ NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS node_enrollments_status_idx ON node_enrollments(status);
