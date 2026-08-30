BEGIN;

-- Browser authentication sessions are separate from the model-continuity
-- sessions introduced in 0001. Only digests of the cookie and CSRF secrets
-- are persisted.
CREATE TABLE browser_sessions (
    id_hash TEXT PRIMARY KEY,
    principal_id TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('ui', 'admin')),
    expires_at TIMESTAMPTZ NOT NULL,
    body JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX browser_sessions_expiry ON browser_sessions(expires_at);

COMMIT;
