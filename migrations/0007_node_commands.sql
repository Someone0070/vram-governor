-- Durable signed controller-to-node command journal.
BEGIN;

CREATE TABLE node_commands (
    id TEXT PRIMARY KEY,
    node_id TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    status TEXT NOT NULL,
    body JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    UNIQUE(node_id, idempotency_key)
);
CREATE INDEX node_commands_node_time ON node_commands(node_id, created_at DESC);
CREATE INDEX node_commands_pending ON node_commands(node_id, expires_at)
    WHERE status IN ('queued', 'sent');

COMMIT;
