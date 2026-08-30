-- Atomic per-principal cloud budget reservations and settlement.
BEGIN;

CREATE TABLE budget_reservations (
    workload_id TEXT PRIMARY KEY REFERENCES workloads(id) ON DELETE CASCADE,
    principal_id TEXT NOT NULL,
    reserved_cents BIGINT NOT NULL CHECK (reserved_cents >= 0),
    actual_cents BIGINT NOT NULL DEFAULT 0 CHECK (actual_cents >= 0),
    status TEXT NOT NULL CHECK (status IN ('reserved','settled','released')),
    body JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX budget_reservations_principal_status
    ON budget_reservations(principal_id, status);

COMMIT;
