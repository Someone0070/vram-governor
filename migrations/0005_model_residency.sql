-- Durable model residency and explainable load/unload transitions.
BEGIN;

-- Residency transitions share the same physical lease namespace as
-- workloads, so the holder is no longer constrained to reference a workload.
ALTER TABLE accelerator_leases
    DROP CONSTRAINT IF EXISTS accelerator_leases_workload_id_fkey;

CREATE TABLE model_residencies (
    target_id TEXT NOT NULL,
    model TEXT NOT NULL,
    body JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (target_id, model)
);
CREATE INDEX model_residencies_observed
    ON model_residencies ((body->>'observed_tier'), updated_at);

CREATE TABLE residency_transitions (
    id TEXT PRIMARY KEY,
    idempotency_key TEXT NOT NULL UNIQUE,
    target_id TEXT NOT NULL,
    accelerator_id TEXT,
    model TEXT NOT NULL,
    status TEXT NOT NULL,
    body JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX residency_transitions_target_time
    ON residency_transitions(target_id, created_at DESC);

COMMIT;
