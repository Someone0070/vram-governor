-- Durable measured model/profile footprints and safety reserves.
-- The migration is deliberately idempotent so interrupted/replayed deploys
-- cannot discard admission evidence.
CREATE TABLE IF NOT EXISTS model_capacities (
    id TEXT PRIMARY KEY,
    target_id TEXT NOT NULL,
    model TEXT NOT NULL,
    profile_id TEXT NOT NULL DEFAULT '',
    model_fingerprint TEXT NOT NULL DEFAULT '',
    runtime_identity TEXT NOT NULL DEFAULT '',
    capability_version TEXT NOT NULL DEFAULT '',
    capability_revision TEXT NOT NULL DEFAULT '',
    vram_total_bytes BIGINT NOT NULL DEFAULT 0,
    ram_total_bytes BIGINT NOT NULL DEFAULT 0,
    unified_memory BOOLEAN NOT NULL DEFAULT FALSE,
    capacity_source TEXT NOT NULL DEFAULT '',
    body JSONB NOT NULL,
    revision BIGINT NOT NULL DEFAULT 1,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    observed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (target_id, model, profile_id)
);

CREATE INDEX IF NOT EXISTS model_capacities_target_model
    ON model_capacities(target_id, model, updated_at DESC);

ALTER TABLE model_capacities
    ADD COLUMN IF NOT EXISTS revision BIGINT NOT NULL DEFAULT 1;

ALTER TABLE model_capacities
    ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT now();

ALTER TABLE model_capacities
    ADD COLUMN IF NOT EXISTS model_fingerprint TEXT NOT NULL DEFAULT '';

ALTER TABLE model_capacities
    ADD COLUMN IF NOT EXISTS runtime_identity TEXT NOT NULL DEFAULT '';

ALTER TABLE model_capacities
    ADD COLUMN IF NOT EXISTS capability_version TEXT NOT NULL DEFAULT '';

ALTER TABLE model_capacities
    ADD COLUMN IF NOT EXISTS capability_revision TEXT NOT NULL DEFAULT '';

ALTER TABLE model_capacities
    ADD COLUMN IF NOT EXISTS observed_at TIMESTAMPTZ NOT NULL DEFAULT now();

ALTER TABLE model_capacities
    ADD COLUMN IF NOT EXISTS vram_total_bytes BIGINT NOT NULL DEFAULT 0;

ALTER TABLE model_capacities
    ADD COLUMN IF NOT EXISTS ram_total_bytes BIGINT NOT NULL DEFAULT 0;

ALTER TABLE model_capacities
    ADD COLUMN IF NOT EXISTS unified_memory BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE model_capacities
    ADD COLUMN IF NOT EXISTS capacity_source TEXT NOT NULL DEFAULT '';

-- Residency projections are body-versioned JSON, so generation/fingerprint
-- fields remain backward compatible with the 0005 schema while making stale
-- replay rows inspectable and indexable after restart.
CREATE INDEX IF NOT EXISTS model_residencies_target_generation
    ON model_residencies(target_id, model, (COALESCE(body->>'target_generation', '0')));
