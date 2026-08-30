BEGIN;

CREATE TABLE scheduler_interference_profiles (
    profile_key TEXT PRIMARY KEY,
    accelerator_id TEXT NOT NULL,
    runtime_version TEXT NOT NULL,
    body JSONB NOT NULL,
    confidence DOUBLE PRECISION NOT NULL,
    version INTEGER NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX scheduler_interference_profiles_accelerator
    ON scheduler_interference_profiles(accelerator_id, updated_at DESC);

COMMIT;
