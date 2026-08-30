BEGIN;

-- Only scheduler safety policy is mutable at runtime. Target identity,
-- endpoints, authorization, and model inventories remain deployment config.
CREATE TABLE target_policy_overrides (
    target_id TEXT PRIMARY KEY,
    body JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

COMMIT;
