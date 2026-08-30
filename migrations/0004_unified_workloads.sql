-- Unified workload control-plane durability. Large bytes remain in the
-- configured ArtifactStore; PostgreSQL stores authoritative state and refs.
BEGIN;

CREATE TABLE principals (
    id TEXT PRIMARY KEY,
    token_hash BYTEA NOT NULL UNIQUE,
    plane TEXT NOT NULL,
    owner_id TEXT NOT NULL,
    scopes JSONB NOT NULL DEFAULT '[]'::jsonb,
    adapters JSONB NOT NULL DEFAULT '[]'::jsonb,
    node_id TEXT,
    max_priority INTEGER NOT NULL DEFAULT 0,
    max_incident_severity TEXT NOT NULL DEFAULT 'S0',
    egress_policy TEXT NOT NULL DEFAULT 'local_only',
    concurrency_limit INTEGER NOT NULL DEFAULT 1,
    budget_cents BIGINT NOT NULL DEFAULT 0,
    disabled_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE workloads (
    id TEXT PRIMARY KEY,
    owner_id TEXT NOT NULL,
    idempotency_key TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL,
    body JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);
CREATE UNIQUE INDEX workloads_owner_idempotency
    ON workloads(owner_id, idempotency_key) WHERE idempotency_key <> '';
CREATE INDEX workloads_status_priority ON workloads(status, ((body->'request'->>'priority')::integer), created_at);

CREATE TABLE accelerator_lease_fences (
    accelerator_id TEXT PRIMARY KEY,
    last_token BIGINT NOT NULL DEFAULT 0
);
CREATE TABLE accelerator_leases (
    accelerator_id TEXT PRIMARY KEY,
    workload_id TEXT NOT NULL REFERENCES workloads(id) ON DELETE CASCADE,
    fencing_token BIGINT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX accelerator_leases_expiry ON accelerator_leases(expires_at);

CREATE TABLE prompt_mappings (
    public_prompt_id TEXT PRIMARY KEY,
    workload_id TEXT NOT NULL REFERENCES workloads(id) ON DELETE CASCADE,
    target_id TEXT,
    backend_prompt_id TEXT,
    client_id TEXT
);

CREATE TABLE artifacts (
    id TEXT PRIMARY KEY,
    owner_id TEXT NOT NULL,
    workload_id TEXT REFERENCES workloads(id) ON DELETE SET NULL,
    name TEXT NOT NULL,
    media_type TEXT,
    size_bytes BIGINT NOT NULL,
    storage_ref TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE audit_events (
    id TEXT PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL,
    actor_id TEXT,
    owner_id TEXT,
    workload_id TEXT REFERENCES workloads(id) ON DELETE SET NULL,
    type TEXT NOT NULL,
    severity TEXT NOT NULL,
    payload JSONB
);
CREATE INDEX audit_events_owner_time ON audit_events(owner_id, timestamp DESC);

CREATE TABLE transformation_approvals (
    workload_id TEXT NOT NULL REFERENCES workloads(id) ON DELETE CASCADE,
    plan_hash TEXT NOT NULL,
    approver_id TEXT NOT NULL,
    approval_mode TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (workload_id, plan_hash)
);

CREATE TABLE notification_outbox (
    id TEXT PRIMARY KEY,
    workload_id TEXT REFERENCES workloads(id) ON DELETE CASCADE,
    destination TEXT NOT NULL,
    payload JSONB NOT NULL,
    signature TEXT,
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    delivered_at TIMESTAMPTZ,
    last_error TEXT
);
CREATE INDEX notification_outbox_pending ON notification_outbox(next_attempt_at) WHERE delivered_at IS NULL;

CREATE TABLE incidents (
    id TEXT PRIMARY KEY,
    owner_id TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('S0','S1','S2','S3','S4')),
    confidence DOUBLE PRECISION NOT NULL,
    summary TEXT NOT NULL,
    evidence_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
    status TEXT NOT NULL,
    proposal JSONB,
    actual_provider TEXT,
    actual_model TEXT,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE scheduler_learning_samples (
    id BIGSERIAL PRIMARY KEY,
    accelerator_id TEXT NOT NULL,
    runtime_version TEXT NOT NULL,
    workload_class TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    predicted JSONB NOT NULL,
    observed JSONB NOT NULL,
    outcome TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMIT;
