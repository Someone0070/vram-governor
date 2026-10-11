-- Durable accelerator lease cleanup intents. The exact owner and fencing
-- token make retries safe when a release failed after the workload stopped.
CREATE TABLE IF NOT EXISTS accelerator_lease_cleanup_intents (
    accelerator_id text NOT NULL,
    owner text NOT NULL,
    fencing_token bigint NOT NULL,
    workload_id text NOT NULL DEFAULT '',
    expected_workload_revision bigint,
    terminal_disposition text,
    terminal_error_code text,
    release_confirmed boolean NOT NULL DEFAULT false,
    terminal_published boolean NOT NULL DEFAULT false,
    audit_published boolean NOT NULL DEFAULT false,
    notification_published boolean NOT NULL DEFAULT false,
    budget_settled boolean NOT NULL DEFAULT false,
    attempts integer NOT NULL DEFAULT 1,
    last_error text,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    next_retry_at timestamptz,
    PRIMARY KEY (accelerator_id, owner, fencing_token, workload_id)
);

CREATE INDEX IF NOT EXISTS accelerator_lease_cleanup_due
    ON accelerator_lease_cleanup_intents(next_retry_at, updated_at);

ALTER TABLE accelerator_lease_cleanup_intents
    ADD COLUMN IF NOT EXISTS workload_id text,
    ADD COLUMN IF NOT EXISTS expected_workload_revision bigint,
    ADD COLUMN IF NOT EXISTS terminal_disposition text,
    ADD COLUMN IF NOT EXISTS terminal_error_code text,
    ADD COLUMN IF NOT EXISTS release_confirmed boolean NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS terminal_published boolean NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS audit_published boolean NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS notification_published boolean NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS budget_settled boolean NOT NULL DEFAULT false;

UPDATE accelerator_lease_cleanup_intents SET workload_id = '' WHERE workload_id IS NULL;
ALTER TABLE accelerator_lease_cleanup_intents ALTER COLUMN workload_id SET DEFAULT '', ALTER COLUMN workload_id SET NOT NULL;
ALTER TABLE accelerator_lease_cleanup_intents DROP CONSTRAINT IF EXISTS accelerator_lease_cleanup_intents_pkey;
ALTER TABLE accelerator_lease_cleanup_intents ADD CONSTRAINT accelerator_lease_cleanup_intents_pkey PRIMARY KEY (accelerator_id, owner, fencing_token, workload_id);

ALTER TABLE accelerator_lease_cleanup_intents
    DROP COLUMN IF EXISTS terminal_error,
    DROP COLUMN IF EXISTS terminal_workload,
    DROP CONSTRAINT IF EXISTS accelerator_lease_cleanup_fence_positive,
    DROP CONSTRAINT IF EXISTS accelerator_lease_cleanup_attempts_positive,
    DROP CONSTRAINT IF EXISTS accelerator_lease_cleanup_typed_complete,
    DROP CONSTRAINT IF EXISTS accelerator_lease_cleanup_phase_order;

ALTER TABLE accelerator_lease_cleanup_intents
    ADD CONSTRAINT accelerator_lease_cleanup_fence_positive CHECK (fencing_token > 0),
    ADD CONSTRAINT accelerator_lease_cleanup_attempts_positive CHECK (attempts >= 1),
    ADD CONSTRAINT accelerator_lease_cleanup_typed_complete CHECK (
        terminal_disposition IS NULL OR
        (workload_id IS NOT NULL AND expected_workload_revision IS NOT NULL AND expected_workload_revision > 0 AND terminal_error_code IS NOT NULL AND length(terminal_error_code) BETWEEN 1 AND 128 AND terminal_disposition IN ('success','failure','cancel'))
    ),
    ADD CONSTRAINT accelerator_lease_cleanup_phase_order CHECK (
        (NOT terminal_published OR release_confirmed) AND
        (NOT audit_published OR terminal_published) AND
        (NOT notification_published OR terminal_published) AND
        (NOT budget_settled OR terminal_published)
    );
