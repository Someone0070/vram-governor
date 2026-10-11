-- Durable production LLM checkpoint lifecycle. The JSON body preserves the
-- complete signed identity while indexed columns make owner/idempotency and
-- restart recovery queryable without trusting a caller's in-memory state.
CREATE TABLE IF NOT EXISTS llm_checkpoint_operations (
    id TEXT PRIMARY KEY,
    owner_id TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    phase TEXT NOT NULL,
    phase_ordinal INTEGER NOT NULL DEFAULT 0,
    node_id TEXT NOT NULL DEFAULT '',
    accelerator_id TEXT NOT NULL DEFAULT '',
    target_id TEXT NOT NULL DEFAULT '',
    slot_id INTEGER NOT NULL DEFAULT -1,
    body JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    UNIQUE(owner_id, idempotency_key)
);
CREATE INDEX IF NOT EXISTS llm_checkpoint_operations_phase_idx ON llm_checkpoint_operations(phase, updated_at);
CREATE INDEX IF NOT EXISTS llm_checkpoint_operations_owner_idx ON llm_checkpoint_operations(owner_id, updated_at);
-- WorkloadRevision is part of the immutable replay identity in the JSON body.
-- Every durable root must carry a canonical, non-zero JSON number so restart
-- and outer-CAS recovery can bind the physical operation to one projection.
CREATE INDEX IF NOT EXISTS llm_checkpoint_operations_workload_revision_idx
    ON llm_checkpoint_operations((body->>'workload_revision'));
-- Cleanup custody is stored in the same immutable operation body so a
-- controller restart can recover an exact resumed handle/fence before lease
-- admission. Keep the accelerator/state lookup indexed even while the row is
-- waiting on an offline node.
CREATE INDEX IF NOT EXISTS llm_checkpoint_operations_cleanup_due_idx
    ON llm_checkpoint_operations((body->>'cleanup_accelerator_id'), (body->>'cleanup_state'), updated_at)
    WHERE COALESCE(body->>'cleanup_state','') IN ('armed', 'owned', 'pending', 'failed', 'stopped');
ALTER TABLE llm_checkpoint_operations ADD COLUMN IF NOT EXISTS accelerator_id TEXT NOT NULL DEFAULT '';
ALTER TABLE llm_checkpoint_operations ADD COLUMN IF NOT EXISTS phase_ordinal INTEGER NOT NULL DEFAULT 0;
UPDATE llm_checkpoint_operations
SET phase_ordinal = CASE phase
        WHEN 'planned' THEN 1
        WHEN 'assigned' THEN 1
        WHEN 'started' THEN 2
        WHEN 'paused' THEN 3
        WHEN 'saved' THEN 4
        WHEN 'stopped' THEN 5
        WHEN 'released' THEN 6
        WHEN 'restore_planned' THEN 6
        WHEN 'restore_assigned' THEN 8
        WHEN 'reloaded' THEN 9
        WHEN 'restored' THEN 10
        WHEN 'resumed' THEN 11
        WHEN 'continued' THEN 12
        WHEN 'reused' THEN 13
        WHEN 'completed' THEN 15
        WHEN 'failed' THEN 15
        WHEN 'cancelled' THEN 15
        WHEN 'restore_failed' THEN 15
        ELSE 0
    END,
    body = jsonb_set(COALESCE(body, '{}'::jsonb), '{phase_ordinal}', to_jsonb(CASE phase
        WHEN 'planned' THEN 1 WHEN 'assigned' THEN 1 WHEN 'started' THEN 2
        WHEN 'paused' THEN 3 WHEN 'saved' THEN 4 WHEN 'stopped' THEN 5
        WHEN 'released' THEN 6 WHEN 'restore_planned' THEN 6
        WHEN 'restore_assigned' THEN 8 WHEN 'reloaded' THEN 9
        WHEN 'restored' THEN 10 WHEN 'resumed' THEN 11 WHEN 'continued' THEN 12 WHEN 'reused' THEN 13
        WHEN 'completed' THEN 15 WHEN 'failed' THEN 15 WHEN 'cancelled' THEN 15
        WHEN 'restore_failed' THEN 15 ELSE 0 END), true)
WHERE phase_ordinal = 0 OR NOT (body ? 'phase_ordinal');

-- Keep the indexed lifecycle vocabulary and its durable ordinal explicit.  A
-- controller may add metadata to body, but it may not introduce a phase that
-- the node journal and recovery code do not understand.
ALTER TABLE llm_checkpoint_operations DROP CONSTRAINT IF EXISTS llm_checkpoint_operations_phase_ck;
ALTER TABLE llm_checkpoint_operations ADD CONSTRAINT llm_checkpoint_operations_phase_ck CHECK (
    phase IN ('planned', 'assigned', 'started', 'paused', 'saved', 'stopped',
              'released', 'restore_planned', 'restore_assigned', 'reloaded',
              'restored', 'resumed', 'continued', 'reused', 'completed', 'failed',
              'cancelled', 'restore_failed')
    AND phase_ordinal > 0
    AND phase_ordinal = CASE phase
        WHEN 'planned' THEN 1
        WHEN 'assigned' THEN 1
        WHEN 'started' THEN 2
        WHEN 'paused' THEN 3
        WHEN 'saved' THEN 4
        WHEN 'stopped' THEN 5
        WHEN 'released' THEN 6
        WHEN 'restore_planned' THEN 6
        WHEN 'restore_assigned' THEN 8
        WHEN 'reloaded' THEN 9
        WHEN 'restored' THEN 10
        WHEN 'resumed' THEN 11
        WHEN 'continued' THEN 12
        WHEN 'reused' THEN 13
        WHEN 'completed' THEN 15
        WHEN 'failed' THEN 15
        WHEN 'cancelled' THEN 15
        WHEN 'restore_failed' THEN 15
        ELSE 0
    END
);
-- A slot can have only one non-terminal lifecycle, including when two
-- different idempotency keys race after assignment.  Slot ownership is
-- target/accelerator scoped (node identity is not part of the resource key).
-- The controller still validates the full identity in body; these columns
-- provide database-level serialization across controller instances.
DROP INDEX IF EXISTS llm_checkpoint_operations_live_slot_idx;
CREATE UNIQUE INDEX IF NOT EXISTS llm_checkpoint_operations_live_slot_idx
    ON llm_checkpoint_operations(target_id, accelerator_id, slot_id)
    WHERE slot_id >= 0 AND phase NOT IN ('completed', 'failed', 'cancelled', 'released', 'restore_failed');

-- The indexed columns serialize ownership, while the body carries the full
-- replay identity. Reject rows that could not be safely reconciled after a
-- restart even when a legacy database still has the old empty defaults.
ALTER TABLE llm_checkpoint_operations DROP CONSTRAINT IF EXISTS llm_checkpoint_operations_identity_ck;
ALTER TABLE llm_checkpoint_operations ADD CONSTRAINT llm_checkpoint_operations_identity_ck CHECK (
    owner_id <> '' AND idempotency_key <> '' AND node_id <> '' AND
    accelerator_id <> '' AND target_id <> '' AND
    COALESCE(body->>'workload_id','') <> '' AND
    COALESCE(body->>'runtime_identity','') <> '' AND
    COALESCE(body->>'model','') <> '' AND
    COALESCE(body->>'model_fingerprint','') <> '' AND
    COALESCE(body->>'profile_fingerprint','') <> '' AND
    COALESCE(body->>'context_fingerprint','') <> '' AND
    COALESCE((body->>'generation')::bigint,0) > 0 AND
    COALESCE((body->>'fence')::bigint,0) > 0 AND
    COALESCE(body->>'conversation_id','') <> '' AND
    COALESCE(jsonb_typeof(body->'workload_revision'),'') = 'number' AND
    COALESCE(body->>'workload_revision','') ~ '^[1-9][0-9]*$'
);
