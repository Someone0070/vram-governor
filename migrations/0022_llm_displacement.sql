-- Durable controller intent for accelerator displacement. JSON body carries
-- the immutable workload/lease/runtime/artifact identities and later-bound
-- observations; this journal never performs physical effects.
CREATE TABLE IF NOT EXISTS llm_displacement_operations (
    id TEXT PRIMARY KEY,
    owner_id TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    accelerator_id TEXT NOT NULL,
    node_id TEXT NOT NULL,
    victim_target_id TEXT NOT NULL,
    urgent_target_id TEXT NOT NULL,
    phase TEXT NOT NULL,
    revision BIGINT NOT NULL CHECK (revision > 0),
    body JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    UNIQUE(owner_id, idempotency_key),
    CHECK (owner_id <> '' AND idempotency_key <> '' AND accelerator_id <> '' AND node_id <> '' AND victim_target_id <> '' AND urgent_target_id <> ''),
    CHECK (COALESCE(body->>'accelerator_id','') = accelerator_id AND COALESCE(body->>'node_id','') = node_id),
    CHECK (COALESCE(body->>'id','') = id AND COALESCE(body->>'owner_id','') = owner_id AND COALESCE(body->>'idempotency_key','') = idempotency_key),
    CHECK (COALESCE(body->>'phase','') = phase AND COALESCE((body->>'revision')::BIGINT,0) = revision),
    CHECK (COALESCE(body->>'victim_workload_id','') <> '' AND COALESCE(body->>'victim_owner_id','') <> '' AND COALESCE(body->>'urgent_workload_id','') <> '' AND COALESCE(body->>'urgent_owner_id','') <> ''),
    CHECK (COALESCE(body->'victim_binding'->>'target_id','') = victim_target_id AND COALESCE(body->'urgent_binding'->>'target_id','') = urgent_target_id),
    CHECK (COALESCE(body->'victim_binding'->>'node_id','') = node_id AND COALESCE(body->'urgent_binding'->>'node_id','') = node_id),
    CHECK (COALESCE(body->'victim_binding'->>'accelerator_id','') = accelerator_id AND COALESCE(body->'urgent_binding'->>'accelerator_id','') = accelerator_id),
    CHECK (COALESCE(body->'original_lease'->>'accelerator_id','') = accelerator_id AND COALESCE(body->'original_lease'->>'workload_id','') = body->>'victim_workload_id' AND COALESCE((body->'original_lease'->>'fencing_token')::BIGINT,0) = COALESCE((body->>'fence')::BIGINT,0)),
    CHECK (COALESCE(body->'victim_binding'->>'actual_alias','') <> '' AND COALESCE(body->'urgent_binding'->>'actual_alias','') <> '' AND jsonb_typeof(body->'victim_binding'->'catalog_aliases') = 'array' AND jsonb_array_length(body->'victim_binding'->'catalog_aliases') > 0 AND jsonb_typeof(body->'urgent_binding'->'catalog_aliases') = 'array' AND jsonb_array_length(body->'urgent_binding'->'catalog_aliases') > 0),
    CHECK (COALESCE(body->'victim_binding'->>'catalog_model','') <> '' AND COALESCE(body->'urgent_binding'->>'catalog_model','') <> '' AND COALESCE(body->'victim_binding'->>'local_plan_id','') <> '' AND COALESCE(body->'urgent_binding'->>'local_plan_id','') <> '' AND COALESCE(body->'victim_binding'->>'local_plan_hash','') <> '' AND COALESCE(body->'urgent_binding'->>'local_plan_hash','') <> '' AND COALESCE(body->'victim_binding'->>'controller_plan_id','') <> '' AND COALESCE(body->'urgent_binding'->>'controller_plan_id','') <> '' AND COALESCE(body->'victim_binding'->>'controller_plan_hash','') <> '' AND COALESCE(body->'urgent_binding'->>'controller_plan_hash','') <> '' AND COALESCE(body->'victim_binding'->>'artifact_digest','') <> '' AND COALESCE(body->'urgent_binding'->>'artifact_digest','') <> '' AND COALESCE(body->'victim_binding'->>'runtime_identity','') <> '' AND COALESCE(body->'urgent_binding'->>'runtime_identity','') <> '' AND COALESCE(body->'victim_binding'->>'profile_identity','') <> '' AND COALESCE(body->'urgent_binding'->>'profile_identity','') <> '' AND COALESCE(body->'victim_binding'->>'context_identity','') <> '' AND COALESCE(body->'urgent_binding'->>'context_identity','') <> '' AND COALESCE(body->'victim_binding'->>'checkpoint_digest','') <> '' AND COALESCE(body->'urgent_binding'->>'checkpoint_digest','') <> '' AND COALESCE(body->'victim_binding'->>'proof_binding','') <> '' AND COALESCE(body->'urgent_binding'->>'proof_binding','') <> '' AND COALESCE(body->>'proof_binding','') <> ''),
    CHECK (phase IN ('planned','pause_intent_sealed','safe_boundary_paused','snapshot_intent_sealed','snapshot_captured','victim_stop_intent_sealed','victim_stopped','urgent_load_intent_sealed','urgent_loaded','urgent_stop_intent_sealed','urgent_stopped','victim_reload_intent_sealed','victim_reloaded','kv_restore_intent_sealed','kv_restored','settlement_intent_sealed','settled','pending','uncertain','manual_reconciliation','completed'))
);
CREATE INDEX IF NOT EXISTS llm_displacement_operations_owner_idx
    ON llm_displacement_operations(owner_id, updated_at, id);
CREATE INDEX IF NOT EXISTS llm_displacement_operations_accelerator_idx
    ON llm_displacement_operations(accelerator_id, created_at);
CREATE UNIQUE INDEX IF NOT EXISTS llm_displacement_unresolved_accelerator_idx
    ON llm_displacement_operations(accelerator_id)
    WHERE phase <> 'completed';
