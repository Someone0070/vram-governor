BEGIN;

CREATE TABLE workload_transition_plans (
    id TEXT PRIMARY KEY,
    workload_id TEXT NOT NULL REFERENCES workloads(id) ON DELETE CASCADE,
    victim_workload_id TEXT REFERENCES workloads(id) ON DELETE SET NULL,
    status TEXT NOT NULL,
    body JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX workload_transition_plans_workload ON workload_transition_plans(workload_id, created_at DESC);
CREATE INDEX workload_transition_plans_victim ON workload_transition_plans(victim_workload_id, created_at DESC);
CREATE INDEX workload_transition_plans_active ON workload_transition_plans(status) WHERE status IN ('planned','executing');

COMMIT;
