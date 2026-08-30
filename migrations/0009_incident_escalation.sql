BEGIN;

ALTER TABLE incidents ADD COLUMN IF NOT EXISTS requested_model_tier TEXT;
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS evidence_classification TEXT;
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS evidence_sanitized BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS egress_policy TEXT NOT NULL DEFAULT 'local_only';
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS analysis_workload_id TEXT REFERENCES workloads(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS incidents_analysis_workload ON incidents(analysis_workload_id);

COMMIT;
