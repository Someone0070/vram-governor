-- VRAM Governor — Phase 3 addition: work queue engine columns
-- (architecture.md §12 Work Item Reliability, §29 Jobs View, §47 Phase 3).
--
-- This migration brings the `jobs` /
-- `work_items` tables already sketched in 0001_init.sql up to what the
-- Phase 3 engine (internal/jobs/manager.go) actually needs:
--
--   * work_items gains a payload (the mock completion request), a
--     tried_workers set (cross-worker retry — docs/gateway-and-queue.md),
--     last_error, and a submission-order seq for FIFO dispatch.
--   * jobs gains max_attempts (the retry cap alongside "tried set
--     exhausted") and denormalized progress counters (§29 Jobs View:
--     processed/current/failed/retried/queued), so a Postgres-backed
--     ProfileStore-style implementation can serve GET /jobs/{id} with a
--     single row read instead of a COUNT(*) aggregate over work_items.

BEGIN;

ALTER TABLE jobs
    ADD COLUMN IF NOT EXISTS max_attempts       INTEGER NOT NULL DEFAULT 8,
    ADD COLUMN IF NOT EXISTS progress_total      INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS progress_queued     INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS progress_running    INTEGER NOT NULL DEFAULT 0, -- "current" per §29
    ADD COLUMN IF NOT EXISTS progress_success    INTEGER NOT NULL DEFAULT 0, -- "processed" per §29
    ADD COLUMN IF NOT EXISTS progress_failed     INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS progress_retried    INTEGER NOT NULL DEFAULT 0;

-- 0001's status enum didn't include the Phase 3 engine's "pending" status
-- name; widen it rather than rename in place (jobs.go uses pending/running/
-- paused/cancelled/completed/completed_with_errors).
ALTER TABLE jobs DROP CONSTRAINT IF EXISTS jobs_status_check;
ALTER TABLE jobs ADD CONSTRAINT jobs_status_check
    CHECK (status IN ('pending', 'queued', 'running', 'paused', 'completed', 'completed_with_errors', 'cancelled', 'failed'));

ALTER TABLE work_items
    ADD COLUMN IF NOT EXISTS payload        JSONB,           -- e.g. {"prompt": "..."} — mock in this phase, real request later
    ADD COLUMN IF NOT EXISTS tried_workers  JSONB NOT NULL DEFAULT '[]'::jsonb, -- cross-worker retry "tried" set
    ADD COLUMN IF NOT EXISTS last_error     TEXT,
    ADD COLUMN IF NOT EXISTS created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    ADD COLUMN IF NOT EXISTS seq            BIGINT NOT NULL DEFAULT 0; -- submission order within job, for FIFO dispatch

ALTER TABLE work_items DROP CONSTRAINT IF EXISTS work_items_state_check;
ALTER TABLE work_items ADD CONSTRAINT work_items_state_check
    CHECK (state IN ('queued', 'leased', 'running', 'success', 'failed', 'lease_expired', 'cancelled'));

CREATE INDEX IF NOT EXISTS idx_work_items_job_seq ON work_items(job_id, seq);

COMMIT;
