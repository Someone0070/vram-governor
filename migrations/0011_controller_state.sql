-- Durable snapshots for controller records whose Go-domain shape evolves
-- faster than the original normalized Phase 1-3 prototype tables. The
-- normalized tables remain available for future analytical projections;
-- these rows are the controller's authoritative restart state.
BEGIN;

CREATE TABLE controller_nodes (
    id TEXT PRIMARY KEY,
    body JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE controller_engines (
    id TEXT PRIMARY KEY,
    node_id TEXT NOT NULL,
    body JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX controller_engines_node ON controller_engines(node_id);

CREATE TABLE controller_performance_profiles (
    node_id TEXT NOT NULL,
    id TEXT NOT NULL,
    body JSONB NOT NULL,
    measured_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (node_id, id)
);
CREATE INDEX controller_profiles_measured ON controller_performance_profiles(measured_at DESC);

CREATE TABLE controller_jobs (
    id TEXT PRIMARY KEY,
    body JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE controller_work_items (
    job_id TEXT NOT NULL,
    item_id TEXT NOT NULL,
    operation_version TEXT NOT NULL,
    body JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (job_id, item_id, operation_version)
);
CREATE INDEX controller_work_items_job ON controller_work_items(job_id);

COMMIT;
