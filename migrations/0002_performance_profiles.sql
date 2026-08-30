-- VRAM Governor — Phase 2 addition: measured PerformanceProfile storage
-- (docs/measurement.md §5). The later controller snapshot migration carries
-- the evolving operational record; this normalized table remains useful for
-- measurement analysis.
--
-- model_artifacts, serving_profiles, and engine_instances already exist in
-- 0001_init.sql — this migration only adds the row Phase 2 introduces: the
-- measured performance profile itself, keyed by the full §1/§20 identity.

BEGIN;

CREATE TABLE performance_profiles (
    id                       TEXT PRIMARY KEY,
    node_id                  TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,

    -- Identity (measurement.md §1) — two rows differing in any of these
    -- are different profiles; the scheduler must never conflate them.
    gpu_model                TEXT NOT NULL,
    vram_total_mb            BIGINT NOT NULL,
    host_cpu                 TEXT,
    host_ram_mb              BIGINT,
    pcie_info                TEXT,
    runtime_name             TEXT NOT NULL,
    runtime_version          TEXT NOT NULL,
    model_artifact_id        TEXT NOT NULL REFERENCES model_artifacts(id),
    quantization             TEXT,
    context_profile          INTEGER NOT NULL,
    shard_count              INTEGER NOT NULL DEFAULT 1,
    concurrency              INTEGER NOT NULL DEFAULT 1,

    -- Measured footprint
    vram_footprint_mb        BIGINT NOT NULL,
    vram_measurement_method  TEXT NOT NULL CHECK (vram_measurement_method IN ('per_pid', 'free_delta')),
    host_ram_footprint_mb    BIGINT,

    -- Measured residency / evict-reload (JSONB: {mean,stdev,p95,min,max,n} per metric)
    evict_reload             JSONB NOT NULL,

    -- Measured KV cache behavior — array of per-context-length rows
    kv                       JSONB,

    -- Measured micro throughput — arrays of {context_tokens|concurrency, tok_per_sec}
    prefill                  JSONB,
    decode                   JSONB,

    -- Detected capabilities (measurement.md §2), verified this run
    capabilities             JSONB NOT NULL,

    measured_at              TIMESTAMPTZ NOT NULL,
    sample_count             INTEGER NOT NULL DEFAULT 0,
    notes                    JSONB, -- honesty disclosures (§6): fallback methods, gaps, warnings

    created_at               TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_performance_profiles_node_id ON performance_profiles(node_id);
CREATE INDEX idx_performance_profiles_identity
    ON performance_profiles(gpu_model, runtime_name, runtime_version, model_artifact_id, quantization, context_profile, shard_count, concurrency);

COMMIT;
