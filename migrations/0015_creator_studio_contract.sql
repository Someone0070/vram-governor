BEGIN;

-- Public runtime identities are append-only. A profile_id + version is the
-- calibration key; application code rejects a conflicting digest.
CREATE TABLE runtime_profiles (
    profile_id TEXT NOT NULL,
    version TEXT NOT NULL,
    digest TEXT NOT NULL,
    adapter TEXT NOT NULL,
    model TEXT NOT NULL DEFAULT '',
    body JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (profile_id, version)
);

CREATE UNIQUE INDEX runtime_profiles_digest_idx
    ON runtime_profiles(profile_id, version, digest);

-- Working sets are advisory and owner-scoped. Release is durable so a
-- controller restart cannot accidentally revive an expired demand forecast.
CREATE TABLE creator_working_sets (
    owner_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    phase_id TEXT NOT NULL,
    body JSONB NOT NULL,
    released_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (owner_id, session_id, phase_id)
);

CREATE INDEX creator_working_sets_active_idx
    ON creator_working_sets(owner_id, session_id, updated_at)
    WHERE released_at IS NULL;

COMMIT;
