BEGIN;

-- These columns index the immutable, hardware-neutral execution definition.
-- Live availability remains outside this identity and continues to be derived
-- from current target/node state at read time.
ALTER TABLE runtime_profiles
    ADD COLUMN capability_revision TEXT NOT NULL DEFAULT '',
    ADD COLUMN capability_definition_hash TEXT NOT NULL DEFAULT '',
    ADD COLUMN modality TEXT NOT NULL DEFAULT 'OTHER',
    ADD COLUMN execution_locality TEXT NOT NULL DEFAULT 'LB_MANAGED',
    ADD COLUMN workflow TEXT NOT NULL DEFAULT '';

CREATE INDEX runtime_profiles_definition_hash_idx
    ON runtime_profiles(capability_definition_hash)
    WHERE capability_definition_hash <> '';

COMMIT;
