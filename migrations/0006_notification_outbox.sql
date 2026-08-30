-- Runtime fields for the durable, signed webhook notification outbox.
BEGIN;

ALTER TABLE notification_outbox
    ADD COLUMN idempotency_key TEXT,
    ADD COLUMN owner_id TEXT,
    ADD COLUMN event_type TEXT,
    ADD COLUMN body JSONB,
    ADD COLUMN created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    ADD COLUMN updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    ADD COLUMN failed_at TIMESTAMPTZ;

UPDATE notification_outbox
SET idempotency_key = id,
    owner_id = COALESCE(owner_id, ''),
    event_type = COALESCE(event_type, 'legacy'),
    body = jsonb_build_object(
        'id', id,
        'idempotency_key', id,
        'workload_id', workload_id,
        'owner_id', COALESCE(owner_id, ''),
        'event_type', COALESCE(event_type, 'legacy'),
        'destination', destination,
        'payload', payload,
        'signature', signature,
        'attempts', attempts,
        'next_attempt_at', next_attempt_at,
        'delivered_at', delivered_at,
        'last_error', last_error,
        'created_at', now(),
        'updated_at', now()
    )
WHERE idempotency_key IS NULL;

ALTER TABLE notification_outbox
    ALTER COLUMN idempotency_key SET NOT NULL,
    ALTER COLUMN owner_id SET NOT NULL,
    ALTER COLUMN event_type SET NOT NULL,
    ALTER COLUMN body SET NOT NULL;

CREATE UNIQUE INDEX notification_outbox_idempotency
    ON notification_outbox(idempotency_key);
CREATE INDEX notification_outbox_owner_time
    ON notification_outbox(owner_id, created_at DESC);

COMMIT;
