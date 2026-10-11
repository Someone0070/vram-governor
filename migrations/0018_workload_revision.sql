-- Durable workload and reservation claim backfill.  State is stored in JSONB,
-- so this migration upgrades legacy rows atomically before any controller CAS
-- can observe a zero revision or an unowned reservation. Revision backfill is
-- intentionally applied to every workload status; terminal history and all
-- unrelated semantic fields remain unchanged, while updated_at records the
-- schema normalization. Reservation identity fields are normalized only for
-- active reserved claims; settled/released reservation bodies are historical
-- evidence and are never rewritten by this migration.
BEGIN;

UPDATE workloads
SET body = jsonb_set(COALESCE(body, '{}'::jsonb), '{revision}', '1'::jsonb, true),
    updated_at = GREATEST(updated_at, now())
WHERE COALESCE(jsonb_typeof(body->'revision'), 'null') <> 'number'
   OR NOT (COALESCE(body->>'revision', '') ~ '^[1-9][0-9]*$');

UPDATE budget_reservations
SET body = jsonb_set(
             jsonb_set(
               jsonb_set(COALESCE(body, '{}'::jsonb), '{revision}',
                 to_jsonb(CASE
                   WHEN jsonb_typeof(body->'revision') = 'number'
                    AND (body->>'revision') ~ '^[1-9][0-9]*$'
                   THEN (body->>'revision')::bigint ELSE 1 END), true),
               '{attempt}',
                 to_jsonb(CASE
                   WHEN jsonb_typeof(body->'attempt') = 'number'
                    AND (body->>'attempt') ~ '^[1-9][0-9]*$'
                   THEN (body->>'attempt')::bigint ELSE 1 END), true),
             '{ownership_token}',
               to_jsonb(CASE
                 WHEN COALESCE(body->>'ownership_token', '') <> ''
                 THEN body->>'ownership_token'
                 ELSE md5(workload_id || ':' || COALESCE(body->>'attempt', '1')) END), true),
    updated_at = GREATEST(updated_at, now())
WHERE status = 'reserved'
  AND (COALESCE(jsonb_typeof(body->'revision'), 'null') <> 'number'
    OR NOT (COALESCE(body->>'revision', '') ~ '^[1-9][0-9]*$')
    OR COALESCE(jsonb_typeof(body->'attempt'), 'null') <> 'number'
    OR NOT (COALESCE(body->>'attempt', '') ~ '^[1-9][0-9]*$')
    OR COALESCE(body->>'ownership_token', '') = '');

-- Publish an unambiguous active reservation claim into its workload. Rows
-- without a matching reservation remain empty and are reconciled normally;
-- no speculative token is invented for them.
UPDATE workloads w
SET body = jsonb_set(
             jsonb_set(w.body, '{budget_reservation_token}', to_jsonb(b.body->>'ownership_token'), true),
             '{budget_reservation_attempt}', to_jsonb((b.body->>'attempt')::bigint), true),
    updated_at = GREATEST(w.updated_at, now())
FROM budget_reservations b
WHERE b.workload_id = w.id
  AND b.status = 'reserved'
  AND w.status IN ('queued', 'waiting', 'pending_approval', 'running')
  AND (COALESCE(w.body->>'budget_reservation_token', '') IS DISTINCT FROM b.body->>'ownership_token'
       OR COALESCE(w.body->>'budget_reservation_attempt', '') IS DISTINCT FROM b.body->>'attempt')
  AND COALESCE(b.body->>'ownership_token', '') <> '';

COMMIT;
