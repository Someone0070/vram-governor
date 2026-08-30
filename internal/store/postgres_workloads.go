package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"vram-governor/internal/domain"
)

type PostgresWorkloadStore struct{ db *sql.DB }

func OpenPostgresWorkloadStore(ctx context.Context, dsn string) (*PostgresWorkloadStore, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, err
	}
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &PostgresWorkloadStore{db: db}, nil
}

func (p *PostgresWorkloadStore) Close() error { return p.db.Close() }

func (p *PostgresWorkloadStore) CreateWorkload(ctx context.Context, w *domain.Workload) (*domain.Workload, bool, error) {
	body, err := json.Marshal(w)
	if err != nil {
		return nil, false, err
	}
	result, err := p.db.ExecContext(ctx, `INSERT INTO workloads(id, owner_id, idempotency_key, status, body, created_at, updated_at) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING`, w.Request.ID, w.Request.OwnerID, w.Request.IdempotencyKey, w.Status, body, w.CreatedAt, w.UpdatedAt)
	if err != nil {
		return nil, false, err
	}
	rows, _ := result.RowsAffected()
	if rows == 1 {
		return cloneWorkload(w), true, nil
	}
	if w.Request.IdempotencyKey != "" {
		return p.getWorkloadByIdempotency(ctx, w.Request.OwnerID, w.Request.IdempotencyKey)
	}
	existing, err := p.GetWorkload(ctx, w.Request.ID)
	return existing, false, err
}

func (p *PostgresWorkloadStore) getWorkloadByIdempotency(ctx context.Context, ownerID, key string) (*domain.Workload, bool, error) {
	var body []byte
	err := p.db.QueryRowContext(ctx, `SELECT body FROM workloads WHERE owner_id=$1 AND idempotency_key=$2`, ownerID, key).Scan(&body)
	if err != nil {
		return nil, false, translateSQLError(err)
	}
	var w domain.Workload
	if err := json.Unmarshal(body, &w); err != nil {
		return nil, false, err
	}
	return &w, false, nil
}

func (p *PostgresWorkloadStore) UpdateWorkload(ctx context.Context, w *domain.Workload) (*domain.Workload, error) {
	body, err := json.Marshal(w)
	if err != nil {
		return nil, err
	}
	result, err := p.db.ExecContext(ctx, `UPDATE workloads SET status=$2, body=$3, updated_at=$4 WHERE id=$1`, w.Request.ID, w.Status, body, w.UpdatedAt)
	if err != nil {
		return nil, err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return nil, ErrNotFound
	}
	return cloneWorkload(w), nil
}

func (p *PostgresWorkloadStore) GetWorkload(ctx context.Context, id string) (*domain.Workload, error) {
	var body []byte
	if err := p.db.QueryRowContext(ctx, `SELECT body FROM workloads WHERE id=$1`, id).Scan(&body); err != nil {
		return nil, translateSQLError(err)
	}
	var w domain.Workload
	if err := json.Unmarshal(body, &w); err != nil {
		return nil, err
	}
	return &w, nil
}

func (p *PostgresWorkloadStore) ListWorkloads(ctx context.Context) ([]*domain.Workload, error) {
	rows, err := p.db.QueryContext(ctx, `SELECT body FROM workloads ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*domain.Workload
	for rows.Next() {
		var body []byte
		if err := rows.Scan(&body); err != nil {
			return nil, err
		}
		var w domain.Workload
		if err := json.Unmarshal(body, &w); err != nil {
			return nil, err
		}
		out = append(out, &w)
	}
	return out, rows.Err()
}

func (p *PostgresWorkloadStore) AcquireAcceleratorLease(ctx context.Context, acceleratorID, workloadID string, ttl time.Duration) (*domain.AcceleratorLease, bool, error) {
	tx, err := p.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return nil, false, err
	}
	defer tx.Rollback()
	var current domain.AcceleratorLease
	err = tx.QueryRowContext(ctx, `SELECT accelerator_id, workload_id, fencing_token, expires_at FROM accelerator_leases WHERE accelerator_id=$1 FOR UPDATE`, acceleratorID).Scan(&current.AcceleratorID, &current.WorkloadID, &current.FencingToken, &current.ExpiresAt)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, false, err
	}
	now := time.Now().UTC()
	if err == nil && current.ExpiresAt.After(now) && current.WorkloadID != workloadID {
		return &current, false, nil
	}
	var token int64
	err = tx.QueryRowContext(ctx, `INSERT INTO accelerator_lease_fences(accelerator_id,last_token) VALUES($1,1) ON CONFLICT(accelerator_id) DO UPDATE SET last_token=accelerator_lease_fences.last_token+1 RETURNING last_token`, acceleratorID).Scan(&token)
	if err != nil {
		return nil, false, err
	}
	lease := &domain.AcceleratorLease{AcceleratorID: acceleratorID, WorkloadID: workloadID, FencingToken: token, ExpiresAt: now.Add(ttl)}
	_, err = tx.ExecContext(ctx, `INSERT INTO accelerator_leases(accelerator_id,workload_id,fencing_token,expires_at) VALUES($1,$2,$3,$4) ON CONFLICT(accelerator_id) DO UPDATE SET workload_id=EXCLUDED.workload_id,fencing_token=EXCLUDED.fencing_token,expires_at=EXCLUDED.expires_at`, acceleratorID, workloadID, token, lease.ExpiresAt)
	if err != nil {
		return nil, false, err
	}
	if err := tx.Commit(); err != nil {
		return nil, false, err
	}
	return lease, true, nil
}

func (p *PostgresWorkloadStore) RenewAcceleratorLease(ctx context.Context, acceleratorID, workloadID string, fencingToken int64, ttl time.Duration) error {
	result, err := p.db.ExecContext(ctx, `UPDATE accelerator_leases SET expires_at=$4 WHERE accelerator_id=$1 AND workload_id=$2 AND fencing_token=$3`, acceleratorID, workloadID, fencingToken, time.Now().UTC().Add(ttl))
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return ErrNotFound
	}
	return nil
}
func (p *PostgresWorkloadStore) ReleaseAcceleratorLease(ctx context.Context, acceleratorID, workloadID string, fencingToken int64) error {
	_, err := p.db.ExecContext(ctx, `DELETE FROM accelerator_leases WHERE accelerator_id=$1 AND workload_id=$2 AND fencing_token=$3`, acceleratorID, workloadID, fencingToken)
	return err
}

func (p *PostgresWorkloadStore) SavePromptMapping(ctx context.Context, m *domain.PromptMapping) error {
	_, err := p.db.ExecContext(ctx, `INSERT INTO prompt_mappings(public_prompt_id,workload_id,target_id,backend_prompt_id,client_id) VALUES($1,$2,NULLIF($3,''),NULLIF($4,''),NULLIF($5,'')) ON CONFLICT(public_prompt_id) DO UPDATE SET workload_id=COALESCE(NULLIF(EXCLUDED.workload_id,''),prompt_mappings.workload_id),target_id=COALESCE(EXCLUDED.target_id,prompt_mappings.target_id),backend_prompt_id=COALESCE(EXCLUDED.backend_prompt_id,prompt_mappings.backend_prompt_id),client_id=COALESCE(EXCLUDED.client_id,prompt_mappings.client_id)`, m.PublicPromptID, m.WorkloadID, m.TargetID, m.BackendPromptID, m.ClientID)
	return err
}
func (p *PostgresWorkloadStore) GetPromptMapping(ctx context.Context, id string) (*domain.PromptMapping, error) {
	var m domain.PromptMapping
	err := p.db.QueryRowContext(ctx, `SELECT public_prompt_id,workload_id,COALESCE(target_id,''),COALESCE(backend_prompt_id,''),COALESCE(client_id,'') FROM prompt_mappings WHERE public_prompt_id=$1`, id).Scan(&m.PublicPromptID, &m.WorkloadID, &m.TargetID, &m.BackendPromptID, &m.ClientID)
	if err != nil {
		return nil, translateSQLError(err)
	}
	return &m, nil
}
func (p *PostgresWorkloadStore) AppendAuditEvent(ctx context.Context, event *domain.AuditEvent) error {
	_, err := p.db.ExecContext(ctx, `INSERT INTO audit_events(id,timestamp,actor_id,owner_id,workload_id,type,severity,payload) VALUES($1,$2,NULLIF($3,''),NULLIF($4,''),NULLIF($5,''),$6,$7,$8)`, event.ID, event.Timestamp, event.ActorID, event.OwnerID, event.WorkloadID, event.Type, event.Severity, event.Payload)
	return err
}
func (p *PostgresWorkloadStore) ListAuditEvents(ctx context.Context, ownerID string, limit int) ([]*domain.AuditEvent, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	query := `SELECT id,timestamp,COALESCE(actor_id,''),COALESCE(owner_id,''),COALESCE(workload_id,''),type,severity,COALESCE(payload,'null'::jsonb) FROM audit_events`
	args := []any{}
	if ownerID != "" {
		query += ` WHERE owner_id=$1 ORDER BY timestamp DESC LIMIT $2`
		args = []any{ownerID, limit}
	} else {
		query += ` ORDER BY timestamp DESC LIMIT $1`
		args = []any{limit}
	}
	rows, err := p.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*domain.AuditEvent
	for rows.Next() {
		var e domain.AuditEvent
		if err := rows.Scan(&e.ID, &e.Timestamp, &e.ActorID, &e.OwnerID, &e.WorkloadID, &e.Type, &e.Severity, &e.Payload); err != nil {
			return nil, err
		}
		out = append(out, &e)
	}
	return out, rows.Err()
}

func (p *PostgresWorkloadStore) UpsertModelResidency(ctx context.Context, residency *domain.ModelResidency) (*domain.ModelResidency, error) {
	body, err := json.Marshal(residency)
	if err != nil {
		return nil, err
	}
	_, err = p.db.ExecContext(ctx, `INSERT INTO model_residencies(target_id,model,body,updated_at) VALUES($1,$2,$3,$4) ON CONFLICT(target_id,model) DO UPDATE SET body=EXCLUDED.body,updated_at=EXCLUDED.updated_at`, residency.TargetID, residency.Model, body, residency.UpdatedAt)
	if err != nil {
		return nil, err
	}
	cp := *residency
	return &cp, nil
}

func (p *PostgresWorkloadStore) GetModelResidency(ctx context.Context, targetID, model string) (*domain.ModelResidency, error) {
	var body []byte
	if err := p.db.QueryRowContext(ctx, `SELECT body FROM model_residencies WHERE target_id=$1 AND model=$2`, targetID, model).Scan(&body); err != nil {
		return nil, translateSQLError(err)
	}
	var residency domain.ModelResidency
	if err := json.Unmarshal(body, &residency); err != nil {
		return nil, err
	}
	return &residency, nil
}

func (p *PostgresWorkloadStore) ListModelResidencies(ctx context.Context) ([]*domain.ModelResidency, error) {
	rows, err := p.db.QueryContext(ctx, `SELECT body FROM model_residencies ORDER BY target_id,model`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*domain.ModelResidency
	for rows.Next() {
		var body []byte
		if err := rows.Scan(&body); err != nil {
			return nil, err
		}
		var residency domain.ModelResidency
		if err := json.Unmarshal(body, &residency); err != nil {
			return nil, err
		}
		out = append(out, &residency)
	}
	return out, rows.Err()
}

func (p *PostgresWorkloadStore) CreateResidencyTransition(ctx context.Context, transition *domain.ResidencyTransition) (*domain.ResidencyTransition, bool, error) {
	body, err := json.Marshal(transition)
	if err != nil {
		return nil, false, err
	}
	result, err := p.db.ExecContext(ctx, `INSERT INTO residency_transitions(id,idempotency_key,target_id,accelerator_id,model,status,body,created_at,updated_at) VALUES($1,$2,$3,NULLIF($4,''),$5,$6,$7,$8,$8) ON CONFLICT DO NOTHING`, transition.ID, transition.IdempotencyKey, transition.TargetID, transition.AcceleratorID, transition.Model, transition.Status, body, transition.CreatedAt)
	if err != nil {
		return nil, false, err
	}
	rows, _ := result.RowsAffected()
	if rows == 1 {
		cp := *transition
		return &cp, true, nil
	}
	var existingBody []byte
	if err := p.db.QueryRowContext(ctx, `SELECT body FROM residency_transitions WHERE idempotency_key=$1`, transition.IdempotencyKey).Scan(&existingBody); err != nil {
		return nil, false, translateSQLError(err)
	}
	var existing domain.ResidencyTransition
	if err := json.Unmarshal(existingBody, &existing); err != nil {
		return nil, false, err
	}
	return &existing, false, nil
}

func (p *PostgresWorkloadStore) UpdateResidencyTransition(ctx context.Context, transition *domain.ResidencyTransition) (*domain.ResidencyTransition, error) {
	body, err := json.Marshal(transition)
	if err != nil {
		return nil, err
	}
	result, err := p.db.ExecContext(ctx, `UPDATE residency_transitions SET status=$2,body=$3,updated_at=$4 WHERE id=$1`, transition.ID, transition.Status, body, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return nil, ErrNotFound
	}
	cp := *transition
	return &cp, nil
}

func (p *PostgresWorkloadStore) ListResidencyTransitions(ctx context.Context, limit int) ([]*domain.ResidencyTransition, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	rows, err := p.db.QueryContext(ctx, `SELECT body FROM residency_transitions ORDER BY created_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*domain.ResidencyTransition
	for rows.Next() {
		var body []byte
		if err := rows.Scan(&body); err != nil {
			return nil, err
		}
		var transition domain.ResidencyTransition
		if err := json.Unmarshal(body, &transition); err != nil {
			return nil, err
		}
		out = append(out, &transition)
	}
	return out, rows.Err()
}

func (p *PostgresWorkloadStore) CreateNotification(ctx context.Context, delivery *domain.NotificationDelivery) (*domain.NotificationDelivery, bool, error) {
	body, err := json.Marshal(delivery)
	if err != nil {
		return nil, false, err
	}
	result, err := p.db.ExecContext(ctx, `INSERT INTO notification_outbox(id,workload_id,destination,payload,signature,attempts,next_attempt_at,last_error,idempotency_key,owner_id,event_type,body,created_at,updated_at) VALUES($1,NULLIF($2,''),$3,$4,NULLIF($5,''),$6,$7,NULLIF($8,''),$9,$10,$11,$12,$13,$14) ON CONFLICT DO NOTHING`, delivery.ID, delivery.WorkloadID, delivery.Destination, delivery.Payload, delivery.Signature, delivery.Attempts, delivery.NextAttemptAt, delivery.LastError, delivery.IdempotencyKey, delivery.OwnerID, delivery.EventType, body, delivery.CreatedAt, delivery.UpdatedAt)
	if err != nil {
		return nil, false, err
	}
	rows, _ := result.RowsAffected()
	if rows == 1 {
		return cloneNotification(delivery), true, nil
	}
	var existingBody []byte
	if err := p.db.QueryRowContext(ctx, `SELECT body FROM notification_outbox WHERE idempotency_key=$1`, delivery.IdempotencyKey).Scan(&existingBody); err != nil {
		return nil, false, translateSQLError(err)
	}
	var existing domain.NotificationDelivery
	if err := json.Unmarshal(existingBody, &existing); err != nil {
		return nil, false, err
	}
	return &existing, false, nil
}

func (p *PostgresWorkloadStore) UpdateNotification(ctx context.Context, delivery *domain.NotificationDelivery) (*domain.NotificationDelivery, error) {
	body, err := json.Marshal(delivery)
	if err != nil {
		return nil, err
	}
	result, err := p.db.ExecContext(ctx, `UPDATE notification_outbox SET signature=NULLIF($2,''),attempts=$3,next_attempt_at=$4,delivered_at=$5,failed_at=$6,last_error=NULLIF($7,''),body=$8,updated_at=$9 WHERE id=$1`, delivery.ID, delivery.Signature, delivery.Attempts, delivery.NextAttemptAt, delivery.DeliveredAt, delivery.FailedAt, delivery.LastError, body, delivery.UpdatedAt)
	if err != nil {
		return nil, err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return nil, ErrNotFound
	}
	return cloneNotification(delivery), nil
}

func (p *PostgresWorkloadStore) ListPendingNotifications(ctx context.Context, now time.Time, limit int) ([]*domain.NotificationDelivery, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	rows, err := p.db.QueryContext(ctx, `SELECT body FROM notification_outbox WHERE delivered_at IS NULL AND failed_at IS NULL AND next_attempt_at <= $1 ORDER BY next_attempt_at LIMIT $2`, now, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanNotifications(rows)
}

func (p *PostgresWorkloadStore) ListNotifications(ctx context.Context, ownerID string, limit int) ([]*domain.NotificationDelivery, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	var rows *sql.Rows
	var err error
	if ownerID == "" {
		rows, err = p.db.QueryContext(ctx, `SELECT body FROM notification_outbox ORDER BY created_at DESC LIMIT $1`, limit)
	} else {
		rows, err = p.db.QueryContext(ctx, `SELECT body FROM notification_outbox WHERE owner_id=$1 ORDER BY created_at DESC LIMIT $2`, ownerID, limit)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanNotifications(rows)
}

func scanNotifications(rows *sql.Rows) ([]*domain.NotificationDelivery, error) {
	var out []*domain.NotificationDelivery
	for rows.Next() {
		var body []byte
		if err := rows.Scan(&body); err != nil {
			return nil, err
		}
		var delivery domain.NotificationDelivery
		if err := json.Unmarshal(body, &delivery); err != nil {
			return nil, err
		}
		out = append(out, &delivery)
	}
	return out, rows.Err()
}

func (p *PostgresWorkloadStore) CreateNodeCommand(ctx context.Context, command *domain.NodeCommand) (*domain.NodeCommand, bool, error) {
	body, err := json.Marshal(command)
	if err != nil {
		return nil, false, err
	}
	result, err := p.db.ExecContext(ctx, `INSERT INTO node_commands(id,node_id,idempotency_key,status,body,created_at,updated_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT DO NOTHING`, command.ID, command.NodeID, command.IdempotencyKey, command.Status, body, command.CreatedAt, command.UpdatedAt, command.ExpiresAt)
	if err != nil {
		return nil, false, err
	}
	rows, _ := result.RowsAffected()
	if rows == 1 {
		return cloneNodeCommand(command), true, nil
	}
	var existingBody []byte
	if err := p.db.QueryRowContext(ctx, `SELECT body FROM node_commands WHERE node_id=$1 AND idempotency_key=$2`, command.NodeID, command.IdempotencyKey).Scan(&existingBody); err != nil {
		return nil, false, translateSQLError(err)
	}
	var existing domain.NodeCommand
	if err := json.Unmarshal(existingBody, &existing); err != nil {
		return nil, false, err
	}
	return &existing, false, nil
}

func (p *PostgresWorkloadStore) UpdateNodeCommand(ctx context.Context, command *domain.NodeCommand) (*domain.NodeCommand, error) {
	body, err := json.Marshal(command)
	if err != nil {
		return nil, err
	}
	result, err := p.db.ExecContext(ctx, `UPDATE node_commands SET status=$2,body=$3,updated_at=$4 WHERE id=$1`, command.ID, command.Status, body, command.UpdatedAt)
	if err != nil {
		return nil, err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return nil, ErrNotFound
	}
	return cloneNodeCommand(command), nil
}

func (p *PostgresWorkloadStore) GetNodeCommand(ctx context.Context, id string) (*domain.NodeCommand, error) {
	var body []byte
	if err := p.db.QueryRowContext(ctx, `SELECT body FROM node_commands WHERE id=$1`, id).Scan(&body); err != nil {
		return nil, translateSQLError(err)
	}
	var command domain.NodeCommand
	if err := json.Unmarshal(body, &command); err != nil {
		return nil, err
	}
	return &command, nil
}

func (p *PostgresWorkloadStore) ListNodeCommands(ctx context.Context, nodeID string, limit int) ([]*domain.NodeCommand, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	query := `SELECT body FROM node_commands`
	var rows *sql.Rows
	var err error
	if nodeID == "" {
		rows, err = p.db.QueryContext(ctx, query+` ORDER BY created_at DESC LIMIT $1`, limit)
	} else {
		rows, err = p.db.QueryContext(ctx, query+` WHERE node_id=$1 ORDER BY created_at DESC LIMIT $2`, nodeID, limit)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*domain.NodeCommand
	for rows.Next() {
		var body []byte
		if err := rows.Scan(&body); err != nil {
			return nil, err
		}
		var command domain.NodeCommand
		if err := json.Unmarshal(body, &command); err != nil {
			return nil, err
		}
		out = append(out, &command)
	}
	return out, rows.Err()
}

func (p *PostgresWorkloadStore) ReserveBudget(ctx context.Context, principalID, workloadID string, amountCents, limitCents int64) (*domain.BudgetReservation, bool, error) {
	tx, err := p.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return nil, false, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, principalID); err != nil {
		return nil, false, err
	}
	var existingBody []byte
	err = tx.QueryRowContext(ctx, `SELECT body FROM budget_reservations WHERE workload_id=$1`, workloadID).Scan(&existingBody)
	if err == nil {
		var existing domain.BudgetReservation
		if err := json.Unmarshal(existingBody, &existing); err != nil {
			return nil, false, err
		}
		if existing.Status != domain.BudgetReleased {
			if err := tx.Commit(); err != nil {
				return nil, false, err
			}
			return &existing, true, nil
		}
	} else if !errors.Is(err, sql.ErrNoRows) {
		return nil, false, err
	}
	var committed int64
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(SUM(CASE WHEN status='reserved' THEN reserved_cents WHEN status='settled' THEN actual_cents ELSE 0 END),0) FROM budget_reservations WHERE principal_id=$1`, principalID).Scan(&committed); err != nil {
		return nil, false, err
	}
	if limitCents > 0 && committed+amountCents > limitCents {
		if err := tx.Commit(); err != nil {
			return nil, false, err
		}
		return nil, false, nil
	}
	now := time.Now().UTC()
	reservation := &domain.BudgetReservation{WorkloadID: workloadID, PrincipalID: principalID, ReservedCents: amountCents, Status: domain.BudgetReserved, CreatedAt: now, UpdatedAt: now}
	body, _ := json.Marshal(reservation)
	_, err = tx.ExecContext(ctx, `INSERT INTO budget_reservations(workload_id,principal_id,reserved_cents,actual_cents,status,body,created_at,updated_at) VALUES($1,$2,$3,0,$4,$5,$6,$6) ON CONFLICT(workload_id) DO UPDATE SET principal_id=EXCLUDED.principal_id,reserved_cents=EXCLUDED.reserved_cents,actual_cents=0,status=EXCLUDED.status,body=EXCLUDED.body,updated_at=EXCLUDED.updated_at`, workloadID, principalID, amountCents, reservation.Status, body, now)
	if err != nil {
		return nil, false, err
	}
	if err := tx.Commit(); err != nil {
		return nil, false, err
	}
	return reservation, true, nil
}

func (p *PostgresWorkloadStore) SettleBudget(ctx context.Context, workloadID string, actualCents int64) (*domain.BudgetReservation, error) {
	var body []byte
	if err := p.db.QueryRowContext(ctx, `SELECT body FROM budget_reservations WHERE workload_id=$1`, workloadID).Scan(&body); err != nil {
		return nil, translateSQLError(err)
	}
	var reservation domain.BudgetReservation
	if err := json.Unmarshal(body, &reservation); err != nil {
		return nil, err
	}
	if actualCents < 0 {
		actualCents = 0
	}
	reservation.ActualCents = actualCents
	reservation.Status = domain.BudgetSettled
	reservation.UpdatedAt = time.Now().UTC()
	body, _ = json.Marshal(&reservation)
	_, err := p.db.ExecContext(ctx, `UPDATE budget_reservations SET actual_cents=$2,status=$3,body=$4,updated_at=$5 WHERE workload_id=$1`, workloadID, actualCents, reservation.Status, body, reservation.UpdatedAt)
	return &reservation, err
}

func (p *PostgresWorkloadStore) ReleaseBudget(ctx context.Context, workloadID string) error {
	var body []byte
	if err := p.db.QueryRowContext(ctx, `SELECT body FROM budget_reservations WHERE workload_id=$1`, workloadID).Scan(&body); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		return err
	}
	var reservation domain.BudgetReservation
	if err := json.Unmarshal(body, &reservation); err != nil {
		return err
	}
	if reservation.Status != domain.BudgetReserved {
		return nil
	}
	reservation.Status = domain.BudgetReleased
	reservation.UpdatedAt = time.Now().UTC()
	body, _ = json.Marshal(&reservation)
	_, err := p.db.ExecContext(ctx, `UPDATE budget_reservations SET status=$2,body=$3,updated_at=$4 WHERE workload_id=$1`, workloadID, reservation.Status, body, reservation.UpdatedAt)
	return err
}

func (p *PostgresWorkloadStore) ListBudgetReservations(ctx context.Context, principalID string) ([]*domain.BudgetReservation, error) {
	query := `SELECT body FROM budget_reservations`
	var rows *sql.Rows
	var err error
	if principalID == "" {
		rows, err = p.db.QueryContext(ctx, query+` ORDER BY created_at DESC`)
	} else {
		rows, err = p.db.QueryContext(ctx, query+` WHERE principal_id=$1 ORDER BY created_at DESC`, principalID)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*domain.BudgetReservation
	for rows.Next() {
		var body []byte
		if err := rows.Scan(&body); err != nil {
			return nil, err
		}
		var reservation domain.BudgetReservation
		if err := json.Unmarshal(body, &reservation); err != nil {
			return nil, err
		}
		out = append(out, &reservation)
	}
	return out, rows.Err()
}

func (p *PostgresWorkloadStore) CreateTransformationApproval(ctx context.Context, approval *domain.TransformationApproval) (*domain.TransformationApproval, bool, error) {
	result, err := p.db.ExecContext(ctx, `INSERT INTO transformation_approvals(workload_id,plan_hash,approver_id,approval_mode,created_at) VALUES($1,$2,$3,$4,$5) ON CONFLICT(workload_id,plan_hash) DO NOTHING`, approval.WorkloadID, approval.PlanHash, approval.ApproverID, approval.ApprovalMode, approval.CreatedAt)
	if err != nil {
		return nil, false, err
	}
	rows, _ := result.RowsAffected()
	if rows == 1 {
		return cloneTransformationApproval(approval), true, nil
	}
	existing, err := p.GetTransformationApproval(ctx, approval.WorkloadID, approval.PlanHash)
	return existing, false, err
}

func (p *PostgresWorkloadStore) GetTransformationApproval(ctx context.Context, workloadID, planHash string) (*domain.TransformationApproval, error) {
	var approval domain.TransformationApproval
	err := p.db.QueryRowContext(ctx, `SELECT workload_id,plan_hash,approver_id,approval_mode,created_at FROM transformation_approvals WHERE workload_id=$1 AND plan_hash=$2`, workloadID, planHash).Scan(&approval.WorkloadID, &approval.PlanHash, &approval.ApproverID, &approval.ApprovalMode, &approval.CreatedAt)
	if err != nil {
		return nil, translateSQLError(err)
	}
	return &approval, nil
}

func (p *PostgresWorkloadStore) ListTransformationApprovals(ctx context.Context, workloadID string) ([]*domain.TransformationApproval, error) {
	query := `SELECT workload_id,plan_hash,approver_id,approval_mode,created_at FROM transformation_approvals`
	args := []any{}
	if workloadID != "" {
		query += ` WHERE workload_id=$1`
		args = append(args, workloadID)
	}
	query += ` ORDER BY created_at DESC`
	rows, err := p.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*domain.TransformationApproval
	for rows.Next() {
		var approval domain.TransformationApproval
		if err := rows.Scan(&approval.WorkloadID, &approval.PlanHash, &approval.ApproverID, &approval.ApprovalMode, &approval.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, &approval)
	}
	return out, rows.Err()
}

func (p *PostgresWorkloadStore) SaveSchedulerLearningSample(ctx context.Context, sample *domain.SchedulerLearningSample) (*domain.SchedulerLearningSample, error) {
	if sample.CreatedAt.IsZero() {
		sample.CreatedAt = time.Now().UTC()
	}
	err := p.db.QueryRowContext(ctx, `INSERT INTO scheduler_learning_samples(accelerator_id,runtime_version,workload_class,fingerprint,predicted,observed,outcome,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id`, sample.AcceleratorID, sample.RuntimeVersion, sample.WorkloadClass, sample.Fingerprint, sample.Predicted, sample.Observed, sample.Outcome, sample.CreatedAt).Scan(&sample.ID)
	if err != nil {
		return nil, err
	}
	return cloneLearningSample(sample), nil
}

func (p *PostgresWorkloadStore) ListSchedulerLearningSamples(ctx context.Context, acceleratorID string, limit int) ([]*domain.SchedulerLearningSample, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	query := `SELECT id,accelerator_id,runtime_version,workload_class,fingerprint,predicted,observed,outcome,created_at FROM scheduler_learning_samples`
	args := []any{}
	if acceleratorID == "" {
		query += ` ORDER BY created_at DESC LIMIT $1`
		args = append(args, limit)
	} else {
		query += ` WHERE accelerator_id=$1 ORDER BY created_at DESC LIMIT $2`
		args = append(args, acceleratorID, limit)
	}
	rows, err := p.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*domain.SchedulerLearningSample
	for rows.Next() {
		var sample domain.SchedulerLearningSample
		if err := rows.Scan(&sample.ID, &sample.AcceleratorID, &sample.RuntimeVersion, &sample.WorkloadClass, &sample.Fingerprint, &sample.Predicted, &sample.Observed, &sample.Outcome, &sample.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, &sample)
	}
	return out, rows.Err()
}

func (p *PostgresWorkloadStore) UpsertInterferenceProfile(ctx context.Context, profile *domain.InterferenceProfile) (*domain.InterferenceProfile, error) {
	body, err := json.Marshal(profile)
	if err != nil {
		return nil, err
	}
	_, err = p.db.ExecContext(ctx, `INSERT INTO scheduler_interference_profiles(profile_key,accelerator_id,runtime_version,body,confidence,version,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(profile_key) DO UPDATE SET accelerator_id=EXCLUDED.accelerator_id,runtime_version=EXCLUDED.runtime_version,body=EXCLUDED.body,confidence=EXCLUDED.confidence,version=EXCLUDED.version,updated_at=EXCLUDED.updated_at`, profile.Key, profile.AcceleratorID, profile.RuntimeVersion, body, profile.Confidence, profile.Version, profile.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return cloneInterferenceProfile(profile), nil
}

func (p *PostgresWorkloadStore) GetInterferenceProfile(ctx context.Context, key string) (*domain.InterferenceProfile, error) {
	var body []byte
	if err := p.db.QueryRowContext(ctx, `SELECT body FROM scheduler_interference_profiles WHERE profile_key=$1`, key).Scan(&body); err != nil {
		return nil, translateSQLError(err)
	}
	var profile domain.InterferenceProfile
	if err := json.Unmarshal(body, &profile); err != nil {
		return nil, err
	}
	return &profile, nil
}

func (p *PostgresWorkloadStore) ListInterferenceProfiles(ctx context.Context) ([]*domain.InterferenceProfile, error) {
	rows, err := p.db.QueryContext(ctx, `SELECT body FROM scheduler_interference_profiles ORDER BY profile_key`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []*domain.InterferenceProfile
	for rows.Next() {
		var body []byte
		if err := rows.Scan(&body); err != nil {
			return nil, err
		}
		var profile domain.InterferenceProfile
		if err := json.Unmarshal(body, &profile); err != nil {
			return nil, err
		}
		result = append(result, &profile)
	}
	return result, rows.Err()
}

func (p *PostgresWorkloadStore) CreateTransitionPlan(ctx context.Context, plan *domain.TransitionPlan) (*domain.TransitionPlan, error) {
	body, err := json.Marshal(plan)
	if err != nil {
		return nil, err
	}
	_, err = p.db.ExecContext(ctx, `INSERT INTO workload_transition_plans(id,workload_id,victim_workload_id,status,body,created_at,updated_at) VALUES($1,$2,NULLIF($3,''),$4,$5,$6,$7)`, plan.ID, plan.WorkloadID, plan.VictimWorkloadID, plan.Status, body, plan.CreatedAt, plan.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return cloneTransitionPlan(plan), nil
}

func (p *PostgresWorkloadStore) UpdateTransitionPlan(ctx context.Context, plan *domain.TransitionPlan) (*domain.TransitionPlan, error) {
	body, err := json.Marshal(plan)
	if err != nil {
		return nil, err
	}
	result, err := p.db.ExecContext(ctx, `UPDATE workload_transition_plans SET status=$2,body=$3,updated_at=$4 WHERE id=$1`, plan.ID, plan.Status, body, plan.UpdatedAt)
	if err != nil {
		return nil, err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return nil, ErrNotFound
	}
	return cloneTransitionPlan(plan), nil
}

func (p *PostgresWorkloadStore) ListTransitionPlans(ctx context.Context, workloadID string, limit int) ([]*domain.TransitionPlan, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	query := `SELECT body FROM workload_transition_plans`
	var args []any
	if workloadID == "" {
		query += ` ORDER BY created_at DESC LIMIT $1`
		args = append(args, limit)
	} else {
		query += ` WHERE workload_id=$1 OR victim_workload_id=$1 ORDER BY created_at DESC LIMIT $2`
		args = append(args, workloadID, limit)
	}
	rows, err := p.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []*domain.TransitionPlan
	for rows.Next() {
		var body []byte
		if err := rows.Scan(&body); err != nil {
			return nil, err
		}
		var plan domain.TransitionPlan
		if err := json.Unmarshal(body, &plan); err != nil {
			return nil, err
		}
		result = append(result, &plan)
	}
	return result, rows.Err()
}

func (p *PostgresWorkloadStore) UpsertTargetPolicyOverride(ctx context.Context, policy *domain.TargetPolicyOverride) (*domain.TargetPolicyOverride, error) {
	body, err := json.Marshal(policy)
	if err != nil {
		return nil, err
	}
	_, err = p.db.ExecContext(ctx, `INSERT INTO target_policy_overrides(target_id,body,updated_at) VALUES($1,$2,$3) ON CONFLICT(target_id) DO UPDATE SET body=EXCLUDED.body,updated_at=EXCLUDED.updated_at`, policy.TargetID, body, policy.UpdatedAt)
	if err != nil {
		return nil, err
	}
	copy := *policy
	return &copy, nil
}

func (p *PostgresWorkloadStore) ListTargetPolicyOverrides(ctx context.Context) ([]*domain.TargetPolicyOverride, error) {
	rows, err := p.db.QueryContext(ctx, `SELECT body FROM target_policy_overrides ORDER BY target_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []*domain.TargetPolicyOverride
	for rows.Next() {
		var body []byte
		if err := rows.Scan(&body); err != nil {
			return nil, err
		}
		var policy domain.TargetPolicyOverride
		if err := json.Unmarshal(body, &policy); err != nil {
			return nil, err
		}
		result = append(result, &policy)
	}
	return result, rows.Err()
}

func translateSQLError(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	return fmt.Errorf("postgres workload store: %w", err)
}

func (p *PostgresWorkloadStore) CreateIncident(ctx context.Context, incident *domain.Incident) (*domain.Incident, error) {
	evidence, _ := json.Marshal(incident.EvidenceRefs)
	_, err := p.db.ExecContext(ctx, `INSERT INTO incidents(id,owner_id,severity,confidence,summary,evidence_refs,status,proposal,actual_provider,actual_model,requested_model_tier,evidence_classification,evidence_sanitized,egress_policy,analysis_workload_id,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,NULLIF($8::text,'')::jsonb,NULLIF($9,''),NULLIF($10,''),NULLIF($11,''),NULLIF($12,''),$13,$14,NULLIF($15,''),$16,$17)`, incident.ID, incident.OwnerID, incident.Severity, incident.Confidence, incident.Summary, evidence, incident.Status, string(incident.Proposal), incident.ActualProvider, incident.ActualModel, incident.RequestedModelTier, incident.EvidenceClassification, incident.EvidenceSanitized, incident.Egress, incident.AnalysisWorkloadID, incident.CreatedAt, incident.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return cloneIncident(incident), nil
}

func (p *PostgresWorkloadStore) UpdateIncident(ctx context.Context, incident *domain.Incident) (*domain.Incident, error) {
	evidence, _ := json.Marshal(incident.EvidenceRefs)
	result, err := p.db.ExecContext(ctx, `UPDATE incidents SET severity=$2,confidence=$3,summary=$4,evidence_refs=$5,status=$6,proposal=NULLIF($7::text,'')::jsonb,actual_provider=NULLIF($8,''),actual_model=NULLIF($9,''),requested_model_tier=NULLIF($10,''),evidence_classification=NULLIF($11,''),evidence_sanitized=$12,egress_policy=$13,analysis_workload_id=NULLIF($14,''),updated_at=$15 WHERE id=$1`, incident.ID, incident.Severity, incident.Confidence, incident.Summary, evidence, incident.Status, string(incident.Proposal), incident.ActualProvider, incident.ActualModel, incident.RequestedModelTier, incident.EvidenceClassification, incident.EvidenceSanitized, incident.Egress, incident.AnalysisWorkloadID, incident.UpdatedAt)
	if err != nil {
		return nil, err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return nil, ErrNotFound
	}
	return cloneIncident(incident), nil
}

func scanIncident(scanner interface{ Scan(...any) error }) (*domain.Incident, error) {
	var incident domain.Incident
	var evidence, proposal []byte
	err := scanner.Scan(&incident.ID, &incident.OwnerID, &incident.Severity, &incident.Confidence, &incident.Summary, &evidence, &incident.Status, &proposal, &incident.ActualProvider, &incident.ActualModel, &incident.RequestedModelTier, &incident.EvidenceClassification, &incident.EvidenceSanitized, &incident.Egress, &incident.AnalysisWorkloadID, &incident.CreatedAt, &incident.UpdatedAt)
	if err != nil {
		return nil, translateSQLError(err)
	}
	if err := json.Unmarshal(evidence, &incident.EvidenceRefs); err != nil {
		return nil, err
	}
	incident.Proposal = append(json.RawMessage(nil), proposal...)
	return &incident, nil
}

func (p *PostgresWorkloadStore) GetIncident(ctx context.Context, id string) (*domain.Incident, error) {
	return scanIncident(p.db.QueryRowContext(ctx, `SELECT id,owner_id,severity,confidence,summary,evidence_refs,status,proposal,COALESCE(actual_provider,''),COALESCE(actual_model,''),COALESCE(requested_model_tier,''),COALESCE(evidence_classification,''),evidence_sanitized,egress_policy,COALESCE(analysis_workload_id,''),created_at,updated_at FROM incidents WHERE id=$1`, id))
}

func (p *PostgresWorkloadStore) ListIncidents(ctx context.Context, ownerID string) ([]*domain.Incident, error) {
	query := `SELECT id,owner_id,severity,confidence,summary,evidence_refs,status,proposal,COALESCE(actual_provider,''),COALESCE(actual_model,''),COALESCE(requested_model_tier,''),COALESCE(evidence_classification,''),evidence_sanitized,egress_policy,COALESCE(analysis_workload_id,''),created_at,updated_at FROM incidents`
	var rows *sql.Rows
	var err error
	if ownerID == "" {
		rows, err = p.db.QueryContext(ctx, query+` ORDER BY created_at DESC`)
	} else {
		rows, err = p.db.QueryContext(ctx, query+` WHERE owner_id=$1 ORDER BY created_at DESC`, ownerID)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*domain.Incident
	for rows.Next() {
		incident, err := scanIncident(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, incident)
	}
	return out, rows.Err()
}
