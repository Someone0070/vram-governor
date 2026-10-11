package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"vram-governor/internal/domain"
)

func decodeLLMDisplacementBody(body []byte) (*LLMDisplacementOperation, error) {
	var op LLMDisplacementOperation
	if err := json.Unmarshal(body, &op); err != nil {
		return nil, err
	}
	if err := validateLLMDisplacementIdentity(&op); err != nil {
		return nil, err
	}
	return &op, nil
}

func (p *PostgresWorkloadStore) CreateLLMDisplacementOperation(ctx context.Context, op *LLMDisplacementOperation) (*LLMDisplacementOperation, bool, error) {
	prepared, err := prepareLLMDisplacementCreate(op)
	if err != nil {
		return nil, false, err
	}
	tx, err := p.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return nil, false, err
	}
	defer tx.Rollback()
	if err := lockAcceleratorLeaseFence(ctx, tx, prepared.AcceleratorID); err != nil {
		return nil, false, err
	}
	// Idempotency reads happen only after the shared accelerator fence lock.
	for _, query := range []struct {
		sql  string
		args []any
	}{{`SELECT body FROM llm_displacement_operations WHERE id=$1`, []any{prepared.ID}}, {`SELECT body FROM llm_displacement_operations WHERE owner_id=$1 AND idempotency_key=$2`, []any{prepared.OwnerID, prepared.IdempotencyKey}}} {
		var body []byte
		readErr := tx.QueryRowContext(ctx, query.sql, query.args...).Scan(&body)
		if readErr == nil {
			existing, decodeErr := decodeLLMDisplacementBody(body)
			if decodeErr != nil {
				return nil, false, decodeErr
			}
			if displacementIdentityEqual(existing, prepared) {
				if err := tx.Commit(); err != nil {
					return nil, false, err
				}
				return existing, false, nil
			}
			return nil, false, ErrLLMDisplacementConflict
		}
		if !errors.Is(readErr, sql.ErrNoRows) {
			return nil, false, readErr
		}
	}
	// The partial unique index is the concurrency backstop, while this typed
	// scan also treats malformed completed bodies or indexed/body drift as
	// retained custody before doing new workload/lease validation.
	priorRows, err := tx.QueryContext(ctx, `SELECT phase,revision,body FROM llm_displacement_operations WHERE accelerator_id=$1`, prepared.AcceleratorID)
	if err != nil {
		return nil, false, err
	}
	for priorRows.Next() {
		var phase string
		var revision int64
		var body []byte
		if err := priorRows.Scan(&phase, &revision, &body); err != nil {
			priorRows.Close()
			return nil, false, err
		}
		prior, decodeErr := decodeLLMDisplacementBody(body)
		if decodeErr != nil {
			priorRows.Close()
			return nil, false, ErrLLMDisplacementConflict
		}
		if phase != prior.Phase || revision <= 0 || uint64(revision) != prior.Revision || prior.Phase != "completed" {
			priorRows.Close()
			return nil, false, ErrLLMDisplacementConflict
		}
	}
	if err := priorRows.Err(); err != nil {
		priorRows.Close()
		return nil, false, err
	}
	priorRows.Close()
	victim, err := readDisplacementWorkload(ctx, tx, prepared.VictimWorkloadID)
	if err != nil {
		return nil, false, err
	}
	urgent, err := readDisplacementWorkload(ctx, tx, prepared.UrgentWorkloadID)
	if err != nil {
		return nil, false, err
	}
	var currentLease domain.AcceleratorLease
	if err := tx.QueryRowContext(ctx, `SELECT accelerator_id,workload_id,fencing_token,expires_at FROM accelerator_leases WHERE accelerator_id=$1 FOR UPDATE`, prepared.AcceleratorID).Scan(&currentLease.AcceleratorID, &currentLease.WorkloadID, &currentLease.FencingToken, &currentLease.ExpiresAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, false, ErrLLMDisplacementConflict
		}
		return nil, false, err
	}
	if err := validateLLMDisplacementWorld(prepared, victim, urgent, &currentLease, time.Now().UTC()); err != nil {
		return nil, false, err
	}
	body, err := json.Marshal(prepared)
	if err != nil {
		return nil, false, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO llm_displacement_operations(id,owner_id,idempotency_key,accelerator_id,node_id,victim_target_id,urgent_target_id,phase,revision,body,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`, prepared.ID, prepared.OwnerID, prepared.IdempotencyKey, prepared.AcceleratorID, prepared.NodeID, prepared.VictimBinding.TargetID, prepared.UrgentBinding.TargetID, prepared.Phase, prepared.Revision, body, prepared.CreatedAt, prepared.UpdatedAt)
	if err != nil {
		return nil, false, translateLLMDisplacementSQLError(err)
	}
	if err := tx.Commit(); err != nil {
		return nil, false, translateLLMDisplacementSQLError(err)
	}
	return cloneLLMDisplacementOperation(prepared), true, nil
}

func readDisplacementWorkload(ctx context.Context, tx *sql.Tx, id string) (*domain.Workload, error) {
	var body []byte
	if err := tx.QueryRowContext(ctx, `SELECT body FROM workloads WHERE id=$1 FOR UPDATE`, id).Scan(&body); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrLLMDisplacementConflict
		}
		return nil, err
	}
	var workload domain.Workload
	if err := json.Unmarshal(body, &workload); err != nil {
		return nil, err
	}
	return &workload, nil
}

func translateLLMDisplacementSQLError(err error) error {
	if err == nil {
		return nil
	}
	s := strings.ToLower(err.Error())
	if strings.Contains(s, "llm_displacement") || strings.Contains(s, "duplicate key") || strings.Contains(s, "unique constraint") || strings.Contains(s, "23505") {
		return ErrLLMDisplacementConflict
	}
	return err
}

func (p *PostgresWorkloadStore) GetLLMDisplacementOperation(ctx context.Context, id string) (*LLMDisplacementOperation, error) {
	var body []byte
	if err := p.db.QueryRowContext(ctx, `SELECT body FROM llm_displacement_operations WHERE id=$1`, id).Scan(&body); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return decodeLLMDisplacementBody(body)
}
func (p *PostgresWorkloadStore) GetLLMDisplacementOperationByIdempotency(ctx context.Context, owner, key string) (*LLMDisplacementOperation, error) {
	var body []byte
	if err := p.db.QueryRowContext(ctx, `SELECT body FROM llm_displacement_operations WHERE owner_id=$1 AND idempotency_key=$2`, owner, key).Scan(&body); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return decodeLLMDisplacementBody(body)
}

func (p *PostgresWorkloadStore) UpdateLLMDisplacementOperation(ctx context.Context, op *LLMDisplacementOperation, expected uint64) (*LLMDisplacementOperation, error) {
	if op == nil {
		return nil, errors.New("llm displacement identity is incomplete")
	}
	next := cloneLLMDisplacementOperation(op)
	tx, err := p.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err := lockAcceleratorLeaseFence(ctx, tx, next.AcceleratorID); err != nil {
		return nil, err
	}
	var oldBody []byte
	if err := tx.QueryRowContext(ctx, `SELECT body FROM llm_displacement_operations WHERE id=$1 FOR UPDATE`, next.ID).Scan(&oldBody); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	old, err := decodeLLMDisplacementBody(oldBody)
	if err != nil {
		return nil, err
	}
	if err := validateDisplacementUpdate(old, next, expected); err != nil {
		return nil, err
	}
	next.Revision = old.Revision + 1
	next.CreatedAt = old.CreatedAt
	next.UpdatedAt = time.Now().UTC().Truncate(time.Microsecond)
	body, err := json.Marshal(next)
	if err != nil {
		return nil, err
	}
	result, err := tx.ExecContext(ctx, `UPDATE llm_displacement_operations SET phase=$1,revision=$2,body=$3,updated_at=$4 WHERE id=$5 AND revision=$6`, next.Phase, next.Revision, body, next.UpdatedAt, next.ID, expected)
	if err != nil {
		return nil, translateLLMDisplacementSQLError(err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return nil, err
	}
	if rows != 1 {
		return nil, ErrLLMDisplacementConflict
	}
	if err := tx.Commit(); err != nil {
		return nil, translateLLMDisplacementSQLError(err)
	}
	return cloneLLMDisplacementOperation(next), nil
}

func (p *PostgresWorkloadStore) ListLLMDisplacementOperations(ctx context.Context, owner string) ([]*LLMDisplacementOperation, error) {
	query := `SELECT body FROM llm_displacement_operations`
	args := []any{}
	if owner != "" {
		query += ` WHERE owner_id=$1`
		args = append(args, owner)
	}
	query += ` ORDER BY created_at,id`
	rows, err := p.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]*LLMDisplacementOperation, 0)
	for rows.Next() {
		var body []byte
		if err := rows.Scan(&body); err != nil {
			return nil, err
		}
		op, err := decodeLLMDisplacementBody(body)
		if err != nil {
			return nil, err
		}
		out = append(out, op)
	}
	return out, rows.Err()
}
