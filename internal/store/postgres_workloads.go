package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	_ "github.com/jackc/pgx/v5/stdlib"

	"vram-governor/internal/domain"
)

type modelCapacityRow interface {
	Scan(...any) error
}

type modelCapacityTx interface {
	QueryRowContext(context.Context, string, ...any) modelCapacityRow
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	Commit() error
	Rollback() error
}

type sqlModelCapacityTx struct{ tx *sql.Tx }

func (tx sqlModelCapacityTx) QueryRowContext(ctx context.Context, query string, args ...any) modelCapacityRow {
	return tx.tx.QueryRowContext(ctx, query, args...)
}
func (tx sqlModelCapacityTx) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	return tx.tx.ExecContext(ctx, query, args...)
}
func (tx sqlModelCapacityTx) Commit() error   { return tx.tx.Commit() }
func (tx sqlModelCapacityTx) Rollback() error { return tx.tx.Rollback() }

type modelCapacityBeginner func(context.Context) (modelCapacityTx, error)

type PostgresWorkloadStore struct {
	db                   *sql.DB
	modelCapacityBeginTx modelCapacityBeginner
}

func translateLLMCheckpointSQLError(err error) error {
	if err == nil {
		return nil
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return ErrLLMCheckpointConflict
	}
	message := strings.ToLower(err.Error())
	if strings.Contains(message, "duplicate key") || strings.Contains(message, "unique constraint") || strings.Contains(message, "llm_checkpoint_operations_live_slot_idx") || strings.Contains(message, "owner_id,idempotency_key") || strings.Contains(message, "llm_checkpoint_operations_pkey") {
		return ErrLLMCheckpointConflict
	}
	return err
}

func (p *PostgresWorkloadStore) CreateLLMCheckpointOperation(ctx context.Context, op *LLMCheckpointOperation) (*LLMCheckpointOperation, bool, error) {
	prepared, err := prepareLLMCheckpointCreate(op)
	if err != nil {
		return nil, false, err
	}
	// Resolve the primary-key path explicitly. A reused command ID must never
	// be reported as a driver error or mapped to a different idempotency key.
	if existing, getErr := p.GetLLMCheckpointOperation(ctx, prepared.ID); getErr == nil {
		if sameLLMCheckpointIdentity(existing, prepared) {
			return existing, false, nil
		}
		return nil, false, ErrLLMCheckpointConflict
	} else if !errors.Is(getErr, ErrNotFound) {
		return nil, false, getErr
	}
	body, err := json.Marshal(prepared)
	if err != nil {
		return nil, false, err
	}
	result, err := p.db.ExecContext(ctx, `INSERT INTO llm_checkpoint_operations(id, owner_id, idempotency_key, phase, phase_ordinal, node_id, accelerator_id, target_id, slot_id, body, created_at, updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) ON CONFLICT DO NOTHING`, prepared.ID, prepared.OwnerID, prepared.IdempotencyKey, prepared.Phase, prepared.PhaseOrdinal, prepared.NodeID, prepared.AcceleratorID, prepared.TargetID, prepared.SlotID, body, prepared.CreatedAt, prepared.UpdatedAt)
	if err != nil {
		return nil, false, translateLLMCheckpointSQLError(err)
	}
	rows, rowsErr := result.RowsAffected()
	if rowsErr != nil {
		return nil, false, rowsErr
	}
	if rows == 0 {
		// A concurrent replay may have won on either the primary key or the
		// idempotency key. Resolve both before reporting a conflict so identical
		// retries remain idempotent even when their preflight reads raced.
		if existing, getErr := p.GetLLMCheckpointOperation(ctx, prepared.ID); getErr == nil {
			if sameLLMCheckpointIdentity(existing, prepared) {
				return existing, false, nil
			}
			return nil, false, ErrLLMCheckpointConflict
		} else if !errors.Is(getErr, ErrNotFound) {
			return nil, false, getErr
		}
		existing, getErr := p.GetLLMCheckpointOperationByIdempotency(ctx, prepared.OwnerID, prepared.IdempotencyKey)
		if getErr == nil {
			if sameLLMCheckpointIdentity(existing, prepared) {
				return existing, false, nil
			}
			return nil, false, ErrLLMCheckpointConflict
		}
		if !errors.Is(getErr, ErrNotFound) {
			return nil, false, getErr
		}
		// The remaining possible conflict is the live-slot unique index.
		return nil, false, ErrLLMCheckpointConflict
	}
	return cloneLLMCheckpointOperation(prepared), true, nil
}
func (p *PostgresWorkloadStore) GetLLMCheckpointOperation(ctx context.Context, id string) (*LLMCheckpointOperation, error) {
	var body []byte
	if err := p.db.QueryRowContext(ctx, `SELECT body FROM llm_checkpoint_operations WHERE id=$1`, id).Scan(&body); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	var op LLMCheckpointOperation
	if err := json.Unmarshal(body, &op); err != nil {
		return nil, err
	}
	if err := validateLLMCheckpointRequiredIdentity(&op); err != nil {
		return nil, err
	}
	return &op, nil
}
func (p *PostgresWorkloadStore) GetLLMCheckpointOperationByIdempotency(ctx context.Context, owner, key string) (*LLMCheckpointOperation, error) {
	var body []byte
	if err := p.db.QueryRowContext(ctx, `SELECT body FROM llm_checkpoint_operations WHERE owner_id=$1 AND idempotency_key=$2`, owner, key).Scan(&body); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	var op LLMCheckpointOperation
	if err := json.Unmarshal(body, &op); err != nil {
		return nil, err
	}
	if err := validateLLMCheckpointRequiredIdentity(&op); err != nil {
		return nil, err
	}
	return &op, nil
}
func (p *PostgresWorkloadStore) UpdateLLMCheckpointOperation(ctx context.Context, op *LLMCheckpointOperation, expected uint64) (*LLMCheckpointOperation, error) {
	if op != nil {
		op = cloneLLMCheckpointOperation(op)
		if op.ConversationID == "" {
			seed := sha256.Sum256([]byte(op.OwnerID + "|" + op.WorkloadID + "|" + fmt.Sprint(op.Generation) + "|" + fmt.Sprint(op.Fence) + "|" + op.ID))
			op.ConversationID = "conv-" + hex.EncodeToString(seed[:12])
		}
	}
	if err := validateLLMCheckpointRequiredIdentity(op); err != nil {
		return nil, err
	}
	if expected == 0 {
		return nil, ErrLLMCheckpointConflict
	}
	current, err := p.GetLLMCheckpointOperation(ctx, op.ID)
	if err != nil {
		return nil, err
	}
	if current.Revision != expected || !llmCheckpointImmutableIdentityEqual(current, op) || !llmCheckpointTransitionAllowedFor(current, op) {
		return nil, ErrLLMCheckpointConflict
	}
	serialized := *cloneLLMCheckpointOperation(op)
	serialized.CreatedAt = current.CreatedAt
	serialized.Revision = current.Revision + 1
	serialized.UpdatedAt = time.Now().UTC().Truncate(time.Microsecond)
	body, err := json.Marshal(&serialized)
	if err != nil {
		return nil, err
	}
	result, err := p.db.ExecContext(ctx, `UPDATE llm_checkpoint_operations SET phase=$1, phase_ordinal=$2, node_id=$3, accelerator_id=$4, target_id=$5, slot_id=$6, body=$7, updated_at=$8 WHERE id=$9 AND ((body->>'revision')::bigint)=$10`, serialized.Phase, serialized.PhaseOrdinal, serialized.NodeID, serialized.AcceleratorID, serialized.TargetID, serialized.SlotID, body, serialized.UpdatedAt, serialized.ID, expected)
	if err != nil {
		return nil, translateLLMCheckpointSQLError(err)
	}
	rows, rowsErr := result.RowsAffected()
	if rowsErr != nil {
		return nil, rowsErr
	}
	if rows != 1 {
		return nil, ErrLLMCheckpointConflict
	}
	return cloneLLMCheckpointOperation(&serialized), nil
}
func (p *PostgresWorkloadStore) ListLLMCheckpointOperations(ctx context.Context, owner string) ([]*LLMCheckpointOperation, error) {
	query := `SELECT body FROM llm_checkpoint_operations`
	args := []any{}
	if owner != "" {
		query += ` WHERE owner_id=$1`
		args = append(args, owner)
	}
	query += ` ORDER BY updated_at, id`
	rows, err := p.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]*LLMCheckpointOperation, 0)
	for rows.Next() {
		var body []byte
		if err := rows.Scan(&body); err != nil {
			return nil, err
		}
		var op LLMCheckpointOperation
		if err := json.Unmarshal(body, &op); err != nil {
			return nil, err
		}
		if err := validateLLMCheckpointRequiredIdentity(&op); err != nil {
			return nil, err
		}
		out = append(out, &op)
	}
	return out, rows.Err()
}

func OpenPostgresWorkloadStore(ctx context.Context, dsn string) (*PostgresWorkloadStore, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, err
	}
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &PostgresWorkloadStore{db: db, modelCapacityBeginTx: func(ctx context.Context) (modelCapacityTx, error) {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return nil, err
		}
		return sqlModelCapacityTx{tx: tx}, nil
	}}, nil
}

func (p *PostgresWorkloadStore) Close() error { return p.db.Close() }

func (p *PostgresWorkloadStore) CreateWorkload(ctx context.Context, w *domain.Workload) (*domain.Workload, bool, error) {
	w = cloneWorkload(w)
	w.Revision = 1
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
	// Preserve the long-standing unconditional update API for non-concurrent
	// administrative callers, but keep its durable revision monotonic. The
	// controller's observer/cancellation paths use CompareAndSwapWorkload.
	if w == nil || w.Revision == 0 {
		return nil, ErrWorkloadConflict
	}
	current, err := p.GetWorkload(ctx, w.Request.ID)
	if err != nil {
		return nil, err
	}
	if current.Revision != w.Revision {
		return nil, ErrWorkloadConflict
	}
	if current.CancellationOwner != w.CancellationOwner {
		return nil, ErrWorkloadConflict
	}
	updated := cloneWorkload(w)
	updated.Revision = current.Revision + 1
	body, err := json.Marshal(updated)
	if err != nil {
		return nil, err
	}
	// Keep the legacy method safe for callers that have not migrated to the
	// explicit CAS API: the revision/owner predicate makes the write atomic
	// with respect to any concurrent observer or cancellation mutation. The
	// preceding read is only used to derive the expected predicate; a stale
	// writer cannot overwrite a newer body.
	result, err := p.db.ExecContext(ctx, `UPDATE workloads SET status=$2, body=$3, updated_at=$4 WHERE id=$1 AND COALESCE((body->>'revision')::bigint,0)=$5 AND COALESCE(body->>'cancellation_owner','')=$6`, updated.Request.ID, updated.Status, body, updated.UpdatedAt, int64(current.Revision), current.CancellationOwner)
	if err != nil {
		return nil, err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return nil, ErrWorkloadConflict
	}
	return cloneWorkload(updated), nil
}

func (p *PostgresWorkloadStore) CompareAndSwapWorkload(ctx context.Context, w *domain.Workload, expectedRevision uint64, expectedStatus domain.WorkloadStatus, expectedCancellationOwner string) (*domain.Workload, error) {
	if workloadRequiresSettlementIntent(w) {
		current, err := p.GetWorkload(ctx, w.Request.ID)
		if err != nil {
			return nil, err
		}
		if !current.BudgetSettlementPending || current.BudgetReservationToken != w.BudgetReservationToken || current.BudgetSettlementAttempt != w.BudgetReservationAttempt {
			return nil, ErrWorkloadConflict
		}
	}
	updated := cloneWorkload(w)
	updated.Revision = expectedRevision + 1
	body, err := json.Marshal(updated)
	if err != nil {
		return nil, err
	}
	result, err := p.db.ExecContext(ctx, `UPDATE workloads SET status=$2, body=$3, updated_at=$4 WHERE id=$1 AND COALESCE((body->>'revision')::bigint,0)=$5 AND status=$6 AND COALESCE(body->>'cancellation_owner','')=$7`, updated.Request.ID, updated.Status, body, updated.UpdatedAt, int64(expectedRevision), expectedStatus, expectedCancellationOwner)
	if err != nil {
		return nil, err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return nil, ErrWorkloadConflict
	}
	return cloneWorkload(updated), nil
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

func (p *PostgresWorkloadStore) UpsertRuntimeProfile(ctx context.Context, profile *domain.RuntimeProfile) (*domain.RuntimeProfile, bool, error) {
	body, err := json.Marshal(profile)
	if err != nil {
		return nil, false, err
	}
	result, err := p.db.ExecContext(ctx, `INSERT INTO runtime_profiles(profile_id, version, digest, adapter, model, workflow, capability_revision, capability_definition_hash, modality, execution_locality, body, created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) ON CONFLICT DO NOTHING`, profile.ProfileID, profile.Version, profile.Digest, profile.Adapter, profile.Model, profile.Workflow, profile.CapabilityRevision, profile.CapabilityDefinitionHash, profile.Modality, profile.ExecutionLocality, body, profile.CreatedAt)
	if err != nil {
		return nil, false, err
	}
	rows, _ := result.RowsAffected()
	if rows == 1 {
		return cloneRuntimeProfile(profile), true, nil
	}
	var digest, adapter, model, workflow string
	var storedBody []byte
	if err := p.db.QueryRowContext(ctx, `SELECT digest, adapter, model, workflow, body FROM runtime_profiles WHERE profile_id=$1 AND version=$2`, profile.ProfileID, profile.Version).Scan(&digest, &adapter, &model, &workflow, &storedBody); err != nil {
		return nil, false, translateSQLError(err)
	}
	var stored domain.RuntimeProfile
	if err := json.Unmarshal(storedBody, &stored); err != nil {
		return nil, false, err
	}
	stored.Adapter, stored.Model, stored.Workflow = adapter, model, workflow
	if legacyRuntimeProfileMeaning(&stored, profile) {
		if _, err := p.db.ExecContext(ctx, `UPDATE runtime_profiles SET workflow=$3, capability_revision=$4, capability_definition_hash=$5, modality=$6, execution_locality=$7, body=$8 WHERE profile_id=$1 AND version=$2 AND capability_definition_hash=''`, profile.ProfileID, profile.Version, profile.Workflow, profile.CapabilityRevision, profile.CapabilityDefinitionHash, profile.Modality, profile.ExecutionLocality, body); err != nil {
			return nil, false, err
		}
		return cloneRuntimeProfile(profile), false, nil
	}
	if digest != profile.Digest || !sameRuntimeProfileMeaning(&stored, profile) {
		return nil, false, fmt.Errorf("runtime profile %s@%s already exists with different immutable semantics", profile.ProfileID, profile.Version)
	}
	return &stored, false, nil
}

func (p *PostgresWorkloadStore) ListRuntimeProfiles(ctx context.Context) ([]*domain.RuntimeProfile, error) {
	rows, err := p.db.QueryContext(ctx, `SELECT adapter, model, workflow, body FROM runtime_profiles ORDER BY profile_id, version`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var profiles []*domain.RuntimeProfile
	for rows.Next() {
		var adapter, model, workflow string
		var body []byte
		if err := rows.Scan(&adapter, &model, &workflow, &body); err != nil {
			return nil, err
		}
		var profile domain.RuntimeProfile
		if err := json.Unmarshal(body, &profile); err != nil {
			return nil, err
		}
		profile.Adapter, profile.Model, profile.Workflow = adapter, model, workflow
		profiles = append(profiles, &profile)
	}
	return profiles, rows.Err()
}

func (p *PostgresWorkloadStore) UpsertWorkingSet(ctx context.Context, workingSet *domain.WorkingSet) (*domain.WorkingSet, error) {
	var existingCreated time.Time
	err := p.db.QueryRowContext(ctx, `SELECT created_at FROM creator_working_sets WHERE owner_id=$1 AND session_id=$2 AND phase_id=$3`, workingSet.OwnerID, workingSet.SessionID, workingSet.PhaseID).Scan(&existingCreated)
	if err == nil {
		workingSet.CreatedAt = existingCreated
	} else if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	body, err := json.Marshal(workingSet)
	if err != nil {
		return nil, err
	}
	_, err = p.db.ExecContext(ctx, `INSERT INTO creator_working_sets(owner_id, session_id, phase_id, body, released_at, created_at, updated_at) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(owner_id, session_id, phase_id) DO UPDATE SET body=EXCLUDED.body, released_at=EXCLUDED.released_at, updated_at=EXCLUDED.updated_at`, workingSet.OwnerID, workingSet.SessionID, workingSet.PhaseID, body, workingSet.ReleasedAt, workingSet.CreatedAt, workingSet.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return cloneWorkingSet(workingSet), nil
}

func (p *PostgresWorkloadStore) ReleaseWorkingSet(ctx context.Context, ownerID, sessionID, phaseID string, releasedAt time.Time) (*domain.WorkingSet, error) {
	var body []byte
	if err := p.db.QueryRowContext(ctx, `SELECT body FROM creator_working_sets WHERE owner_id=$1 AND session_id=$2 AND phase_id=$3`, ownerID, sessionID, phaseID).Scan(&body); err != nil {
		return nil, translateSQLError(err)
	}
	var workingSet domain.WorkingSet
	if err := json.Unmarshal(body, &workingSet); err != nil {
		return nil, err
	}
	workingSet.ReleasedAt = &releasedAt
	workingSet.UpdatedAt = releasedAt
	body, err := json.Marshal(&workingSet)
	if err != nil {
		return nil, err
	}
	if _, err := p.db.ExecContext(ctx, `UPDATE creator_working_sets SET body=$4, released_at=$5, updated_at=$5 WHERE owner_id=$1 AND session_id=$2 AND phase_id=$3`, ownerID, sessionID, phaseID, body, releasedAt); err != nil {
		return nil, err
	}
	return &workingSet, nil
}

func (p *PostgresWorkloadStore) ListWorkingSets(ctx context.Context, ownerID, sessionID string, includeReleased bool) ([]*domain.WorkingSet, error) {
	rows, err := p.db.QueryContext(ctx, `SELECT body FROM creator_working_sets WHERE ($1='' OR owner_id=$1) AND ($2='' OR session_id=$2) AND ($3 OR released_at IS NULL) ORDER BY session_id, phase_id`, ownerID, sessionID, includeReleased)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var sets []*domain.WorkingSet
	for rows.Next() {
		var body []byte
		if err := rows.Scan(&body); err != nil {
			return nil, err
		}
		var workingSet domain.WorkingSet
		if err := json.Unmarshal(body, &workingSet); err != nil {
			return nil, err
		}
		sets = append(sets, &workingSet)
	}
	return sets, rows.Err()
}

func (p *PostgresWorkloadStore) AcquireAcceleratorLease(ctx context.Context, acceleratorID, workloadID string, ttl time.Duration) (*domain.AcceleratorLease, bool, error) {
	return p.acquireAcceleratorLease(ctx, acceleratorID, workloadID, "", ttl)
}

// AcquireAcceleratorLeaseForCheckpointRecovery is the explicit, durable
// compensation reacquire seam.  Ordinary callers cannot bypass an unresolved
// checkpoint cleanup row, even when they request the same workload.
func (p *PostgresWorkloadStore) AcquireAcceleratorLeaseForCheckpointRecovery(ctx context.Context, acceleratorID, workloadID, operationID string, ttl time.Duration) (*domain.AcceleratorLease, bool, error) {
	return p.acquireAcceleratorLease(ctx, acceleratorID, workloadID, operationID, ttl)
}

func (p *PostgresWorkloadStore) acquireAcceleratorLease(ctx context.Context, acceleratorID, workloadID, recoveryOperationID string, ttl time.Duration) (*domain.AcceleratorLease, bool, error) {
	tx, err := p.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return nil, false, err
	}
	defer tx.Rollback()
	// Every actor that can create displacement custody or acquire this lease
	// takes this same row lock first. Insert the sentinel even when the lease is
	// absent, then lock it before inspecting any lease or journal state.
	if err := lockAcceleratorLeaseFence(ctx, tx, acceleratorID); err != nil {
		return nil, false, err
	}
	var current domain.AcceleratorLease
	err = tx.QueryRowContext(ctx, `SELECT accelerator_id, workload_id, fencing_token, expires_at FROM accelerator_leases WHERE accelerator_id=$1 FOR UPDATE`, acceleratorID).Scan(&current.AcceleratorID, &current.WorkloadID, &current.FencingToken, &current.ExpiresAt)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, false, err
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	// A durable resumed-generation cleanup intent fences this accelerator even
	// after the lease TTL has elapsed. Scan every unresolved row: choosing only
	// the newest row can let an older live generation overlap a new owner.
	var recoveryOp *LLMCheckpointOperation
	cleanupRows, cleanupErr := tx.QueryContext(ctx, `SELECT body FROM llm_checkpoint_operations WHERE COALESCE(body->>'cleanup_accelerator_id','')=$1 AND COALESCE(body->>'cleanup_state','') IN ('armed','owned','pending','failed','stopped')`, acceleratorID)
	if cleanupErr != nil {
		return nil, false, cleanupErr
	}
	var cleanupOps []*LLMCheckpointOperation
	for cleanupRows.Next() {
		var cleanupBody []byte
		if err := cleanupRows.Scan(&cleanupBody); err != nil {
			cleanupRows.Close()
			return nil, false, err
		}
		var cleanupOp LLMCheckpointOperation
		if err := json.Unmarshal(cleanupBody, &cleanupOp); err != nil {
			cleanupRows.Close()
			return nil, false, err
		}
		cleanupOps = append(cleanupOps, &cleanupOp)
	}
	if err := cleanupRows.Err(); err != nil {
		cleanupRows.Close()
		return nil, false, err
	}
	cleanupRows.Close()
	// Read typed displacement rows separately from checkpoint cleanup records.
	// Scan every phase, including completed rows, and trust completion only when
	// indexed phase/revision and the strictly validated immutable body agree.
	displacementRows, displacementErr := tx.QueryContext(ctx, `SELECT phase,revision,body FROM llm_displacement_operations WHERE accelerator_id=$1`, acceleratorID)
	if displacementErr != nil {
		return nil, false, displacementErr
	}
	for displacementRows.Next() {
		var indexedPhase string
		var indexedRevision int64
		var body []byte
		if err := displacementRows.Scan(&indexedPhase, &indexedRevision, &body); err != nil {
			displacementRows.Close()
			return nil, false, err
		}
		displacement, decodeErr := decodeLLMDisplacementBody(body)
		if decodeErr != nil {
			displacementRows.Close()
			return nil, false, decodeErr
		}
		if indexedPhase != displacement.Phase || indexedRevision <= 0 || uint64(indexedRevision) != displacement.Revision {
			lease := displacement.OriginalLease
			if lease == nil {
				lease = &domain.AcceleratorLease{AcceleratorID: acceleratorID, WorkloadID: displacement.VictimWorkloadID, FencingToken: int64(displacement.Fence)}
			}
			displacementRows.Close()
			return lease, false, nil
		}
		if displacement.Phase != "completed" {
			lease := displacement.OriginalLease
			if lease == nil {
				lease = &domain.AcceleratorLease{AcceleratorID: acceleratorID, WorkloadID: displacement.VictimWorkloadID, FencingToken: int64(displacement.Fence)}
			}
			displacementRows.Close()
			return lease, false, nil
		}
	}
	if err := displacementRows.Err(); err != nil {
		displacementRows.Close()
		return nil, false, err
	}
	displacementRows.Close()
	for _, cleanupOp := range cleanupOps {
		if recoveryOperationID != "" && cleanupOp.CleanupState == "armed" && cleanupOp.WorkloadID == workloadID && (cleanupOp.ID == recoveryOperationID || cleanupOp.CleanupOperationID == recoveryOperationID) {
			recoveryOp = cleanupOp
			break
		}
	}
	for _, cleanupOp := range cleanupOps {
		if cleanupOp == recoveryOp {
			continue
		}
		fence := cleanupOp.CleanupFence
		if fence == 0 {
			fence = cleanupOp.Fence
		}
		return &domain.AcceleratorLease{AcceleratorID: acceleratorID, WorkloadID: cleanupOp.WorkloadID, FencingToken: int64(fence), ExpiresAt: now.Add(ttl)}, false, nil
	}
	if err == nil && current.ExpiresAt.After(now) {
		return &current, false, nil
	}
	var token int64
	fenceFloor := int64(0)
	if recoveryOp != nil && recoveryOp.CleanupFence > 0 {
		fenceFloor = int64(recoveryOp.CleanupFence)
	}
	err = tx.QueryRowContext(ctx, `INSERT INTO accelerator_lease_fences(accelerator_id,last_token) VALUES($1,GREATEST(1,$2+1)) ON CONFLICT(accelerator_id) DO UPDATE SET last_token=GREATEST(accelerator_lease_fences.last_token,$2)+1 RETURNING last_token`, acceleratorID, fenceFloor).Scan(&token)
	if err != nil {
		return nil, false, err
	}
	lease := &domain.AcceleratorLease{AcceleratorID: acceleratorID, WorkloadID: workloadID, FencingToken: token, ExpiresAt: now.Add(ttl).Truncate(time.Microsecond)}
	_, err = tx.ExecContext(ctx, `INSERT INTO accelerator_leases(accelerator_id,workload_id,fencing_token,expires_at) VALUES($1,$2,$3,$4) ON CONFLICT(accelerator_id) DO UPDATE SET workload_id=EXCLUDED.workload_id,fencing_token=EXCLUDED.fencing_token,expires_at=EXCLUDED.expires_at`, acceleratorID, workloadID, token, lease.ExpiresAt)
	if err != nil {
		return nil, false, err
	}
	if recoveryOp != nil {
		recoveryOp.CleanupState = "pending"
		if recoveryOp.CleanupOperationID == "" {
			recoveryOp.CleanupOperationID = recoveryOperationID
		}
		recoveryOp.CleanupAcceleratorID = acceleratorID
		recoveryOp.CleanupFence = uint64(token)
		if recoveryOp.CleanupGeneration == 0 {
			recoveryOp.CleanupGeneration = recoveryOp.Generation
		}
		recoveryOp.Revision++
		recoveryOp.UpdatedAt = time.Now().UTC().Truncate(time.Microsecond)
		body, marshalErr := json.Marshal(recoveryOp)
		if marshalErr != nil {
			return nil, false, marshalErr
		}
		result, updateErr := tx.ExecContext(ctx, `UPDATE llm_checkpoint_operations SET phase=$1, phase_ordinal=$2, node_id=$3, accelerator_id=$4, target_id=$5, slot_id=$6, body=$7, updated_at=$8 WHERE id=$9 AND ((body->>'revision')::bigint)=$10`, recoveryOp.Phase, recoveryOp.PhaseOrdinal, recoveryOp.NodeID, recoveryOp.AcceleratorID, recoveryOp.TargetID, recoveryOp.SlotID, body, recoveryOp.UpdatedAt, recoveryOp.ID, recoveryOp.Revision-1)
		if updateErr != nil {
			return nil, false, updateErr
		}
		if affected, rowsErr := result.RowsAffected(); rowsErr != nil {
			return nil, false, rowsErr
		} else if affected != 1 {
			return nil, false, ErrLLMCheckpointConflict
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, false, err
	}
	return lease, true, nil
}

func lockAcceleratorLeaseFence(ctx context.Context, tx *sql.Tx, acceleratorID string) error {
	var ignored int64
	// The no-op conflict update both creates the sentinel and takes its row lock
	// when it already exists. PostgreSQL retains that lock until transaction end.
	return tx.QueryRowContext(ctx, `INSERT INTO accelerator_lease_fences(accelerator_id,last_token) VALUES($1,0) ON CONFLICT(accelerator_id) DO UPDATE SET last_token=accelerator_lease_fences.last_token RETURNING last_token`, acceleratorID).Scan(&ignored)
}

func lockResidencyLeaseOrigin(ctx context.Context, tx *sql.Tx, lease *domain.AcceleratorLease) error {
	if lease == nil || lease.AcceleratorID == "" || lease.WorkloadID == "" || lease.FencingToken <= 0 {
		return fmt.Errorf("%w: incomplete accelerator lease origin", ErrResidencyTransitionConflict)
	}
	if err := lockAcceleratorLeaseFence(ctx, tx, lease.AcceleratorID); err != nil { return err }
	var current domain.AcceleratorLease
	if err := tx.QueryRowContext(ctx, `SELECT accelerator_id,workload_id,fencing_token,expires_at FROM accelerator_leases WHERE accelerator_id=$1 FOR UPDATE`, lease.AcceleratorID).Scan(&current.AcceleratorID, &current.WorkloadID, &current.FencingToken, &current.ExpiresAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) { return ErrResidencyTransitionConflict }
		return err
	}
	return validateCurrentResidencyLeaseOrigin(&current, lease, time.Now().UTC())
}

func recheckLockedResidencyLeaseOrigin(ctx context.Context, tx *sql.Tx, lease *domain.AcceleratorLease) error {
	var current domain.AcceleratorLease
	if err := tx.QueryRowContext(ctx, `SELECT accelerator_id,workload_id,fencing_token,expires_at FROM accelerator_leases WHERE accelerator_id=$1 FOR UPDATE`, lease.AcceleratorID).Scan(&current.AcceleratorID, &current.WorkloadID, &current.FencingToken, &current.ExpiresAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) { return ErrResidencyTransitionConflict }
		return err
	}
	return validateCurrentResidencyLeaseOrigin(&current, lease, time.Now().UTC())
}

func (p *PostgresWorkloadStore) RenewAcceleratorLease(ctx context.Context, acceleratorID, workloadID string, fencingToken int64, ttl time.Duration) error {
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := lockAcceleratorLeaseFence(ctx, tx, acceleratorID); err != nil { return err }
	var current domain.AcceleratorLease
	if err := tx.QueryRowContext(ctx, `SELECT accelerator_id,workload_id,fencing_token,expires_at FROM accelerator_leases WHERE accelerator_id=$1 FOR UPDATE`, acceleratorID).Scan(&current.AcceleratorID, &current.WorkloadID, &current.FencingToken, &current.ExpiresAt); err != nil {
		return translateSQLError(err)
	}
	if current.WorkloadID != workloadID || current.FencingToken != fencingToken { return ErrNotFound }
	result, err := tx.ExecContext(ctx, `UPDATE accelerator_leases SET expires_at=$4 WHERE accelerator_id=$1 AND workload_id=$2 AND fencing_token=$3`, acceleratorID, workloadID, fencingToken, time.Now().UTC().Add(ttl).Truncate(time.Microsecond))
	if err != nil { return err }
	rows, _ := result.RowsAffected()
	if rows == 0 { return ErrNotFound }
	return tx.Commit()
}
func (p *PostgresWorkloadStore) ReleaseAcceleratorLease(ctx context.Context, acceleratorID, workloadID string, fencingToken int64) error {
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := lockAcceleratorLeaseFence(ctx, tx, acceleratorID); err != nil { return err }
	var current domain.AcceleratorLease
	if err := tx.QueryRowContext(ctx, `SELECT accelerator_id,workload_id,fencing_token,expires_at FROM accelerator_leases WHERE accelerator_id=$1 FOR UPDATE`, acceleratorID).Scan(&current.AcceleratorID, &current.WorkloadID, &current.FencingToken, &current.ExpiresAt); err != nil {
		return translateSQLError(err)
	}
	if current.WorkloadID != workloadID || current.FencingToken != fencingToken { return ErrNotFound }
	result, err := tx.ExecContext(ctx, `DELETE FROM accelerator_leases WHERE accelerator_id=$1 AND workload_id=$2 AND fencing_token=$3`, acceleratorID, workloadID, fencingToken)
	if err != nil { return err }
	rows, _ := result.RowsAffected()
	if rows == 0 { return ErrNotFound }
	return tx.Commit()
}

func (p *PostgresWorkloadStore) GetAcceleratorLease(ctx context.Context, acceleratorID string) (*domain.AcceleratorLease, error) {
	var lease domain.AcceleratorLease
	err := p.db.QueryRowContext(ctx, `SELECT accelerator_id,workload_id,fencing_token,expires_at FROM accelerator_leases WHERE accelerator_id=$1`, acceleratorID).Scan(&lease.AcceleratorID, &lease.WorkloadID, &lease.FencingToken, &lease.ExpiresAt)
	if err != nil {
		return nil, translateSQLError(err)
	}
	return &lease, nil
}

func (p *PostgresWorkloadStore) RecordAcceleratorLeaseCleanupIntent(ctx context.Context, intent *domain.AcceleratorLeaseCleanupIntent) (*domain.AcceleratorLeaseCleanupIntent, error) {
	if err := validateLeaseCleanupIntent(intent); err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	if intent.CreatedAt.IsZero() {
		intent.CreatedAt = now
	}
	if intent.UpdatedAt.IsZero() {
		intent.UpdatedAt = now
	}
	if intent.Attempts <= 0 {
		intent.Attempts = 1
	}
	result, err := p.db.ExecContext(ctx, `INSERT INTO accelerator_lease_cleanup_intents(accelerator_id,owner,fencing_token,workload_id,expected_workload_revision,terminal_disposition,terminal_error_code,release_confirmed,terminal_published,audit_published,notification_published,budget_settled,attempts,last_error,created_at,updated_at,next_retry_at) VALUES($1,$2,$3,$4,NULLIF($5,0),NULLIF($6,''),NULLIF($7,''),$8,$9,$10,$11,$12,$13,NULLIF($14,''),$15,$16,$17) ON CONFLICT(accelerator_id,owner,fencing_token,workload_id) DO UPDATE SET attempts=GREATEST(accelerator_lease_cleanup_intents.attempts,EXCLUDED.attempts),last_error=EXCLUDED.last_error,updated_at=EXCLUDED.updated_at,next_retry_at=EXCLUDED.next_retry_at,release_confirmed=accelerator_lease_cleanup_intents.release_confirmed OR EXCLUDED.release_confirmed,terminal_published=accelerator_lease_cleanup_intents.terminal_published OR EXCLUDED.terminal_published,audit_published=accelerator_lease_cleanup_intents.audit_published OR EXCLUDED.audit_published,notification_published=accelerator_lease_cleanup_intents.notification_published OR EXCLUDED.notification_published,budget_settled=accelerator_lease_cleanup_intents.budget_settled OR EXCLUDED.budget_settled WHERE accelerator_lease_cleanup_intents.expected_workload_revision IS NOT DISTINCT FROM EXCLUDED.expected_workload_revision AND accelerator_lease_cleanup_intents.terminal_disposition IS NOT DISTINCT FROM EXCLUDED.terminal_disposition AND accelerator_lease_cleanup_intents.terminal_error_code IS NOT DISTINCT FROM EXCLUDED.terminal_error_code`, intent.AcceleratorID, intent.Owner, intent.FencingToken, intent.WorkloadID, intent.ExpectedWorkloadRevision, intent.TerminalDisposition, intent.TerminalErrorCode, intent.ReleaseConfirmed, intent.TerminalPublished, intent.AuditPublished, intent.NotificationPublished, intent.BudgetSettled, intent.Attempts, intent.LastError, intent.CreatedAt, intent.UpdatedAt, intent.NextRetryAt)
	if err != nil {
		return nil, err
	}
	if affected, rowsErr := result.RowsAffected(); rowsErr != nil {
		return nil, rowsErr
	} else if affected == 0 {
		// The partial ON CONFLICT predicate rejected an immutable mismatch.
		// Read the exact primary-key row below and distinguish an idempotent
		// replay from a conflicting continuation.
	}
	rows, err := p.db.QueryContext(ctx, `SELECT accelerator_id,owner,fencing_token,COALESCE(workload_id,''),COALESCE(expected_workload_revision,0),COALESCE(terminal_disposition,''),COALESCE(terminal_error_code,''),release_confirmed,terminal_published,audit_published,notification_published,budget_settled,attempts,COALESCE(last_error,''),created_at,updated_at,next_retry_at FROM accelerator_lease_cleanup_intents WHERE accelerator_id=$1 AND owner=$2 AND fencing_token=$3 AND COALESCE(workload_id,'')=$4`, intent.AcceleratorID, intent.Owner, intent.FencingToken, intent.WorkloadID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if !rows.Next() {
		return nil, ErrAcceleratorLeaseCleanupConflict
	}
	var stored AcceleratorLeaseCleanupIntentRow
	if err := rows.Scan(&stored.AcceleratorID, &stored.Owner, &stored.FencingToken, &stored.WorkloadID, &stored.ExpectedWorkloadRevision, &stored.TerminalDisposition, &stored.TerminalErrorCode, &stored.ReleaseConfirmed, &stored.TerminalPublished, &stored.AuditPublished, &stored.NotificationPublished, &stored.BudgetSettled, &stored.Attempts, &stored.LastError, &stored.CreatedAt, &stored.UpdatedAt, &stored.NextRetryAt); err != nil {
		return nil, err
	}
	if stored.WorkloadID != intent.WorkloadID || stored.ExpectedWorkloadRevision != intent.ExpectedWorkloadRevision || stored.TerminalDisposition != intent.TerminalDisposition || stored.TerminalErrorCode != intent.TerminalErrorCode {
		return nil, ErrAcceleratorLeaseCleanupConflict
	}
	return stored.Intent(), nil
}

type AcceleratorLeaseCleanupIntentRow struct {
	AcceleratorID                                                                             string
	Owner                                                                                     string
	FencingToken                                                                              int64
	WorkloadID                                                                                string
	ExpectedWorkloadRevision                                                                  uint64
	TerminalDisposition                                                                       string
	TerminalErrorCode                                                                         string
	ReleaseConfirmed, TerminalPublished, AuditPublished, NotificationPublished, BudgetSettled bool
	Attempts                                                                                  int
	LastError                                                                                 string
	CreatedAt, UpdatedAt                                                                      time.Time
	NextRetryAt                                                                               *time.Time
}

func (r AcceleratorLeaseCleanupIntentRow) Intent() *domain.AcceleratorLeaseCleanupIntent {
	return &domain.AcceleratorLeaseCleanupIntent{AcceleratorID: r.AcceleratorID, Owner: r.Owner, FencingToken: r.FencingToken, WorkloadID: r.WorkloadID, ExpectedWorkloadRevision: r.ExpectedWorkloadRevision, TerminalDisposition: r.TerminalDisposition, TerminalErrorCode: r.TerminalErrorCode, ReleaseConfirmed: r.ReleaseConfirmed, TerminalPublished: r.TerminalPublished, AuditPublished: r.AuditPublished, NotificationPublished: r.NotificationPublished, BudgetSettled: r.BudgetSettled, Attempts: r.Attempts, LastError: r.LastError, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt, NextRetryAt: r.NextRetryAt}
}

func (p *PostgresWorkloadStore) ListAcceleratorLeaseCleanupIntents(ctx context.Context, now time.Time, limit int) ([]*domain.AcceleratorLeaseCleanupIntent, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	rows, err := p.db.QueryContext(ctx, `SELECT accelerator_id,owner,fencing_token,COALESCE(workload_id,''),COALESCE(expected_workload_revision,0),COALESCE(terminal_disposition,''),COALESCE(terminal_error_code,''),release_confirmed,terminal_published,audit_published,notification_published,budget_settled,attempts,COALESCE(last_error,''),created_at,updated_at,next_retry_at FROM accelerator_lease_cleanup_intents WHERE next_retry_at IS NULL OR next_retry_at <= $1 ORDER BY updated_at,accelerator_id,owner,fencing_token LIMIT $2`, now, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*domain.AcceleratorLeaseCleanupIntent
	for rows.Next() {
		var row AcceleratorLeaseCleanupIntentRow
		if err := rows.Scan(&row.AcceleratorID, &row.Owner, &row.FencingToken, &row.WorkloadID, &row.ExpectedWorkloadRevision, &row.TerminalDisposition, &row.TerminalErrorCode, &row.ReleaseConfirmed, &row.TerminalPublished, &row.AuditPublished, &row.NotificationPublished, &row.BudgetSettled, &row.Attempts, &row.LastError, &row.CreatedAt, &row.UpdatedAt, &row.NextRetryAt); err != nil {
			return nil, err
		}
		out = append(out, row.Intent())
	}
	return out, rows.Err()
}

func (p *PostgresWorkloadStore) DeleteAcceleratorLeaseCleanupIntent(ctx context.Context, acceleratorID, owner string, fencingToken int64) error {
	_, err := p.db.ExecContext(ctx, `DELETE FROM accelerator_lease_cleanup_intents WHERE accelerator_id=$1 AND owner=$2 AND fencing_token=$3`, acceleratorID, owner, fencingToken)
	return err
}

func (p *PostgresWorkloadStore) DeleteAcceleratorLeaseCleanupIntentForWorkload(ctx context.Context, acceleratorID, owner string, fencingToken int64, workloadID string) error {
	_, err := p.db.ExecContext(ctx, `DELETE FROM accelerator_lease_cleanup_intents WHERE accelerator_id=$1 AND owner=$2 AND fencing_token=$3 AND COALESCE(workload_id,'')=$4`, acceleratorID, owner, fencingToken, workloadID)
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
	_, err := p.db.ExecContext(ctx, `INSERT INTO audit_events(id,timestamp,actor_id,owner_id,workload_id,type,severity,payload) VALUES($1,$2,NULLIF($3,''),NULLIF($4,''),NULLIF($5,''),$6,$7,$8) ON CONFLICT(id) DO NOTHING`, event.ID, event.Timestamp, event.ActorID, event.OwnerID, event.WorkloadID, event.Type, event.Severity, event.Payload)
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
	if residency.Revision == 0 {
		residency.Revision = 1
	}
	body, err := json.Marshal(residency)
	if err != nil {
		return nil, err
	}
	// The generation/fingerprint predicate and revision advance must happen in
	// the same statement as the upsert. A read-then-write sequence lets an
	// older transition win after a newer refresh has already committed.
	var storedBody []byte
	err = p.db.QueryRowContext(ctx, `
		INSERT INTO model_residencies(target_id,model,body,updated_at)
		VALUES($1,$2,$3,$4)
		ON CONFLICT(target_id,model) DO UPDATE SET
			body = jsonb_set(
				EXCLUDED.body,
				'{revision}', to_jsonb(COALESCE((model_residencies.body->>'revision')::bigint,0)+1), true),
			updated_at = EXCLUDED.updated_at
		WHERE (COALESCE((EXCLUDED.body->>'target_generation')::bigint,0) > COALESCE((model_residencies.body->>'target_generation')::bigint,0)
				AND COALESCE(EXCLUDED.body->>'execution_fingerprint','') <> '')
			OR (COALESCE((EXCLUDED.body->>'target_generation')::bigint,0) = COALESCE((model_residencies.body->>'target_generation')::bigint,0)
				AND COALESCE(EXCLUDED.body->>'execution_fingerprint','') <> ''
				AND COALESCE(model_residencies.body->>'execution_fingerprint','') <> ''
				AND EXCLUDED.body->>'execution_fingerprint' = model_residencies.body->>'execution_fingerprint')
		RETURNING body`, residency.TargetID, residency.Model, body, residency.UpdatedAt).Scan(&storedBody)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrModelResidencyGenerationConflict
	}
	if err != nil {
		return nil, err
	}
	var stored domain.ModelResidency
	if err := json.Unmarshal(storedBody, &stored); err != nil {
		return nil, err
	}
	return &stored, nil
}

func (p *PostgresWorkloadStore) CreateModelResidency(ctx context.Context, residency *domain.ModelResidency) (*domain.ModelResidency, bool, error) {
	if residency.Revision == 0 {
		residency = cloneResidency(residency)
		residency.Revision = 1
	}
	body, err := json.Marshal(residency)
	if err != nil {
		return nil, false, err
	}
	result, err := p.db.ExecContext(ctx, `INSERT INTO model_residencies(target_id,model,body,updated_at) VALUES($1,$2,$3,$4) ON CONFLICT(target_id,model) DO NOTHING`, residency.TargetID, residency.Model, body, residency.UpdatedAt)
	if err != nil {
		return nil, false, err
	}
	rows, _ := result.RowsAffected()
	if rows == 1 {
		return cloneResidency(residency), true, nil
	}
	existing, err := p.GetModelResidency(ctx, residency.TargetID, residency.Model)
	if err != nil {
		return nil, false, err
	}
	if !residencyGenerationCompatible(existing, residency) {
		return nil, false, fmt.Errorf("%w existing_generation=%d incoming_generation=%d existing_fingerprint=%q incoming_fingerprint=%q", ErrModelResidencyGenerationConflict, existing.TargetGeneration, residency.TargetGeneration, existing.ExecutionFingerprint, residency.ExecutionFingerprint)
	}
	return existing, false, nil
}

func (p *PostgresWorkloadStore) CompareAndSwapModelResidency(ctx context.Context, residency *domain.ModelResidency, expectedRevision uint64) (*domain.ModelResidency, error) {
	updated := *residency
	updated.Revision = expectedRevision + 1
	body, err := json.Marshal(&updated)
	if err != nil {
		return nil, err
	}
	result, err := p.db.ExecContext(ctx, `UPDATE model_residencies SET body=$3,updated_at=$4 WHERE target_id=$1 AND model=$2 AND COALESCE((body->>'revision')::bigint,0)=$5 AND ((COALESCE((body->>'target_generation')::bigint,0) < $6 AND COALESCE($7,'') <> '') OR (COALESCE((body->>'target_generation')::bigint,0) = $6 AND COALESCE(body->>'execution_fingerprint','') <> '' AND COALESCE($7,'') <> '' AND body->>'execution_fingerprint' = $7))`, updated.TargetID, updated.Model, body, updated.UpdatedAt, int64(expectedRevision), int64(updated.TargetGeneration), updated.ExecutionFingerprint)
	if err != nil {
		return nil, err
	}
	rows, _ := result.RowsAffected()
	if rows != 1 {
		if current, readErr := p.GetModelResidency(ctx, updated.TargetID, updated.Model); readErr == nil && current.Revision == expectedRevision && !residencyGenerationCompatible(current, &updated) {
			return nil, ErrModelResidencyGenerationConflict
		}
		return nil, ErrModelResidencyConflict
	}
	return &updated, nil
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
	if err := validateResidencyTransitionStoredOrigin(transition); err != nil || residencyTransitionHasLeaseOrigin(transition) {
		if err != nil { return nil, false, err }
		return nil, false, fmt.Errorf("%w: CreateResidencyTransition cannot issue or accept lease-origin provenance", ErrResidencyTransitionConflict)
	}
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
	if err := verifyResidencyTransitionReplay(&existing, transition); err != nil {
		return nil, false, err
	}
	return &existing, false, nil
}

func (p *PostgresWorkloadStore) AllocateResidencyTransition(ctx context.Context, transition *domain.ResidencyTransition) (*domain.ResidencyTransition, bool, error) {
	if err := validateResidencyTransitionStoredOrigin(transition); err != nil || residencyTransitionHasLeaseOrigin(transition) {
		if err != nil { return nil, false, err }
		return nil, false, fmt.Errorf("%w: unleased allocation cannot issue or accept lease-origin provenance", ErrResidencyTransitionConflict)
	}
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, false, err
	}
	rollback := func(err error) (*domain.ResidencyTransition, bool, error) { _ = tx.Rollback(); return nil, false, err }
	resourceKey := transition.TargetID + "\x1f" + transition.Model // NUL is invalid in a PostgreSQL text parameter
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, resourceKey); err != nil {
		return rollback(err)
	}
	var existingBody []byte
	err = tx.QueryRowContext(ctx, `SELECT body FROM residency_transitions WHERE idempotency_key=$1 OR id=$2 LIMIT 1`, transition.IdempotencyKey, transition.ID).Scan(&existingBody)
	if err == nil {
		var existing domain.ResidencyTransition
		if unmarshalErr := json.Unmarshal(existingBody, &existing); unmarshalErr != nil {
			return rollback(unmarshalErr)
		}
		if verifyErr := verifyResidencyTransitionReplay(&existing, transition); verifyErr != nil {
			return rollback(verifyErr)
		}
		if commitErr := tx.Commit(); commitErr != nil {
			return nil, false, commitErr
		}
		return &existing, false, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return rollback(err)
	}
	var highwater *int64
	if err := tx.QueryRowContext(ctx, `SELECT MAX(NULLIF(body->>'fencing_token','')::bigint) FROM residency_transitions WHERE target_id=$1 AND model=$2`, transition.TargetID, transition.Model).Scan(&highwater); err != nil {
		return rollback(err)
	}
	allocated := cloneTransition(transition)
	if allocated.Revision == 0 {
		allocated.Revision = 1
	}
	if highwater == nil {
		if allocated.FencingToken <= 0 {
			allocated.FencingToken = 1
		}
	} else {
		if *highwater == math.MaxInt64 { return rollback(fmt.Errorf("%w: residency transition model fence exhausted", ErrResidencyTransitionConflict)) }
		if allocated.FencingToken <= *highwater { allocated.FencingToken = *highwater + 1 }
	}
	body, err := json.Marshal(allocated)
	if err != nil {
		return rollback(err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO residency_transitions(id,idempotency_key,target_id,accelerator_id,model,status,body,created_at,updated_at) VALUES($1,$2,$3,NULLIF($4,''),$5,$6,$7,$8,$8)`, allocated.ID, allocated.IdempotencyKey, allocated.TargetID, allocated.AcceleratorID, allocated.Model, allocated.Status, body, allocated.CreatedAt); err != nil {
		return rollback(err)
	}
	if err := tx.Commit(); err != nil {
		return nil, false, err
	}
	return allocated, true, nil
}

func (p *PostgresWorkloadStore) AllocateResidencyTransitionWithLease(ctx context.Context, transition *domain.ResidencyTransition, lease *domain.AcceleratorLease) (*domain.ResidencyTransition, bool, error) {
	resource, err := validateResidencyTransitionLeaseOriginRequest(transition, lease)
	if err != nil { return nil, false, err }
	tx, err := p.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil { return nil, false, err }
	rollback := func(err error) (*domain.ResidencyTransition, bool, error) { _ = tx.Rollback(); return nil, false, err }
	// Lease writers, lease-aware allocation and lifecycle coordination share
	// fence-sentinel -> lease-row ordering. The expiry check follows the row
	// lock, so time spent waiting cannot turn an expired tuple into authority.
	if err := lockResidencyLeaseOrigin(ctx, tx, lease); err != nil { return rollback(err) }
	resourceKey := transition.TargetID + "\x1f" + transition.Model // NUL is invalid in a PostgreSQL text parameter
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, resourceKey); err != nil { return rollback(err) }
	if err := recheckLockedResidencyLeaseOrigin(ctx, tx, lease); err != nil { return rollback(err) }
	var keyBody []byte
	keyErr := tx.QueryRowContext(ctx, `SELECT body FROM residency_transitions WHERE idempotency_key=$1 FOR UPDATE`, transition.IdempotencyKey).Scan(&keyBody)
	if err := recheckLockedResidencyLeaseOrigin(ctx, tx, lease); err != nil { return rollback(err) }
	if keyErr == nil {
		var existing domain.ResidencyTransition
		if err := json.Unmarshal(keyBody, &existing); err != nil { return rollback(err) }
		var idBody []byte
		idErr := tx.QueryRowContext(ctx, `SELECT body FROM residency_transitions WHERE id=$1 FOR UPDATE`, transition.ID).Scan(&idBody)
		if err := recheckLockedResidencyLeaseOrigin(ctx, tx, lease); err != nil { return rollback(err) }
		if idErr == nil {
			var byID domain.ResidencyTransition
			if err := json.Unmarshal(idBody, &byID); err != nil { return rollback(err) }
			if byID.ID != existing.ID { return rollback(fmt.Errorf("%w: transition id and idempotency key identify different rows", ErrResidencyTransitionConflict)) }
		} else if !errors.Is(idErr, sql.ErrNoRows) { return rollback(idErr) }
		if err := verifyResidencyTransitionLeaseReplay(&existing, transition, lease); err != nil { return rollback(err) }
		if err := tx.Commit(); err != nil { return nil, false, err }
		return &existing, false, nil
	}
	if !errors.Is(keyErr, sql.ErrNoRows) { return rollback(keyErr) }
	var idBody []byte
	idErr := tx.QueryRowContext(ctx, `SELECT body FROM residency_transitions WHERE id=$1 FOR UPDATE`, transition.ID).Scan(&idBody)
	if err := recheckLockedResidencyLeaseOrigin(ctx, tx, lease); err != nil { return rollback(err) }
	if idErr == nil {
		var existing domain.ResidencyTransition
		if err := json.Unmarshal(idBody, &existing); err != nil { return rollback(err) }
		if err := verifyResidencyTransitionLeaseReplay(&existing, transition, lease); err != nil { return rollback(err) }
		if err := tx.Commit(); err != nil { return nil, false, err }
		return &existing, false, nil
	}
	if !errors.Is(idErr, sql.ErrNoRows) { return rollback(idErr) }
	var highwater *int64
	if err := tx.QueryRowContext(ctx, `SELECT MAX(NULLIF(body->>'fencing_token','')::bigint) FROM residency_transitions WHERE target_id=$1 AND model=$2`, transition.TargetID, transition.Model).Scan(&highwater); err != nil { return rollback(err) }
	allocated := cloneTransition(transition)
	if allocated.Revision == 0 { allocated.Revision = 1 }
	if highwater != nil {
		if *highwater == math.MaxInt64 { return rollback(fmt.Errorf("%w: residency transition model fence exhausted", ErrResidencyTransitionConflict)) }
		if allocated.FencingToken <= *highwater { allocated.FencingToken = *highwater + 1 }
	}
	allocated.LeaseOriginAcceleratorID = resource
	allocated.LeaseOriginWorkloadID = lease.WorkloadID
	allocated.LeaseOriginFencingToken = lease.FencingToken
	allocated.LeaseOriginAllocated = true
	body, err := json.Marshal(allocated)
	if err != nil { return rollback(err) }
	if err := recheckLockedResidencyLeaseOrigin(ctx, tx, lease); err != nil { return rollback(err) }
	if _, err := tx.ExecContext(ctx, `INSERT INTO residency_transitions(id,idempotency_key,target_id,accelerator_id,model,status,body,created_at,updated_at) VALUES($1,$2,$3,NULLIF($4,''),$5,$6,$7,$8,$8)`, allocated.ID, allocated.IdempotencyKey, allocated.TargetID, allocated.AcceleratorID, allocated.Model, allocated.Status, body, allocated.CreatedAt); err != nil { return rollback(err) }
	if err := recheckLockedResidencyLeaseOrigin(ctx, tx, lease); err != nil { return rollback(err) }
	if err := tx.Commit(); err != nil { return nil, false, err }
	return allocated, true, nil
}

func (p *PostgresWorkloadStore) GetResidencyTransitionByIdempotencyForLease(ctx context.Context, idempotencyKey string, lease *domain.AcceleratorLease) (*domain.ResidencyTransition, error) {
	if idempotencyKey == "" { return nil, ErrNotFound }
	tx, err := p.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil { return nil, err }
	defer tx.Rollback()
	if err := lockResidencyLeaseOrigin(ctx, tx, lease); err != nil { return nil, err }
	var body []byte
	readErr := tx.QueryRowContext(ctx, `SELECT body FROM residency_transitions WHERE idempotency_key=$1 FOR UPDATE`, idempotencyKey).Scan(&body)
	if err := recheckLockedResidencyLeaseOrigin(ctx, tx, lease); err != nil { return nil, err }
	if readErr != nil { return nil, translateSQLError(readErr) }
	var transition domain.ResidencyTransition
	if err := json.Unmarshal(body, &transition); err != nil { return nil, err }
	if transition.LeaseOriginAcceleratorID != lease.AcceleratorID || transition.LeaseOriginWorkloadID != lease.WorkloadID ||
		transition.LeaseOriginFencingToken != lease.FencingToken || !transition.LeaseOriginAllocated || transition.FencingToken < lease.FencingToken {
		return nil, fmt.Errorf("%w: transition replay has no exact allocated lease origin", ErrResidencyTransitionConflict)
	}
	if err := recheckLockedResidencyLeaseOrigin(ctx, tx, lease); err != nil { return nil, err }
	if err := tx.Commit(); err != nil { return nil, err }
	return &transition, nil
}

func (p *PostgresWorkloadStore) CompareAndSwapResidencyTransition(ctx context.Context, transition *domain.ResidencyTransition, expectedRevision uint64, expectedStatus domain.ResidencyTransitionStatus, expectedFence int64) (*domain.ResidencyTransition, error) {
	if err := validateResidencyTransitionStoredOrigin(transition); err != nil { return nil, err }
	var currentBody []byte
	if err := p.db.QueryRowContext(ctx, `SELECT body FROM residency_transitions WHERE id=$1`, transition.ID).Scan(&currentBody); err != nil {
		return nil, translateSQLError(err)
	}
	var current domain.ResidencyTransition
	if err := json.Unmarshal(currentBody, &current); err != nil {
		return nil, err
	}
	if err := verifyResidencyTransitionReplay(&current, transition); err != nil {
		return nil, err
	}
	stored := cloneTransition(transition)
	stored.Revision = expectedRevision + 1
	body, err := json.Marshal(stored)
	if err != nil {
		return nil, err
	}
	// Identity is part of the atomic CAS predicate as well as the replay
	// validation above. A concurrent recovery/transition writer must not be
	// able to replace the row between the read and this update with a newer
	// target generation or a different execution fingerprint.
	result, err := p.db.ExecContext(ctx, `UPDATE residency_transitions SET status=$2,body=$3,updated_at=$4 WHERE id=$1 AND COALESCE((body->>'revision')::bigint,0)=$5 AND status=$6 AND COALESCE((body->>'fencing_token')::bigint,0)=$7 AND COALESCE((body->>'target_generation')::bigint,0)=COALESCE($8,0) AND COALESCE(body->>'execution_fingerprint','')=COALESCE($9,'') AND COALESCE(body->>'lease_origin_accelerator_id','')=$10 AND COALESCE(body->>'lease_origin_workload_id','')=$11 AND COALESCE((body->>'lease_origin_fencing_token')::bigint,0)=$12 AND COALESCE((body->>'lease_origin_allocated')::boolean,false)=$13`, transition.ID, transition.Status, body, time.Now().UTC(), expectedRevision, expectedStatus, expectedFence, int64(transition.TargetGeneration), transition.ExecutionFingerprint, transition.LeaseOriginAcceleratorID, transition.LeaseOriginWorkloadID, transition.LeaseOriginFencingToken, transition.LeaseOriginAllocated)
	if err != nil {
		return nil, err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return nil, ErrResidencyTransitionConflict
	}
	return stored, nil
}

func (p *PostgresWorkloadStore) UpdateResidencyTransition(ctx context.Context, transition *domain.ResidencyTransition) (*domain.ResidencyTransition, error) {
	if err := validateResidencyTransitionStoredOrigin(transition); err != nil { return nil, err }
	body, err := json.Marshal(transition)
	if err != nil {
		return nil, err
	}
	result, err := p.db.ExecContext(ctx, `UPDATE residency_transitions SET status=$2,body=$3,updated_at=$4 WHERE id=$1 AND COALESCE(body->>'lease_origin_accelerator_id','')=$5 AND COALESCE(body->>'lease_origin_workload_id','')=$6 AND COALESCE((body->>'lease_origin_fencing_token')::bigint,0)=$7 AND COALESCE((body->>'lease_origin_allocated')::boolean,false)=$8 AND (COALESCE((body->>'lease_origin_allocated')::boolean,false)=false OR (COALESCE(body->>'idempotency_key','')=$9 AND COALESCE(body->>'target_id','')=$10 AND COALESCE(body->>'accelerator_id','')=$11 AND COALESCE(body->>'model','')=$12 AND COALESCE(body->>'from_tier','')=$13 AND COALESCE(body->>'to_tier','')=$14 AND COALESCE(body->>'reason','')=$15 AND COALESCE(body->>'requested_by','')=$16 AND COALESCE(body->>'workload_id','')=$17 AND COALESCE((body->>'fencing_token')::bigint,0)=$18 AND COALESCE(body->>'capability_version','')=$19 AND COALESCE(body->>'capability_revision','')=$20 AND COALESCE((body->>'target_generation')::bigint,0)=$21 AND COALESCE(body->>'execution_fingerprint','')=$22))`, transition.ID, transition.Status, body, time.Now().UTC(), transition.LeaseOriginAcceleratorID, transition.LeaseOriginWorkloadID, transition.LeaseOriginFencingToken, transition.LeaseOriginAllocated, transition.IdempotencyKey, transition.TargetID, transition.AcceleratorID, transition.Model, transition.FromTier, transition.ToTier, transition.Reason, transition.RequestedBy, transition.WorkloadID, transition.FencingToken, transition.CapabilityVersion, transition.CapabilityRevision, int64(transition.TargetGeneration), transition.ExecutionFingerprint)
	if err != nil {
		return nil, err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		if _, readErr := p.GetResidencyTransition(ctx, transition.ID); errors.Is(readErr, ErrNotFound) {
			return nil, ErrNotFound
		}
		return nil, ErrResidencyTransitionConflict
	}
	cp := *transition
	return &cp, nil
}

func (p *PostgresWorkloadStore) GetResidencyTransitionByIdempotency(ctx context.Context, idempotencyKey string) (*domain.ResidencyTransition, error) {
	if idempotencyKey == "" {
		return nil, ErrNotFound
	}
	var body []byte
	if err := p.db.QueryRowContext(ctx, `SELECT body FROM residency_transitions WHERE idempotency_key=$1`, idempotencyKey).Scan(&body); err != nil {
		return nil, translateSQLError(err)
	}
	var transition domain.ResidencyTransition
	if err := json.Unmarshal(body, &transition); err != nil {
		return nil, err
	}
	return &transition, nil
}

func (p *PostgresWorkloadStore) GetResidencyTransition(ctx context.Context, id string) (*domain.ResidencyTransition, error) {
	var body []byte
	if err := p.db.QueryRowContext(ctx, `SELECT body FROM residency_transitions WHERE id=$1`, id).Scan(&body); err != nil {
		return nil, translateSQLError(err)
	}
	var transition domain.ResidencyTransition
	if err := json.Unmarshal(body, &transition); err != nil {
		return nil, err
	}
	return &transition, nil
}

func (p *PostgresWorkloadStore) MaxResidencyFencingToken(ctx context.Context, targetID, model string) (int64, error) {
	var max *int64
	err := p.db.QueryRowContext(ctx, `SELECT MAX(NULLIF(body->>'fencing_token','')::bigint) FROM residency_transitions WHERE target_id=$1 AND model=$2`, targetID, model).Scan(&max)
	if err != nil {
		return 0, err
	}
	if max == nil {
		return 0, nil
	}
	return *max, nil
}

func (p *PostgresWorkloadStore) ListActiveResidencyTransitions(ctx context.Context, targetID, model string) ([]*domain.ResidencyTransition, error) {
	rows, err := p.db.QueryContext(ctx, `SELECT body FROM residency_transitions WHERE target_id=$1 AND model=$2 AND (status IN ('planned','running') OR (status='succeeded' AND body->>'projection_repair_pending'='true')) ORDER BY created_at DESC`, targetID, model)
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

func (p *PostgresWorkloadStore) ListResidencyTransitions(ctx context.Context, limit int) ([]*domain.ResidencyTransition, error) {
	if limit < 0 {
		rows, err := p.db.QueryContext(ctx, `SELECT body FROM residency_transitions ORDER BY created_at DESC`)
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

func (p *PostgresWorkloadStore) UpsertModelCapacity(ctx context.Context, capacity *ModelCapacity) (*ModelCapacity, error) {
	if capacity == nil || capacity.TargetID == "" || capacity.Model == "" {
		return nil, errors.New("model capacity requires target and model")
	}
	if capacity.FootprintBytes() < 0 || capacity.VRAMReserveBytes < 0 || capacity.RuntimeHardCapBytes < 0 || capacity.RAMBytes < 0 || capacity.RAMReserveBytes < 0 || capacity.VRAMTotalBytes < 0 || capacity.RAMTotalBytes < 0 {
		return nil, errors.New("model capacity bytes may not be negative or overflow")
	}
	copy := *capacity
	copy.ID = modelCapacityID(copy.TargetID, copy.Model, copy.ProfileID)
	if copy.UpdatedAt.IsZero() {
		copy.UpdatedAt = time.Now().UTC()
	}
	if copy.ObservedAt.IsZero() {
		copy.ObservedAt = copy.UpdatedAt
	}
	body, err := json.Marshal(&copy)
	if err != nil {
		return nil, err
	}
	// The row lock and revision increment make concurrent measurements
	// deterministic. The JSON body remains the compatibility envelope for
	// fields added by newer agents. Keep the transaction boundary behind a
	// narrow interface so rollback/CAS semantics are testable without a live
	// PostgreSQL server.
	begin := p.modelCapacityBeginTx
	if begin == nil && p.db != nil {
		begin = func(ctx context.Context) (modelCapacityTx, error) {
			tx, err := p.db.BeginTx(ctx, nil)
			if err != nil {
				return nil, err
			}
			return sqlModelCapacityTx{tx: tx}, nil
		}
	}
	if begin == nil {
		return nil, errors.New("model capacity transaction is unavailable")
	}
	tx, err := begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var revision uint64
	err = tx.QueryRowContext(ctx, `INSERT INTO model_capacities(id,target_id,model,profile_id,model_fingerprint,runtime_identity,capability_version,capability_revision,vram_total_bytes,ram_total_bytes,unified_memory,capacity_source,body,revision,updated_at,observed_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,1,$14,$15) ON CONFLICT(target_id,model,profile_id) DO UPDATE SET model_fingerprint=EXCLUDED.model_fingerprint,runtime_identity=EXCLUDED.runtime_identity,capability_version=EXCLUDED.capability_version,capability_revision=EXCLUDED.capability_revision,vram_total_bytes=EXCLUDED.vram_total_bytes,ram_total_bytes=EXCLUDED.ram_total_bytes,unified_memory=EXCLUDED.unified_memory,capacity_source=EXCLUDED.capacity_source,body=EXCLUDED.body,revision=model_capacities.revision+1,updated_at=EXCLUDED.updated_at,observed_at=EXCLUDED.observed_at RETURNING revision`, copy.ID, copy.TargetID, copy.Model, copy.ProfileID, copy.ModelFingerprint, copy.RuntimeIdentity, copy.CapabilityVersion, copy.CapabilityRevision, copy.VRAMTotalBytes, copy.RAMTotalBytes, copy.UnifiedMemory, copy.CapacitySource, body, copy.UpdatedAt, copy.ObservedAt).Scan(&revision)
	if err != nil {
		return nil, err
	}
	copy.Revision = revision
	// Keep the JSON compatibility envelope aligned with the scalar revision
	// used by the row lock, so exports and older readers see the same value.
	if _, err := tx.ExecContext(ctx, `UPDATE model_capacities SET body=jsonb_set(body,'{revision}',to_jsonb($2::bigint),true) WHERE id=$1`, copy.ID, revision); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &copy, nil
}

func (p *PostgresWorkloadStore) GetModelCapacity(ctx context.Context, targetID, model, profileID string) (*ModelCapacity, error) {
	var body []byte
	var revision uint64
	if err := p.db.QueryRowContext(ctx, `SELECT body,revision FROM model_capacities WHERE target_id=$1 AND model=$2 AND profile_id=$3`, targetID, model, profileID).Scan(&body, &revision); err != nil {
		return nil, translateSQLError(err)
	}
	var capacity ModelCapacity
	if err := json.Unmarshal(body, &capacity); err != nil {
		return nil, err
	}
	capacity.Revision = revision
	return &capacity, nil
}

func (p *PostgresWorkloadStore) ListModelCapacities(ctx context.Context, targetID, model string) ([]*ModelCapacity, error) {
	query := `SELECT body,revision FROM model_capacities`
	args := []any{}
	clauses := []string{}
	if targetID != "" {
		clauses = append(clauses, fmt.Sprintf("target_id=$%d", len(args)+1))
		args = append(args, targetID)
	}
	if model != "" {
		clauses = append(clauses, fmt.Sprintf("model=$%d", len(args)+1))
		args = append(args, model)
	}
	if len(clauses) > 0 {
		query += " WHERE " + strings.Join(clauses, " AND ")
	}
	query += " ORDER BY target_id,model,profile_id"
	rows, err := p.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]*ModelCapacity, 0)
	for rows.Next() {
		var body []byte
		var revision uint64
		if err := rows.Scan(&body, &revision); err != nil {
			return nil, err
		}
		var capacity ModelCapacity
		if err := json.Unmarshal(body, &capacity); err != nil {
			return nil, err
		}
		capacity.Revision = revision
		result = append(result, &capacity)
	}
	return result, rows.Err()
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
	if command.Revision == 0 {
		command = cloneNodeCommand(command)
		command.Revision = 1
	}
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
	// A conflict can be on either the scoped idempotency key or the command ID.
	// Read both identities so reusing either one with different signed args is
	// rejected rather than reported as an unrelated not-found error.
	if err := p.db.QueryRowContext(ctx, `SELECT body FROM node_commands WHERE id=$1 OR (node_id=$2 AND idempotency_key=$3) LIMIT 1`, command.ID, command.NodeID, command.IdempotencyKey).Scan(&existingBody); err != nil {
		return nil, false, translateSQLError(err)
	}
	var existing domain.NodeCommand
	if err := json.Unmarshal(existingBody, &existing); err != nil {
		return nil, false, err
	}
	if err := verifyNodeCommandReplay(&existing, command); err != nil {
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

func (p *PostgresWorkloadStore) CompareAndSwapNodeCommand(ctx context.Context, command *domain.NodeCommand, expectedAttempts int, expected ...domain.NodeCommandStatus) (*domain.NodeCommand, error) {
	var existingBody []byte
	if err := p.db.QueryRowContext(ctx, `SELECT body FROM node_commands WHERE id=$1`, command.ID).Scan(&existingBody); err != nil {
		return nil, translateSQLError(err)
	}
	var existing domain.NodeCommand
	if err := json.Unmarshal(existingBody, &existing); err != nil {
		return nil, err
	}
	return p.CompareAndSwapNodeCommandRevision(ctx, command, existing.Revision, expectedAttempts, existing.Uncertain, expected...)
}

func (p *PostgresWorkloadStore) CompareAndSwapNodeCommandRevision(ctx context.Context, command *domain.NodeCommand, expectedRevision uint64, expectedAttempts int, expectedUncertain bool, expected ...domain.NodeCommandStatus) (*domain.NodeCommand, error) {
	if len(expected) == 0 {
		return nil, ErrNodeCommandConflict
	}
	var existingBody []byte
	if err := p.db.QueryRowContext(ctx, `SELECT body FROM node_commands WHERE id=$1`, command.ID).Scan(&existingBody); err != nil {
		return nil, translateSQLError(err)
	}
	var existing domain.NodeCommand
	if err := json.Unmarshal(existingBody, &existing); err != nil {
		return nil, err
	}
	if err := verifyNodeCommandDelivery(&existing, command); err != nil {
		return nil, err
	}
	updated := cloneNodeCommand(command)
	updated.Revision = existing.Revision + 1
	body, err := json.Marshal(updated)
	if err != nil {
		return nil, err
	}
	args := []any{updated.ID, updated.Status, body, updated.UpdatedAt, int64(expectedRevision), expectedAttempts, expectedUncertain}
	placeholders := make([]string, 0, len(expected))
	for i, status := range expected {
		placeholders = append(placeholders, fmt.Sprintf("$%d", len(args)+i+1))
		args = append(args, status)
	}
	query := fmt.Sprintf(`UPDATE node_commands SET status=$2,body=$3,updated_at=$4 WHERE id=$1 AND COALESCE((body->>'revision')::bigint,1)=$5 AND COALESCE((body->>'attempts')::int,0)=$6 AND COALESCE((body->>'uncertain')::boolean,false)=$7 AND status IN (%s)`, strings.Join(placeholders, ","))
	result, err := p.db.ExecContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return nil, ErrNodeCommandConflict
	}
	return updated, nil
}

func (p *PostgresWorkloadStore) AdvanceNodeCommandRecovery(ctx context.Context, id string) (*domain.NodeCommand, error) {
	for attempt := 0; attempt < 8; attempt++ {
		var body []byte
		if err := p.db.QueryRowContext(ctx, `SELECT body FROM node_commands WHERE id=$1`, id).Scan(&body); err != nil {
			return nil, translateSQLError(err)
		}
		var current domain.NodeCommand
		if err := json.Unmarshal(body, &current); err != nil {
			return nil, err
		}
		if !current.Uncertain || current.EvidenceKind == "authoritative_observation" {
			return &current, nil
		}
		updated := cloneNodeCommand(&current)
		updated.RecoveryAttempts++
		next := time.Now().UTC().Add(nodeCommandRecoveryBackoff(updated.RecoveryAttempts))
		updated.RecoveryNextAt = &next
		updated.UpdatedAt = time.Now().UTC()
		updated.Revision = current.Revision + 1
		updatedBody, err := json.Marshal(updated)
		if err != nil {
			return nil, err
		}
		result, err := p.db.ExecContext(ctx, `UPDATE node_commands SET status=$2,body=$3,updated_at=$4 WHERE id=$1 AND COALESCE((body->>'revision')::bigint,1)=$5 AND COALESCE((body->>'uncertain')::boolean,false)=true AND COALESCE((body->>'evidence_kind'),'') <> 'authoritative_observation'`, updated.ID, updated.Status, updatedBody, updated.UpdatedAt, int64(current.Revision))
		if err != nil {
			return nil, err
		}
		rows, _ := result.RowsAffected()
		if rows == 1 {
			return updated, nil
		}
	}
	// A continuously busy command must still make durable progress.  Fall
	// back to a row-locked transaction instead of returning a conflict with no
	// retry state: the lock serializes this recovery update with result delivery
	// while the uncertainty/evidence predicates retain the safety boundary.
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var body []byte
	if err := tx.QueryRowContext(ctx, `SELECT body FROM node_commands WHERE id=$1 FOR UPDATE`, id).Scan(&body); err != nil {
		return nil, translateSQLError(err)
	}
	var current domain.NodeCommand
	if err := json.Unmarshal(body, &current); err != nil {
		return nil, err
	}
	if !current.Uncertain || current.EvidenceKind == "authoritative_observation" {
		return &current, nil
	}
	updated := cloneNodeCommand(&current)
	updated.RecoveryAttempts++
	next := time.Now().UTC().Add(nodeCommandRecoveryBackoff(updated.RecoveryAttempts))
	updated.RecoveryNextAt = &next
	updated.UpdatedAt = time.Now().UTC()
	updated.Revision = current.Revision + 1
	updatedBody, err := json.Marshal(updated)
	if err != nil {
		return nil, err
	}
	result, err := tx.ExecContext(ctx, `UPDATE node_commands SET status=$2,body=$3,updated_at=$4 WHERE id=$1 AND COALESCE((body->>'revision')::bigint,1)=$5 AND COALESCE((body->>'uncertain')::boolean,false)=true AND COALESCE((body->>'evidence_kind'),'') <> 'authoritative_observation'`, updated.ID, updated.Status, updatedBody, updated.UpdatedAt, int64(current.Revision))
	if err != nil {
		return nil, err
	}
	rows, _ := result.RowsAffected()
	if rows != 1 {
		return nil, ErrNodeCommandConflict
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return updated, nil
}

func (p *PostgresWorkloadStore) PromoteNodeCommandUncertain(ctx context.Context, id, nodeID string, result json.RawMessage, commandError string) (*domain.NodeCommand, error) {
	for attempt := 0; attempt < 4; attempt++ {
		var body []byte
		if err := p.db.QueryRowContext(ctx, `SELECT body FROM node_commands WHERE id=$1`, id).Scan(&body); err != nil {
			return nil, translateSQLError(err)
		}
		var current domain.NodeCommand
		if err := json.Unmarshal(body, &current); err != nil {
			return nil, err
		}
		if current.NodeID != nodeID {
			return nil, ErrNotFound
		}
		if !current.Uncertain && (current.Status == domain.NodeCommandSucceeded || current.Status == domain.NodeCommandFailed) && current.EvidenceKind == "authoritative_observation" {
			return nil, ErrNodeCommandConflict
		}
		updated := cloneNodeCommand(&current)
		updated.Status = domain.NodeCommandSent
		updated.Uncertain = true
		updated.Result = append(json.RawMessage(nil), result...)
		updated.Error = commandError
		updated.UpdatedAt = time.Now().UTC()
		updated.Revision = current.Revision + 1
		updatedBody, err := json.Marshal(updated)
		if err != nil {
			return nil, err
		}
		res, err := p.db.ExecContext(ctx, `UPDATE node_commands SET status=$2,body=$3,updated_at=$4 WHERE id=$1 AND node_id=$5 AND COALESCE((body->>'revision')::bigint,1)=$6 AND COALESCE((body->>'evidence_kind'),'') <> 'authoritative_observation'`, updated.ID, updated.Status, updatedBody, updated.UpdatedAt, nodeID, int64(current.Revision))
		if err != nil {
			return nil, err
		}
		rows, _ := res.RowsAffected()
		if rows == 1 {
			return updated, nil
		}
	}
	return nil, ErrNodeCommandConflict
}

func (p *PostgresWorkloadStore) ListNodeCommandRecovery(ctx context.Context, nodeID, reconcilesCommandID string) ([]*domain.NodeCommand, error) {
	query := `SELECT body FROM node_commands`
	args := make([]any, 0, 2)
	where := make([]string, 0, 2)
	if nodeID != "" {
		where = append(where, "node_id=$1")
		args = append(args, nodeID)
	}
	if reconcilesCommandID != "" {
		where = append(where, fmt.Sprintf("body->>'reconciles_command_id'=$%d", len(args)+1))
		args = append(args, reconcilesCommandID)
	}
	if len(where) > 0 {
		query += ` WHERE ` + strings.Join(where, " AND ")
	}
	query += ` ORDER BY created_at ASC`
	rows, err := p.db.QueryContext(ctx, query, args...)
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
	reservation, allowed, _, err := p.ReserveBudgetClaim(ctx, principalID, workloadID, amountCents, limitCents, "budget:"+workloadID+":legacy")
	return reservation, allowed, err
}

func (p *PostgresWorkloadStore) ReserveBudgetClaim(ctx context.Context, principalID, workloadID string, amountCents, limitCents int64, attemptToken string) (*domain.BudgetReservation, bool, bool, error) {
	if strings.TrimSpace(attemptToken) == "" {
		return nil, false, false, fmt.Errorf("%w: empty budget attempt token", ErrWorkloadConflict)
	}
	tx, err := p.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return nil, false, false, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, principalID); err != nil {
		return nil, false, false, err
	}
	var existingBody []byte
	err = tx.QueryRowContext(ctx, `SELECT body FROM budget_reservations WHERE workload_id=$1`, workloadID).Scan(&existingBody)
	if err == nil {
		var existing domain.BudgetReservation
		if err := json.Unmarshal(existingBody, &existing); err != nil {
			return nil, false, false, err
		}
		if existing.Status != domain.BudgetReleased {
			normalized := false
			if existing.Revision == 0 {
				existing.Revision = 1
				normalized = true
			}
			if existing.Attempt == 0 {
				existing.Attempt = 1
				normalized = true
			}
			if existing.OwnershipToken == "" {
				existing.OwnershipToken = fmt.Sprintf("budget:%s:%d", workloadID, existing.Attempt)
				normalized = true
			}
			if existing.Status != domain.BudgetReserved || existing.WorkloadID != workloadID || existing.PrincipalID != principalID || existing.OwnershipToken != attemptToken || existing.ReservedCents != amountCents || existing.LimitCents != limitCents || existing.Currency != defaultBudgetCurrency {
				return &existing, false, false, fmt.Errorf("%w: active budget reservation belongs to another attempt", ErrWorkloadConflict)
			}
			if normalized {
				updatedBody, marshalErr := json.Marshal(&existing)
				if marshalErr != nil {
					return nil, false, false, marshalErr
				}
				if _, updateErr := tx.ExecContext(ctx, `UPDATE budget_reservations SET body=$2,updated_at=$3 WHERE workload_id=$1 AND status <> 'released'`, workloadID, updatedBody, time.Now().UTC()); updateErr != nil {
					return nil, false, false, updateErr
				}
			}
			if err := tx.Commit(); err != nil {
				return nil, false, false, err
			}
			return &existing, true, false, nil
		}
	} else if !errors.Is(err, sql.ErrNoRows) {
		return nil, false, false, err
	}
	var committed int64
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(SUM(CASE WHEN status='reserved' THEN reserved_cents WHEN status='settled' THEN actual_cents ELSE 0 END),0) FROM budget_reservations WHERE principal_id=$1`, principalID).Scan(&committed); err != nil {
		return nil, false, false, err
	}
	if limitCents > 0 && committed+amountCents > limitCents {
		if err := tx.Commit(); err != nil {
			return nil, false, false, err
		}
		return nil, false, false, nil
	}
	now := time.Now().UTC()
	attempt := uint64(1)
	if existingBody != nil {
		var previous domain.BudgetReservation
		if json.Unmarshal(existingBody, &previous) == nil {
			attempt = previous.Attempt + 1
		}
	}
	reservation := &domain.BudgetReservation{WorkloadID: workloadID, PrincipalID: principalID, Revision: 1, Attempt: attempt, OwnershipToken: attemptToken, ReservedCents: amountCents, LimitCents: limitCents, Currency: defaultBudgetCurrency, Status: domain.BudgetReserved, CreatedAt: now, UpdatedAt: now}
	if existingBody != nil {
		var previous domain.BudgetReservation
		if json.Unmarshal(existingBody, &previous) == nil {
			reservation.CreatedAt = previous.CreatedAt
		}
	}
	body, _ := json.Marshal(reservation)
	_, err = tx.ExecContext(ctx, `INSERT INTO budget_reservations(workload_id,principal_id,reserved_cents,actual_cents,status,body,created_at,updated_at) VALUES($1,$2,$3,0,$4,$5,$6,$6) ON CONFLICT(workload_id) DO UPDATE SET principal_id=EXCLUDED.principal_id,reserved_cents=EXCLUDED.reserved_cents,actual_cents=0,status=EXCLUDED.status,body=EXCLUDED.body,updated_at=EXCLUDED.updated_at`, workloadID, principalID, amountCents, reservation.Status, body, now)
	if err != nil {
		return nil, false, false, err
	}
	if err := tx.Commit(); err != nil {
		return nil, false, false, err
	}
	return reservation, true, true, nil
}

// ReserveAndLinkBudgetClaim performs the reservation and workload linkage in
// one serializable transaction. The workload row is locked before the budget
// advisory key is evaluated, so failed admission cannot leave an unowned
// reservation for a later cleanup path to guess at.
func (p *PostgresWorkloadStore) ReserveAndLinkBudgetClaim(ctx context.Context, principalID, workloadID string, amountCents, limitCents int64, attemptToken string, expectedRevision uint64, expectedStatus domain.WorkloadStatus, expectedCancellationOwner string) (*domain.BudgetReservation, *domain.Workload, bool, bool, error) {
	if strings.TrimSpace(attemptToken) == "" {
		return nil, nil, false, false, fmt.Errorf("%w: empty budget attempt token", ErrWorkloadConflict)
	}
	tx, err := p.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return nil, nil, false, false, err
	}
	defer tx.Rollback()
	var workloadBody []byte
	if err := tx.QueryRowContext(ctx, `SELECT body FROM workloads WHERE id=$1 FOR UPDATE`, workloadID).Scan(&workloadBody); err != nil {
		return nil, nil, false, false, translateSQLError(err)
	}
	var workload domain.Workload
	if err := json.Unmarshal(workloadBody, &workload); err != nil {
		return nil, nil, false, false, err
	}
	if workload.Revision != expectedRevision || workload.Status != expectedStatus || workload.CancellationOwner != expectedCancellationOwner || (workload.Request.PrincipalID != "" && workload.Request.PrincipalID != principalID) || (workload.BudgetReservationToken != "" && (workload.BudgetReservationToken != attemptToken || (workload.BudgetReservationCents != 0 && workload.BudgetReservationCents != amountCents) || (workload.BudgetReservationLimitCents != 0 && workload.BudgetReservationLimitCents != limitCents) || (workload.BudgetReservationCurrency != "" && workload.BudgetReservationCurrency != defaultBudgetCurrency))) {
		return nil, &workload, false, false, ErrWorkloadConflict
	}
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, principalID); err != nil {
		return nil, nil, false, false, err
	}
	var existingBody []byte
	err = tx.QueryRowContext(ctx, `SELECT body FROM budget_reservations WHERE workload_id=$1 FOR UPDATE`, workloadID).Scan(&existingBody)
	var reservation domain.BudgetReservation
	created := false
	if err == nil {
		if unmarshalErr := json.Unmarshal(existingBody, &reservation); unmarshalErr != nil {
			return nil, nil, false, false, unmarshalErr
		}
		if reservation.Status != domain.BudgetReleased {
			if reservation.Revision == 0 {
				reservation.Revision = 1
			}
			if reservation.Attempt == 0 {
				reservation.Attempt = 1
			}
			if reservation.OwnershipToken == "" {
				reservation.OwnershipToken = fmt.Sprintf("budget:%s:%d", workloadID, reservation.Attempt)
			}
			if reservation.Status != domain.BudgetReserved || reservation.WorkloadID != workloadID || reservation.PrincipalID != principalID || reservation.OwnershipToken != attemptToken || reservation.ReservedCents != amountCents || reservation.LimitCents != limitCents || reservation.Currency != defaultBudgetCurrency || (workload.BudgetReservationAttempt != 0 && workload.BudgetReservationAttempt != reservation.Attempt) {
				return &reservation, &workload, false, false, fmt.Errorf("%w: active budget reservation belongs to another attempt", ErrWorkloadConflict)
			}
		} else {
			err = sql.ErrNoRows
		}
	} else if !errors.Is(err, sql.ErrNoRows) {
		return nil, nil, false, false, err
	}
	if errors.Is(err, sql.ErrNoRows) {
		var committed int64
		if queryErr := tx.QueryRowContext(ctx, `SELECT COALESCE(SUM(CASE WHEN status='reserved' THEN reserved_cents WHEN status='settled' THEN actual_cents ELSE 0 END),0) FROM budget_reservations WHERE principal_id=$1`, principalID).Scan(&committed); queryErr != nil {
			return nil, nil, false, false, queryErr
		}
		if limitCents > 0 && committed+amountCents > limitCents {
			if commitErr := tx.Commit(); commitErr != nil {
				return nil, nil, false, false, commitErr
			}
			return nil, &workload, false, false, nil
		}
		now := time.Now().UTC()
		attempt := uint64(1)
		if existingBody != nil {
			var previous domain.BudgetReservation
			if json.Unmarshal(existingBody, &previous) == nil {
				attempt = previous.Attempt + 1
				reservation.CreatedAt = previous.CreatedAt
			}
		}
		reservation = domain.BudgetReservation{WorkloadID: workloadID, PrincipalID: principalID, Revision: 1, Attempt: attempt, OwnershipToken: attemptToken, ReservedCents: amountCents, LimitCents: limitCents, Currency: defaultBudgetCurrency, Status: domain.BudgetReserved, CreatedAt: now, UpdatedAt: now}
		if existingBody != nil {
			var previous domain.BudgetReservation
			if json.Unmarshal(existingBody, &previous) == nil {
				reservation.CreatedAt = previous.CreatedAt
			}
		}
		body, marshalErr := json.Marshal(&reservation)
		if marshalErr != nil {
			return nil, nil, false, false, marshalErr
		}
		if _, execErr := tx.ExecContext(ctx, `INSERT INTO budget_reservations(workload_id,principal_id,reserved_cents,actual_cents,status,body,created_at,updated_at) VALUES($1,$2,$3,0,$4,$5,$6,$6) ON CONFLICT(workload_id) DO UPDATE SET principal_id=EXCLUDED.principal_id,reserved_cents=EXCLUDED.reserved_cents,actual_cents=0,status=EXCLUDED.status,body=EXCLUDED.body,updated_at=EXCLUDED.updated_at`, workloadID, principalID, amountCents, reservation.Status, body, now); execErr != nil {
			return nil, nil, false, false, execErr
		}
		created = true
	}
	now := time.Now().UTC()
	workload.BudgetReservationToken = reservation.OwnershipToken
	workload.BudgetReservationAttempt = reservation.Attempt
	workload.BudgetReservationCents = reservation.ReservedCents
	workload.BudgetReservationLimitCents = reservation.LimitCents
	workload.BudgetReservationCurrency = reservation.Currency
	workload.Revision = expectedRevision + 1
	workload.UpdatedAt = now
	updatedBody, marshalErr := json.Marshal(&workload)
	if marshalErr != nil {
		return nil, nil, false, false, marshalErr
	}
	result, execErr := tx.ExecContext(ctx, `UPDATE workloads SET status=$2,body=$3,updated_at=$4 WHERE id=$1 AND COALESCE((body->>'revision')::bigint,0)=$5 AND status=$6 AND COALESCE(body->>'cancellation_owner','')=$7`, workloadID, workload.Status, updatedBody, now, int64(expectedRevision), expectedStatus, expectedCancellationOwner)
	if execErr != nil {
		return nil, nil, false, false, execErr
	}
	rows, _ := result.RowsAffected()
	if rows != 1 {
		return nil, nil, false, false, ErrWorkloadConflict
	}
	if err := tx.Commit(); err != nil {
		return nil, nil, false, false, err
	}
	return &reservation, &workload, true, created, nil
}

func (p *PostgresWorkloadStore) SettleBudget(ctx context.Context, workloadID string, actualCents int64) (*domain.BudgetReservation, error) {
	return nil, errors.New("budget settlement requires ownership token")
}

func (p *PostgresWorkloadStore) SettleBudgetClaim(ctx context.Context, workloadID, ownershipToken string, attempt uint64, actualCents int64) (*domain.BudgetReservation, error) {
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var body []byte
	if err := tx.QueryRowContext(ctx, `SELECT body FROM budget_reservations WHERE workload_id=$1 FOR UPDATE`, workloadID).Scan(&body); err != nil {
		return nil, translateSQLError(err)
	}
	var reservation domain.BudgetReservation
	if err := json.Unmarshal(body, &reservation); err != nil {
		return nil, err
	}
	if ownershipToken == "" || reservation.OwnershipToken != ownershipToken || attempt == 0 || reservation.Attempt != attempt {
		return nil, ErrWorkloadConflict
	}
	if actualCents < 0 {
		actualCents = 0
	}
	if reservation.Status == domain.BudgetSettled {
		if reservation.ActualCents == actualCents {
			if err := tx.Commit(); err != nil {
				return nil, err
			}
			return &reservation, nil
		}
		return nil, ErrWorkloadConflict
	}
	if reservation.Status != domain.BudgetReserved {
		return nil, ErrWorkloadConflict
	}
	reservation.ActualCents = actualCents
	reservation.Status = domain.BudgetSettled
	reservation.Revision++
	reservation.UpdatedAt = time.Now().UTC()
	body, _ = json.Marshal(&reservation)
	result, err := tx.ExecContext(ctx, `UPDATE budget_reservations SET actual_cents=$2,status=$3,body=$4,updated_at=$5 WHERE workload_id=$1 AND status='reserved' AND body->>'ownership_token'=$6`, workloadID, actualCents, reservation.Status, body, reservation.UpdatedAt, ownershipToken)
	if err != nil {
		return nil, err
	}
	rows, _ := result.RowsAffected()
	if rows != 1 {
		return nil, ErrWorkloadConflict
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &reservation, nil
}

func (p *PostgresWorkloadStore) ReleaseBudget(ctx context.Context, workloadID string) error {
	return errors.New("budget release requires ownership token")
}

func (p *PostgresWorkloadStore) ReleaseBudgetClaim(ctx context.Context, workloadID, ownershipToken string, attempt uint64) error {
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var body []byte
	if err := tx.QueryRowContext(ctx, `SELECT body FROM budget_reservations WHERE workload_id=$1 FOR UPDATE`, workloadID).Scan(&body); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		return err
	}
	var reservation domain.BudgetReservation
	if err := json.Unmarshal(body, &reservation); err != nil {
		return err
	}
	if ownershipToken == "" || reservation.OwnershipToken != ownershipToken || attempt == 0 || reservation.Attempt != attempt {
		if reservation.OwnershipToken != ownershipToken {
			return ErrWorkloadConflict
		}
		return ErrWorkloadConflict
	}
	if reservation.Status == domain.BudgetReleased {
		if err := tx.Commit(); err != nil {
			return err
		}
		return nil
	}
	if reservation.Status != domain.BudgetReserved {
		return ErrWorkloadConflict
	}
	reservation.Status = domain.BudgetReleased
	reservation.Revision++
	reservation.UpdatedAt = time.Now().UTC()
	body, _ = json.Marshal(&reservation)
	result, err := tx.ExecContext(ctx, `UPDATE budget_reservations SET status=$2,body=$3,updated_at=$4 WHERE workload_id=$1 AND status='reserved' AND body->>'ownership_token'=$5`, workloadID, reservation.Status, body, reservation.UpdatedAt, ownershipToken)
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows != 1 {
		return ErrWorkloadConflict
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	return nil
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
	result, err := p.db.ExecContext(ctx, `INSERT INTO scheduler_interference_profiles(profile_key,accelerator_id,runtime_version,body,confidence,version,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(profile_key) DO UPDATE SET accelerator_id=EXCLUDED.accelerator_id,runtime_version=EXCLUDED.runtime_version,body=EXCLUDED.body,confidence=EXCLUDED.confidence,version=EXCLUDED.version,updated_at=EXCLUDED.updated_at WHERE scheduler_interference_profiles.version < EXCLUDED.version`, profile.Key, profile.AcceleratorID, profile.RuntimeVersion, body, profile.Confidence, profile.Version, profile.UpdatedAt)
	if err != nil {
		return nil, err
	}
	if rows, rowsErr := result.RowsAffected(); rowsErr == nil && rows == 0 {
		return nil, ErrInterferenceProfileConflict
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
