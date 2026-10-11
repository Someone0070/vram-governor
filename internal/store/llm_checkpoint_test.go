package store

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"vram-governor/internal/domain"
)

// llmCheckpointSQLFake is a small executable database/sql driver. It stores
// both the JSON body and the indexed columns used by the PostgreSQL methods,
// so these tests exercise the store's database calls and CAS predicates rather
// than merely checking emitted SQL strings.
type llmCheckpointSQLFake struct{}

type llmCheckpointSQLFakeRow struct {
	body             []byte
	id, owner, key   string
	phase            string
	target, accel    string
	slot             int64
	createdAt        time.Time
	indexedUpdatedAt time.Time
}

type llmCheckpointSQLFakeState struct {
	mu     sync.Mutex
	rows   map[string]llmCheckpointSQLFakeRow
	leases map[string]llmCheckpointSQLFakeLease
	fences map[string]int64
}

type llmCheckpointSQLFakeLease struct {
	acceleratorID string
	workloadID    string
	fencingToken  int64
	expiresAt     time.Time
}

type llmCheckpointSQLFakeConn struct{ state *llmCheckpointSQLFakeState }

type llmCheckpointSQLFakeRows struct {
	columns []string
	values  [][]driver.Value
	index   int
}

type llmCheckpointSQLFakeResult int64

func (r llmCheckpointSQLFakeResult) LastInsertId() (int64, error) { return 0, nil }
func (r llmCheckpointSQLFakeResult) RowsAffected() (int64, error) { return int64(r), nil }

var (
	llmCheckpointSQLFakeOnce sync.Once
	llmCheckpointSQLFakeSeq  atomic.Uint64
	llmCheckpointSQLFakes    sync.Map
)

func (llmCheckpointSQLFake) Open(name string) (driver.Conn, error) {
	state, ok := llmCheckpointSQLFakes.Load(name)
	if !ok {
		return nil, errors.New("unknown llm checkpoint fake database")
	}
	return &llmCheckpointSQLFakeConn{state: state.(*llmCheckpointSQLFakeState)}, nil
}

func (c *llmCheckpointSQLFakeConn) Prepare(string) (driver.Stmt, error) { return nil, driver.ErrSkip }
func (c *llmCheckpointSQLFakeConn) Close() error                        { return nil }
func (c *llmCheckpointSQLFakeConn) Begin() (driver.Tx, error) {
	return &llmCheckpointSQLFakeTx{}, nil
}

func (c *llmCheckpointSQLFakeConn) BeginTx(context.Context, driver.TxOptions) (driver.Tx, error) {
	// The fake serializes each statement through state.mu.  The production
	// method still exercises database/sql's serializable transaction boundary;
	// this lightweight Tx only needs to model commit/rollback for contract
	// tests and deliberately shares the same durable state.
	return &llmCheckpointSQLFakeTx{}, nil
}

type llmCheckpointSQLFakeTx struct{}

func (*llmCheckpointSQLFakeTx) Commit() error   { return nil }
func (*llmCheckpointSQLFakeTx) Rollback() error { return nil }

func (c *llmCheckpointSQLFakeConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	values := llmCheckpointSQLFakeValues(args)
	normalized := llmCheckpointSQLFakeSQL(query)
	c.state.mu.Lock()
	defer c.state.mu.Unlock()
	if strings.HasPrefix(normalized, "insert into llm_checkpoint_operations") {
		if len(values) != 12 && len(values) != 11 {
			return nil, fmt.Errorf("fake checkpoint insert argument count: %d", len(values))
		}
		var op LLMCheckpointOperation
		bodyIndex := 9
		if len(values) == 11 {
			bodyIndex = 8
		}
		body, ok := values[bodyIndex].([]byte)
		if !ok {
			return nil, fmt.Errorf("fake checkpoint body type %T", values[8])
		}
		if err := json.Unmarshal(body, &op); err != nil {
			return nil, err
		}
		id, owner, key := fmt.Sprint(values[0]), fmt.Sprint(values[1]), fmt.Sprint(values[2])
		for _, existing := range c.state.rows {
			if existing.id == id || existing.owner == owner && existing.key == key || existing.slot >= 0 && op.SlotID >= 0 && existing.slot == int64(op.SlotID) && existing.target == op.TargetID && existing.accel == op.AcceleratorID && llmCheckpointHoldsSlot(existing.phase) && llmCheckpointHoldsSlot(op.Phase) {
				// The production INSERT uses ON CONFLICT DO NOTHING. A zero
				// affected-row result lets the store resolve idempotent replay
				// versus live-slot conflict exactly as PostgreSQL does.
				return llmCheckpointSQLFakeResult(0), nil
			}
		}
		acceleratorIndex, targetIndex, slotIndex, createdIndex, updatedIndex := 6, 7, 8, 10, 11
		if len(values) == 11 {
			acceleratorIndex, targetIndex, slotIndex, createdIndex, updatedIndex = 5, 6, 7, 9, 10
		}
		createdAt, ok := values[createdIndex].(time.Time)
		if !ok {
			return nil, fmt.Errorf("fake checkpoint created_at type %T", values[9])
		}
		updatedAt, ok := values[updatedIndex].(time.Time)
		if !ok {
			return nil, fmt.Errorf("fake checkpoint updated_at type %T", values[10])
		}
		c.state.rows[id] = llmCheckpointSQLFakeRow{body: append([]byte(nil), body...), id: id, owner: owner, key: key, phase: fmt.Sprint(values[3]), target: fmt.Sprint(values[targetIndex]), accel: fmt.Sprint(values[acceleratorIndex]), slot: values[slotIndex].(int64), createdAt: createdAt, indexedUpdatedAt: updatedAt}
		return llmCheckpointSQLFakeResult(1), nil
	}
	if strings.HasPrefix(normalized, "update llm_checkpoint_operations set") {
		if len(values) != 10 && len(values) != 9 {
			return nil, fmt.Errorf("fake checkpoint update argument count: %d", len(values))
		}
		idIndex, expectedIndex, phaseIndex, accelIndex, targetIndex, slotIndex, bodyIndex, updatedIndex := 8, 9, 0, 3, 4, 5, 6, 7
		if len(values) == 9 {
			idIndex, expectedIndex, phaseIndex, accelIndex, targetIndex, slotIndex, bodyIndex, updatedIndex = 7, 8, 0, 2, 3, 4, 5, 6
		}
		id := fmt.Sprint(values[idIndex])
		row, ok := c.state.rows[id]
		if !ok {
			return llmCheckpointSQLFakeResult(0), nil
		}
		body, ok := values[bodyIndex].([]byte)
		if !ok {
			return nil, fmt.Errorf("fake checkpoint update body type %T", values[5])
		}
		var next LLMCheckpointOperation
		if err := json.Unmarshal(body, &next); err != nil {
			return nil, err
		}
		if uint64(values[expectedIndex].(int64)) != rowRevision(row.body) {
			return llmCheckpointSQLFakeResult(0), nil
		}
		for otherID, existing := range c.state.rows {
			if otherID == id || existing.slot < 0 || next.SlotID < 0 || existing.slot != int64(next.SlotID) || existing.target != next.TargetID || existing.accel != next.AcceleratorID {
				continue
			}
			if llmCheckpointHoldsSlot(existing.phase) && llmCheckpointHoldsSlot(next.Phase) {
				return llmCheckpointSQLFakeResult(0), nil
			}
		}
		updatedAt, ok := values[updatedIndex].(time.Time)
		if !ok {
			return nil, fmt.Errorf("fake checkpoint update updated_at type %T", values[6])
		}
		row.body = append([]byte(nil), body...)
		row.phase = fmt.Sprint(values[phaseIndex])
		row.target = fmt.Sprint(values[targetIndex])
		row.accel = fmt.Sprint(values[accelIndex])
		row.slot = values[slotIndex].(int64)
		row.indexedUpdatedAt = updatedAt
		c.state.rows[id] = row
		return llmCheckpointSQLFakeResult(1), nil
	}
	if strings.HasPrefix(normalized, "insert into accelerator_leases") {
		if len(values) != 4 {
			return nil, fmt.Errorf("fake accelerator lease insert argument count: %d", len(values))
		}
		acceleratorID, workloadID := fmt.Sprint(values[0]), fmt.Sprint(values[1])
		fencingToken, ok := values[2].(int64)
		if !ok {
			return nil, fmt.Errorf("fake accelerator lease fence type %T", values[2])
		}
		expiresAt, ok := values[3].(time.Time)
		if !ok {
			return nil, fmt.Errorf("fake accelerator lease expiry type %T", values[3])
		}
		if c.state.leases == nil {
			c.state.leases = make(map[string]llmCheckpointSQLFakeLease)
		}
		c.state.leases[acceleratorID] = llmCheckpointSQLFakeLease{acceleratorID: acceleratorID, workloadID: workloadID, fencingToken: fencingToken, expiresAt: expiresAt}
		return llmCheckpointSQLFakeResult(1), nil
	}
	return nil, fmt.Errorf("unsupported llm checkpoint fake Exec SQL: %s", normalized)
}

func (c *llmCheckpointSQLFakeConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	values := llmCheckpointSQLFakeValues(args)
	normalized := llmCheckpointSQLFakeSQL(query)
	c.state.mu.Lock()
	defer c.state.mu.Unlock()
	if strings.Contains(normalized, "from accelerator_leases") {
		acceleratorID := fmt.Sprint(values[0])
		if lease, ok := c.state.leases[acceleratorID]; ok {
			return &llmCheckpointSQLFakeRows{columns: []string{"accelerator_id", "workload_id", "fencing_token", "expires_at"}, values: [][]driver.Value{{lease.acceleratorID, lease.workloadID, lease.fencingToken, lease.expiresAt}}}, nil
		}
		return &llmCheckpointSQLFakeRows{columns: []string{"accelerator_id", "workload_id", "fencing_token", "expires_at"}}, nil
	}
	if strings.Contains(normalized, "insert into accelerator_lease_fences") {
		acceleratorID := fmt.Sprint(values[0])
		floor := int64(0)
		if len(values) > 1 {
			floor, _ = values[1].(int64)
		}
		if c.state.fences[acceleratorID] < floor {
			c.state.fences[acceleratorID] = floor
		}
		c.state.fences[acceleratorID]++
		if c.state.fences[acceleratorID] < 1 {
			c.state.fences[acceleratorID] = 1
		}
		return &llmCheckpointSQLFakeRows{columns: []string{"last_token"}, values: [][]driver.Value{{c.state.fences[acceleratorID]}}}, nil
	}
	// The displacement lease guard uses a separate typed scan across every
	// operation row. This legacy fixture has no displacement rows, but supports
	// that production query shape explicitly rather than folding it into the
	// checkpoint body scan.
	if strings.HasPrefix(normalized, "select phase,revision,body from llm_displacement_operations") {
		return &llmCheckpointSQLFakeRows{columns: []string{"phase", "revision", "body"}}, nil
	}
	if !strings.HasPrefix(normalized, "select body from llm_checkpoint_operations") {
		return nil, fmt.Errorf("unsupported llm checkpoint fake Query SQL: %s", normalized)
	}
	selected := make([]llmCheckpointSQLFakeRow, 0, len(c.state.rows))
	switch {
	case strings.Contains(normalized, "where id=$1"):
		id := fmt.Sprint(values[0])
		if row, ok := c.state.rows[id]; ok {
			selected = append(selected, row)
		}
	case strings.Contains(normalized, "where owner_id=$1 and idempotency_key=$2"):
		owner, key := fmt.Sprint(values[0]), fmt.Sprint(values[1])
		for _, row := range c.state.rows {
			if row.owner == owner && row.key == key {
				selected = append(selected, row)
			}
		}
	case strings.Contains(normalized, "where owner_id=$1"):
		owner := fmt.Sprint(values[0])
		for _, row := range c.state.rows {
			if row.owner == owner {
				selected = append(selected, row)
			}
		}
	default:
		for _, row := range c.state.rows {
			selected = append(selected, row)
		}
	}
	if strings.Contains(normalized, "cleanup_accelerator_id") {
		acceleratorID := fmt.Sprint(values[0])
		filtered := selected[:0]
		for _, row := range selected {
			var op LLMCheckpointOperation
			if json.Unmarshal(row.body, &op) != nil || op.CleanupAcceleratorID != acceleratorID {
				continue
			}
			switch op.CleanupState {
			case "armed", "pending", "failed", "stopped":
				filtered = append(filtered, row)
			}
		}
		selected = filtered
	}
	sort.Slice(selected, func(i, j int) bool {
		if selected[i].indexedUpdatedAt.Equal(selected[j].indexedUpdatedAt) {
			return selected[i].id < selected[j].id
		}
		return selected[i].indexedUpdatedAt.Before(selected[j].indexedUpdatedAt)
	})
	rows := make([][]driver.Value, 0, len(selected))
	for _, row := range selected {
		rows = append(rows, []driver.Value{append([]byte(nil), row.body...)})
	}
	return &llmCheckpointSQLFakeRows{columns: []string{"body"}, values: rows}, nil
}

func (r *llmCheckpointSQLFakeRows) Columns() []string {
	if len(r.columns) > 0 {
		return r.columns
	}
	return []string{"body"}
}
func (r *llmCheckpointSQLFakeRows) Close() error { return nil }
func (r *llmCheckpointSQLFakeRows) Next(dst []driver.Value) error {
	if r.index >= len(r.values) {
		return io.EOF
	}
	copy(dst, r.values[r.index])
	r.index++
	return nil
}

func llmCheckpointSQLFakeValues(args []driver.NamedValue) []driver.Value {
	values := make([]driver.Value, len(args))
	for i, arg := range args {
		values[i] = arg.Value
	}
	return values
}

func llmCheckpointSQLFakeSQL(query string) string {
	return strings.ToLower(strings.Join(strings.Fields(query), " "))
}

func rowRevision(body []byte) uint64 {
	var op LLMCheckpointOperation
	if err := json.Unmarshal(body, &op); err != nil {
		return 0
	}
	return op.Revision
}

func newLLMCheckpointSQLFake(t *testing.T) (*sql.DB, *llmCheckpointSQLFakeState) {
	t.Helper()
	llmCheckpointSQLFakeOnce.Do(func() {
		sql.Register("llm-checkpoint-fake", llmCheckpointSQLFake{})
	})
	name := fmt.Sprintf("checkpoint-%d", llmCheckpointSQLFakeSeq.Add(1))
	state := &llmCheckpointSQLFakeState{rows: make(map[string]llmCheckpointSQLFakeRow), leases: make(map[string]llmCheckpointSQLFakeLease), fences: make(map[string]int64)}
	llmCheckpointSQLFakes.Store(name, state)
	db, err := sql.Open("llm-checkpoint-fake", name)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		llmCheckpointSQLFakes.Delete(name)
	})
	return db, state
}

func checkpointContractOperation(id, owner, key, target, accelerator string, slot int, phase string) *LLMCheckpointOperation {
	stamp := time.Date(2026, 9, 29, 12, 34, 56, 123456789, time.FixedZone("PDT", -7*60*60))
	return &LLMCheckpointOperation{ID: id, IdempotencyKey: key, OwnerID: owner, WorkloadID: "work-" + id, NodeID: "node-a", AcceleratorID: accelerator, TargetID: target, Model: "model-a", SlotID: slot, Generation: 7, Fence: 11, RuntimeIdentity: "runtime-a", ModelFingerprint: "model-fp-a", ProfileFingerprint: "profile-a", ContextFingerprint: "ctx:4096", ConversationID: "conversation-a", ContinuationConversationID: "continuation-a", WorkloadRevision: 7, Phase: phase, CreatedAt: stamp, UpdatedAt: stamp}
}

func TestLLMCheckpointOperationPostgresContract(t *testing.T) {
	db, state := newLLMCheckpointSQLFake(t)
	store := &PostgresWorkloadStore{db: db}
	ctx := context.Background()

	first := checkpointContractOperation("pg-op-1", "owner-a", "key-a", "target-a", "gpu-a", 4, "planned")
	created, inserted, err := store.CreateLLMCheckpointOperation(ctx, first)
	if err != nil || !inserted || created.Revision != 1 || created.Phase != "planned" {
		t.Fatalf("postgres create: %+v inserted=%v err=%v", created, inserted, err)
	}
	if !created.UpdatedAt.Equal(first.UpdatedAt.UTC().Truncate(time.Microsecond)) {
		t.Fatalf("create timestamp was not canonicalized: got=%s want=%s", created.UpdatedAt, first.UpdatedAt.UTC().Truncate(time.Microsecond))
	}
	state.mu.Lock()
	indexedUpdatedAt := state.rows[first.ID].indexedUpdatedAt
	var embedded LLMCheckpointOperation
	_ = json.Unmarshal(state.rows[first.ID].body, &embedded)
	state.mu.Unlock()
	if !embedded.UpdatedAt.Equal(indexedUpdatedAt) || !created.UpdatedAt.Equal(indexedUpdatedAt) {
		t.Fatalf("JSON/indexed UpdatedAt diverged: embedded=%s indexed=%s returned=%s", embedded.UpdatedAt, indexedUpdatedAt, created.UpdatedAt)
	}

	replay := *first
	replay.Revision = 999
	replayed, inserted, err := store.CreateLLMCheckpointOperation(ctx, &replay)
	if err != nil || inserted || replayed.ID != first.ID || replayed.Revision != 1 || replayed.Phase != "planned" {
		t.Fatalf("same identity replay: %+v inserted=%v err=%v", replayed, inserted, err)
	}
	differentID := *first
	differentID.ID = "pg-op-1-different-id"
	if _, _, err := store.CreateLLMCheckpointOperation(ctx, &differentID); !errors.Is(err, ErrLLMCheckpointConflict) {
		t.Fatalf("same owner/key with different id was accepted: %v", err)
	}
	differentOwner := *first
	differentOwner.OwnerID = "owner-b"
	differentOwner.IdempotencyKey = "key-b"
	if _, _, err := store.CreateLLMCheckpointOperation(ctx, &differentOwner); !errors.Is(err, ErrLLMCheckpointConflict) {
		t.Fatalf("same id with different owner/key was accepted: %v", err)
	}
	if byKey, err := store.GetLLMCheckpointOperationByIdempotency(ctx, first.OwnerID, first.IdempotencyKey); err != nil || byKey.ID != first.ID {
		t.Fatalf("idempotency mapping was corrupted: %+v %v", byKey, err)
	}

	if _, err := store.UpdateLLMCheckpointOperation(ctx, created, 0); !errors.Is(err, ErrLLMCheckpointConflict) {
		t.Fatalf("revision-zero CAS was accepted: %v", err)
	}
	skipped := *created
	skipped.Phase = "saved"
	skipped.PhaseOrdinal = llmCheckpointPhaseOrdinal(skipped.Phase)
	if _, err := store.UpdateLLMCheckpointOperation(ctx, &skipped, created.Revision); !errors.Is(err, ErrLLMCheckpointConflict) {
		t.Fatalf("assigned-to-saved lifecycle skip was accepted: %v", err)
	}
	assigned := *created
	assigned.Phase = "assigned"
	assigned.PhaseOrdinal = llmCheckpointPhaseOrdinal(assigned.Phase)
	assignedRow, err := store.UpdateLLMCheckpointOperation(ctx, &assigned, created.Revision)
	if err != nil || assignedRow.Phase != "assigned" {
		t.Fatalf("assignment CAS success: %+v %v", assignedRow, err)
	}
	started := *assignedRow
	started.Phase = "started"
	started.PhaseOrdinal = llmCheckpointPhaseOrdinal(started.Phase)
	startedRow, err := store.UpdateLLMCheckpointOperation(ctx, &started, assignedRow.Revision)
	if err != nil || startedRow.Phase != "started" {
		t.Fatalf("start CAS success: %+v %v", startedRow, err)
	}
	paused := *startedRow
	paused.Phase = "paused"
	paused.PhaseOrdinal = llmCheckpointPhaseOrdinal(paused.Phase)
	pausedRow, err := store.UpdateLLMCheckpointOperation(ctx, &paused, startedRow.Revision)
	if err != nil || pausedRow.Revision != 4 || pausedRow.Phase != "paused" {
		t.Fatalf("pause CAS success: %+v %v", pausedRow, err)
	}
	next := *pausedRow
	next.Phase = "saved"
	next.PhaseOrdinal = llmCheckpointPhaseOrdinal(next.Phase)
	updated, err := store.UpdateLLMCheckpointOperation(ctx, &next, pausedRow.Revision)
	if err != nil || updated.Revision != 5 || updated.Phase != "saved" {
		t.Fatalf("CAS success: %+v %v", updated, err)
	}
	state.mu.Lock()
	indexedUpdatedAt = state.rows[first.ID].indexedUpdatedAt
	_ = json.Unmarshal(state.rows[first.ID].body, &embedded)
	state.mu.Unlock()
	if !embedded.UpdatedAt.Equal(indexedUpdatedAt) || !updated.UpdatedAt.Equal(indexedUpdatedAt) {
		t.Fatalf("update JSON/indexed UpdatedAt diverged: embedded=%s indexed=%s returned=%s", embedded.UpdatedAt, indexedUpdatedAt, updated.UpdatedAt)
	}
	if _, err := store.UpdateLLMCheckpointOperation(ctx, &next, created.Revision); !errors.Is(err, ErrLLMCheckpointConflict) {
		t.Fatalf("stale CAS was accepted: %v", err)
	}
	badIdentity := *updated
	badIdentity.TargetID = "target-b"
	if _, err := store.UpdateLLMCheckpointOperation(ctx, &badIdentity, updated.Revision); !errors.Is(err, ErrLLMCheckpointConflict) {
		t.Fatalf("immutable target identity changed: %v", err)
	}

	// Same target/accelerator/slot conflicts; changing accelerator does not.
	second := checkpointContractOperation("pg-op-2", "owner-c", "key-c", "target-a", "gpu-a", 4, "planned")
	if _, _, err := store.CreateLLMCheckpointOperation(ctx, second); !errors.Is(err, ErrLLMCheckpointConflict) {
		t.Fatalf("same target/accelerator/slot was not serialized: %v", err)
	}
	differentAccelerator := checkpointContractOperation("pg-op-3", "owner-c", "key-c2", "target-a", "gpu-b", 4, "planned")
	if _, inserted, err := store.CreateLLMCheckpointOperation(ctx, differentAccelerator); err != nil || !inserted {
		t.Fatalf("different accelerator was incorrectly blocked: inserted=%v err=%v", inserted, err)
	}

	// "released" records physical slot cleanup and frees the unique slot;
	// it remains resumable, so a later restore phase is legal. The strict DAG
	// requires the durable stop confirmation before release.
	stop := *updated
	stop.Phase = "stopped"
	stop.PhaseOrdinal = llmCheckpointPhaseOrdinal(stop.Phase)
	stopped, err := store.UpdateLLMCheckpointOperation(ctx, &stop, updated.Revision)
	if err != nil || stopped.Phase != "stopped" {
		t.Fatalf("stop update: %+v %v", stopped, err)
	}
	release := *stopped
	release.Phase = "released"
	release.PhaseOrdinal = llmCheckpointPhaseOrdinal(release.Phase)
	released, err := store.UpdateLLMCheckpointOperation(ctx, &release, stopped.Revision)
	if err != nil || released.Phase != "released" {
		t.Fatalf("terminal/release update: %+v %v", released, err)
	}
	third := checkpointContractOperation("pg-op-4", "owner-d", "key-d", "target-a", "gpu-a", 4, "planned")
	if _, inserted, err := store.CreateLLMCheckpointOperation(ctx, third); err != nil || !inserted {
		t.Fatalf("released slot was not freed: inserted=%v err=%v", inserted, err)
	}
	resuming := *released
	resuming.Phase = "restore_planned"
	resuming.PhaseOrdinal = llmCheckpointPhaseOrdinal(resuming.Phase)
	resuming.SlotID = -1
	resumed, err := store.UpdateLLMCheckpointOperation(ctx, &resuming, released.Revision)
	if err != nil || resumed.Phase != "restore_planned" {
		t.Fatalf("released checkpoint could not resume: %+v %v", resumed, err)
	}
	restorePhases := []string{"restore_assigned", "reloaded", "restored", "resumed", "continued", "reused"}
	for _, phase := range restorePhases {
		next := *resumed
		next.Phase = phase
		next.PhaseOrdinal = llmCheckpointPhaseOrdinal(phase)
		next.SlotID = -1
		resumed, err = store.UpdateLLMCheckpointOperation(ctx, &next, resumed.Revision)
		if err != nil {
			t.Fatalf("restore phase %s: %v", phase, err)
		}
	}
	final := *resumed
	final.Phase = "completed"
	final.PhaseOrdinal = llmCheckpointPhaseOrdinal(final.Phase)
	if _, err := store.UpdateLLMCheckpointOperation(ctx, &final, resumed.Revision); err != nil {
		t.Fatalf("final terminal transition: %v", err)
	}

	rows, err := store.ListLLMCheckpointOperations(ctx, "owner-a")
	if err != nil || len(rows) != 1 || rows[0].ID != first.ID {
		t.Fatalf("owner-filtered list: %+v %v", rows, err)
	}
	all, err := store.ListLLMCheckpointOperations(ctx, "")
	if err != nil || len(all) != 3 {
		t.Fatalf("all list: len=%d rows=%+v err=%v", len(all), all, err)
	}

	// A reopened *sql.DB must reconstruct get/list/idempotency state from the
	// same fake durable backing store.
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	reopenedDB, err := sql.Open("llm-checkpoint-fake", findLLMCheckpointFakeDSN(state))
	if err != nil {
		t.Fatal(err)
	}
	defer reopenedDB.Close()
	reopened := &PostgresWorkloadStore{db: reopenedDB}
	if got, err := reopened.GetLLMCheckpointOperationByIdempotency(ctx, first.OwnerID, first.IdempotencyKey); err != nil || got.ID != first.ID {
		t.Fatalf("restart idempotency lookup: %+v %v", got, err)
	}

	// Two writers using the same revision have exactly one winner.
	base, err := reopened.GetLLMCheckpointOperation(ctx, differentAccelerator.ID)
	if err != nil {
		t.Fatal(err)
	}
	casResults := make(chan error, 2)
	for i := 0; i < 2; i++ {
		candidate := *base
		candidate.Error = fmt.Sprintf("writer-%d", i)
		go func(candidate LLMCheckpointOperation) {
			_, updateErr := reopened.UpdateLLMCheckpointOperation(ctx, &candidate, base.Revision)
			casResults <- updateErr
		}(candidate)
	}
	var successes, conflicts int
	for i := 0; i < 2; i++ {
		updateErr := <-casResults
		switch {
		case updateErr == nil:
			successes++
		default:
			if errors.Is(updateErr, ErrLLMCheckpointConflict) {
				conflicts++
			} else {
				t.Fatalf("concurrent CAS error: %v", updateErr)
			}
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("concurrent CAS results: successes=%d conflicts=%d", successes, conflicts)
	}
}

func findLLMCheckpointFakeDSN(state *llmCheckpointSQLFakeState) string {
	var found string
	llmCheckpointSQLFakes.Range(func(key, value any) bool {
		if value == state {
			found = key.(string)
			return false
		}
		return true
	})
	return found
}

func TestLLMCheckpointOperationRestartAndCAS(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()
	op := &LLMCheckpointOperation{ID: "op", IdempotencyKey: "key", OwnerID: "owner", WorkloadID: "w", NodeID: "node", AcceleratorID: "gpu0", TargetID: "target", Model: "model", ModelFingerprint: "model", RuntimeIdentity: "runtime", ProfileFingerprint: "profile", ContextFingerprint: "ctx:4096", ConversationID: "conv-op", ContinuationConversationID: "continuation-op", WorkloadRevision: 1, SlotID: -1, Generation: 1, Fence: 2, Phase: "planned"}
	got, created, err := s.CreateLLMCheckpointOperation(ctx, op)
	if err != nil || !created || got.Revision != 1 {
		t.Fatalf("create: %#v %v %v", got, created, err)
	}
	replay, created, err := s.CreateLLMCheckpointOperation(ctx, op)
	if err != nil || created || replay.ID != op.ID {
		t.Fatalf("replay: %#v %v %v", replay, created, err)
	}
	replay.Phase = "assigned"
	replay.PhaseOrdinal = llmCheckpointPhaseOrdinal(replay.Phase)
	updated, err := s.UpdateLLMCheckpointOperation(ctx, replay, 1)
	if err != nil || updated.Revision != 2 {
		t.Fatalf("assigned cas update: %#v %v", updated, err)
	}
	replay = updated
	replay.Phase = "started"
	replay.PhaseOrdinal = llmCheckpointPhaseOrdinal(replay.Phase)
	updated, err = s.UpdateLLMCheckpointOperation(ctx, replay, 2)
	if err != nil || updated.Revision != 3 {
		t.Fatalf("started cas update: %#v %v", updated, err)
	}
	replay = updated
	replay.Phase = "paused"
	replay.PhaseOrdinal = llmCheckpointPhaseOrdinal(replay.Phase)
	updated, err = s.UpdateLLMCheckpointOperation(ctx, replay, 3)
	if err != nil || updated.Revision != 4 {
		t.Fatalf("pause cas update: %#v %v", updated, err)
	}
	replay = updated
	replay.Phase = "saved"
	replay.PhaseOrdinal = llmCheckpointPhaseOrdinal(replay.Phase)
	updated, err = s.UpdateLLMCheckpointOperation(ctx, replay, 4)
	if err != nil || updated.Revision != 5 {
		t.Fatalf("cas update: %#v %v", updated, err)
	}
	if _, err := s.UpdateLLMCheckpointOperation(ctx, replay, 1); err == nil {
		t.Fatal("stale update accepted")
	}
	rows, err := s.ListLLMCheckpointOperations(ctx, "owner")
	if err != nil || len(rows) != 1 || rows[0].Phase != "saved" {
		t.Fatalf("restart list: %#v %v", rows, err)
	}
}

func TestLLMCheckpointOperationWorkloadRevisionReplayIdentity(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()
	base := &LLMCheckpointOperation{ID: "revision-op", IdempotencyKey: "revision-key", OwnerID: "owner", WorkloadID: "work", NodeID: "node", AcceleratorID: "gpu0", TargetID: "target", Model: "model", ModelFingerprint: "model", RuntimeIdentity: "runtime", ProfileFingerprint: "profile", ContextFingerprint: "ctx:4096", ConversationID: "conv-revision", ContinuationConversationID: "continuation-revision", WorkloadRevision: 7, SlotID: -1, Generation: 1, Fence: 2, Phase: "planned"}
	created, inserted, err := s.CreateLLMCheckpointOperation(ctx, base)
	if err != nil || !inserted || created.WorkloadRevision != 7 {
		t.Fatalf("revision-bound create failed: %+v inserted=%v err=%v", created, inserted, err)
	}
	changed := *base
	changed.WorkloadRevision = 8
	if _, inserted, err := s.CreateLLMCheckpointOperation(ctx, &changed); !errors.Is(err, ErrLLMCheckpointConflict) || inserted {
		t.Fatalf("replay with a different workload revision was accepted: inserted=%v err=%v", inserted, err)
	}
	assigned := *created
	assigned.Phase = "assigned"
	assigned.PhaseOrdinal = llmCheckpointPhaseOrdinal(assigned.Phase)
	assigned.WorkloadRevision = 8
	if _, err := s.UpdateLLMCheckpointOperation(ctx, &assigned, created.Revision); !errors.Is(err, ErrLLMCheckpointConflict) {
		t.Fatalf("CAS with a different workload revision was accepted: %v", err)
	}
}

func TestLLMCheckpointOperationWorkloadRevisionValidationParity(t *testing.T) {
	ctx := context.Background()
	type backend struct {
		name  string
		store LLMCheckpointOperationStore
		state *llmCheckpointSQLFakeState
	}

	memory := backend{name: "memory", store: NewMemoryStore()}
	db, state := newLLMCheckpointSQLFake(t)
	postgres := backend{name: "fake-postgres", store: &PostgresWorkloadStore{db: db}, state: state}

	for _, tc := range []backend{memory, postgres} {
		t.Run(tc.name, func(t *testing.T) {
			base := checkpointContractOperation("revision-parity-"+tc.name, "revision-owner", "revision-key-"+tc.name, "target", "gpu-"+tc.name, -1, "planned")
			base.WorkloadRevision = 7
			created, inserted, err := tc.store.CreateLLMCheckpointOperation(ctx, base)
			if err != nil || !inserted || created.WorkloadRevision != 7 {
				t.Fatalf("nonzero workload revision create failed: %+v inserted=%v err=%v", created, inserted, err)
			}

			replay := *base
			replay.Revision = 99
			replayed, inserted, err := tc.store.CreateLLMCheckpointOperation(ctx, &replay)
			if err != nil || inserted || replayed.ID != base.ID || replayed.WorkloadRevision != 7 {
				t.Fatalf("same revision replay was not idempotent: %+v inserted=%v err=%v", replayed, inserted, err)
			}

			changed := *base
			changed.WorkloadRevision = 8
			if _, inserted, err := tc.store.CreateLLMCheckpointOperation(ctx, &changed); !errors.Is(err, ErrLLMCheckpointConflict) || inserted {
				t.Fatalf("changed workload revision replay was accepted: inserted=%v err=%v", inserted, err)
			}

			zero := *base
			zero.ID += "-zero"
			zero.IdempotencyKey += "-zero"
			zero.WorkloadRevision = 0
			if _, inserted, err := tc.store.CreateLLMCheckpointOperation(ctx, &zero); err == nil || inserted || !strings.Contains(err.Error(), "workload revision") {
				t.Fatalf("zero workload revision root was accepted: inserted=%v err=%v", inserted, err)
			}

			assigned := *created
			assigned.Phase = "assigned"
			assigned.PhaseOrdinal = llmCheckpointPhaseOrdinal(assigned.Phase)
			assigned.WorkloadRevision = 8
			if _, err := tc.store.UpdateLLMCheckpointOperation(ctx, &assigned, created.Revision); !errors.Is(err, ErrLLMCheckpointConflict) {
				t.Fatalf("changed workload revision CAS was accepted: %v", err)
			}

			if tc.state != nil {
				tc.state.mu.Lock()
				row := tc.state.rows[base.ID]
				var body map[string]any
				if err := json.Unmarshal(row.body, &body); err != nil {
					tc.state.mu.Unlock()
					t.Fatal(err)
				}
				body["workload_revision"] = "malformed"
				row.body, err = json.Marshal(body)
				if err != nil {
					tc.state.mu.Unlock()
					t.Fatal(err)
				}
				tc.state.rows[base.ID] = row
				tc.state.mu.Unlock()
				if _, err := tc.store.GetLLMCheckpointOperation(ctx, base.ID); err == nil {
					t.Fatal("fake PostgreSQL accepted malformed workload revision")
				}
			}
		})
	}
}

func TestLLMCheckpointOperationSameSlotSerialization(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()
	first := &LLMCheckpointOperation{ID: "slot-op-1", IdempotencyKey: "slot-key-1", OwnerID: "owner-1", WorkloadID: "w1", NodeID: "node", AcceleratorID: "gpu0", TargetID: "target", Model: "model", ModelFingerprint: "model", RuntimeIdentity: "runtime", ProfileFingerprint: "profile", ContextFingerprint: "ctx:4096", ConversationID: "conv-slot1", ContinuationConversationID: "continuation-slot1", WorkloadRevision: 1, SlotID: -1, Generation: 1, Fence: 2, Phase: "planned"}
	if _, _, err := s.CreateLLMCheckpointOperation(ctx, first); err != nil {
		t.Fatal(err)
	}
	assigned := *first
	assigned.SlotID = 3
	assigned.Phase = "assigned"
	assigned.PhaseOrdinal = llmCheckpointPhaseOrdinal(assigned.Phase)
	if _, err := s.UpdateLLMCheckpointOperation(ctx, &assigned, 1); err != nil {
		t.Fatal(err)
	}
	second := &LLMCheckpointOperation{ID: "slot-op-2", IdempotencyKey: "slot-key-2", OwnerID: "owner-2", WorkloadID: "w2", NodeID: "node", AcceleratorID: "gpu0", TargetID: "target", Model: "model", ModelFingerprint: "model", RuntimeIdentity: "runtime", ProfileFingerprint: "profile", ContextFingerprint: "ctx:4096", ConversationID: "conv-slot2", ContinuationConversationID: "continuation-slot2", WorkloadRevision: 1, SlotID: -1, Generation: 1, Fence: 4, Phase: "planned"}
	if _, _, err := s.CreateLLMCheckpointOperation(ctx, second); err != nil {
		t.Fatal(err)
	}
	secondAssigned := *second
	secondAssigned.SlotID = 3
	secondAssigned.Phase = "assigned"
	secondAssigned.PhaseOrdinal = llmCheckpointPhaseOrdinal(secondAssigned.Phase)
	if _, err := s.UpdateLLMCheckpointOperation(ctx, &secondAssigned, 1); err == nil {
		t.Fatal("distinct idempotency keys acquired the same live slot")
	}
}

func TestAcceleratorLeaseAdmissionScansEveryUnresolvedCheckpointRow(t *testing.T) {
	ctx := context.Background()
	type backend struct {
		name  string
		store interface {
			CreateLLMCheckpointOperation(context.Context, *LLMCheckpointOperation) (*LLMCheckpointOperation, bool, error)
			AcquireAcceleratorLease(context.Context, string, string, time.Duration) (*domain.AcceleratorLease, bool, error)
			AcquireAcceleratorLeaseForCheckpointRecovery(context.Context, string, string, string, time.Duration) (*domain.AcceleratorLease, bool, error)
			GetLLMCheckpointOperation(context.Context, string) (*LLMCheckpointOperation, error)
		}
	}
	_ = backend{}

	// Keep this contract explicit instead of relying on a LIMIT-shaped fixture:
	// the older row is the one that must fence admission even when another
	// unresolved row was written later.
	makeOperation := func(id, workload, operation string, fence uint64) *LLMCheckpointOperation {
		op := checkpointContractOperation(id, "admission-owner", "admission-key-"+id, "admission-target", "admission-gpu", -1, "restore_planned")
		op.WorkloadID = workload
		op.SnapshotName = id + ".kv"
		op.CompensationOf = "checkpoint:" + id
		op.CleanupState = "pending"
		op.CleanupOperationID = operation
		op.CleanupAcceleratorID = "admission-gpu"
		op.CleanupTargetID = op.TargetID
		op.CleanupNodeID = op.NodeID
		op.CleanupGeneration = op.Generation
		op.CleanupFence = fence
		return op
	}

	for _, tc := range []struct {
		name  string
		store interface {
			CreateLLMCheckpointOperation(context.Context, *LLMCheckpointOperation) (*LLMCheckpointOperation, bool, error)
			AcquireAcceleratorLease(context.Context, string, string, time.Duration) (*domain.AcceleratorLease, bool, error)
			AcquireAcceleratorLeaseForCheckpointRecovery(context.Context, string, string, string, time.Duration) (*domain.AcceleratorLease, bool, error)
			GetLLMCheckpointOperation(context.Context, string) (*LLMCheckpointOperation, error)
		}
	}{
		{name: "memory", store: NewMemoryStore()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, op := range []*LLMCheckpointOperation{
				makeOperation("admission-old-"+tc.name, "old-workload", "old-operation", 11),
				makeOperation("admission-new-"+tc.name, "new-workload", "new-operation", 12),
				func() *LLMCheckpointOperation {
					op := makeOperation("admission-owned-"+tc.name, "owned-workload", "owned-operation", 13)
					op.CleanupState = "owned"
					return op
				}(),
			} {
				if _, _, err := tc.store.CreateLLMCheckpointOperation(ctx, op); err != nil {
					t.Fatal(err)
				}
			}
			for _, workload := range []string{"replacement", "old-workload"} {
				lease, acquired, err := tc.store.AcquireAcceleratorLease(ctx, "admission-gpu", workload, time.Minute)
				if err != nil || acquired || lease == nil || lease.FencingToken <= 0 {
					t.Fatalf("unresolved checkpoint custody was bypassed for %s: lease=%+v acquired=%v err=%v", workload, lease, acquired, err)
				}
			}
		})
	}

	db, _ := newLLMCheckpointSQLFake(t)
	pg := &PostgresWorkloadStore{db: db}
	t.Run("fake-postgres", func(t *testing.T) {
		for _, op := range []*LLMCheckpointOperation{
			makeOperation("admission-old-postgres", "old-workload", "old-operation", 11),
			makeOperation("admission-new-postgres", "new-workload", "new-operation", 12),
		} {
			if _, _, err := pg.CreateLLMCheckpointOperation(ctx, op); err != nil {
				t.Fatal(err)
			}
		}
		for _, workload := range []string{"replacement", "old-workload"} {
			lease, acquired, err := pg.AcquireAcceleratorLease(ctx, "admission-gpu", workload, time.Minute)
			if err != nil || acquired || lease == nil || lease.FencingToken <= 0 {
				t.Fatalf("unresolved checkpoint custody was bypassed for %s: lease=%+v acquired=%v err=%v", workload, lease, acquired, err)
			}
		}
	})

	for _, tc := range []struct {
		name  string
		store interface {
			CreateLLMCheckpointOperation(context.Context, *LLMCheckpointOperation) (*LLMCheckpointOperation, bool, error)
			AcquireAcceleratorLease(context.Context, string, string, time.Duration) (*domain.AcceleratorLease, bool, error)
			AcquireAcceleratorLeaseForCheckpointRecovery(context.Context, string, string, string, time.Duration) (*domain.AcceleratorLease, bool, error)
			GetLLMCheckpointOperation(context.Context, string) (*LLMCheckpointOperation, error)
		}
	}{
		{name: "memory", store: NewMemoryStore()},
		func() struct {
			name  string
			store interface {
				CreateLLMCheckpointOperation(context.Context, *LLMCheckpointOperation) (*LLMCheckpointOperation, bool, error)
				AcquireAcceleratorLease(context.Context, string, string, time.Duration) (*domain.AcceleratorLease, bool, error)
				AcquireAcceleratorLeaseForCheckpointRecovery(context.Context, string, string, string, time.Duration) (*domain.AcceleratorLease, bool, error)
				GetLLMCheckpointOperation(context.Context, string) (*LLMCheckpointOperation, error)
			}
		} {
			db, _ := newLLMCheckpointSQLFake(t)
			return struct {
				name  string
				store interface {
					CreateLLMCheckpointOperation(context.Context, *LLMCheckpointOperation) (*LLMCheckpointOperation, bool, error)
					AcquireAcceleratorLease(context.Context, string, string, time.Duration) (*domain.AcceleratorLease, bool, error)
					AcquireAcceleratorLeaseForCheckpointRecovery(context.Context, string, string, string, time.Duration) (*domain.AcceleratorLease, bool, error)
					GetLLMCheckpointOperation(context.Context, string) (*LLMCheckpointOperation, error)
				}
			}{name: "fake-postgres", store: &PostgresWorkloadStore{db: db}}
		}(),
	} {
		t.Run("authorized-recovery-reacquire-"+tc.name, func(t *testing.T) {
			op := makeOperation("admission-recovery-"+tc.name, "recovery-workload", "recovery-operation", 3)
			op.CleanupState = "armed"
			if _, _, err := tc.store.CreateLLMCheckpointOperation(ctx, op); err != nil {
				t.Fatal(err)
			}
			lease, acquired, err := tc.store.AcquireAcceleratorLeaseForCheckpointRecovery(ctx, "admission-gpu", "recovery-workload", "recovery-operation", time.Minute)
			if err != nil || !acquired || lease == nil || lease.FencingToken <= int64(op.CleanupFence) {
				t.Fatalf("authorized recovery could not establish fresh custody: lease=%+v acquired=%v err=%v", lease, acquired, err)
			}
			updated, err := tc.store.GetLLMCheckpointOperation(ctx, op.ID)
			if err != nil || updated.CleanupState != "pending" || updated.CleanupFence != uint64(lease.FencingToken) {
				t.Fatalf("fresh lease was not atomically journaled: op=%+v err=%v", updated, err)
			}
			if _, acquired, err := tc.store.AcquireAcceleratorLease(ctx, "admission-gpu", "recovery-workload", time.Minute); err != nil || acquired {
				t.Fatalf("ordinary same-workload reacquisition bypassed cleanup custody: acquired=%v err=%v", acquired, err)
			}
		})
	}
}
