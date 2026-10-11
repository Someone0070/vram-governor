package store

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"vram-governor/internal/domain"
)

// Executable database/sql harness for environments without a PostgreSQL
// daemon. It records and evaluates the exact SQL emitted by the production
// store, including transaction commit/rollback and CAS predicates.
type fakePGState struct {
	dsn                                                                  string
	mu                                                                   sync.Mutex
	advisoryMu                                                           sync.Mutex
	advisory                                                             map[string]*sync.Mutex
	residency, modelResidency, nodes, budgets, workloads, cleanupIntents, leases map[string][]byte
	sql                                                                  []string
	commits, rollbacks                                                   int
	failNext                                                             string
	advanceConflicts                                                     int
	expireLeasesOnFenceLock                                              bool
	expireLeaseAfterModelLock                                             bool
	expireLeaseAfterTransitionLock                                        bool
	fenceLockAttempt                                                     chan struct{}
	nodeLocksMu                                                          sync.Mutex
	nodeLocks                                                            map[string]*sync.Mutex
	insertDelay                                                          time.Duration
	activeInserts                                                        int
	maxActiveInserts                                                     int
}
type fakePGDriver struct{}

var fakePGStates sync.Map
var fakePGSeq atomic.Uint64

func (fakePGDriver) Open(name string) (driver.Conn, error) {
	v, ok := fakePGStates.Load(name)
	if !ok {
		return nil, errors.New("unknown fake postgres database")
	}
	return &fakePGConn{state: v.(*fakePGState)}, nil
}

type fakePGConn struct {
	state          *fakePGState
	activeAdvisory *sync.Mutex
	activeTx       *fakePGTx
}

func (*fakePGConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("prepare unsupported")
}
func (*fakePGConn) Close() error                                                   { return nil }
func (c *fakePGConn) Begin() (driver.Tx, error)                                    { return c.begin() }
func (c *fakePGConn) BeginTx(context.Context, driver.TxOptions) (driver.Tx, error) { return c.begin() }
func (c *fakePGConn) begin() (driver.Tx, error) {
	c.state.mu.Lock()
	r, mr, n, b, w, ci, l := clonePGRows(c.state.residency), clonePGRows(c.state.modelResidency), clonePGRows(c.state.nodes), clonePGRows(c.state.budgets), clonePGRows(c.state.workloads), clonePGRows(c.state.cleanupIntents), clonePGRows(c.state.leases)
	c.state.mu.Unlock()
	tx := &fakePGTx{conn: c, residency: r, modelResidency: mr, nodes: n, budgets: b, workloads: w, cleanupIntents: ci, leases: l, snapshotResidency: clonePGRows(r), snapshotModelResidency: clonePGRows(mr), snapshotNodes: clonePGRows(n), snapshotBudgets: clonePGRows(b), snapshotWorkloads: clonePGRows(w), snapshotCleanupIntents: clonePGRows(ci), snapshotLeases: clonePGRows(l)}
	c.activeTx = tx
	return tx, nil
}
func (c *fakePGConn) ExecContext(ctx context.Context, q string, a []driver.NamedValue) (driver.Result, error) {
	if c.activeTx != nil {
		return fakePGExec(ctx, c.state, c, c.activeTx, c.activeTx.residency, c.activeTx.modelResidency, c.activeTx.nodes, c.activeTx.budgets, c.activeTx.workloads, c.activeTx.cleanupIntents, c.activeTx.leases, q, a)
	}
	return fakePGExec(ctx, c.state, c, nil, c.state.residency, c.state.modelResidency, c.state.nodes, c.state.budgets, c.state.workloads, c.state.cleanupIntents, c.state.leases, q, a)
}
func (c *fakePGConn) QueryContext(ctx context.Context, q string, a []driver.NamedValue) (driver.Rows, error) {
	if c.activeTx != nil {
		return fakePGQuery(ctx, c.state, c, c.activeTx, c.activeTx.residency, c.activeTx.modelResidency, c.activeTx.nodes, c.activeTx.budgets, c.activeTx.workloads, c.activeTx.cleanupIntents, c.activeTx.leases, q, a)
	}
	return fakePGQuery(ctx, c.state, c, nil, c.state.residency, c.state.modelResidency, c.state.nodes, c.state.budgets, c.state.workloads, c.state.cleanupIntents, c.state.leases, q, a)
}

type fakePGTx struct {
	conn                                                                                                                 *fakePGConn
	residency, modelResidency, nodes, budgets, workloads, cleanupIntents, leases                                         map[string][]byte
	snapshotResidency, snapshotModelResidency, snapshotNodes, snapshotBudgets, snapshotWorkloads, snapshotCleanupIntents, snapshotLeases map[string][]byte
	done                                                                                                                 bool
	advisoryLock                                                                                                         *sync.Mutex
	nodeLock                                                                                                             *sync.Mutex
}

var _ driver.ExecerContext = (*fakePGTx)(nil)
var _ driver.QueryerContext = (*fakePGTx)(nil)

func (t *fakePGTx) Commit() error {
	if t.done {
		return errors.New("transaction closed")
	}
	t.conn.state.mu.Lock()
	mergePGRows(t.snapshotResidency, t.residency, t.conn.state.residency)
	mergePGRows(t.snapshotModelResidency, t.modelResidency, t.conn.state.modelResidency)
	mergePGRows(t.snapshotNodes, t.nodes, t.conn.state.nodes)
	mergePGRows(t.snapshotBudgets, t.budgets, t.conn.state.budgets)
	mergePGRows(t.snapshotWorkloads, t.workloads, t.conn.state.workloads)
	mergePGRows(t.snapshotCleanupIntents, t.cleanupIntents, t.conn.state.cleanupIntents)
	mergePGRows(t.snapshotLeases, t.leases, t.conn.state.leases)
	t.conn.state.commits++
	t.conn.state.mu.Unlock()
	t.done = true
	t.conn.activeTx = nil
	if t.advisoryLock != nil {
		t.advisoryLock.Unlock()
	} else if t.conn.activeAdvisory != nil {
		t.conn.activeAdvisory.Unlock()
		t.conn.activeAdvisory = nil
	}
	if t.nodeLock != nil {
		t.nodeLock.Unlock()
		t.nodeLock = nil
	}
	return nil
}
func (t *fakePGTx) Rollback() error {
	if t.done {
		return nil
	}
	t.conn.state.mu.Lock()
	t.conn.state.rollbacks++
	t.conn.state.mu.Unlock()
	t.done = true
	t.conn.activeTx = nil
	if t.advisoryLock != nil {
		t.advisoryLock.Unlock()
	} else if t.conn.activeAdvisory != nil {
		t.conn.activeAdvisory.Unlock()
		t.conn.activeAdvisory = nil
	}
	if t.nodeLock != nil {
		t.nodeLock.Unlock()
		t.nodeLock = nil
	}
	return nil
}
func (t *fakePGTx) ExecContext(ctx context.Context, q string, a []driver.NamedValue) (driver.Result, error) {
	return fakePGExec(ctx, t.conn.state, t.conn, t, t.residency, t.modelResidency, t.nodes, t.budgets, t.workloads, t.cleanupIntents, t.leases, q, a)
}
func (t *fakePGTx) QueryContext(ctx context.Context, q string, a []driver.NamedValue) (driver.Rows, error) {
	return fakePGQuery(ctx, t.conn.state, t.conn, t, t.residency, t.modelResidency, t.nodes, t.budgets, t.workloads, t.cleanupIntents, t.leases, q, a)
}

type fakePGRows struct {
	columns []string
	values  [][]driver.Value
	index   int
}

func (r *fakePGRows) Columns() []string { return r.columns }
func (r *fakePGRows) Close() error      { return nil }
func (r *fakePGRows) Next(dst []driver.Value) error {
	if r.index >= len(r.values) {
		return io.EOF
	}
	copy(dst, r.values[r.index])
	r.index++
	return nil
}
func clonePGRows(in map[string][]byte) map[string][]byte {
	out := make(map[string][]byte, len(in))
	for k, v := range in {
		out[k] = append([]byte(nil), v...)
	}
	return out
}
func mergePGRows(before, current, destination map[string][]byte) {
	for key, value := range current {
		if old, existed := before[key]; !existed || string(old) != string(value) {
			destination[key] = append([]byte(nil), value...)
		}
	}
	for key := range before {
		if _, exists := current[key]; !exists {
			delete(destination, key)
		}
	}
}
func pgArgs(in []driver.NamedValue) []driver.Value {
	out := make([]driver.Value, len(in))
	for i, v := range in {
		out[i] = v.Value
	}
	return out
}
func pgSQL(q string) string { return strings.ToLower(strings.Join(strings.Fields(q), " ")) }

func fakePGExec(ctx context.Context, state *fakePGState, conn *fakePGConn, tx *fakePGTx, residency, modelResidency, nodes, budgets, workloads, cleanupIntents, leases map[string][]byte, q string, named []driver.NamedValue) (driver.Result, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	v := pgArgs(named)
	n := pgSQL(q)
	state.mu.Lock()
	state.sql = append(state.sql, n)
	if state.failNext != "" && strings.Contains(n, state.failNext) {
		state.failNext = ""
		state.mu.Unlock()
		return nil, errors.New("injected fake postgres failure")
	}
	state.mu.Unlock()
	if strings.HasPrefix(n, "insert into accelerator_lease_cleanup_intents") {
		key := fmt.Sprintf("%s\x00%s\x00%d\x00%s", v[0], v[1], v[2], v[3])
		var intent domain.AcceleratorLeaseCleanupIntent
		intent.AcceleratorID, intent.Owner, intent.FencingToken = fmt.Sprint(v[0]), fmt.Sprint(v[1]), v[2].(int64)
		intent.WorkloadID, intent.ExpectedWorkloadRevision, intent.TerminalDisposition, intent.TerminalErrorCode = fmt.Sprint(v[3]), uint64(v[4].(int64)), fmt.Sprint(v[5]), fmt.Sprint(v[6])
		intent.ReleaseConfirmed, intent.TerminalPublished, intent.AuditPublished, intent.NotificationPublished, intent.BudgetSettled = v[7].(bool), v[8].(bool), v[9].(bool), v[10].(bool), v[11].(bool)
		intent.Attempts, intent.LastError = int(v[12].(int64)), fmt.Sprint(v[13])
		intent.CreatedAt, intent.UpdatedAt = v[14].(time.Time), v[15].(time.Time)
		if v[16] != nil {
			next := v[16].(time.Time)
			intent.NextRetryAt = &next
		}
		if existingBody, exists := cleanupIntents[key]; exists {
			var existing domain.AcceleratorLeaseCleanupIntent
			_ = json.Unmarshal(existingBody, &existing)
			if existing.WorkloadID != intent.WorkloadID || existing.ExpectedWorkloadRevision != intent.ExpectedWorkloadRevision || existing.TerminalDisposition != intent.TerminalDisposition || existing.TerminalErrorCode != intent.TerminalErrorCode {
				return driver.RowsAffected(0), nil
			}
			if intent.Attempts < existing.Attempts {
				intent.Attempts = existing.Attempts
			}
			intent.ReleaseConfirmed = existing.ReleaseConfirmed || intent.ReleaseConfirmed
			intent.TerminalPublished = existing.TerminalPublished || intent.TerminalPublished
			intent.AuditPublished = existing.AuditPublished || intent.AuditPublished
			intent.NotificationPublished = existing.NotificationPublished || intent.NotificationPublished
			intent.BudgetSettled = existing.BudgetSettled || intent.BudgetSettled
			intent.CreatedAt = existing.CreatedAt
		}
		body, err := json.Marshal(&intent)
		if err != nil {
			return nil, err
		}
		cleanupIntents[key] = body
		return driver.RowsAffected(1), nil
	}
	if strings.HasPrefix(n, "delete from accelerator_lease_cleanup_intents") {
		prefix := fmt.Sprintf("%s\x00%s\x00%d", v[0], v[1], v[2])
		if len(v) > 3 {
			delete(cleanupIntents, prefix+"\x00"+fmt.Sprint(v[3]))
		} else {
			for key := range cleanupIntents {
				if key == prefix || strings.HasPrefix(key, prefix+"\x00") {
					delete(cleanupIntents, key)
				}
			}
		}
		return driver.RowsAffected(1), nil
	}
	if strings.HasPrefix(n, "select pg_advisory_xact_lock") {
		key := fmt.Sprint(v[0])
		state.advisoryMu.Lock()
		lock := state.advisory[key]
		if lock == nil {
			lock = &sync.Mutex{}
			state.advisory[key] = lock
		}
		state.advisoryMu.Unlock()
		if tx != nil {
			lock.Lock()
			tx.advisoryLock = lock
			// PostgreSQL transactions acquire the advisory lock before reading
			// the resource high-water mark. Refresh the fake snapshot after the
			// wait so concurrent same-resource allocators observe the committed
			// predecessor rather than a stale begin-time view.
			state.mu.Lock()
			tx.residency = clonePGRows(state.residency)
			tx.modelResidency = clonePGRows(state.modelResidency)
			tx.nodes = clonePGRows(state.nodes)
			tx.workloads = clonePGRows(state.workloads)
			tx.leases = clonePGRows(state.leases)
			tx.snapshotResidency = clonePGRows(tx.residency)
			tx.snapshotModelResidency = clonePGRows(tx.modelResidency)
			tx.snapshotNodes = clonePGRows(tx.nodes)
			tx.snapshotWorkloads = clonePGRows(tx.workloads)
			tx.snapshotLeases = clonePGRows(tx.leases)
			state.mu.Unlock()
			if state.expireLeaseAfterModelLock { expireSemanticLeases(state, tx) }
		} else if conn != nil {
			lock.Lock()
			conn.activeAdvisory = lock
		}
		return driver.RowsAffected(0), nil
	}
	if strings.HasPrefix(n, "insert into accelerator_leases") {
		lease := &domain.AcceleratorLease{AcceleratorID: fmt.Sprint(v[0]), WorkloadID: fmt.Sprint(v[1]), FencingToken: v[2].(int64), ExpiresAt: v[3].(time.Time)}
		body, err := json.Marshal(lease)
		if err != nil { return nil, err }
		leases[lease.AcceleratorID] = body
		return driver.RowsAffected(1), nil
	}
	if strings.HasPrefix(n, "update accelerator_leases set") {
		key := fmt.Sprint(v[0])
		body, ok := leases[key]
		if !ok { return driver.RowsAffected(0), nil }
		var current domain.AcceleratorLease
		if err := json.Unmarshal(body, &current); err != nil { return nil, err }
		if current.WorkloadID != fmt.Sprint(v[1]) || current.FencingToken != v[2].(int64) { return driver.RowsAffected(0), nil }
		current.ExpiresAt = v[3].(time.Time)
		updated, err := json.Marshal(&current)
		if err != nil { return nil, err }
		leases[key] = updated
		return driver.RowsAffected(1), nil
	}
	if strings.HasPrefix(n, "delete from accelerator_leases") {
		key := fmt.Sprint(v[0])
		body, ok := leases[key]
		if !ok { return driver.RowsAffected(0), nil }
		var current domain.AcceleratorLease
		if err := json.Unmarshal(body, &current); err != nil { return nil, err }
		if current.WorkloadID != fmt.Sprint(v[1]) || current.FencingToken != v[2].(int64) { return driver.RowsAffected(0), nil }
		delete(leases, key)
		return driver.RowsAffected(1), nil
	}
	if strings.HasPrefix(n, "update model_residencies set") {
		key := fmt.Sprint(v[0]) + "\x00" + fmt.Sprint(v[1])
		old, ok := modelResidency[key]
		if !ok {
			return driver.RowsAffected(0), nil
		}
		var current domain.ModelResidency
		if err := json.Unmarshal(old, &current); err != nil {
			return nil, err
		}
		incomingGen := uint64(v[5].(int64))
		incomingFP := fmt.Sprint(v[6])
		candidate := current
		candidate.TargetGeneration = incomingGen
		candidate.ExecutionFingerprint = incomingFP
		if current.Revision != uint64(v[4].(int64)) || !residencyGenerationCompatible(&current, &candidate) {
			return driver.RowsAffected(0), nil
		}
		modelResidency[key] = append([]byte(nil), v[2].([]byte)...)
		return driver.RowsAffected(1), nil
	}
	if strings.HasPrefix(n, "insert into model_residencies") {
		key := fmt.Sprint(v[0]) + "\x00" + fmt.Sprint(v[1])
		if _, exists := modelResidency[key]; exists {
			return driver.RowsAffected(0), nil
		}
		modelResidency[key] = append([]byte(nil), v[2].([]byte)...)
		return driver.RowsAffected(1), nil
	}
	if strings.HasPrefix(n, "insert into residency_transitions") {
		state.mu.Lock()
		if state.insertDelay > 0 {
			state.activeInserts++
			if state.activeInserts > state.maxActiveInserts {
				state.maxActiveInserts = state.activeInserts
			}
		}
		delay := state.insertDelay
		state.mu.Unlock()
		if delay > 0 {
			time.Sleep(delay)
			state.mu.Lock()
			state.activeInserts--
			state.mu.Unlock()
		}
		if tx == nil {
			state.mu.Lock()
			defer state.mu.Unlock()
		}
		id, key := fmt.Sprint(v[0]), fmt.Sprint(v[1])
		if _, ok := residency[id]; ok {
			return driver.RowsAffected(0), nil
		}
		for _, b := range residency {
			var r domain.ResidencyTransition
			_ = json.Unmarshal(b, &r)
			if r.IdempotencyKey == key {
				return driver.RowsAffected(0), nil
			}
		}
		residency[id] = append([]byte(nil), v[6].([]byte)...)
		return driver.RowsAffected(1), nil
	}
	if strings.HasPrefix(n, "insert into node_commands") {
		id := fmt.Sprint(v[0])
		if _, ok := nodes[id]; ok {
			return driver.RowsAffected(0), nil
		}
		nodes[id] = append([]byte(nil), v[4].([]byte)...)
		return driver.RowsAffected(1), nil
	}
	if strings.HasPrefix(n, "update workloads set") {
		id := fmt.Sprint(v[0])
		body, ok := workloads[id]
		if !ok {
			return driver.RowsAffected(0), nil
		}
		var current domain.Workload
		if err := json.Unmarshal(body, &current); err != nil {
			return nil, err
		}
		if current.Revision != uint64(v[4].(int64)) || string(current.Status) != fmt.Sprint(v[5]) || current.CancellationOwner != fmt.Sprint(v[6]) {
			return driver.RowsAffected(0), nil
		}
		workloads[id] = append([]byte(nil), v[2].([]byte)...)
		return driver.RowsAffected(1), nil
	}
	if strings.HasPrefix(n, "insert into budget_reservations") {
		id := fmt.Sprint(v[0])
		budgets[id] = append([]byte(nil), v[4].([]byte)...)
		return driver.RowsAffected(1), nil
	}
	if strings.HasPrefix(n, "update budget_reservations set") {
		id := fmt.Sprint(v[0])
		b, ok := budgets[id]
		if !ok {
			return driver.RowsAffected(0), nil
		}
		var reservation domain.BudgetReservation
		if err := json.Unmarshal(b, &reservation); err != nil {
			return nil, err
		}
		if reservation.Status != domain.BudgetReserved || reservation.OwnershipToken != fmt.Sprint(v[len(v)-1]) {
			return driver.RowsAffected(0), nil
		}
		bodyIndex := 2
		if strings.Contains(n, "actual_cents=") {
			bodyIndex = 3
		}
		budgets[id] = append([]byte(nil), v[bodyIndex].([]byte)...)
		return driver.RowsAffected(1), nil
	}
	if strings.HasPrefix(n, "update residency_transitions set") {
		id := fmt.Sprint(v[0])
		b, ok := residency[id]
		if !ok {
			return driver.RowsAffected(0), nil
		}
		var r domain.ResidencyTransition
		if err := json.Unmarshal(b, &r); err != nil {
			return nil, err
		}
		if strings.Contains(n, "coalesce((body->>'revision')::bigint,0)") {
			if r.Revision != uint64(v[4].(int64)) || string(r.Status) != fmt.Sprint(v[5]) || r.FencingToken != v[6].(int64) {
				return driver.RowsAffected(0), nil
			}
		} else if len(v) > 7 && strings.Contains(n, "lease_origin_accelerator_id") {
			if r.LeaseOriginAcceleratorID != fmt.Sprint(v[4]) || r.LeaseOriginWorkloadID != fmt.Sprint(v[5]) ||
				r.LeaseOriginFencingToken != v[6].(int64) || r.LeaseOriginAllocated != v[7].(bool) {
				return driver.RowsAffected(0), nil
			}
		}
		if strings.Contains(n, "coalesce((body->>'revision')::bigint,0)") && strings.Contains(n, "lease_origin_accelerator_id") {
			var incoming domain.ResidencyTransition
			if err := json.Unmarshal(v[2].([]byte), &incoming); err != nil { return nil, err }
			if r.LeaseOriginAcceleratorID != incoming.LeaseOriginAcceleratorID || r.LeaseOriginWorkloadID != incoming.LeaseOriginWorkloadID ||
				r.LeaseOriginFencingToken != incoming.LeaseOriginFencingToken || r.LeaseOriginAllocated != incoming.LeaseOriginAllocated {
				return driver.RowsAffected(0), nil
			}
		}
		if strings.Contains(n, "body->>'idempotency_key'") && r.LeaseOriginAllocated {
			var incoming domain.ResidencyTransition
			if err := json.Unmarshal(v[2].([]byte), &incoming); err != nil { return nil, err }
			if verifyResidencyTransitionCanonical(&r, &incoming, true) != nil { return driver.RowsAffected(0), nil }
		}
		residency[id] = append([]byte(nil), v[2].([]byte)...)
		return driver.RowsAffected(1), nil
	}
	if strings.HasPrefix(n, "update node_commands set") {
		id := fmt.Sprint(v[0])
		b, ok := nodes[id]
		if !ok {
			return driver.RowsAffected(0), nil
		}
		var c domain.NodeCommand
		if err := json.Unmarshal(b, &c); err != nil {
			return nil, err
		}
		if strings.Contains(n, "node_id=$5") {
			if c.NodeID != fmt.Sprint(v[4]) || c.Revision != uint64(v[5].(int64)) || (!c.Uncertain && (c.Status == domain.NodeCommandSucceeded || c.Status == domain.NodeCommandFailed) && c.EvidenceKind == "authoritative_observation") {
				return driver.RowsAffected(0), nil
			}
			nodes[id] = append([]byte(nil), v[2].([]byte)...)
			return driver.RowsAffected(1), nil
		}
		// AdvanceNodeCommandRecovery has only the revision predicate (the
		// operation itself increments attempts) and no delivery attempts/status
		// parameters.
		if strings.Contains(n, "evidence_kind") && !strings.Contains(n, "status in") {
			if tx == nil {
				state.mu.Lock()
				if state.advanceConflicts > 0 {
					state.advanceConflicts--
					state.mu.Unlock()
					return driver.RowsAffected(0), nil
				}
				state.mu.Unlock()
			}
			if c.Revision != uint64(v[4].(int64)) || !c.Uncertain || c.EvidenceKind == "authoritative_observation" {
				return driver.RowsAffected(0), nil
			}
			nodes[id] = append([]byte(nil), v[2].([]byte)...)
			return driver.RowsAffected(1), nil
		}
		expectedRevision := uint64(0)
		expectedAttempts := int(v[4].(int64))
		expectedUncertain := c.Uncertain
		statusStart := 5
		if strings.Contains(n, "body->>'revision'") {
			expectedRevision = uint64(v[4].(int64))
			expectedAttempts = int(v[5].(int64))
			expectedUncertain = v[6].(bool)
			statusStart = 7
		}
		if strings.Contains(n, "body->>'revision'") && c.Revision != expectedRevision {
			return driver.RowsAffected(0), nil
		}
		if c.Attempts != expectedAttempts || c.Uncertain != expectedUncertain {
			return driver.RowsAffected(0), nil
		}
		allowed := false
		for _, x := range v[statusStart:] {
			if string(c.Status) == fmt.Sprint(x) {
				allowed = true
			}
		}
		if !allowed {
			return driver.RowsAffected(0), nil
		}
		nodes[id] = append([]byte(nil), v[2].([]byte)...)
		return driver.RowsAffected(1), nil
	}
	return nil, fmt.Errorf("unsupported fake Exec SQL: %s", n)
}
func fakePGQuery(ctx context.Context, state *fakePGState, conn *fakePGConn, tx *fakePGTx, residency, modelResidency, nodes, budgets, workloads, cleanupIntents, leases map[string][]byte, q string, named []driver.NamedValue) (driver.Rows, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	v := pgArgs(named)
	n := pgSQL(q)
	state.mu.Lock()
	state.sql = append(state.sql, n)
	state.mu.Unlock()
	if strings.HasPrefix(n, "insert into accelerator_lease_fences") && strings.Contains(n, "returning last_token") {
		key := "lease-fence:" + fmt.Sprint(v[0])
		state.nodeLocksMu.Lock()
		lock := state.nodeLocks[key]
		if lock == nil { lock = &sync.Mutex{}; state.nodeLocks[key] = lock }
		state.nodeLocksMu.Unlock()
		if tx != nil {
			if state.fenceLockAttempt != nil { select { case state.fenceLockAttempt <- struct{}{}: default: } }
			lock.Lock()
			tx.nodeLock = lock
			// Refresh after the sentinel wait so expiry and ownership are checked
			// against the currently committed lease row, not the tx's old snapshot.
			state.mu.Lock()
			if state.expireLeasesOnFenceLock {
				if body := state.leases[fmt.Sprint(v[0])]; body != nil {
					var lease domain.AcceleratorLease
					if err := json.Unmarshal(body, &lease); err != nil { state.mu.Unlock(); return nil, err }
					lease.ExpiresAt = time.Now().UTC().Add(-time.Second)
					expired, err := json.Marshal(&lease)
					if err != nil { state.mu.Unlock(); return nil, err }
					state.leases[lease.AcceleratorID] = expired
				}
			}
			tx.leases = clonePGRows(state.leases)
			tx.snapshotLeases = clonePGRows(tx.leases)
			state.mu.Unlock()
		}
		return &fakePGRows{columns: []string{"last_token"}, values: [][]driver.Value{{int64(0)}}}, nil
	}
	if strings.Contains(n, "from accelerator_leases") {
		body, ok := leases[fmt.Sprint(v[0])]
		if !ok { return nil, sql.ErrNoRows }
		var lease domain.AcceleratorLease
		if err := json.Unmarshal(body, &lease); err != nil { return nil, err }
		return &fakePGRows{columns: []string{"accelerator_id", "workload_id", "fencing_token", "expires_at"}, values: [][]driver.Value{{lease.AcceleratorID, lease.WorkloadID, lease.FencingToken, lease.ExpiresAt}}}, nil
	}
	if strings.HasPrefix(n, "select accelerator_id,owner,fencing_token") && strings.Contains(n, "where accelerator_id=$1 and owner=$2 and fencing_token=$3") {
		key := fmt.Sprintf("%s\x00%s\x00%d\x00%s", v[0], v[1], v[2], v[3])
		body, ok := cleanupIntents[key]
		if !ok {
			return &fakePGRows{columns: []string{"accelerator_id"}}, nil
		}
		var intent domain.AcceleratorLeaseCleanupIntent
		if err := json.Unmarshal(body, &intent); err != nil {
			return nil, err
		}
		return &fakePGRows{columns: []string{"accelerator_id", "owner", "fencing_token", "workload_id", "expected_workload_revision", "terminal_disposition", "terminal_error_code", "release_confirmed", "terminal_published", "audit_published", "notification_published", "budget_settled", "attempts", "last_error", "created_at", "updated_at", "next_retry_at"}, values: [][]driver.Value{{intent.AcceleratorID, intent.Owner, intent.FencingToken, intent.WorkloadID, int64(intent.ExpectedWorkloadRevision), intent.TerminalDisposition, intent.TerminalErrorCode, intent.ReleaseConfirmed, intent.TerminalPublished, intent.AuditPublished, intent.NotificationPublished, intent.BudgetSettled, int64(intent.Attempts), intent.LastError, intent.CreatedAt, intent.UpdatedAt, intent.NextRetryAt}}}, nil
	}
	if strings.HasPrefix(n, "select accelerator_id,owner,fencing_token") && strings.Contains(n, "accelerator_lease_cleanup_intents") {
		now := v[0].(time.Time)
		values := make([][]driver.Value, 0)
		for _, body := range cleanupIntents {
			var intent domain.AcceleratorLeaseCleanupIntent
			if err := json.Unmarshal(body, &intent); err != nil {
				return nil, err
			}
			if intent.NextRetryAt != nil && intent.NextRetryAt.After(now) {
				continue
			}
			values = append(values, []driver.Value{intent.AcceleratorID, intent.Owner, intent.FencingToken, intent.WorkloadID, int64(intent.ExpectedWorkloadRevision), intent.TerminalDisposition, intent.TerminalErrorCode, intent.ReleaseConfirmed, intent.TerminalPublished, intent.AuditPublished, intent.NotificationPublished, intent.BudgetSettled, int64(intent.Attempts), intent.LastError, intent.CreatedAt, intent.UpdatedAt, intent.NextRetryAt})
		}
		return &fakePGRows{columns: []string{"accelerator_id", "owner", "fencing_token", "workload_id", "expected_workload_revision", "terminal_disposition", "terminal_error_code", "release_confirmed", "terminal_published", "audit_published", "notification_published", "budget_settled", "attempts", "last_error", "created_at", "updated_at", "next_retry_at"}, values: values}, nil
	}
	if strings.HasPrefix(n, "select body from model_residencies") {
		key := fmt.Sprint(v[0]) + "\x00" + fmt.Sprint(v[1])
		body, ok := modelResidency[key]
		if !ok {
			return nil, sql.ErrNoRows
		}
		return &fakePGRows{columns: []string{"body"}, values: [][]driver.Value{{append([]byte(nil), body...)}}}, nil
	}
	if strings.HasPrefix(n, "insert into model_residencies") {
		key := fmt.Sprint(v[0]) + "\x00" + fmt.Sprint(v[1])
		incoming := append([]byte(nil), v[2].([]byte)...)
		var next domain.ModelResidency
		if err := json.Unmarshal(incoming, &next); err != nil {
			return nil, err
		}
		currentBody, exists := modelResidency[key]
		if !exists {
			modelResidency[key] = incoming
			return &fakePGRows{columns: []string{"body"}, values: [][]driver.Value{{incoming}}}, nil
		}
		var current domain.ModelResidency
		if err := json.Unmarshal(currentBody, &current); err != nil {
			return nil, err
		}
		if !residencyGenerationCompatible(&current, &next) {
			return &fakePGRows{columns: []string{"body"}, values: nil}, nil
		}
		next.Revision = current.Revision + 1
		updated, err := json.Marshal(&next)
		if err != nil {
			return nil, err
		}
		modelResidency[key] = updated
		return &fakePGRows{columns: []string{"body"}, values: [][]driver.Value{{updated}}}, nil
	}
	if tx != nil && strings.Contains(n, "for update") && !strings.Contains(n, "from budget_reservations") && !strings.Contains(n, "from residency_transitions") && !strings.Contains(n, "from accelerator_leases") {
		id := fmt.Sprint(v[0])
		state.nodeLocksMu.Lock()
		lock := state.nodeLocks[id]
		if lock == nil {
			lock = &sync.Mutex{}
			state.nodeLocks[id] = lock
		}
		state.nodeLocksMu.Unlock()
		lock.Lock()
		tx.nodeLock = lock
	}
	if strings.Contains(n, "max(nullif(body->>'fencing_token'") {
		if tx == nil {
			state.mu.Lock()
			defer state.mu.Unlock()
		}
		var max int64
		for _, b := range residency {
			var r domain.ResidencyTransition
			_ = json.Unmarshal(b, &r)
			if r.TargetID == fmt.Sprint(v[0]) && r.Model == fmt.Sprint(v[1]) && r.FencingToken > max {
				max = r.FencingToken
			}
		}
		if max == 0 {
			return &fakePGRows{columns: []string{"max"}, values: [][]driver.Value{{nil}}}, nil
		}
		return &fakePGRows{columns: []string{"max"}, values: [][]driver.Value{{max}}}, nil
	}
	if strings.Contains(n, "from residency_transitions") {
		if tx == nil {
			state.mu.Lock()
			defer state.mu.Unlock()
		}
		if strings.Contains(n, "status in") {
			values := make([][]driver.Value, 0)
			for _, b := range residency {
				var r domain.ResidencyTransition
				_ = json.Unmarshal(b, &r)
				if r.TargetID == fmt.Sprint(v[0]) && r.Model == fmt.Sprint(v[1]) && (r.Status == domain.ResidencyTransitionPlanned || r.Status == domain.ResidencyTransitionRunning || (r.Status == domain.ResidencyTransitionSucceeded && r.ProjectionRepairPending)) {
					values = append(values, []driver.Value{append([]byte(nil), b...)})
				}
			}
			return &fakePGRows{columns: []string{"body"}, values: values}, nil
		}
		if tx != nil && strings.Contains(n, "for update") && state.expireLeaseAfterTransitionLock { expireSemanticLeases(state, tx) }
		var found []byte
		if strings.Contains(n, "idempotency_key") {
			for id, b := range residency {
				var r domain.ResidencyTransition
				_ = json.Unmarshal(b, &r)
				if r.IdempotencyKey == fmt.Sprint(v[0]) || (len(v) > 1 && id == fmt.Sprint(v[1])) {
					found = b
					break
				}
			}
		} else {
			found = residency[fmt.Sprint(v[0])]
		}
		if found == nil {
			return nil, sql.ErrNoRows
		}
		return &fakePGRows{columns: []string{"body"}, values: [][]driver.Value{{append([]byte(nil), found...)}}}, nil
	}
	if strings.Contains(n, "from workloads") {
		id := fmt.Sprint(v[0])
		body, ok := workloads[id]
		if !ok {
			return nil, sql.ErrNoRows
		}
		return &fakePGRows{columns: []string{"body"}, values: [][]driver.Value{{append([]byte(nil), body...)}}}, nil
	}
	if strings.Contains(n, "from node_commands") {
		if tx == nil {
			state.mu.Lock()
			defer state.mu.Unlock()
		}
		if strings.Contains(n, "where node_id") {
			wantedNode := fmt.Sprint(v[0])
			wantedParent := ""
			if len(v) > 1 {
				wantedParent = fmt.Sprint(v[1])
			}
			values := make([][]driver.Value, 0)
			for _, b := range nodes {
				var c domain.NodeCommand
				_ = json.Unmarshal(b, &c)
				if c.NodeID == wantedNode && (wantedParent == "" || c.ReconcilesCommandID == wantedParent) {
					values = append(values, []driver.Value{append([]byte(nil), b...)})
				}
			}
			return &fakePGRows{columns: []string{"body"}, values: values}, nil
		}
		found := nodes[fmt.Sprint(v[0])]
		if found == nil {
			return nil, sql.ErrNoRows
		}
		return &fakePGRows{columns: []string{"body"}, values: [][]driver.Value{{append([]byte(nil), found...)}}}, nil
	}
	if strings.Contains(n, "from budget_reservations") {
		if strings.Contains(n, "sum(case") {
			principal := fmt.Sprint(v[0])
			var committed int64
			for _, b := range budgets {
				var reservation domain.BudgetReservation
				_ = json.Unmarshal(b, &reservation)
				if reservation.PrincipalID != principal {
					continue
				}
				if reservation.Status == domain.BudgetReserved {
					committed += reservation.ReservedCents
				} else if reservation.Status == domain.BudgetSettled {
					committed += reservation.ActualCents
				}
			}
			return &fakePGRows{columns: []string{"sum"}, values: [][]driver.Value{{committed}}}, nil
		}
		id := fmt.Sprint(v[0])
		body, ok := budgets[id]
		if !ok {
			return nil, sql.ErrNoRows
		}
		if tx != nil && strings.Contains(n, "for update") {
			state.nodeLocksMu.Lock()
			lock := state.nodeLocks["budget:"+id]
			if lock == nil {
				lock = &sync.Mutex{}
				state.nodeLocks["budget:"+id] = lock
			}
			state.nodeLocksMu.Unlock()
			lock.Lock()
			tx.nodeLock = lock
			state.mu.Lock()
			tx.budgets = clonePGRows(state.budgets)
			tx.snapshotBudgets = clonePGRows(tx.budgets)
			state.mu.Unlock()
			body = tx.budgets[id]
		}
		return &fakePGRows{columns: []string{"body"}, values: [][]driver.Value{{append([]byte(nil), body...)}}}, nil
	}
	return nil, fmt.Errorf("unsupported fake Query SQL: %s", n)
}

func expireSemanticLeases(state *fakePGState, tx *fakePGTx) {
	state.mu.Lock()
	defer state.mu.Unlock()
	for id, body := range state.leases {
		var lease domain.AcceleratorLease
		if json.Unmarshal(body, &lease) != nil { continue }
		lease.ExpiresAt = time.Now().UTC().Add(-time.Second)
		expired, err := json.Marshal(&lease)
		if err != nil { continue }
		state.leases[id] = expired
	}
	tx.leases = clonePGRows(state.leases)
	tx.snapshotLeases = clonePGRows(tx.leases)
}
func newFakePG(t *testing.T) (*PostgresWorkloadStore, *fakePGState) {
	t.Helper()
	name := fmt.Sprintf("fake-%d", fakePGSeq.Add(1))
	s := &fakePGState{dsn: name, residency: map[string][]byte{}, modelResidency: map[string][]byte{}, nodes: map[string][]byte{}, budgets: map[string][]byte{}, workloads: map[string][]byte{}, cleanupIntents: map[string][]byte{}, leases: map[string][]byte{}, advisory: map[string]*sync.Mutex{}, nodeLocks: map[string]*sync.Mutex{}}
	fakePGStates.Store(name, s)
	sql.Register("vram-fake-pg-"+name, fakePGDriver{})
	db, err := sql.Open("vram-fake-pg-"+name, name)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close(); fakePGStates.Delete(name) })
	return &PostgresWorkloadStore{db: db}, s
}

// This small transactional driver exercises the exact production SQL emitted
// by the displacement journal and lease paths. Its per-accelerator mutex
// models PostgreSQL's shared fence-row lock and partial unique index; it is a
// semantic fixture, never a live PostgreSQL claim.
type displacementSemanticState struct {
	mu        sync.Mutex
	ops       map[string][]byte
	indexed   map[string]displacementSemanticIndex
	workloads map[string][]byte
	leases    map[string]domain.AcceleratorLease
	locks     map[string]*sync.Mutex
	sql       []string
}
type displacementSemanticIndex struct {
	phase    string
	revision int64
}
type displacementSemanticDriver struct{ state *displacementSemanticState }
type displacementSemanticConn struct {
	state *displacementSemanticState
	tx    *displacementSemanticTx
}
type displacementSemanticTx struct {
	conn          *displacementSemanticConn
	lock          *sync.Mutex
	pending       map[string][]byte
	pendingLeases map[string]domain.AcceleratorLease
	deletedLeases map[string]struct{}
	done          bool
}
type displacementSemanticRows struct {
	cols   []string
	values [][]driver.Value
	at     int
}

func (d displacementSemanticDriver) Open(string) (driver.Conn, error) {
	return &displacementSemanticConn{state: d.state}, nil
}
func (c *displacementSemanticConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("prepare unsupported")
}
func (c *displacementSemanticConn) Close() error { return nil }
func (c *displacementSemanticConn) Begin() (driver.Tx, error) {
	return c.BeginTx(context.Background(), driver.TxOptions{})
}
func (c *displacementSemanticConn) BeginTx(context.Context, driver.TxOptions) (driver.Tx, error) {
	c.tx = &displacementSemanticTx{conn: c, pending: map[string][]byte{}, pendingLeases: map[string]domain.AcceleratorLease{}, deletedLeases: map[string]struct{}{}}
	return c.tx, nil
}
func (c *displacementSemanticConn) ExecContext(ctx context.Context, q string, a []driver.NamedValue) (driver.Result, error) {
	return displacementSemanticExec(ctx, c.state, c.tx, q, a)
}
func (c *displacementSemanticConn) QueryContext(ctx context.Context, q string, a []driver.NamedValue) (driver.Rows, error) {
	return displacementSemanticQuery(ctx, c.state, c.tx, q, a)
}
func (t *displacementSemanticTx) Commit() error {
	if t.done {
		return errors.New("transaction closed")
	}
	t.conn.state.mu.Lock()
	for id, b := range t.pending {
		t.conn.state.ops[id] = append([]byte(nil), b...)
		var op LLMDisplacementOperation
		if json.Unmarshal(b, &op) == nil {
			t.conn.state.indexed[id] = displacementSemanticIndex{phase: op.Phase, revision: int64(op.Revision)}
		}
	}
	for id, lease := range t.pendingLeases {
		t.conn.state.leases[id] = lease
	}
	for id := range t.deletedLeases {
		delete(t.conn.state.leases, id)
	}
	t.conn.state.mu.Unlock()
	t.done = true
	t.conn.tx = nil
	if t.lock != nil {
		t.lock.Unlock()
	}
	return nil
}
func (t *displacementSemanticTx) Rollback() error {
	if t.done {
		return nil
	}
	t.done = true
	t.conn.tx = nil
	if t.lock != nil {
		t.lock.Unlock()
	}
	return nil
}
func (t *displacementSemanticTx) ExecContext(ctx context.Context, q string, a []driver.NamedValue) (driver.Result, error) {
	return displacementSemanticExec(ctx, t.conn.state, t, q, a)
}
func (t *displacementSemanticTx) QueryContext(ctx context.Context, q string, a []driver.NamedValue) (driver.Rows, error) {
	return displacementSemanticQuery(ctx, t.conn.state, t, q, a)
}
func (r *displacementSemanticRows) Columns() []string { return r.cols }
func (r *displacementSemanticRows) Close() error      { return nil }
func (r *displacementSemanticRows) Next(dst []driver.Value) error {
	if r.at >= len(r.values) {
		return io.EOF
	}
	copy(dst, r.values[r.at])
	r.at++
	return nil
}
func displacementSemanticExec(ctx context.Context, state *displacementSemanticState, tx *displacementSemanticTx, q string, a []driver.NamedValue) (driver.Result, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	v := pgArgs(a)
	n := pgSQL(q)
	state.mu.Lock()
	state.sql = append(state.sql, n)
	state.mu.Unlock()
	switch {
	case strings.HasPrefix(n, "insert into accelerator_lease_fences"):
		return driver.RowsAffected(1), nil
	case strings.HasPrefix(n, "insert into accelerator_leases"):
		tx.pendingLeases[fmt.Sprint(v[0])] = domain.AcceleratorLease{AcceleratorID: fmt.Sprint(v[0]), WorkloadID: fmt.Sprint(v[1]), FencingToken: v[2].(int64), ExpiresAt: v[3].(time.Time)}
		return driver.RowsAffected(1), nil
	case strings.HasPrefix(n, "update accelerator_leases set"):
		key := fmt.Sprint(v[0])
		state.mu.Lock()
		current, ok := state.leases[key]
		state.mu.Unlock()
		if !ok || current.WorkloadID != fmt.Sprint(v[1]) || current.FencingToken != v[2].(int64) { return driver.RowsAffected(0), nil }
		current.ExpiresAt = v[3].(time.Time)
		tx.pendingLeases[key] = current
		return driver.RowsAffected(1), nil
	case strings.HasPrefix(n, "delete from accelerator_leases"):
		key := fmt.Sprint(v[0])
		state.mu.Lock()
		current, ok := state.leases[key]
		state.mu.Unlock()
		if !ok || current.WorkloadID != fmt.Sprint(v[1]) || current.FencingToken != v[2].(int64) { return driver.RowsAffected(0), nil }
		tx.deletedLeases[key] = struct{}{}
		return driver.RowsAffected(1), nil
	case strings.HasPrefix(n, "insert into llm_displacement_operations"):
		var incoming LLMDisplacementOperation
		if err := json.Unmarshal(v[9].([]byte), &incoming); err != nil {
			return nil, err
		}
		state.mu.Lock()
		defer state.mu.Unlock()
		for _, body := range state.ops {
			var old LLMDisplacementOperation
			_ = json.Unmarshal(body, &old)
			if old.ID == incoming.ID || (old.OwnerID == incoming.OwnerID && old.IdempotencyKey == incoming.IdempotencyKey) || (old.AcceleratorID == incoming.AcceleratorID && displacementUnresolved(old.Phase)) {
				return nil, errors.New("duplicate key violates llm_displacement constraint")
			}
		}
		tx.pending[incoming.ID] = append([]byte(nil), v[9].([]byte)...)
		return driver.RowsAffected(1), nil
	case strings.HasPrefix(n, "update llm_displacement_operations"):
		id := fmt.Sprint(v[4])
		state.mu.Lock()
		oldBody := state.ops[id]
		state.mu.Unlock()
		if oldBody == nil {
			return driver.RowsAffected(0), nil
		}
		var old LLMDisplacementOperation
		if err := json.Unmarshal(oldBody, &old); err != nil {
			return nil, err
		}
		if old.Revision != uint64(v[5].(int64)) {
			return driver.RowsAffected(0), nil
		}
		tx.pending[id] = append([]byte(nil), v[2].([]byte)...)
		return driver.RowsAffected(1), nil
	default:
		return nil, fmt.Errorf("unsupported displacement semantic Exec SQL: %s", n)
	}
}
func displacementSemanticQuery(ctx context.Context, state *displacementSemanticState, tx *displacementSemanticTx, q string, a []driver.NamedValue) (driver.Rows, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	v := pgArgs(a)
	n := pgSQL(q)
	state.mu.Lock()
	state.sql = append(state.sql, n)
	state.mu.Unlock()
	if strings.Contains(n, "insert into accelerator_lease_fences") && strings.Contains(n, "do update") && strings.Contains(n, "returning last_token") && strings.Contains(n, "values($1,0)") {
		key := fmt.Sprint(v[0])
		state.mu.Lock()
		lock := state.locks[key]
		if lock == nil {
			lock = &sync.Mutex{}
			state.locks[key] = lock
		}
		state.mu.Unlock()
		lock.Lock()
		tx.lock = lock
		return &displacementSemanticRows{cols: []string{"last_token"}, values: [][]driver.Value{{int64(0)}}}, nil
	}
	if strings.Contains(n, "insert into accelerator_lease_fences") && strings.Contains(n, "returning last_token") {
		return &displacementSemanticRows{cols: []string{"last_token"}, values: [][]driver.Value{{int64(1)}}}, nil
	}
	if strings.Contains(n, "from accelerator_lease_fences") {
		return &displacementSemanticRows{cols: []string{"last_token"}, values: [][]driver.Value{{int64(0)}}}, nil
	}
	if strings.Contains(n, "from accelerator_leases") {
		state.mu.Lock()
		defer state.mu.Unlock()
		lease, ok := state.leases[fmt.Sprint(v[0])]
		if !ok {
			return nil, sql.ErrNoRows
		}
		return &displacementSemanticRows{cols: []string{"accelerator_id", "workload_id", "fencing_token", "expires_at"}, values: [][]driver.Value{{lease.AcceleratorID, lease.WorkloadID, lease.FencingToken, lease.ExpiresAt}}}, nil
	}
	if strings.Contains(n, "from workloads") {
		state.mu.Lock()
		defer state.mu.Unlock()
		body := state.workloads[fmt.Sprint(v[0])]
		if body == nil {
			return nil, sql.ErrNoRows
		}
		return &displacementSemanticRows{cols: []string{"body"}, values: [][]driver.Value{{append([]byte(nil), body...)}}}, nil
	}
	if strings.HasPrefix(n, "select phase,revision,body from llm_displacement_operations") {
		state.mu.Lock()
		defer state.mu.Unlock()
		values := make([][]driver.Value, 0)
		for id, body := range state.ops {
			var op LLMDisplacementOperation
			if err := json.Unmarshal(body, &op); err != nil {
				return nil, err
			}
			if op.AcceleratorID != fmt.Sprint(v[0]) {
				continue
			}
			idx, ok := state.indexed[id]
			if !ok {
				idx = displacementSemanticIndex{phase: op.Phase, revision: int64(op.Revision)}
			}
			values = append(values, []driver.Value{idx.phase, idx.revision, append([]byte(nil), body...)})
		}
		return &displacementSemanticRows{cols: []string{"phase", "revision", "body"}, values: values}, nil
	}
	if strings.Contains(n, "from llm_displacement_operations") {
		state.mu.Lock()
		defer state.mu.Unlock()
		for _, body := range state.ops {
			var op LLMDisplacementOperation
			if err := json.Unmarshal(body, &op); err != nil {
				return nil, err
			}
			match := false
			switch {
			case strings.Contains(n, "where id=$1"):
				match = op.ID == fmt.Sprint(v[0])
			case strings.Contains(n, "where owner_id=$1"):
				match = op.OwnerID == fmt.Sprint(v[0]) && op.IdempotencyKey == fmt.Sprint(v[1])
			case strings.Contains(n, "phase <> 'completed'"):
				match = op.AcceleratorID == fmt.Sprint(v[0]) && displacementUnresolved(op.Phase)
			}
			if match {
				return &displacementSemanticRows{cols: []string{"body"}, values: [][]driver.Value{{append([]byte(nil), body...)}}}, nil
			}
		}
		if strings.Contains(n, "phase <> 'completed'") {
			return &displacementSemanticRows{cols: []string{"body"}}, nil
		}
		return nil, sql.ErrNoRows
	}
	if strings.Contains(n, "from llm_checkpoint_operations") {
		return &displacementSemanticRows{cols: []string{"body"}}, nil
	}
	return nil, fmt.Errorf("unsupported displacement semantic Query SQL: %s", n)
}

func newDisplacementSemanticPG(t *testing.T) (*PostgresWorkloadStore, *displacementSemanticState) {
	t.Helper()
	state := &displacementSemanticState{ops: map[string][]byte{}, indexed: map[string]displacementSemanticIndex{}, workloads: map[string][]byte{}, leases: map[string]domain.AcceleratorLease{}, locks: map[string]*sync.Mutex{}}
	name := fmt.Sprintf("displacement-semantic-%d", fakePGSeq.Add(1))
	sql.Register("vram-"+name, displacementSemanticDriver{state})
	db, err := sql.Open("vram-"+name, name)
	if err != nil {
		t.Fatal(err)
	}
	backing := &PostgresWorkloadStore{db: db}
	t.Cleanup(func() { _ = db.Close() })
	return backing, state
}

func displacementWorldWorkload(op *LLMDisplacementOperation, victim bool) *domain.Workload {
	binding := op.UrgentBinding
	id, owner, revision := op.UrgentWorkloadID, op.UrgentOwnerID, op.UrgentWorkloadRevision
	status := domain.WorkloadQueued
	if victim {
		binding = op.VictimBinding
		id, owner, revision = op.VictimWorkloadID, op.VictimOwnerID, op.VictimWorkloadRevision
		status = domain.WorkloadRunning
	}
	now := time.Now().UTC()
	return &domain.Workload{Request: domain.WorkloadRequest{ID: id, OwnerID: owner}, Revision: revision, Status: status, Plan: &domain.ExecutionPlan{ID: binding.ControllerPlanID, WorkloadID: id, PlanHash: binding.ControllerPlanHash, TargetID: binding.TargetID, AcceleratorID: op.AcceleratorID}, ProgressNode: op.NodeID, CreatedAt: now, UpdatedAt: now}
}
func seedDisplacementSemanticWorld(state *displacementSemanticState, op *LLMDisplacementOperation) {
	// A live PostgreSQL TIMESTAMPTZ value is microsecond precision. Keep the
	// semantic fixture's caller and stored lease identical to Acquire's value.
	op.OriginalLease.ExpiresAt = op.OriginalLease.ExpiresAt.UTC().Truncate(time.Microsecond)
	victim, _ := json.Marshal(displacementWorldWorkload(op, true))
	urgent, _ := json.Marshal(displacementWorldWorkload(op, false))
	state.mu.Lock()
	defer state.mu.Unlock()
	state.workloads[op.VictimWorkloadID] = victim
	state.workloads[op.UrgentWorkloadID] = urgent
	lease := *op.OriginalLease
	state.leases[op.AcceleratorID] = lease
}

func completedDisplacementFixture(op *LLMDisplacementOperation) *LLMDisplacementOperation {
	completed := cloneLLMDisplacementOperation(op)
	completed.Phase = "completed"
	completed.Revision = uint64(len(displacementPhases))
	for _, step := range displacementSteps {
		commandID := "cmd-" + step
		completed.CommandIntents = append(completed.CommandIntents, LLMDisplacementCommandIntent{Step: step, CommandID: commandID, Digest: "intent-" + step, Signature: "intent-signature-" + step})
		resultID := "result-" + step
		if step == "snapshot" {
			resultID = "snapshot-authenticated"
		}
		result := displacementResult(step, commandID, resultID, "result-digest-"+step, completed.ProofBinding)
		completed.ObservedResults = append(completed.ObservedResults, result)
		if step == "snapshot" {
			completed.SnapshotIdentity = resultID
		}
	}
	completed.SafeBoundaryObserved = true
	completed.SnapshotObserved = true
	completed.VictimStopObserved = true
	completed.UrgentLoadObserved = true
	completed.UrgentStopObserved = true
	completed.VictimReloadObserved = true
	completed.KVRestoreObserved = true
	completed.LeaseSettled = true
	completed.SnapshotCustodySettled = true
	completed.ObservedProof = completed.ObservedResults[len(completed.ObservedResults)-1].Digest
	return completed
}

func seedDisplacementSemanticOperation(state *displacementSemanticState, op *LLMDisplacementOperation, indexedPhase string, indexedRevision int64) {
	body, _ := json.Marshal(op)
	if indexedPhase == "" {
		indexedPhase = op.Phase
	}
	if indexedRevision == 0 {
		indexedRevision = int64(op.Revision)
	}
	state.mu.Lock()
	state.ops[op.ID] = body
	state.indexed[op.ID] = displacementSemanticIndex{phase: indexedPhase, revision: indexedRevision}
	state.mu.Unlock()
}

func TestPostgresLLMDisplacementSemantics(t *testing.T) {
	backing, state := newDisplacementSemanticPG(t)
	ctx := context.Background()
	t.Run("create_locks_before_idempotency_and_is_idempotent", func(t *testing.T) {
		state.mu.Lock()
		state.sql = nil
		state.mu.Unlock()
		op := displacementFixture("pg-op", "gpu0")
		seedDisplacementSemanticWorld(state, op)
		if _, created, err := backing.CreateLLMDisplacementOperation(ctx, op); err != nil || !created {
			t.Fatalf("create: created=%t err=%v", created, err)
		}
		state.mu.Lock()
		var victim domain.Workload
		_ = json.Unmarshal(state.workloads[op.VictimWorkloadID], &victim)
		victim.Revision++
		expired := state.leases[op.AcceleratorID]
		expired.ExpiresAt = time.Now().Add(-time.Hour)
		state.workloads[op.VictimWorkloadID], _ = json.Marshal(victim)
		state.leases[op.AcceleratorID] = expired
		state.mu.Unlock()
		if _, created, err := backing.CreateLLMDisplacementOperation(ctx, op); err != nil || created {
			t.Fatalf("retry: created=%t err=%v", created, err)
		}
		state.mu.Lock()
		defer state.mu.Unlock()
		fenceLock, idempotency := -1, -1
		for i, q := range state.sql {
			if strings.Contains(q, "insert into accelerator_lease_fences") && strings.Contains(q, "do update") && strings.Contains(q, "returning last_token") {
				fenceLock = i
			}
			if strings.Contains(q, "from llm_displacement_operations") && strings.Contains(q, "where id=$1") {
				idempotency = i
			}
		}
		if fenceLock < 0 || idempotency <= fenceLock {
			t.Fatalf("fence lock order invalid: %v", state.sql)
		}
	})
	t.Run("create_validates_stored_world", func(t *testing.T) {
		cases := []struct {
			name   string
			mutate func(*displacementSemanticState, *LLMDisplacementOperation)
		}{
			{"victim_revision", func(s *displacementSemanticState, o *LLMDisplacementOperation) {
				var w domain.Workload
				_ = json.Unmarshal(s.workloads[o.VictimWorkloadID], &w)
				w.Revision++
				s.workloads[o.VictimWorkloadID], _ = json.Marshal(w)
			}},
			{"cross_owner", func(s *displacementSemanticState, o *LLMDisplacementOperation) {
				var w domain.Workload
				_ = json.Unmarshal(s.workloads[o.UrgentWorkloadID], &w)
				w.Request.OwnerID = "other-owner"
				s.workloads[o.UrgentWorkloadID], _ = json.Marshal(w)
			}},
			{"cross_node", func(s *displacementSemanticState, o *LLMDisplacementOperation) {
				var w domain.Workload
				_ = json.Unmarshal(s.workloads[o.VictimWorkloadID], &w)
				w.ProgressNode = "node-other"
				s.workloads[o.VictimWorkloadID], _ = json.Marshal(w)
			}},
			{"cross_target", func(s *displacementSemanticState, o *LLMDisplacementOperation) {
				var w domain.Workload
				_ = json.Unmarshal(s.workloads[o.UrgentWorkloadID], &w)
				w.Plan.TargetID = "target-other"
				s.workloads[o.UrgentWorkloadID], _ = json.Marshal(w)
			}},
			{"stale_fence", func(s *displacementSemanticState, o *LLMDisplacementOperation) {
				l := s.leases[o.AcceleratorID]
				l.FencingToken++
				s.leases[o.AcceleratorID] = l
			}},
			{"expired_lease", func(s *displacementSemanticState, o *LLMDisplacementOperation) {
				l := s.leases[o.AcceleratorID]
				l.ExpiresAt = time.Now().Add(-time.Hour)
				s.leases[o.AcceleratorID] = l
			}},
			{"missing_lease", func(s *displacementSemanticState, o *LLMDisplacementOperation) { delete(s.leases, o.AcceleratorID) }},
			{"lease_expiry_precision_mismatch", func(s *displacementSemanticState, o *LLMDisplacementOperation) {
				l := s.leases[o.AcceleratorID]
				l.ExpiresAt = l.ExpiresAt.Add(time.Nanosecond)
				s.leases[o.AcceleratorID] = l
			}},
			{"controller_plan_mismatch", func(s *displacementSemanticState, o *LLMDisplacementOperation) {
				var w domain.Workload
				_ = json.Unmarshal(s.workloads[o.VictimWorkloadID], &w)
				w.Plan.ID = "wrong-controller-plan"
				s.workloads[o.VictimWorkloadID], _ = json.Marshal(w)
			}},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				b, st := newDisplacementSemanticPG(t)
				op := displacementFixture("pg-invalid-"+tc.name, "gpu-"+tc.name)
				seedDisplacementSemanticWorld(st, op)
				st.mu.Lock()
				tc.mutate(st, op)
				st.mu.Unlock()
				if _, _, err := b.CreateLLMDisplacementOperation(ctx, op); !errors.Is(err, ErrLLMDisplacementConflict) {
					t.Fatalf("stale stored world accepted: %v", err)
				}
			})
		}
	})
	t.Run("newly_acquired_expiry_is_microsecond_canonical", func(t *testing.T) {
		b, st := newDisplacementSemanticPG(t)
		lease, created, err := b.AcquireAcceleratorLease(ctx, "gpu-precision", "precision-workload", 1501*time.Nanosecond)
		if err != nil || !created || lease == nil {
			t.Fatalf("acquire: %+v %t %v", lease, created, err)
		}
		if lease.ExpiresAt.Nanosecond()%1000 != 0 {
			t.Fatalf("returned PostgreSQL lease retained sub-microsecond expiry: %s", lease.ExpiresAt)
		}
		st.mu.Lock()
		stored := st.leases["gpu-precision"]
		st.mu.Unlock()
		if !stored.ExpiresAt.Equal(lease.ExpiresAt) {
			t.Fatalf("returned expiry differs from stored timestamp: %s != %s", lease.ExpiresAt, stored.ExpiresAt)
		}
	})
	t.Run("fail_closed_completed_and_malformed_displacement_rows", func(t *testing.T) {
		cases := []struct {
			name   string
			mutate func(*LLMDisplacementOperation) (string, int64)
		}{
			{"malformed_completed_normal_phase_revision", func(op *LLMDisplacementOperation) (string, int64) { op.Revision = 1; return "", 0 }},
			{"malformed_completed_history", func(op *LLMDisplacementOperation) (string, int64) { op.ObservedResults[0].Signature = ""; return "", 0 }},
			{"indexed_phase_body_mismatch", func(op *LLMDisplacementOperation) (string, int64) { return "planned", 0 }},
			{"indexed_revision_body_mismatch", func(op *LLMDisplacementOperation) (string, int64) { return "", int64(op.Revision + 1) }},
			{"unknown_phase_history", func(op *LLMDisplacementOperation) (string, int64) { op.Phase = "future_phase"; return "", 0 }},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				for _, recovery := range []bool{false, true} {
					b, st := newDisplacementSemanticPG(t)
					op := completedDisplacementFixture(displacementFixture("malformed-"+tc.name, "gpu-malformed"))
					indexedPhase, indexedRevision := tc.mutate(op)
					seedDisplacementSemanticOperation(st, op, indexedPhase, indexedRevision)
					var lease *domain.AcceleratorLease
					var created bool
					var err error
					if recovery {
						lease, created, err = b.AcquireAcceleratorLeaseForCheckpointRecovery(ctx, op.AcceleratorID, op.VictimWorkloadID, "checkpoint-op", time.Minute)
					} else {
						lease, created, err = b.AcquireAcceleratorLease(ctx, op.AcceleratorID, "replacement", time.Minute)
					}
					if created || (err == nil && lease == nil) {
						t.Fatalf("recovery=%t malformed displacement released custody: %+v %t %v", recovery, lease, created, err)
					}
				}
				if tc.name == "malformed_completed_normal_phase_revision" {
					b, st := newDisplacementSemanticPG(t)
					createOp := displacementFixture("create-malformed-completed-revision", "gpu-malformed-create")
					seedDisplacementSemanticWorld(st, createOp)
					malformed := completedDisplacementFixture(createOp)
					malformed.Revision = 1
					seedDisplacementSemanticOperation(st, malformed, "completed", 1)
					if _, _, err := b.CreateLLMDisplacementOperation(ctx, createOp); err == nil {
						t.Fatal("Create accepted malformed completed row with matching indexed/body revision 1")
					}
				}
			})
		}
	})
	t.Run("validated_completed_displacement_allows_acquisition", func(t *testing.T) {
		for _, recovery := range []bool{false, true} {
			b, st := newDisplacementSemanticPG(t)
			op := completedDisplacementFixture(displacementFixture("completed-valid", "gpu-completed"))
			seedDisplacementSemanticOperation(st, op, "", 0)
			var lease *domain.AcceleratorLease
			var created bool
			var err error
			if recovery {
				lease, created, err = b.AcquireAcceleratorLeaseForCheckpointRecovery(ctx, op.AcceleratorID, "replacement", "checkpoint-op", time.Minute)
			} else {
				lease, created, err = b.AcquireAcceleratorLease(ctx, op.AcceleratorID, "replacement", time.Minute)
			}
			if err != nil || !created || lease == nil || lease.WorkloadID != "replacement" {
				t.Fatalf("recovery=%t validated completed row blocked new acquisition: %+v %t %v", recovery, lease, created, err)
			}
		}
	})
	t.Run("ordinary_and_recovery_acquire_block_after_shared_lock", func(t *testing.T) {
		state.mu.Lock()
		expired := state.leases["gpu0"]
		expired.ExpiresAt = time.Now().Add(-time.Hour)
		state.leases["gpu0"] = expired
		state.mu.Unlock()
		for _, recovery := range []bool{false, true} {
			state.mu.Lock()
			state.sql = nil
			state.mu.Unlock()
			var lease *domain.AcceleratorLease
			var created bool
			var err error
			for _, workload := range []string{"victim", "urgent", "other-workload"} {
				if recovery {
					lease, created, err = backing.AcquireAcceleratorLeaseForCheckpointRecovery(ctx, "gpu0", workload, "checkpoint-op", time.Minute)
				} else {
					lease, created, err = backing.AcquireAcceleratorLease(ctx, "gpu0", workload, time.Minute)
				}
				if err != nil || created || lease == nil {
					t.Fatalf("recovery=%t workload=%s escaped unresolved expired journal: %+v %t %v", recovery, workload, lease, created, err)
				}
			}
			state.mu.Lock()
			fenceLock, leaseRead, unresolved := -1, -1, -1
			for i, q := range state.sql {
				if strings.Contains(q, "insert into accelerator_lease_fences") && strings.Contains(q, "do update") {
					fenceLock = i
				}
				if strings.Contains(q, "from accelerator_leases") {
					leaseRead = i
				}
				if strings.Contains(q, "select phase,revision,body from llm_displacement_operations") {
					unresolved = i
				}
			}
			state.mu.Unlock()
			if fenceLock < 0 || leaseRead <= fenceLock || unresolved <= fenceLock {
				t.Fatalf("recovery=%t lock did not precede both checks", recovery)
			}
		}
	})
	t.Run("unique_unresolved_conflict_rolls_back", func(t *testing.T) {
		world := displacementFixture("world-reset", "gpu0")
		seedDisplacementSemanticWorld(state, world)
		state.mu.Lock()
		before := len(state.ops)
		state.mu.Unlock()
		second := displacementFixture("second-pg-op", "gpu0")
		second.OriginalLease = world.OriginalLease
		_, _, err := backing.CreateLLMDisplacementOperation(ctx, second)
		if !errors.Is(err, ErrLLMDisplacementConflict) {
			t.Fatalf("second unresolved operation result: %v", err)
		}
		state.mu.Lock()
		after := len(state.ops)
		state.mu.Unlock()
		if after != before {
			t.Fatalf("failed insert changed durable operations: before=%d after=%d", before, after)
		}
	})
	t.Run("concurrent_intent_creation_serializes", func(t *testing.T) {
		world := displacementFixture("race-world", "gpu-race")
		seedDisplacementSemanticWorld(state, world)
		var wg sync.WaitGroup
		errs := make(chan error, 2)
		for _, id := range []string{"race-a", "race-b"} {
			wg.Add(1)
			go func(id string) {
				defer wg.Done()
				op := displacementFixture(id, "gpu-race")
				op.OriginalLease = world.OriginalLease
				_, _, err := backing.CreateLLMDisplacementOperation(ctx, op)
				errs <- err
			}(id)
		}
		wg.Wait()
		close(errs)
		created, conflict := 0, 0
		for err := range errs {
			if err == nil {
				created++
			} else if errors.Is(err, ErrLLMDisplacementConflict) {
				conflict++
			} else {
				t.Fatalf("unexpected concurrent PG result: %v", err)
			}
		}
		if created != 1 || conflict != 1 {
			t.Fatalf("concurrent PG create created=%d conflicts=%d", created, conflict)
		}
	})
}

// TestDeterministicPostgresResidencyAndNodeCASHarness exercises the production
// Postgres transaction/CAS methods against a deterministic transactional test
// driver. It is deliberately named as a semantic harness: it is not a live
// PostgreSQL integration test. The verifier runs the real migration fixture
// separately, and a DSN-gated integration test remains the live-database path.
func TestDeterministicPostgresResidencyAndNodeCASHarness(t *testing.T) {
	backing, state := newFakePG(t)
	ctx := context.Background()
	var wg sync.WaitGroup
	rows := make(chan *domain.ResidencyTransition, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			r, _, err := backing.AllocateResidencyTransition(ctx, &domain.ResidencyTransition{ID: fmt.Sprintf("pg-%d", i), IdempotencyKey: fmt.Sprintf("pg-key-%d", i), TargetID: "target", Model: "model", FromTier: domain.ResidencyColdDisk, ToTier: domain.ResidencyHotVRAM, Reason: "harness", Status: domain.ResidencyTransitionPlanned, CreatedAt: time.Now().UTC()})
			if err != nil {
				t.Errorf("allocate: %v", err)
				return
			}
			rows <- r
		}(i)
	}
	wg.Wait()
	close(rows)
	seen := map[int64]bool{}
	for r := range rows {
		if seen[r.FencingToken] {
			t.Fatalf("duplicate fence %d", r.FencingToken)
		}
		seen[r.FencingToken] = true
	}
	if len(seen) != 8 {
		t.Fatalf("expected 8 fences, got %d", len(seen))
	}
	// Independent advisory keys must overlap; only allocators for the same
	// canonical target/model are serialized by the production transaction.
	state.mu.Lock()
	state.insertDelay = 25 * time.Millisecond
	state.maxActiveInserts = 0
	state.mu.Unlock()
	var independent sync.WaitGroup
	for _, targetID := range []string{"independent-a", "independent-b"} {
		independent.Add(1)
		go func(targetID string) {
			defer independent.Done()
			if _, _, err := backing.AllocateResidencyTransition(ctx, &domain.ResidencyTransition{ID: "independent-" + targetID, IdempotencyKey: "independent-key-" + targetID, TargetID: targetID, Model: "model", FromTier: domain.ResidencyColdDisk, ToTier: domain.ResidencyHotVRAM, Reason: "independent", Status: domain.ResidencyTransitionPlanned, CreatedAt: time.Now().UTC()}); err != nil {
				t.Errorf("independent allocate: %v", err)
			}
		}(targetID)
	}
	independent.Wait()
	state.mu.Lock()
	maxActive := state.maxActiveInserts
	state.insertDelay = 0
	state.mu.Unlock()
	if maxActive < 2 {
		t.Fatalf("independent advisory keys were globally serialized: max concurrent inserts=%d", maxActive)
	}
	r, _, err := backing.AllocateResidencyTransition(ctx, &domain.ResidencyTransition{ID: "cas-pg", IdempotencyKey: "cas-pg-key", TargetID: "cas-target", Model: "model", FromTier: domain.ResidencyColdDisk, ToTier: domain.ResidencyHotVRAM, Reason: "cas", Status: domain.ResidencyTransitionPlanned, FencingToken: 20, CreatedAt: time.Now().UTC()})
	if err != nil {
		t.Fatal(err)
	}
	r.Status = domain.ResidencyTransitionRunning
	u, err := backing.CompareAndSwapResidencyTransition(ctx, r, r.Revision, domain.ResidencyTransitionPlanned, r.FencingToken)
	if err != nil || u.Revision != r.Revision+1 {
		t.Fatalf("transition CAS: %+v %v", u, err)
	}
	stale := *r
	stale.Status = domain.ResidencyTransitionSucceeded
	if _, err := backing.CompareAndSwapResidencyTransition(ctx, &stale, r.Revision, domain.ResidencyTransitionPlanned, r.FencingToken); !errors.Is(err, ErrResidencyTransitionConflict) {
		t.Fatalf("stale CAS accepted: %v", err)
	}
	identity := *u
	identity.Model = "other"
	if _, err := backing.CompareAndSwapResidencyTransition(ctx, &identity, u.Revision, u.Status, u.FencingToken); !errors.Is(err, ErrResidencyTransitionConflict) {
		t.Fatalf("identity CAS accepted: %v", err)
	}
	byKey, err := backing.GetResidencyTransitionByIdempotency(ctx, "cas-pg-key")
	if err != nil || byKey.ID != "cas-pg" {
		t.Fatalf("idempotency recovery query: %+v %v", byKey, err)
	}
	active, err := backing.ListActiveResidencyTransitions(ctx, "cas-target", "model")
	if err != nil || len(active) != 1 || active[0].ID != "cas-pg" {
		t.Fatalf("active recovery query: %+v %v", active, err)
	}
	state.mu.Lock()
	state.failNext = "insert into residency_transitions"
	rollbackBeforeFailure := state.rollbacks
	state.mu.Unlock()
	if _, _, err := backing.AllocateResidencyTransition(ctx, &domain.ResidencyTransition{ID: "failed-pg", IdempotencyKey: "failed-pg-key", TargetID: "failed-target", Model: "model", FromTier: domain.ResidencyColdDisk, ToTier: domain.ResidencyHotVRAM, Reason: "injected", Status: domain.ResidencyTransitionPlanned, CreatedAt: time.Now().UTC()}); err == nil {
		t.Fatal("injected production insert failure was accepted")
	}
	if _, err := backing.GetResidencyTransitionByIdempotency(ctx, "failed-pg-key"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("failed transaction leaked row: %v", err)
	}
	state.mu.Lock()
	rollbackAfterFailure := state.rollbacks
	state.mu.Unlock()
	if rollbackAfterFailure <= rollbackBeforeFailure {
		t.Fatal("injected production allocation failure did not roll back its transaction")
	}
	now := time.Now().UTC()
	c, created, err := backing.CreateNodeCommand(ctx, &domain.NodeCommand{ID: "pg-node", IdempotencyKey: "pg-node-key", NodeID: "node", Command: "load_model", Args: map[string]any{"target_id": "target", "model": "model"}, Signature: "sig", Status: domain.NodeCommandQueued, CreatedAt: now, ExpiresAt: now.Add(time.Minute), UpdatedAt: now})
	if err != nil || !created {
		t.Fatalf("node create: %+v %v %v", c, created, err)
	}
	c.Status = domain.NodeCommandSent
	c.Attempts = 1
	sent, err := backing.CompareAndSwapNodeCommandRevision(ctx, c, c.Revision, 0, false, domain.NodeCommandQueued)
	if err != nil || sent.Revision <= c.Revision {
		t.Fatalf("delivery CAS: %v", err)
	}
	staleDelivery := *sent
	staleDelivery.Status = domain.NodeCommandQueued
	if _, err := backing.CompareAndSwapNodeCommandRevision(ctx, &staleDelivery, c.Revision, sent.Attempts, false, domain.NodeCommandSent); !errors.Is(err, ErrNodeCommandConflict) {
		t.Fatalf("stale attempt accepted: %v", err)
	}
	uncertain := *sent
	uncertain.Uncertain = true
	uncertain.Error = "side effect uncertain"
	uncertainResult, err := backing.CompareAndSwapNodeCommandRevision(ctx, &uncertain, sent.Revision, sent.Attempts, false, domain.NodeCommandSent)
	if err != nil || !uncertainResult.Uncertain {
		t.Fatalf("uncertain CAS: %+v %v", uncertainResult, err)
	}
	state.mu.Lock()
	state.advanceConflicts = 8
	state.mu.Unlock()
	state.nodeLocksMu.Lock()
	rowLock := state.nodeLocks[sent.ID]
	if rowLock == nil {
		rowLock = &sync.Mutex{}
		state.nodeLocks[sent.ID] = rowLock
	}
	state.nodeLocksMu.Unlock()
	rowLock.Lock()
	advanceDone := make(chan struct {
		row *domain.NodeCommand
		err error
	}, 1)
	go func() {
		row, advanceErr := backing.AdvanceNodeCommandRecovery(ctx, sent.ID)
		advanceDone <- struct {
			row *domain.NodeCommand
			err error
		}{row: row, err: advanceErr}
	}()
	select {
	case result := <-advanceDone:
		rowLock.Unlock()
		t.Fatalf("recovery fallback ignored held row lock: row=%+v err=%v", result.row, result.err)
	case <-time.After(100 * time.Millisecond):
	}
	rowLock.Unlock()
	advancedResult := <-advanceDone
	advanced, err := advancedResult.row, advancedResult.err
	if err != nil || advanced.RecoveryAttempts != 1 || advanced.RecoveryNextAt == nil || advanced.Revision <= uncertainResult.Revision {
		t.Fatalf("durable recovery advance: %+v %v", advanced, err)
	}
	state.mu.Lock()
	remainingAdvanceConflicts := state.advanceConflicts
	state.mu.Unlock()
	if remainingAdvanceConflicts != 0 {
		t.Fatalf("recovery did not exhaust forced optimistic conflicts through row lock: remaining=%d", remainingAdvanceConflicts)
	}
	// Reopen through a distinct database/sql pool over the same durable fake
	// backend; sharing the original *sql.DB would not prove persistence across
	// controller/store reconstruction.
	reopenedDB, err := sql.Open("vram-fake-pg-"+state.dsn, state.dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer reopenedDB.Close()
	reopenedStore := &PostgresWorkloadStore{db: reopenedDB}
	reopened, err := reopenedStore.GetNodeCommand(ctx, sent.ID)
	if err != nil || reopened.RecoveryAttempts != advanced.RecoveryAttempts || reopened.RecoveryNextAt == nil || !reopened.RecoveryNextAt.Equal(*advanced.RecoveryNextAt) {
		t.Fatalf("reopened store lost durable recovery progression: row=%+v err=%v", reopened, err)
	}
	promotedObservation := json.RawMessage(`{"tier":"hot_vram","fence":7}`)
	promoted, err := backing.PromoteNodeCommandUncertain(ctx, sent.ID, sent.NodeID, promotedObservation, "dominant uncertainty")
	if err != nil || !promoted.Uncertain || promoted.Revision <= uncertainResult.Revision {
		t.Fatalf("uncertain promotion: %+v %v", promoted, err)
	}
	blocked := *sent
	blocked.Status = domain.NodeCommandFailed
	if _, err := backing.CompareAndSwapNodeCommandRevision(ctx, &blocked, sent.Revision, sent.Attempts, false, domain.NodeCommandSent); !errors.Is(err, ErrNodeCommandConflict) {
		t.Fatalf("stale blocked result overwrote uncertain row: %v", err)
	}
	settled := *promoted
	settled.Uncertain = false
	settled.Status = domain.NodeCommandSucceeded
	settled.EvidenceKind = "authoritative_observation"
	settled.Result = json.RawMessage(`{"tier":"hot_vram"}`)
	settledResult, err := backing.CompareAndSwapNodeCommandRevision(ctx, &settled, promoted.Revision, promoted.Attempts, true, domain.NodeCommandSent)
	if err != nil || settledResult.Uncertain || settledResult.Revision <= promoted.Revision {
		t.Fatalf("uncertain settlement CAS: %+v %v", settledResult, err)
	}
	if _, err := backing.PromoteNodeCommandUncertain(ctx, settledResult.ID, settledResult.NodeID, settledResult.Result, "late duplicate uncertainty"); !errors.Is(err, ErrNodeCommandConflict) {
		t.Fatalf("late uncertainty reopened authoritative settlement: %v", err)
	}
	for i := 0; i < 125; i++ {
		terminal := &domain.NodeCommand{ID: fmt.Sprintf("pg-terminal-%03d", i), IdempotencyKey: fmt.Sprintf("pg-terminal-%03d", i), NodeID: "node", Command: "load_model", Args: map[string]any{"target_id": "other", "model": "model"}, Signature: "sig", Status: domain.NodeCommandSucceeded, CreatedAt: now.Add(time.Duration(i+1) * time.Second), ExpiresAt: now.Add(time.Hour), UpdatedAt: now}
		if _, _, err := backing.CreateNodeCommand(ctx, terminal); err != nil {
			t.Fatal(err)
		}
	}
	recoveryRows, err := backing.ListNodeCommandRecovery(ctx, "node", "")
	if err != nil {
		t.Fatal(err)
	}
	foundSettled := false
	for _, row := range recoveryRows {
		if row.ID == "pg-node" && row.Status == domain.NodeCommandSucceeded && row.Revision == settledResult.Revision {
			foundSettled = true
		}
	}
	if !foundSettled || len(recoveryRows) < 126 {
		t.Fatalf("exhaustive node recovery query hid durable row: found=%v rows=%d", foundSettled, len(recoveryRows))
	}
	if state.commits == 0 || len(state.sql) == 0 {
		t.Fatal("transaction activity missing")
	}
}

func TestDeterministicPostgresModelResidencyGenerationCAS(t *testing.T) {
	backing, _ := newFakePG(t)
	ctx := context.Background()
	old := &domain.ModelResidency{ID: "target::model", TargetID: "target", Model: "model", TargetGeneration: 2, ExecutionFingerprint: "old", ObservedTier: domain.ResidencyColdDisk, UpdatedAt: time.Now().UTC()}
	stored, err := backing.UpsertModelResidency(ctx, old)
	if err != nil || stored.Revision != 1 {
		t.Fatalf("seed residency: %+v %v", stored, err)
	}
	higher := *stored
	higher.TargetGeneration = 3
	higher.ExecutionFingerprint = "new"
	higher.ObservedTier = domain.ResidencyWarmRAM
	higher.UpdatedAt = time.Now().UTC()
	replaced, err := backing.CompareAndSwapModelResidency(ctx, &higher, stored.Revision)
	if err != nil || replaced.TargetGeneration != 3 || replaced.ExecutionFingerprint != "new" || replaced.Revision != 2 {
		t.Fatalf("higher generation did not replace atomically: %+v %v", replaced, err)
	}
	sameGeneration := *replaced
	sameGeneration.ExecutionFingerprint = "different"
	if _, err := backing.CompareAndSwapModelResidency(ctx, &sameGeneration, replaced.Revision); !errors.Is(err, ErrModelResidencyGenerationConflict) {
		t.Fatalf("equal-generation fingerprint mismatch accepted: %v", err)
	}
	lower := *replaced
	lower.TargetGeneration = 1
	lower.ExecutionFingerprint = "old"
	if _, err := backing.CompareAndSwapModelResidency(ctx, &lower, replaced.Revision); !errors.Is(err, ErrModelResidencyGenerationConflict) {
		t.Fatalf("lower generation accepted: %v", err)
	}
	final, err := backing.GetModelResidency(ctx, "target", "model")
	if err != nil || final.TargetGeneration != 3 || final.ExecutionFingerprint != "new" || final.Revision != 2 {
		t.Fatalf("generation CAS changed durable row after rejection: %+v %v", final, err)
	}
}

func TestDeterministicPostgresModelResidencyFingerprintMatrix(t *testing.T) {
	cases := []struct {
		name        string
		existingFP  string
		incomingGen uint64
		incomingFP  string
		wantErr     bool
	}{
		{name: "equal-both-empty", existingFP: "", incomingGen: 2, incomingFP: "", wantErr: true},
		{name: "equal-existing-only", existingFP: "stored", incomingGen: 2, incomingFP: "", wantErr: true},
		{name: "equal-incoming-only", existingFP: "", incomingGen: 2, incomingFP: "stored", wantErr: true},
		{name: "equal-exact", existingFP: "stored", incomingGen: 2, incomingFP: "stored"},
		{name: "lower", existingFP: "stored", incomingGen: 1, incomingFP: "stored", wantErr: true},
		{name: "higher-empty", existingFP: "stored", incomingGen: 3, incomingFP: "", wantErr: true},
		{name: "legacy-upgrade", existingFP: "", incomingGen: 3, incomingFP: "new"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			backing, _ := newFakePG(t)
			ctx := context.Background()
			stored, err := backing.UpsertModelResidency(ctx, &domain.ModelResidency{ID: "matrix::model", TargetID: "matrix", Model: "model", TargetGeneration: 2, ExecutionFingerprint: tc.existingFP})
			if err != nil {
				t.Fatal(err)
			}
			incoming := *stored
			incoming.TargetGeneration = tc.incomingGen
			incoming.ExecutionFingerprint = tc.incomingFP
			_, err = backing.CompareAndSwapModelResidency(ctx, &incoming, stored.Revision)
			if tc.wantErr {
				if !errors.Is(err, ErrModelResidencyGenerationConflict) {
					t.Fatalf("matrix case accepted: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("matrix case rejected: %v", err)
			}
		})
	}
}

func TestDeterministicPostgresLeaseCleanupIntentCAS(t *testing.T) {
	backing, _ := newFakePG(t)
	ctx := context.Background()
	now := time.Now().UTC().Add(-time.Second)
	intent := &domain.AcceleratorLeaseCleanupIntent{AcceleratorID: "pg-cleanup", Owner: "owner-a", FencingToken: 7, Attempts: 4, LastError: "release failed", CreatedAt: now, UpdatedAt: now}
	if _, err := backing.RecordAcceleratorLeaseCleanupIntent(ctx, intent); err != nil {
		t.Fatal(err)
	}
	intent.Attempts = 2
	intent.LastError = "older retry"
	updated, err := backing.RecordAcceleratorLeaseCleanupIntent(ctx, intent)
	if err != nil || updated.Attempts != 4 {
		t.Fatalf("lower duplicate attempts regressed: %+v %v", updated, err)
	}
	intents, err := backing.ListAcceleratorLeaseCleanupIntents(ctx, time.Now().UTC(), 10)
	if err != nil || len(intents) != 1 || intents[0].FencingToken != 7 {
		t.Fatalf("list cleanup intent: %+v %v", intents, err)
	}
	if err := backing.DeleteAcceleratorLeaseCleanupIntent(ctx, "pg-cleanup", "owner-b", 7); err != nil {
		t.Fatal(err)
	}
	if intents, _ := backing.ListAcceleratorLeaseCleanupIntents(ctx, time.Now().UTC(), 10); len(intents) != 1 {
		t.Fatal("wrong-owner delete removed cleanup intent")
	}
	if err := backing.DeleteAcceleratorLeaseCleanupIntent(ctx, "pg-cleanup", "owner-a", 6); err != nil {
		t.Fatal(err)
	}
	if intents, _ := backing.ListAcceleratorLeaseCleanupIntents(ctx, time.Now().UTC(), 10); len(intents) != 1 {
		t.Fatal("wrong-fence delete removed cleanup intent")
	}
	if err := backing.DeleteAcceleratorLeaseCleanupIntent(ctx, "pg-cleanup", "owner-a", 7); err != nil {
		t.Fatal(err)
	}
	if intents, _ := backing.ListAcceleratorLeaseCleanupIntents(ctx, time.Now().UTC(), 10); len(intents) != 0 {
		t.Fatalf("exact cleanup delete left intent: %+v", intents)
	}
}

func TestDeterministicPostgresLeaseCleanupRetryAttemptsAdvanceAndDelete(t *testing.T) {
	backing, _ := newFakePG(t)
	ctx := context.Background()
	now := time.Now().UTC()
	intent := &domain.AcceleratorLeaseCleanupIntent{AcceleratorID: "pg-retry-gpu", Owner: "retry-owner", FencingToken: 3, Attempts: 1, LastError: "first", CreatedAt: now, UpdatedAt: now, NextRetryAt: storeTestTimePtr(now.Add(time.Second))}
	stored, err := backing.RecordAcceleratorLeaseCleanupIntent(ctx, intent)
	if err != nil || stored.Attempts != 1 {
		t.Fatalf("initial retry intent: %+v %v", stored, err)
	}
	previousNext := stored.NextRetryAt
	for attempt, delay := range []time.Duration{2 * time.Second, 4 * time.Second} {
		updated := *stored
		updated.Attempts = attempt + 2
		updated.UpdatedAt = now.Add(time.Duration(attempt+1) * time.Second)
		updated.NextRetryAt = storeTestTimePtr(now.Add(delay))
		stored, err = backing.RecordAcceleratorLeaseCleanupIntent(ctx, &updated)
		if err != nil || stored.Attempts != attempt+2 || stored.NextRetryAt == nil || !stored.NextRetryAt.After(*previousNext) {
			t.Fatalf("retry attempt %d did not advance monotonically: %+v %v", attempt+2, stored, err)
		}
		previousNext = stored.NextRetryAt
	}
	if err := backing.DeleteAcceleratorLeaseCleanupIntent(ctx, "pg-retry-gpu", "retry-owner", 3); err != nil {
		t.Fatal(err)
	}
	if rows, err := backing.ListAcceleratorLeaseCleanupIntents(ctx, now.Add(time.Hour), 10); err != nil || len(rows) != 0 {
		t.Fatalf("successful retry did not delete exact intent: %+v %v", rows, err)
	}
}

func TestDeterministicPostgresTypedLeaseCleanupIntentExactRecord(t *testing.T) {
	backing, _ := newFakePG(t)
	ctx := context.Background()
	now := time.Now().UTC().Add(-time.Second)
	future := now.Add(time.Hour)
	intent := &domain.AcceleratorLeaseCleanupIntent{
		AcceleratorID:            "pg-typed-cleanup",
		Owner:                    "owner-a",
		FencingToken:             11,
		WorkloadID:               "pg-workload",
		ExpectedWorkloadRevision: 4,
		TerminalDisposition:      "failure",
		TerminalErrorCode:        "terminal_failure",
		ReleaseConfirmed:         false,
		TerminalPublished:        false,
		AuditPublished:           false,
		NotificationPublished:    false,
		BudgetSettled:            false,
		Attempts:                 3,
		LastError:                "release failed",
		CreatedAt:                now,
		UpdatedAt:                now,
		NextRetryAt:              &future,
	}
	stored, err := backing.RecordAcceleratorLeaseCleanupIntent(ctx, intent)
	if err != nil {
		t.Fatal(err)
	}
	if stored.WorkloadID != intent.WorkloadID || stored.ExpectedWorkloadRevision != intent.ExpectedWorkloadRevision || stored.TerminalDisposition != intent.TerminalDisposition || stored.TerminalErrorCode != intent.TerminalErrorCode || stored.Attempts != intent.Attempts || stored.NextRetryAt == nil || !stored.NextRetryAt.Equal(future) {
		t.Fatalf("typed exact record lost fields: %+v", stored)
	}
	if due, err := backing.ListAcceleratorLeaseCleanupIntents(ctx, now, 10); err != nil || len(due) != 0 {
		t.Fatalf("future exact record appeared due: %+v err=%v", due, err)
	}

	conflict := *intent
	conflict.TerminalDisposition = "cancel"
	if _, err := backing.RecordAcceleratorLeaseCleanupIntent(ctx, &conflict); !errors.Is(err, ErrAcceleratorLeaseCleanupConflict) {
		t.Fatalf("conflicting typed continuation was accepted: %v", err)
	}

	progress := *intent
	progress.ReleaseConfirmed = true
	progress.TerminalPublished = true
	progress.AuditPublished = true
	progress.NotificationPublished = true
	progress.BudgetSettled = true
	progress.Attempts = 2
	progress.LastError = "older retry"
	progress.NextRetryAt = nil
	updated, err := backing.RecordAcceleratorLeaseCleanupIntent(ctx, &progress)
	if err != nil {
		t.Fatal(err)
	}
	if !updated.ReleaseConfirmed || !updated.TerminalPublished || !updated.AuditPublished || !updated.NotificationPublished || !updated.BudgetSettled || updated.Attempts != 3 {
		t.Fatalf("phase/attempt monotonicity failed: %+v", updated)
	}
}

// TestDeterministicPostgresBudgetClaimSettleReleaseConcurrency is the same
// deterministic transaction harness for budget claim ownership. It must not
// be presented as proof against a live PostgreSQL server.
func TestDeterministicPostgresBudgetClaimSettleReleaseConcurrency(t *testing.T) {
	backing, _ := newFakePG(t)
	ctx := context.Background()
	first, allowed, created, err := backing.ReserveBudgetClaim(ctx, "principal", "budget-workload", 10, 100, "attempt-a")
	if err != nil || !allowed || !created || first == nil {
		t.Fatalf("initial budget claim: reservation=%+v allowed=%t created=%t err=%v", first, allowed, created, err)
	}
	if _, allowed, created, err := backing.ReserveBudgetClaim(ctx, "principal", "budget-workload", 10, 100, "attempt-b"); !errors.Is(err, ErrWorkloadConflict) || allowed || created {
		t.Fatalf("foreign claim was accepted: allowed=%t created=%t err=%v", allowed, created, err)
	}
	if resumed, allowed, created, err := backing.ReserveBudgetClaim(ctx, "principal", "budget-workload", 10, 100, "attempt-a"); err != nil || !allowed || created || resumed.Attempt != first.Attempt {
		t.Fatalf("same-attempt resume failed: reservation=%+v allowed=%t created=%t err=%v", resumed, allowed, created, err)
	}
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() {
			_, settleErr := backing.SettleBudgetClaim(ctx, "budget-workload", "attempt-a", first.Attempt, 9)
			results <- settleErr
		}()
	}
	for i := 0; i < 2; i++ {
		if settleErr := <-results; settleErr != nil {
			t.Fatalf("same-token concurrent settle failed: %v", settleErr)
		}
	}
	if err := backing.ReleaseBudgetClaim(ctx, "budget-workload", "attempt-a", first.Attempt); !errors.Is(err, ErrWorkloadConflict) {
		t.Fatalf("opposite release after settle was accepted: %v", err)
	}
	if _, err := backing.SettleBudgetClaim(ctx, "budget-workload", "attempt-b", first.Attempt, 9); !errors.Is(err, ErrWorkloadConflict) {
		t.Fatalf("foreign settle was accepted: %v", err)
	}
	second, allowed, created, err := backing.ReserveBudgetClaim(ctx, "principal", "budget-release", 10, 100, "attempt-release")
	if err != nil || !allowed || !created {
		t.Fatalf("release claim: %+v allowed=%t created=%t err=%v", second, allowed, created, err)
	}
	if err := backing.ReleaseBudgetClaim(ctx, "budget-release", "attempt-release", second.Attempt); err != nil {
		t.Fatalf("release: %v", err)
	}
	if err := backing.ReleaseBudgetClaim(ctx, "budget-release", "attempt-release", second.Attempt); err != nil {
		t.Fatalf("same-token release idempotency: %v", err)
	}
}

func TestDeterministicPostgresReserveAndLinkBudgetClaimAtomic(t *testing.T) {
	backing, state := newFakePG(t)
	ctx := context.Background()
	now := time.Now().UTC()
	workload := &domain.Workload{Request: domain.WorkloadRequest{ID: "pg-atomic-budget", PrincipalID: "principal"}, Revision: 1, Status: domain.WorkloadQueued, CreatedAt: now, UpdatedAt: now}
	body, err := json.Marshal(workload)
	if err != nil {
		t.Fatal(err)
	}
	state.mu.Lock()
	state.workloads[workload.Request.ID] = body
	state.mu.Unlock()
	type result struct {
		reservation *domain.BudgetReservation
		workload    *domain.Workload
		err         error
	}
	results := make(chan result, 2)
	for _, token := range []string{"pg-attempt-a", "pg-attempt-b"} {
		go func(token string) {
			reservation, linked, _, _, callErr := backing.ReserveAndLinkBudgetClaim(ctx, "principal", workload.Request.ID, 17, 100, token, 1, domain.WorkloadQueued, "")
			results <- result{reservation: reservation, workload: linked, err: callErr}
		}(token)
	}
	var winner result
	conflicts := 0
	for i := 0; i < 2; i++ {
		out := <-results
		if out.err == nil {
			winner = out
		} else if errors.Is(out.err, ErrWorkloadConflict) {
			conflicts++
		} else {
			t.Fatalf("unexpected atomic claim error: %v", out.err)
		}
	}
	if winner.reservation == nil || winner.workload == nil || conflicts != 1 || winner.workload.BudgetReservationToken != winner.reservation.OwnershipToken || winner.workload.BudgetReservationCents != 17 || winner.workload.BudgetReservationLimitCents != 100 || winner.workload.BudgetReservationCurrency != defaultBudgetCurrency {
		t.Fatalf("postgres atomic claim/link failed: winner=%+v conflicts=%d", winner, conflicts)
	}
	state.mu.Lock()
	budgetBody := state.budgets[workload.Request.ID]
	workloadBody := state.workloads[workload.Request.ID]
	state.mu.Unlock()
	var storedBudget domain.BudgetReservation
	var storedWorkload domain.Workload
	if json.Unmarshal(budgetBody, &storedBudget) != nil || json.Unmarshal(workloadBody, &storedWorkload) != nil || storedBudget.Status != domain.BudgetReserved || storedBudget.PrincipalID != "principal" || storedBudget.ReservedCents != 17 || storedBudget.LimitCents != 100 || storedWorkload.Revision != 2 {
		t.Fatalf("atomic postgres rows were not durably linked: budget=%s workload=%s", budgetBody, workloadBody)
	}
}
