package jobs

import (
	"context"
	"fmt"
	"log/slog"
	"math/rand"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"vram-governor/internal/domain"
	"vram-governor/internal/store"
)

// ---------------------------------------------------------------------
// Mapping to docs/gateway-and-queue.md ("Keep" table):
//
//   lb-proxy mechanism                          -> this file
//   -------------------------------------------------------------------
//   Zero-gap dispatch (tryDispatchQueue)        -> Manager.tryDispatchLocked,
//                                                   called from SubmitJob,
//                                                   RegisterWorker, and
//                                                   completeItem/reaper (slot free)
//   Headroom-gated pick (active < maxConcurrent) -> pickWorkerLocked
//   Capacity-weighted random among candidates    -> pickWorkerLocked
//   At-least-once + cross-backend "tried" set    -> WorkItem.TriedWorkers,
//                                                   applied in failItemLocked
//   Client-abort / late-duplicate drop           -> completeItem's lease-token
//                                                   + job-cancelled checks
//
// Upgrade over lb-proxy per that doc: capacity comes from the measured
// domain.PerformanceProfile.Concurrency (RegisterWorker), leases carry real
// expiry timestamps (reapLocked), and dedupe uses the §12 identity tuple
// job_id+item_id+operation_version (ItemKey).
// ---------------------------------------------------------------------

// ItemInput is a caller-submitted work item (POST /jobs payload shape).
type ItemInput struct {
	ItemID           string         `json:"item_id,omitempty"` // generated if empty
	OperationVersion string         `json:"operation_version,omitempty"`
	Payload          map[string]any `json:"payload"`
}

// workerSlot is the manager's bookkeeping for one registered Worker.
type workerSlot struct {
	worker     Worker
	slots      int
	unmeasured bool
	active     int
}

// WorkerStatus is the read-only view of a registered worker exposed for
// visibility (measurement.md honesty rule: unmeasured capacity must be
// surfaced, never silently guessed).
type WorkerStatus struct {
	ID         string `json:"id"`
	Slots      int    `json:"slots"`
	Active     int    `json:"active"`
	Unmeasured bool   `json:"unmeasured"`
}

// Manager is the Phase 3 work-queue engine: job/work-item lifecycle,
// leases+reaper, at-least-once+dedupe, cross-worker retry, and zero-gap
// dispatch, on top of a single flat worker pool (§13 note: multi-node
// priority/spill across pools is Phase 4, out of scope here).
type Manager struct {
	log   *slog.Logger
	store store.JobStore

	mu        sync.Mutex
	jobs      map[string]*domain.Job
	items     map[itemIdentity]*domain.WorkItem
	itemOrder map[string][]itemIdentity // jobID -> full identities in submission order
	jobOrder  []string                  // job submission order (for stable listing)
	workers   map[string]*workerSlot
	leaseTok  map[itemIdentity]int64 // key: full item identity -> current lease generation

	leaseTTL           time.Duration
	defaultMaxAttempts int
	reaperInterval     time.Duration

	idSeq  int64
	stopCh chan struct{}
	doneCh chan struct{}
}

// itemIdentity is deliberately a comparable struct rather than a joined
// string. OperationVersion is part of the durable idempotency identity, and
// using fields also avoids delimiter-collision bugs.
type itemIdentity struct {
	jobID            string
	itemID           string
	operationVersion string
}

func itemKey(jobID, itemID, operationVersion string) itemIdentity {
	return itemIdentity{jobID: jobID, itemID: itemID, operationVersion: operationVersion}
}

// NewManager constructs a queue engine backed by st for persistence
// write-through. leaseTTL and reaperInterval get sane defaults if zero.
func NewManager(log *slog.Logger, st store.JobStore, leaseTTL, reaperInterval time.Duration, defaultMaxAttempts int) *Manager {
	if leaseTTL <= 0 {
		leaseTTL = 30 * time.Second
	}
	if reaperInterval <= 0 {
		reaperInterval = 500 * time.Millisecond
	}
	if defaultMaxAttempts <= 0 {
		defaultMaxAttempts = 8
	}
	return &Manager{
		log:                log,
		store:              st,
		jobs:               make(map[string]*domain.Job),
		items:              make(map[itemIdentity]*domain.WorkItem),
		itemOrder:          make(map[string][]itemIdentity),
		workers:            make(map[string]*workerSlot),
		leaseTok:           make(map[itemIdentity]int64),
		leaseTTL:           leaseTTL,
		defaultMaxAttempts: defaultMaxAttempts,
		reaperInterval:     reaperInterval,
		stopCh:             make(chan struct{}),
		doneCh:             make(chan struct{}),
	}
}

// Start launches the background lease-expiry reaper (architecture.md §12
// "lease expires -> item requeued"). Call once; Stop() to shut it down.
func (m *Manager) Start(ctx context.Context) {
	go m.reaperLoop(ctx)
}

func (m *Manager) Stop() {
	close(m.stopCh)
	<-m.doneCh
}

func (m *Manager) reaperLoop(ctx context.Context) {
	defer close(m.doneCh)
	ticker := time.NewTicker(m.reaperInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-m.stopCh:
			return
		case <-ticker.C:
			m.reapExpiredLeases()
		}
	}
}

// ---------------------------------------------------------------------
// Worker registration (capacity-add triggers zero-gap dispatch)
// ---------------------------------------------------------------------

// RegisterWorker adds w to the pool with a slot count derived from the
// measured profile's Concurrency field (Phase 2 domain.PerformanceProfile).
// profile == nil (or Concurrency <= 0) means "no measurement yet": the
// worker is marked unmeasured and defaults conservatively to 1 slot,
// per docs/measurement.md's honesty rule (never guess a number).
func (m *Manager) RegisterWorker(w Worker, profile *domain.PerformanceProfile) WorkerStatus {
	m.mu.Lock()
	slots := 1
	unmeasured := true
	if profile != nil && profile.Concurrency > 0 {
		slots = profile.Concurrency
		unmeasured = false
	}
	m.workers[w.ID()] = &workerSlot{worker: w, slots: slots, unmeasured: unmeasured}
	status := WorkerStatus{ID: w.ID(), Slots: slots, Unmeasured: unmeasured}
	m.tryDispatchLocked() // capacity added -> zero-gap dispatch
	m.mu.Unlock()

	if unmeasured {
		m.log.Warn("worker registered with UNMEASURED capacity — defaulting to 1 slot", "worker_id", w.ID())
	} else {
		m.log.Info("worker registered", "worker_id", w.ID(), "slots", slots)
	}
	return status
}

// Workers returns the current status of every registered worker, including
// the unmeasured flag (surfaced per the measurement.md honesty rule).
func (m *Manager) Workers() []WorkerStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]WorkerStatus, 0, len(m.workers))
	for id, ws := range m.workers {
		out = append(out, WorkerStatus{ID: id, Slots: ws.slots, Active: ws.active, Unmeasured: ws.unmeasured})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// ---------------------------------------------------------------------
// Job submission (new-work triggers zero-gap dispatch)
// ---------------------------------------------------------------------

func (m *Manager) nextID(prefix string) string {
	n := atomic.AddInt64(&m.idSeq, 1)
	return fmt.Sprintf("%s-%d-%d", prefix, time.Now().UnixNano(), n)
}

// SubmitJob creates a job with the given inline work items and immediately
// attempts to dispatch as much of it as current worker headroom allows
// (zero-gap dispatch — docs/gateway-and-queue.md).
func (m *Manager) SubmitJob(operation, pool string, inputs []ItemInput, maxAttempts int) (*domain.Job, error) {
	if len(inputs) == 0 {
		return nil, fmt.Errorf("jobs: submit requires at least one work item")
	}
	if maxAttempts <= 0 {
		maxAttempts = m.defaultMaxAttempts
	}
	now := time.Now().UTC()
	job := &domain.Job{
		ID:          m.nextID("job"),
		Operation:   operation,
		Pool:        pool,
		Status:      domain.JobRunning,
		CreatedAt:   now,
		UpdatedAt:   now,
		MaxAttempts: maxAttempts,
		Progress:    domain.JobProgress{Total: len(inputs), Queued: len(inputs)},
	}

	m.mu.Lock()
	m.jobs[job.ID] = job
	m.jobOrder = append(m.jobOrder, job.ID)
	order := make([]itemIdentity, 0, len(inputs))
	for i, in := range inputs {
		itemID := in.ItemID
		if itemID == "" {
			itemID = fmt.Sprintf("item-%d", i)
		}
		opVersion := in.OperationVersion
		if opVersion == "" {
			opVersion = "v1"
		}
		wi := &domain.WorkItem{
			JobID:            job.ID,
			ItemID:           itemID,
			OperationVersion: opVersion,
			State:            domain.WorkItemQueued,
			Payload:          in.Payload,
			CreatedAt:        now,
			UpdatedAt:        now,
			Seq:              int64(i),
		}
		key := itemKey(job.ID, itemID, opVersion)
		if _, exists := m.items[key]; exists {
			m.mu.Unlock()
			return nil, fmt.Errorf("jobs: duplicate item identity %q/%q", itemID, opVersion)
		}
		m.items[key] = wi
		order = append(order, key)
	}
	m.itemOrder[job.ID] = order
	m.tryDispatchLocked() // new work -> zero-gap dispatch

	// Snapshot everything for persistence/return while still holding the
	// lock — items may already be LEASED (and being mutated by a just-
	// spawned runItem goroutine) by the time tryDispatchLocked returns, so
	// reading the live pointers after Unlock would race.
	jobSnap := cloneJob(job)
	itemSnaps := make([]*domain.WorkItem, 0, len(order))
	for _, key := range order {
		itemSnaps = append(itemSnaps, cloneWorkItem(m.items[key]))
	}
	m.mu.Unlock()

	m.persistJob(jobSnap)
	for _, wi := range itemSnaps {
		m.persistItem(wi)
	}
	return jobSnap, nil
}

// ---------------------------------------------------------------------
// Zero-gap dispatch core
// ---------------------------------------------------------------------

// tryDispatchLocked fills every currently available worker slot with the
// next eligible queued item, across all non-paused/non-cancelled jobs in
// submission order. Callers must hold m.mu. This is invoked synchronously
// (never on a poll timer) from every event that can create headroom or
// work: SubmitJob, RegisterWorker, and item completion/expiry.
func (m *Manager) tryDispatchLocked() {
	for _, jobID := range m.jobOrder {
		job := m.jobs[jobID]
		if job.Status == domain.JobPaused || job.Status == domain.JobCancelled ||
			job.Status == domain.JobCompleted || job.Status == domain.JobCompletedWithErrors {
			continue
		}
		for _, key := range m.itemOrder[jobID] {
			item := m.items[key]
			if item.State != domain.WorkItemQueued {
				continue
			}
			ws, workerID := m.pickWorkerLocked(item)
			if ws == nil {
				continue // no eligible free worker right now for this item
			}
			m.leaseLocked(job, item, workerID, ws)
		}
	}
}

// pickWorkerLocked returns a worker with a free slot that has not already
// been tried for this item (the cross-backend-retry "tried" set), chosen by
// capacity-weighted random among eligible candidates (lb-proxy's baseline
// policy per docs/gateway-and-queue.md, kept until the full §37 cost
// function exists).
func (m *Manager) pickWorkerLocked(item *domain.WorkItem) (*workerSlot, string) {
	type candidate struct {
		id     string
		ws     *workerSlot
		weight int
	}
	var candidates []candidate
	for id, ws := range m.workers {
		if ws.active >= ws.slots {
			continue
		}
		if contains(item.TriedWorkers, id) {
			continue
		}
		candidates = append(candidates, candidate{id: id, ws: ws, weight: ws.slots - ws.active})
	}
	if len(candidates) == 0 {
		return nil, ""
	}
	total := 0
	for _, c := range candidates {
		total += c.weight
	}
	r := rand.Intn(total)
	for _, c := range candidates {
		if r < c.weight {
			return c.ws, c.id
		}
		r -= c.weight
	}
	last := candidates[len(candidates)-1]
	return last.ws, last.id
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

// leaseLocked transitions item QUEUED->LEASED, assigns a lease owner+expiry
// and a fresh lease token (dedupe/late-duplicate guard), then spawns the
// actual execution off-lock.
func (m *Manager) leaseLocked(job *domain.Job, item *domain.WorkItem, workerID string, ws *workerSlot) {
	now := time.Now().UTC()
	item.State = domain.WorkItemLeased
	item.LeaseOwner = workerID
	item.LeaseExpiry = now.Add(m.leaseTTL)
	item.Attempt++
	item.UpdatedAt = now
	ws.active++

	job.Progress.Queued--
	job.Progress.Running++
	job.UpdatedAt = now

	key := itemKey(item.JobID, item.ItemID, item.OperationVersion)
	m.leaseTok[key]++
	token := m.leaseTok[key]

	jobID, itemID, operationVersion := item.JobID, item.ItemID, item.OperationVersion
	itemCopy := *item // snapshot payload for the goroutine
	leaseDeadline := item.LeaseExpiry

	m.persistJobAsync(job)
	m.persistItemAsync(item)

	go m.runItem(jobID, itemID, operationVersion, workerID, ws.worker, token, itemCopy, leaseDeadline)
}

// runItem actually calls the worker off the manager lock, then reports the
// outcome back through completeItem which re-validates the lease token
// before applying any state change (the client-abort/late-duplicate drop).
func (m *Manager) runItem(jobID, itemID, operationVersion, workerID string, w Worker, token int64, item domain.WorkItem, leaseDeadline time.Time) {
	m.mu.Lock()
	if cur := m.items[itemKey(jobID, itemID, operationVersion)]; cur != nil && cur.State == domain.WorkItemLeased {
		cur.State = domain.WorkItemRunning
		cur.UpdatedAt = time.Now().UTC()
	}
	m.mu.Unlock()

	ctx, cancel := context.WithDeadline(context.Background(), leaseDeadline)
	defer cancel()
	res, err := w.Execute(ctx, item)
	m.completeItem(jobID, itemID, operationVersion, workerID, token, res, err)
}

// completeItem applies a worker's outcome to a WorkItem, but only if the
// lease token still matches (guards against late results after lease
// expiry/reassignment) and the job hasn't been cancelled in the meantime
// (client-abort drop: the result is dropped, not re-leased or counted).
func (m *Manager) completeItem(jobID, itemID, operationVersion, workerID string, token int64, res Result, execErr error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := itemKey(jobID, itemID, operationVersion)
	item := m.items[key]
	job := m.jobs[jobID]
	if item == nil || job == nil {
		return
	}

	ws := m.workers[workerID]
	if ws != nil && ws.active > 0 {
		ws.active-- // always free the slot the worker occupied, even if we drop the result
	}

	if m.leaseTok[key] != token {
		// Stale/late result: the lease expired (and was requeued/reassigned)
		// or this exact item has already moved on. Drop it — do not
		// re-lease, do not double-count (§12 "late duplicate result
		// ignored").
		m.tryDispatchLocked()
		return
	}

	now := time.Now().UTC()

	if job.Status == domain.JobCancelled {
		// Client-abort/cancel drop: an abandoned item's in-flight result is
		// dropped outright, not re-leased and not counted, per the
		// lb-proxy "phantom retry" fix ported from docs/gateway-and-queue.md.
		// The item is marked CANCELLED purely for display; no success/failed
		// counter moves.
		if item.State == domain.WorkItemLeased || item.State == domain.WorkItemRunning {
			item.State = domain.WorkItemCancelled
			item.UpdatedAt = now
			job.Progress.Running--
			job.UpdatedAt = now
			m.persistItemAsync(item)
			m.persistJobAsync(job)
		}
		m.tryDispatchLocked()
		return
	}

	if item.State == domain.WorkItemSuccess || item.State == domain.WorkItemFailed {
		// Already terminal (shouldn't happen given the token check above,
		// but keep as a defensive dedupe backstop).
		m.tryDispatchLocked()
		return
	}

	item.UpdatedAt = now
	job.UpdatedAt = now
	job.Progress.Running--

	if execErr == nil {
		item.State = domain.WorkItemSuccess
		item.ResultRef = res.Output
		job.Progress.Success++
	} else {
		m.failItemLocked(job, item, workerID, execErr.Error(), now)
	}

	m.recomputeJobStatusLocked(job)
	m.tryDispatchLocked() // a slot just freed -> zero-gap dispatch

	m.persistJobAsync(job)
	m.persistItemAsync(item)
}

// failItemLocked implements cross-worker retry: the failed worker joins the
// item's "tried" set, and the item goes back to QUEUED unless every
// eligible worker has now been tried, or the job's max-attempt cap is hit —
// whichever comes first — in which case it becomes terminally FAILED.
func (m *Manager) failItemLocked(job *domain.Job, item *domain.WorkItem, workerID, errMsg string, now time.Time) {
	item.LastError = errMsg
	if !contains(item.TriedWorkers, workerID) {
		item.TriedWorkers = append(item.TriedWorkers, workerID)
	}

	eligible := len(m.workers)
	exhausted := eligible > 0 && len(item.TriedWorkers) >= eligible
	capped := item.Attempt >= job.MaxAttempts

	if exhausted || capped {
		item.State = domain.WorkItemFailed
		job.Progress.Failed++
		return
	}
	item.State = domain.WorkItemQueued
	job.Progress.Queued++
	job.Progress.Retried++
}

// recomputeJobStatusLocked flips a RUNNING job to a terminal status once
// every item is terminal (SUCCESS or FAILED) and nothing is queued/running.
func (m *Manager) recomputeJobStatusLocked(job *domain.Job) {
	if job.Status == domain.JobCancelled || job.Status == domain.JobPaused {
		return
	}
	if job.Progress.Queued > 0 || job.Progress.Running > 0 {
		return
	}
	if job.Progress.Failed > 0 {
		job.Status = domain.JobCompletedWithErrors
	} else {
		job.Status = domain.JobCompleted
	}
}

// ---------------------------------------------------------------------
// Lease-expiry reaper (§12 LEASE_EXPIRED -> QUEUED)
// ---------------------------------------------------------------------

func (m *Manager) reapExpiredLeases() {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now().UTC()
	dispatched := false
	for jobID, order := range m.itemOrder {
		job := m.jobs[jobID]
		for _, key := range order {
			item := m.items[key]
			if item.State != domain.WorkItemLeased && item.State != domain.WorkItemRunning {
				continue
			}
			if item.LeaseExpiry.IsZero() || now.Before(item.LeaseExpiry) {
				continue
			}
			// Bump the lease token so any late result from the original
			// worker call is recognized as stale and dropped.
			m.leaseTok[key]++

			if ws := m.workers[item.LeaseOwner]; ws != nil && ws.active > 0 {
				ws.active--
			}
			job.Progress.Running--

			owner := item.LeaseOwner
			item.State = domain.WorkItemLeaseExpired
			item.UpdatedAt = now
			item.LastError = "lease expired: no result from worker " + owner + " within TTL"
			if !contains(item.TriedWorkers, owner) {
				item.TriedWorkers = append(item.TriedWorkers, owner)
			}

			eligible := len(m.workers)
			if (eligible > 0 && len(item.TriedWorkers) >= eligible) || item.Attempt >= job.MaxAttempts {
				item.State = domain.WorkItemFailed
				job.Progress.Failed++
			} else {
				item.State = domain.WorkItemQueued
				job.Progress.Queued++
				job.Progress.Retried++
			}
			job.UpdatedAt = now
			m.recomputeJobStatusLocked(job)
			m.persistJobAsync(job)
			m.persistItemAsync(item)
			dispatched = true
		}
	}
	if dispatched {
		m.tryDispatchLocked() // freed lease(s) -> zero-gap dispatch of requeued/other items
	}
}

// ---------------------------------------------------------------------
// Pause / cancel
// ---------------------------------------------------------------------

func (m *Manager) PauseJob(jobID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	job, ok := m.jobs[jobID]
	if !ok {
		return store.ErrNotFound
	}
	if job.Status == domain.JobRunning || job.Status == domain.JobPending {
		job.Status = domain.JobPaused
		job.UpdatedAt = time.Now().UTC()
		m.persistJobAsync(job)
	}
	return nil
}

// CancelJob stops new dispatch for the job's items immediately and marks it
// cancelled. Any already-queued items are marked CANCELLED (never
// dispatched); any in-flight (leased/running) items are left to resolve —
// their late results will be dropped by completeItem's job-cancelled check
// (client-abort drop), not re-leased or counted.
func (m *Manager) CancelJob(jobID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	job, ok := m.jobs[jobID]
	if !ok {
		return store.ErrNotFound
	}
	if job.Status == domain.JobCancelled || job.Status == domain.JobCompleted || job.Status == domain.JobCompletedWithErrors {
		return nil
	}
	now := time.Now().UTC()
	for _, key := range m.itemOrder[jobID] {
		item := m.items[key]
		if item.State == domain.WorkItemQueued {
			item.State = domain.WorkItemCancelled
			item.UpdatedAt = now
			job.Progress.Queued--
			m.persistItemAsync(item)
		}
	}
	job.Status = domain.JobCancelled
	job.UpdatedAt = now
	m.persistJobAsync(job)
	return nil
}

// ---------------------------------------------------------------------
// Reads
// ---------------------------------------------------------------------

func cloneJob(j *domain.Job) *domain.Job {
	cp := *j
	return &cp
}

func cloneWorkItem(wi *domain.WorkItem) *domain.WorkItem {
	cp := *wi
	cp.TriedWorkers = append([]string(nil), wi.TriedWorkers...)
	return &cp
}

func (m *Manager) GetJob(jobID string) (*domain.Job, []*domain.WorkItem, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	job, ok := m.jobs[jobID]
	if !ok {
		return nil, nil, store.ErrNotFound
	}
	order := m.itemOrder[jobID]
	items := make([]*domain.WorkItem, 0, len(order))
	for _, key := range order {
		items = append(items, cloneWorkItem(m.items[key]))
	}
	return cloneJob(job), items, nil
}

func (m *Manager) ListJobs() []*domain.Job {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*domain.Job, 0, len(m.jobOrder))
	for _, id := range m.jobOrder {
		out = append(out, cloneJob(m.jobs[id]))
	}
	return out
}

// ---------------------------------------------------------------------
// Store write-through (best-effort; queue correctness never depends on it —
// canonical state lives in Manager's own maps, per the pattern already
// established for liveness logic sitting above the dumb NodeStore).
// ---------------------------------------------------------------------

func (m *Manager) persistJob(j *domain.Job) {
	if m.store == nil {
		return
	}
	if _, err := m.store.UpsertJob(context.Background(), cloneJob(j)); err != nil {
		m.log.Error("job store write-through failed", "job_id", j.ID, "err", err)
	}
}

func (m *Manager) persistItem(wi *domain.WorkItem) {
	if m.store == nil {
		return
	}
	if _, err := m.store.UpsertWorkItem(context.Background(), cloneWorkItem(wi)); err != nil {
		m.log.Error("work item store write-through failed", "job_id", wi.JobID, "item_id", wi.ItemID, "err", err)
	}
}

// persistJobAsync/persistItemAsync snapshot under the caller's lock (already
// held) and persist off-lock so store latency never blocks dispatch.
func (m *Manager) persistJobAsync(j *domain.Job) {
	snap := cloneJob(j)
	go m.persistJob(snap)
}

func (m *Manager) persistItemAsync(wi *domain.WorkItem) {
	snap := cloneWorkItem(wi)
	go m.persistItem(snap)
}
