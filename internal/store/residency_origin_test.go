package store

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"strings"
	"sync"
	"testing"
	"time"

	"vram-governor/internal/domain"
)

func leaseOriginTransition(id, key, target, accelerator string, fence int64) *domain.ResidencyTransition {
	return &domain.ResidencyTransition{
		ID: id, IdempotencyKey: key, TargetID: target, AcceleratorID: accelerator, Model: "origin-model",
		FromTier: domain.ResidencyColdDisk, ToTier: domain.ResidencyHotVRAM, Reason: "origin-test",
		RequestedBy: "origin-owner", WorkloadID: "admission-workload", FencingToken: fence,
		CapabilityVersion: "origin-v1", CapabilityRevision: domain.CapabilityContractVersion,
		TargetGeneration: 1, ExecutionFingerprint: "origin-execution", Status: domain.ResidencyTransitionPlanned,
		CreatedAt: time.Now().UTC(),
	}
}

func TestResidencyTransitionLeaseOriginMemoryAndPostgres(t *testing.T) {
	ctx := context.Background()
	for _, backend := range []string{"memory", "postgres-semantic"} {
		t.Run(backend, func(t *testing.T) {
			var backing WorkloadStore
			var pgState *fakePGState
			var liveLease *domain.AcceleratorLease
			if backend == "memory" {
				memory := NewMemoryStore()
				var acquired bool
				var err error
				liveLease, acquired, err = memory.AcquireAcceleratorLease(ctx, "origin-gpu", "lease-owner", time.Minute)
				if err != nil || !acquired { t.Fatalf("acquire memory lease: acquired=%t err=%v", acquired, err) }
				backing = memory
			} else {
				postgres, state := newFakePG(t)
				backing, pgState = postgres, state
				liveLease = &domain.AcceleratorLease{AcceleratorID: "origin-gpu", WorkloadID: "lease-owner", FencingToken: 7, ExpiresAt: time.Now().UTC().Add(time.Minute)}
				body, err := json.Marshal(liveLease)
				if err != nil { t.Fatal(err) }
				pgState.leases[liveLease.AcceleratorID] = body
			}

			// Legacy allocations still advance the independent target/model fence,
			// but do not acquire or impersonate accelerator-lease provenance.
			historical := leaseOriginTransition("historical", "historical-key", "origin-target", "origin-gpu", liveLease.FencingToken+10)
			if _, _, err := backing.AllocateResidencyTransition(ctx, historical); err != nil { t.Fatalf("allocate historical model fence: %v", err) }
			requested := leaseOriginTransition("owned", "owned-key", "origin-target", "origin-gpu", liveLease.FencingToken)
			// The legacy allocation above legitimately locks the model first; measure only the leased operation below.
			var leasedSQLStart int
			if pgState != nil {
				pgState.mu.Lock()
				leasedSQLStart = len(pgState.sql)
				pgState.mu.Unlock()
			}
			allocated, created, err := backing.AllocateResidencyTransitionWithLease(ctx, requested, liveLease)
			if err != nil || !created { t.Fatalf("leased allocate: created=%t err=%v", created, err) }
			var leasedSQL []string
			if pgState != nil {
				pgState.mu.Lock()
				leasedSQL = append([]string(nil), pgState.sql[leasedSQLStart:]...)
				pgState.mu.Unlock()
			}
			if !allocated.LeaseOriginAllocated || allocated.LeaseOriginAcceleratorID != liveLease.AcceleratorID ||
				allocated.LeaseOriginWorkloadID != liveLease.WorkloadID || allocated.LeaseOriginFencingToken != liveLease.FencingToken ||
				allocated.FencingToken <= liveLease.FencingToken+10 {
				t.Fatalf("allocation did not bind exact lease independently of model highwater: %+v", allocated)
			}

			// Exact lease replay is idempotent even when the allocated model fence
			// is above the accelerator fence; a foreign lease cannot claim it.
			replay, created, err := backing.AllocateResidencyTransitionWithLease(ctx, requested, liveLease)
			if err != nil || created || replay.ID != allocated.ID { t.Fatalf("exact replay: created=%t row=%+v err=%v", created, replay, err) }
			byKey, err := backing.GetResidencyTransitionByIdempotencyForLease(ctx, requested.IdempotencyKey, liveLease)
			if err != nil || byKey == nil || byKey.ID != allocated.ID { t.Fatalf("lease-bound idempotency read: row=%+v err=%v", byKey, err) }
			persisted, err := backing.GetResidencyTransition(ctx, allocated.ID)
			if err != nil || persisted == nil || !persisted.LeaseOriginAllocated || persisted.LeaseOriginWorkloadID != liveLease.WorkloadID {
				t.Fatalf("persisted reconstruction lost origin: row=%+v err=%v", persisted, err)
			}
			foreign := *liveLease
			foreign.WorkloadID = "different-lease-owner"
			if _, err := backing.GetResidencyTransitionByIdempotencyForLease(ctx, requested.IdempotencyKey, &foreign); !errors.Is(err, ErrResidencyTransitionConflict) {
				t.Fatalf("foreign lease replay error=%v", err)
			}

			// Neither generic creation nor legacy allocation can accept caller-
			// asserted provenance, and a valid-shaped replacement cannot rewrite
			// the immutable origin through Update/CAS.
			for _, operation := range []struct{name string; call func() error}{
				{"create", func() error { _, _, err := backing.CreateResidencyTransition(ctx, allocated); return err }},
				{"unleased allocate", func() error { _, _, err := backing.AllocateResidencyTransition(ctx, allocated); return err }},
			} {
				if err := operation.call(); !errors.Is(err, ErrResidencyTransitionConflict) { t.Errorf("%s caller-origin error=%v", operation.name, err) }
			}
			for _, mutate := range []struct{name string; apply func(*domain.ResidencyTransition)}{
				{"target generation", func(row *domain.ResidencyTransition) { row.TargetGeneration++ }},
				{"model fence", func(row *domain.ResidencyTransition) { row.FencingToken++ }},
				{"request actor", func(row *domain.ResidencyTransition) { row.RequestedBy = "rewritten-actor" }},
				{"idempotency key", func(row *domain.ResidencyTransition) { row.IdempotencyKey = "rewritten-key" }},
			} {
				tamperedIdentity := *allocated
				mutate.apply(&tamperedIdentity)
				if _, err := backing.UpdateResidencyTransition(ctx, &tamperedIdentity); !errors.Is(err, ErrResidencyTransitionConflict) {
					t.Errorf("origin-issued %s rewrite Update error=%v", mutate.name, err)
				}
			}
			forgedSucceeded := leaseOriginTransition("forged-success", "forged-success-key", "origin-target", liveLease.AcceleratorID, liveLease.FencingToken)
			forgedSucceeded.Status = domain.ResidencyTransitionSucceeded
			forgedSucceeded.Revision = 1
			forgedSucceeded.ObservedTier = domain.ResidencyHotVRAM
			forgedSucceeded.ObservedFence = liveLease.FencingToken
			finishedAt := time.Now().UTC()
			forgedSucceeded.FinishedAt = &finishedAt
			if _, _, err := backing.AllocateResidencyTransitionWithLease(ctx, forgedSucceeded, liveLease); !errors.Is(err, ErrResidencyTransitionConflict) {
				t.Errorf("precompleted leased allocation input error=%v", err)
			}
			tampered := *allocated
			tampered.LeaseOriginWorkloadID = "other-origin"
			if _, err := backing.UpdateResidencyTransition(ctx, &tampered); !errors.Is(err, ErrResidencyTransitionConflict) { t.Errorf("origin Update error=%v", err) }
			if _, err := backing.CompareAndSwapResidencyTransition(ctx, &tampered, allocated.Revision, allocated.Status, allocated.FencingToken); !errors.Is(err, ErrResidencyTransitionConflict) { t.Errorf("origin CAS error=%v", err) }
			updated := *allocated
			updated.Status = domain.ResidencyTransitionRunning
			if _, err := backing.UpdateResidencyTransition(ctx, &updated); err != nil { t.Fatalf("legitimate origin-preserving Update: %v", err) }
			updated.Status = domain.ResidencyTransitionFailed
			final, err := backing.CompareAndSwapResidencyTransition(ctx, &updated, allocated.Revision, domain.ResidencyTransitionRunning, allocated.FencingToken)
			if err != nil {
				t.Fatalf("legitimate origin-preserving CAS: %v", err)
			}
			if _, err := backing.GetResidencyTransitionByIdempotencyForLease(ctx, historical.IdempotencyKey, liveLease); !errors.Is(err, ErrResidencyTransitionConflict) {
				t.Errorf("legacy unleased row acquired admission authority: %v", err)
			}

			wrongResource := leaseOriginTransition("wrong-resource", "wrong-resource-key", "origin-target", "other-gpu", liveLease.FencingToken)
			if _, _, err := backing.AllocateResidencyTransitionWithLease(ctx, wrongResource, liveLease); !errors.Is(err, ErrResidencyTransitionConflict) { t.Errorf("wrong resource allocation error=%v", err) }
			staleLease := *liveLease
			staleLease.FencingToken++
			staleRequest := leaseOriginTransition("stale-lease", "stale-lease-key", "origin-target", liveLease.AcceleratorID, staleLease.FencingToken)
			if _, _, err := backing.AllocateResidencyTransitionWithLease(ctx, staleRequest, &staleLease); !errors.Is(err, ErrResidencyTransitionConflict) { t.Errorf("stale lease allocation error=%v", err) }
			shadow := leaseOriginTransition("legacy-shadow", "legacy-shadow-key", "origin-target", liveLease.AcceleratorID, liveLease.FencingToken+30)
			if _, _, err := backing.CreateResidencyTransition(ctx, shadow); err != nil { t.Fatalf("create legacy same-key shadow: %v", err) }
			shadowRequest := leaseOriginTransition("legacy-shadow-new-id", shadow.IdempotencyKey, shadow.TargetID, shadow.AcceleratorID, liveLease.FencingToken)
			if _, _, err := backing.AllocateResidencyTransitionWithLease(ctx, shadowRequest, liveLease); !errors.Is(err, ErrResidencyTransitionConflict) { t.Errorf("same-key unleased shadow became lease allocation: %v", err) }
			idCollision := leaseOriginTransition(historical.ID, "historical-id-collision", historical.TargetID, historical.AcceleratorID, liveLease.FencingToken)
			if _, _, err := backing.AllocateResidencyTransitionWithLease(ctx, idCollision, liveLease); !errors.Is(err, ErrResidencyTransitionConflict) { t.Errorf("different idempotency key reused a durable transition ID: %v", err) }
			partial := leaseOriginTransition("partial-origin", "partial-origin-key", "origin-target", liveLease.AcceleratorID, liveLease.FencingToken)
			partial.LeaseOriginWorkloadID = liveLease.WorkloadID
			if _, _, err := backing.CreateResidencyTransition(ctx, partial); !errors.Is(err, ErrResidencyTransitionConflict) { t.Errorf("partial caller provenance accepted by Create: %v", err) }
			stripped := *final
			stripped.LeaseOriginAcceleratorID = ""
			stripped.LeaseOriginWorkloadID = ""
			stripped.LeaseOriginFencingToken = 0
			stripped.LeaseOriginAllocated = false
			if _, err := backing.UpdateResidencyTransition(ctx, &stripped); !errors.Is(err, ErrResidencyTransitionConflict) { t.Errorf("origin stripping Update error=%v", err) }
			if _, err := backing.CompareAndSwapResidencyTransition(ctx, &stripped, final.Revision, final.Status, final.FencingToken); !errors.Is(err, ErrResidencyTransitionConflict) { t.Errorf("origin stripping CAS error=%v", err) }

			overflow := leaseOriginTransition("overflow-highwater", "overflow-highwater-key", "overflow-target", liveLease.AcceleratorID, math.MaxInt64)
			if _, _, err := backing.AllocateResidencyTransition(ctx, overflow); err != nil { t.Fatalf("seed max model highwater: %v", err) }
			overflowRequest := leaseOriginTransition("overflow-leased", "overflow-leased-key", "overflow-target", liveLease.AcceleratorID, liveLease.FencingToken)
			if _, _, err := backing.AllocateResidencyTransitionWithLease(ctx, overflowRequest, liveLease); !errors.Is(err, ErrResidencyTransitionConflict) { t.Errorf("max model-fence allocation error=%v", err) }

			if pgState != nil {
				joined := strings.Join(leasedSQL, "\n")
				if !strings.Contains(joined, "insert into accelerator_lease_fences") || !strings.Contains(joined, "from accelerator_leases") || !strings.Contains(joined, "pg_advisory_xact_lock") {
					t.Fatalf("semantic PostgreSQL fixture did not observe lease and model locking: %s", joined)
				}
				lockIndex := strings.Index(joined, "insert into accelerator_lease_fences")
				leaseIndex := strings.Index(joined, "from accelerator_leases")
				modelIndex := strings.Index(joined, "pg_advisory_xact_lock")
				if !(lockIndex >= 0 && lockIndex < leaseIndex && leaseIndex < modelIndex) { t.Fatalf("lock ordering sentinel=%d lease=%d model=%d", lockIndex, leaseIndex, modelIndex) }
			}
		})
	}
}

func TestPostgresLeaseOriginRechecksExpiryAfterFenceWait(t *testing.T) {
	ctx := context.Background()
	postgres, state := newFakePG(t)
	lease := &domain.AcceleratorLease{AcceleratorID: "wait-gpu", WorkloadID: "wait-owner", FencingToken: 11, ExpiresAt: time.Now().UTC().Add(time.Minute)}
	body, err := json.Marshal(lease)
	if err != nil { t.Fatal(err) }
	state.leases[lease.AcceleratorID] = body
	// The semantic fixture expires the row only after the allocator has taken
	// the shared sentinel lock and refreshed its snapshot. This models a lease
	// that was live before waiting but expires by the post-lock authority check.
	state.expireLeasesOnFenceLock = true
	_, _, err = postgres.AllocateResidencyTransitionWithLease(ctx,
		leaseOriginTransition("expired-after-wait", "expired-after-wait-key", "wait-target", lease.AcceleratorID, lease.FencingToken), lease)
	if !errors.Is(err, ErrResidencyTransitionConflict) { t.Fatalf("expired-after-wait allocate error=%v", err) }
	if len(state.residency) != 0 { t.Fatalf("expired lease wrote transition rows: %v", state.residency) }
	joined := strings.Join(state.sql, "\n")
	if strings.Index(joined, "insert into accelerator_lease_fences") < 0 || strings.Index(joined, "from accelerator_leases") < strings.Index(joined, "insert into accelerator_lease_fences") {
		t.Fatalf("expired lease was not checked after shared fence lock: %s", joined)
	}
}

func TestPostgresLeaseOriginExpiresWhileWaitingForFenceSentinel(t *testing.T) {
	ctx := context.Background()
	postgres, state := newFakePG(t)
	lease := &domain.AcceleratorLease{AcceleratorID: "blocked-gpu", WorkloadID: "blocked-owner", FencingToken: 19, ExpiresAt: time.Now().UTC().Add(time.Minute)}
	body, err := json.Marshal(lease)
	if err != nil { t.Fatal(err) }
	state.leases[lease.AcceleratorID] = body
	state.fenceLockAttempt = make(chan struct{}, 1)
	key := "lease-fence:" + lease.AcceleratorID
	state.nodeLocksMu.Lock()
	lock := &sync.Mutex{}
	state.nodeLocks[key] = lock
	state.nodeLocksMu.Unlock()
	lock.Lock()
	result := make(chan error, 1)
	go func() {
		_, _, allocateErr := postgres.AllocateResidencyTransitionWithLease(ctx,
			leaseOriginTransition("blocked-expiry", "blocked-expiry-key", "blocked-target", lease.AcceleratorID, lease.FencingToken), lease)
		result <- allocateErr
	}()
	select {
	case <-state.fenceLockAttempt:
	case <-time.After(5 * time.Second):
		lock.Unlock()
		t.Fatal("allocator did not reach the shared lease fence lock")
	}
	state.mu.Lock()
	var current domain.AcceleratorLease
	if err := json.Unmarshal(state.leases[lease.AcceleratorID], &current); err != nil { state.mu.Unlock(); lock.Unlock(); t.Fatal(err) }
	current.ExpiresAt = time.Now().UTC().Add(-time.Second)
	expired, err := json.Marshal(&current)
	if err != nil { state.mu.Unlock(); lock.Unlock(); t.Fatal(err) }
	state.leases[lease.AcceleratorID] = expired
	state.mu.Unlock()
	lock.Unlock()
	select {
	case err := <-result:
		if !errors.Is(err, ErrResidencyTransitionConflict) { t.Fatalf("allocator accepted lease expired while waiting: %v", err) }
	case <-time.After(5 * time.Second):
		t.Fatal("allocator did not finish after the lease fence was released")
	}
	if len(state.residency) != 0 { t.Fatalf("expired-after-wait allocation wrote a transition: %v", state.residency) }
}

func TestPostgresLeaseOriginRechecksExpiryAfterModelAndTransitionWaits(t *testing.T) {
	for _, point := range []struct{name string; model, transition bool}{
		{"model advisory", true, false},
		{"transition row", false, true},
	} {
		t.Run(point.name, func(t *testing.T) {
			ctx := context.Background()
			postgres, state := newFakePG(t)
			lease := &domain.AcceleratorLease{AcceleratorID: "late-expiry-gpu", WorkloadID: "late-expiry-owner", FencingToken: 31, ExpiresAt: time.Now().UTC().Add(time.Minute)}
			body, err := json.Marshal(lease)
			if err != nil { t.Fatal(err) }
			state.leases[lease.AcceleratorID] = body
			state.expireLeaseAfterModelLock = point.model
			state.expireLeaseAfterTransitionLock = point.transition
			_, _, err = postgres.AllocateResidencyTransitionWithLease(ctx,
				leaseOriginTransition("late-expiry", "late-expiry-key", "late-expiry-target", lease.AcceleratorID, lease.FencingToken), lease)
			if !errors.Is(err, ErrResidencyTransitionConflict) { t.Fatalf("allocation accepted expiry after %s wait: %v", point.name, err) }
			if len(state.residency) != 0 || state.commits != 0 { t.Fatalf("expired lease committed after %s wait: rows=%v commits=%d", point.name, state.residency, state.commits) }
		})
	}
}

func TestPostgresLeaseBoundReplayRechecksExpiryAfterTransitionWait(t *testing.T) {
	ctx := context.Background()
	postgres, state := newFakePG(t)
	lease := &domain.AcceleratorLease{AcceleratorID: "replay-expiry-gpu", WorkloadID: "replay-expiry-owner", FencingToken: 37, ExpiresAt: time.Now().UTC().Add(time.Minute)}
	body, err := json.Marshal(lease)
	if err != nil { t.Fatal(err) }
	state.leases[lease.AcceleratorID] = body
	request := leaseOriginTransition("replay-expiry-transition", "replay-expiry-key", "replay-expiry-target", lease.AcceleratorID, lease.FencingToken)
	allocated, created, err := postgres.AllocateResidencyTransitionWithLease(ctx, request, lease)
	if err != nil || !created { t.Fatalf("seed allocated receipt: created=%t err=%v", created, err) }

	first, err := postgres.GetResidencyTransitionByIdempotencyForLease(ctx, request.IdempotencyKey, lease)
	if err != nil || first == nil || first.ID != allocated.ID { t.Fatalf("positive lease-bound replay: row=%+v err=%v", first, err) }
	if state.commits != 2 { t.Fatalf("positive replay did not commit exactly once after allocation: commits=%d", state.commits) }
	if missing, missingErr := postgres.GetResidencyTransitionByIdempotencyForLease(ctx, "missing-replay-key", lease); missing != nil || !errors.Is(missingErr, ErrNotFound) {
		t.Fatalf("positive live-lease missing-key read: row=%+v err=%v", missing, missingErr)
	}

	state.expireLeaseAfterTransitionLock = true
	expiredReceipt, err := postgres.GetResidencyTransitionByIdempotencyForLease(ctx, request.IdempotencyKey, lease)
	if expiredReceipt != nil || !errors.Is(err, ErrResidencyTransitionConflict) || errors.Is(err, ErrNotFound) {
		t.Fatalf("expired transition-lock receipt replay returned authority: row=%+v err=%v", expiredReceipt, err)
	}
	if state.commits != 2 { t.Fatalf("expired receipt replay committed after wait: commits=%d", state.commits) }

	// Renew the same exact lease tuple so the missing-key case independently
	// reaches the transition-row read live before the fake advances expiry.
	lease.ExpiresAt = time.Now().UTC().Add(time.Minute)
	renewedBody, err := json.Marshal(lease)
	if err != nil { t.Fatal(err) }
	state.mu.Lock()
	state.leases[lease.AcceleratorID] = renewedBody
	state.mu.Unlock()
	expiredMissing, err := postgres.GetResidencyTransitionByIdempotencyForLease(ctx, "missing-replay-key", lease)
	if expiredMissing != nil || !errors.Is(err, ErrResidencyTransitionConflict) || errors.Is(err, ErrNotFound) {
		t.Fatalf("expired transition-lock missing-key read was masked as NotFound: row=%+v err=%v", expiredMissing, err)
	}
	if state.commits != 2 { t.Fatalf("expired reads committed after wait: commits=%d", state.commits) }
	stored, err := postgres.GetResidencyTransition(ctx, allocated.ID)
	if err != nil || stored == nil || stored.ID != allocated.ID || !stored.LeaseOriginAllocated { t.Fatalf("expired read changed durable receipt: row=%+v err=%v", stored, err) }

	joined := strings.Join(state.sql, "\n")
	readLock := strings.Index(joined, "select body from residency_transitions where idempotency_key=$1 for update")
	postWaitLease := -1
	if readLock >= 0 { postWaitLease = strings.Index(joined[readLock+1:], "from accelerator_leases") }
	if readLock < 0 || postWaitLease < 0 { t.Fatalf("semantic replay did not recheck the lease after transition row read: %s", joined) }
}

func TestPostgresLeaseOriginInsertFailureRollsBack(t *testing.T) {
	ctx := context.Background()
	postgres, state := newFakePG(t)
	lease := &domain.AcceleratorLease{AcceleratorID: "rollback-gpu", WorkloadID: "rollback-owner", FencingToken: 23, ExpiresAt: time.Now().UTC().Add(time.Minute)}
	body, err := json.Marshal(lease)
	if err != nil { t.Fatal(err) }
	state.leases[lease.AcceleratorID] = body
	state.failNext = "insert into residency_transitions"
	_, _, err = postgres.AllocateResidencyTransitionWithLease(ctx,
		leaseOriginTransition("rollback-origin", "rollback-origin-key", "rollback-target", lease.AcceleratorID, lease.FencingToken), lease)
	if err == nil { t.Fatal("injected atomic insert failure was accepted") }
	if len(state.residency) != 0 || state.commits != 0 || state.rollbacks != 1 { t.Fatalf("failed insert did not roll back atomically: rows=%v commits=%d rollbacks=%d", state.residency, state.commits, state.rollbacks) }
}

func TestResidencyLeaseOriginUsesCanonicalVirtualResource(t *testing.T) {
	ctx := context.Background()
	for _, backend := range []string{"memory", "postgres-semantic"} {
		t.Run(backend, func(t *testing.T) {
			var backing WorkloadStore
			var lease *domain.AcceleratorLease
			if backend == "memory" {
				memory := NewMemoryStore()
				var acquired bool
				var err error
				lease, acquired, err = memory.AcquireAcceleratorLease(ctx, "virtual/virtual-target", "virtual-owner", time.Minute)
				if err != nil || !acquired { t.Fatalf("acquire virtual lease: acquired=%t err=%v", acquired, err) }
				backing = memory
			} else {
				postgres, state := newFakePG(t)
				lease = &domain.AcceleratorLease{AcceleratorID: "virtual/virtual-target", WorkloadID: "virtual-owner", FencingToken: 5, ExpiresAt: time.Now().UTC().Add(time.Minute)}
				body, err := json.Marshal(lease)
				if err != nil { t.Fatal(err) }
				state.leases[lease.AcceleratorID] = body
				backing = postgres
			}
			request := leaseOriginTransition("virtual-transition", "virtual-transition-key", "virtual-target", "", lease.FencingToken)
			row, created, err := backing.AllocateResidencyTransitionWithLease(ctx, request, lease)
			if err != nil || !created { t.Fatalf("allocate virtual transition: created=%t err=%v", created, err) }
			if row.AcceleratorID != "" || row.LeaseOriginAcceleratorID != "virtual/virtual-target" || !row.LeaseOriginAllocated {
				t.Fatalf("virtual lease provenance used noncanonical resource: %+v", row)
			}
		})
	}
}

func TestPostgresLeaseRenewAndReleaseSerializeOnSharedFence(t *testing.T) {
	ctx := context.Background()
	postgres, state := newDisplacementSemanticPG(t)
	lease, acquired, err := postgres.AcquireAcceleratorLease(ctx, "writer-gpu", "writer-owner", time.Minute)
	if err != nil || !acquired || lease == nil { t.Fatalf("acquire lease: lease=%+v acquired=%t err=%v", lease, acquired, err) }
	state.mu.Lock()
	state.sql = nil
	state.mu.Unlock()
	if err := postgres.RenewAcceleratorLease(ctx, lease.AcceleratorID, lease.WorkloadID, lease.FencingToken, time.Minute); err != nil { t.Fatalf("renew lease: %v", err) }
	state.mu.Lock()
	renewSQL := append([]string(nil), state.sql...)
	state.sql = nil
	state.mu.Unlock()
	if len(renewSQL) < 3 || !strings.HasPrefix(renewSQL[0], "insert into accelerator_lease_fences") || !strings.Contains(renewSQL[1], "from accelerator_leases") || !strings.HasPrefix(renewSQL[2], "update accelerator_leases") {
		t.Fatalf("renew did not serialize sentinel -> exact row -> update: %v", renewSQL)
	}
	if err := postgres.ReleaseAcceleratorLease(ctx, lease.AcceleratorID, lease.WorkloadID, lease.FencingToken); err != nil { t.Fatalf("release lease: %v", err) }
	state.mu.Lock()
	releaseSQL := append([]string(nil), state.sql...)
	state.mu.Unlock()
	if len(releaseSQL) < 3 || !strings.HasPrefix(releaseSQL[0], "insert into accelerator_lease_fences") || !strings.Contains(releaseSQL[1], "from accelerator_leases") || !strings.HasPrefix(releaseSQL[2], "delete from accelerator_leases") {
		t.Fatalf("release did not serialize sentinel -> exact row -> delete: %v", releaseSQL)
	}
	if _, err := postgres.GetAcceleratorLease(ctx, lease.AcceleratorID); !errors.Is(err, ErrNotFound) { t.Fatalf("released lease remained current: %v", err) }
}

