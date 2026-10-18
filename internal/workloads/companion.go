package workloads

import (
	"context"
	"fmt"
	"sync"
	"time"

	"vram-governor/internal/domain"
)

// Companion accelerators let one target use several GPUs: a llama.cpp
// router that splits models across both cards of a node (CT200: RTX 4070
// SUPER + RX 6900 XT) next to one router per card. The split target owns its
// primary accelerator through the ordinary target lease and additionally
// holds a lease on each companion while it has work, so a per-card target on
// a companion GPU cannot start beside it (its own lease acquisition finds the
// GPU taken), and vice versa. Reclaim treats any shared GPU as the same
// accelerator, so loading on one evicts the other's resident models.

// targetAccelerators lists every GPU a target uses, primary first.
func targetAccelerators(target Target) []string {
	if target.AcceleratorID == "" {
		return nil
	}
	out := []string{target.AcceleratorID}
	for _, id := range target.CompanionAcceleratorIDs {
		if id != "" && id != target.AcceleratorID {
			out = append(out, id)
		}
	}
	return out
}

// targetsShareAccelerator reports whether two targets use any GPU in common.
func targetsShareAccelerator(a, b Target) bool {
	for _, left := range targetAccelerators(a) {
		for _, right := range targetAccelerators(b) {
			if left == right {
				return true
			}
		}
	}
	return false
}

type companionHold struct {
	leases     []*domain.AcceleratorLease
	lastNeeded time.Time
}

type companionLeases struct {
	mu      sync.Mutex
	holds   map[string]*companionHold
	started sync.Once
}

// companionGrace keeps companion leases briefly after a target goes idle, so
// back-to-back requests do not hand the second GPU to another target between
// them, and so an admission between acquiring the companions and publishing
// its reservation is not released underneath it.
var companionGrace = 5 * time.Second

func companionOwner(targetID string) string { return "companion:" + targetID }

// holdCompanionLeases makes sure target holds a lease on each companion GPU.
// It returns a non-empty reason when a companion is in use by another target.
func (m *Manager) holdCompanionLeases(ctx context.Context, target Target) (string, error) {
	if len(target.CompanionAcceleratorIDs) == 0 {
		return "", nil
	}
	m.companions.started.Do(func() { go m.keepCompanionLeases() })
	m.companions.mu.Lock()
	defer m.companions.mu.Unlock()
	if m.companions.holds == nil {
		m.companions.holds = make(map[string]*companionHold)
	}
	if hold := m.companions.holds[target.ID]; hold != nil {
		hold.lastNeeded = time.Now()
		return "", nil
	}
	var acquired []*domain.AcceleratorLease
	release := func() {
		for _, lease := range acquired {
			_ = m.store.ReleaseAcceleratorLease(context.WithoutCancel(ctx), lease.AcceleratorID, lease.WorkloadID, lease.FencingToken)
		}
	}
	for _, id := range targetAccelerators(target)[1:] {
		lease, ok, err := m.store.AcquireAcceleratorLease(ctx, id, companionOwner(target.ID), m.leaseTTL)
		if err != nil {
			release()
			return "", err
		}
		if !ok {
			release()
			holder := ""
			if lease != nil {
				holder = lease.WorkloadID
			}
			return fmt.Sprintf("companion accelerator %s is in use by %s", id, holder), nil
		}
		acquired = append(acquired, lease)
	}
	m.companions.holds[target.ID] = &companionHold{leases: acquired, lastNeeded: time.Now()}
	return "", nil
}

// keepCompanionLeases renews companion leases while their target has work and
// releases them once it has been idle for companionGrace. It is the only
// release path, so no admission or completion path has to remember it; a
// controller crash leaves leases that simply expire.
func (m *Manager) keepCompanionLeases() {
	interval := m.leaseTTL / 3
	if interval <= 0 || interval > 5*time.Second {
		interval = 5 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		ctx := m.lifecycleContext()
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		m.companions.mu.Lock()
		for targetID, hold := range m.companions.holds {
			if m.targetActiveCount(targetID) > 0 {
				hold.lastNeeded = time.Now()
			}
			if time.Since(hold.lastNeeded) > companionGrace {
				for _, lease := range hold.leases {
					_ = m.store.ReleaseAcceleratorLease(ctx, lease.AcceleratorID, lease.WorkloadID, lease.FencingToken)
				}
				delete(m.companions.holds, targetID)
				continue
			}
			for _, lease := range hold.leases {
				if err := m.store.RenewAcceleratorLease(ctx, lease.AcceleratorID, lease.WorkloadID, lease.FencingToken, m.leaseTTL); err != nil {
					m.log.Warn("companion accelerator lease renewal failed", "target_id", targetID, "accelerator_id", lease.AcceleratorID, "error", err)
				}
			}
		}
		m.companions.mu.Unlock()
	}
}
