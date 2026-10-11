package workloads

import (
	"context"
	"fmt"
	"strings"
	"time"

	"vram-governor/internal/domain"
)

type gpuTargetFence struct {
	target     Target
	generation uint64
}

func (m *Manager) snapshotAcceleratorTargetFences(acceleratorID string) []gpuTargetFence {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]gpuTargetFence, 0)
	for id, target := range m.targets {
		if target.AcceleratorID == acceleratorID {
			result = append(result, gpuTargetFence{target: target, generation: m.targetGenerations[id]})
		}
	}
	return result
}

func (m *Manager) acceleratorTargetFencesMatch(fences []gpuTargetFence) bool {
	for _, fence := range fences {
		if !m.targetFenceMatches(fence.target, fence.generation) {
			return false
		}
	}
	return true
}

// SetManagedGPUPerformance replaces the node's advertised, locally
// allowlisted accelerator set. No control command is sent for an unadvertised
// GPU, so existing nodes do not acquire extra startup latency.
func (m *Manager) SetManagedGPUPerformance(nodeID string, indices []int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.gpuPowerGeneration[nodeID]++
	for acceleratorID := range m.managedGPUPerformance {
		if strings.HasPrefix(acceleratorID, nodeID+"-gpu") {
			delete(m.managedGPUPerformance, acceleratorID)
		}
	}
	for _, index := range indices {
		if index >= 0 {
			m.managedGPUPerformance[fmt.Sprintf("%s-gpu%d", nodeID, index)] = struct{}{}
		}
	}
	if len(indices) > 0 {
		m.pendingGPUIdleReconcile[nodeID] = true
		delete(m.gpuIdleRetryAfter, nodeID)
	} else {
		delete(m.pendingGPUIdleReconcile, nodeID)
		delete(m.gpuIdleRetryAfter, nodeID)
	}
}

// ReconcileGPUIdleAfterTelemetry applies idle once a newly connected node's
// accelerators are visible to the controller. This also clears an active clock
// lock left behind by a controller restart without unloading warm models.
func (m *Manager) ReconcileGPUIdleAfterTelemetry(nodeID string) {
	m.mu.Lock()
	if !m.pendingGPUIdleReconcile[nodeID] || m.gpuIdleReconcileInFlight[nodeID] || time.Now().Before(m.gpuIdleRetryAfter[nodeID]) {
		m.mu.Unlock()
		return
	}
	m.gpuIdleReconcileInFlight[nodeID] = true
	generation := m.gpuPowerGeneration[nodeID]
	var accelerators []string
	for acceleratorID := range m.managedGPUPerformance {
		if strings.HasPrefix(acceleratorID, nodeID+"-gpu") {
			accelerators = append(accelerators, acceleratorID)
		}
	}
	m.mu.Unlock()
	if m.nodes == nil {
		m.mu.Lock()
		delete(m.gpuIdleReconcileInFlight, nodeID)
		m.mu.Unlock()
		return
	}
	node, err := m.nodes.GetNode(context.Background(), nodeID)
	if err != nil {
		m.mu.Lock()
		delete(m.gpuIdleReconcileInFlight, nodeID)
		m.mu.Unlock()
		return
	}
	available := make(map[string]struct{}, len(node.Accelerators))
	for _, accelerator := range node.Accelerators {
		available[accelerator.ID] = struct{}{}
	}
	for _, acceleratorID := range accelerators {
		if _, exists := available[acceleratorID]; !exists {
			m.mu.Lock()
			delete(m.gpuIdleReconcileInFlight, nodeID)
			m.mu.Unlock()
			return
		}
	}
	workloads, err := m.store.ListWorkloads(context.Background())
	if err != nil {
		m.mu.Lock()
		delete(m.gpuIdleReconcileInFlight, nodeID)
		m.mu.Unlock()
		return
	}
	for _, workload := range workloads {
		if workload.Status != domain.WorkloadRunning {
			continue
		}
		for _, acceleratorID := range accelerators {
			if workload.Decision.AcceleratorID == acceleratorID {
				// A restored or still-running workload must not be slowed by
				// an initial idle command. Normal release will park it later.
				m.mu.Lock()
				if m.gpuPowerGeneration[nodeID] == generation {
					delete(m.pendingGPUIdleReconcile, nodeID)
				}
				delete(m.gpuIdleReconcileInFlight, nodeID)
				m.mu.Unlock()
				return
			}
		}
	}
	go func() {
		allSucceeded := true
		for _, acceleratorID := range accelerators {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			err := m.setGPUPerformanceProfile(ctx, acceleratorID, "idle", "gpu-power:initial-idle:"+nodeID+":"+acceleratorID+":"+newID("reconcile"))
			cancel()
			if err != nil {
				allSucceeded = false
				m.log.Warn("initial GPU idle reconciliation failed", "accelerator_id", acceleratorID, "error", err)
			}
		}
		m.mu.Lock()
		if allSucceeded && m.gpuPowerGeneration[nodeID] == generation {
			delete(m.pendingGPUIdleReconcile, nodeID)
			delete(m.gpuIdleRetryAfter, nodeID)
		}
		delete(m.gpuIdleReconcileInFlight, nodeID)
		m.mu.Unlock()
	}()
}

// setGPUPerformanceProfile serializes transitions for one physical accelerator.
// The in-flight marker is a short state fence; the signed GPU command itself
// runs with every manager/state mutex released. A waiter sleeps on the marker
// channel and retries after the prior command publishes its result.
func (m *Manager) setGPUPerformanceProfile(ctx context.Context, acceleratorID, profile, idempotencyKey string) error {
	if acceleratorID == "" || profile == "" {
		return nil
	}
	m.mu.RLock()
	control := m.gpuPowerControl
	_, managed := m.managedGPUPerformance[acceleratorID]
	m.mu.RUnlock()
	if control == nil || !managed {
		return nil
	}
	_, nodeID, ok := m.nodeControlForTarget(ctx, Target{AcceleratorID: acceleratorID})
	if !ok {
		return nil
	}
	for {
		m.powerProfileLocksMu.Lock()
		inFlight := m.powerProfileInFlight[acceleratorID]
		if inFlight == nil {
			inFlight = make(chan struct{})
			m.powerProfileInFlight[acceleratorID] = inFlight
			m.powerProfileLocksMu.Unlock()
			defer func() {
				m.powerProfileLocksMu.Lock()
				if current := m.powerProfileInFlight[acceleratorID]; current == inFlight {
					delete(m.powerProfileInFlight, acceleratorID)
					close(inFlight)
				}
				m.powerProfileLocksMu.Unlock()
			}()
			break
		}
		m.powerProfileLocksMu.Unlock()
		select {
		case <-inFlight:
			continue
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	m.mu.Lock()
	m.gpuCommandFences[acceleratorID]++
	fence := m.gpuCommandFences[acceleratorID]
	m.mu.Unlock()
	targetFences := m.snapshotAcceleratorTargetFences(acceleratorID)
	if profile == "idle" {
		m.placementMu.Lock()
		for _, placement := range m.activePlacements {
			if placement.acceleratorID == acceleratorID {
				m.placementMu.Unlock()
				return nil
			}
		}
		m.placementMu.Unlock()
	}
	result, err := control(ctx, nodeID, "set_gpu_performance_profile", map[string]any{
		"accelerator_id": acceleratorID,
		"profile":        profile,
		"fencing_token":  int64(fence),
	}, idempotencyKey)
	if err == nil {
		if managed, _ := result["managed"].(bool); !managed {
			err = fmt.Errorf("node did not apply advertised GPU performance control")
		}
	}
	if err == nil {
		if reported, _ := result["accelerator_id"].(string); reported != acceleratorID {
			err = fmt.Errorf("GPU performance result accelerator mismatch")
		}
	}
	if err == nil && !m.acceleratorTargetFencesMatch(targetFences) {
		err = fmt.Errorf("GPU performance result target facts changed during command")
	}
	if err != nil {
		if profile == "idle" {
			m.mu.Lock()
			m.gpuPowerGeneration[nodeID]++
			m.pendingGPUIdleReconcile[nodeID] = true
			m.gpuIdleRetryAfter[nodeID] = time.Now().Add(30 * time.Second)
			m.mu.Unlock()
		}
		return err
	}
	m.log.Info("GPU performance profile applied", "accelerator_id", acceleratorID, "profile", profile)
	return nil
}
