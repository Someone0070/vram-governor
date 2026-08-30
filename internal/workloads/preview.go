package workloads

import (
	"context"
	"fmt"
	"sort"
	"time"

	"vram-governor/internal/domain"
)

// Preview evaluates placement without creating a workload, acquiring a
// lease, reserving budget, loading a model, or disturbing a running victim.
func (m *Manager) Preview(ctx context.Context, req domain.WorkloadRequest) (*domain.PlacementPreview, error) {
	if req.OwnerID == "" {
		return nil, fmt.Errorf("owner_id is required")
	}
	if req.PlacementPolicy == "" {
		req.PlacementPolicy = domain.PlacementBestFit
	}
	if req.PlacementPolicy == domain.PlacementSticky && req.PlacementKey == "" {
		return nil, fmt.Errorf("placement_key is required for sticky placement")
	}
	m.mu.RLock()
	adapter := m.adapters[req.Adapter]
	targets := make([]Target, 0, len(m.targets))
	for _, target := range m.targets {
		targets = append(targets, target)
	}
	m.mu.RUnlock()
	if adapter == nil {
		return nil, fmt.Errorf("unknown adapter %q", req.Adapter)
	}
	if err := adapter.Validate(ctx, req); err != nil {
		return nil, err
	}
	requirements, err := adapter.Requirements(ctx, req)
	if err != nil {
		return nil, err
	}
	workload := &domain.Workload{Request: req, Status: domain.WorkloadQueued, CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}
	estimates := m.estimateTargets(ctx, targets, workload, requirements)
	boundTarget := ""
	if req.PlacementPolicy == domain.PlacementSticky {
		boundTarget = m.boundTarget(ctx, req)
	}
	preview := &domain.PlacementPreview{Requirements: domain.RequirementsPreview{Model: requirements.Model, RequiredModels: requirements.RequiredModels, CustomNodes: requirements.CustomNodes, EstimatedVRAMMB: requirements.EstimatedVRAMMB, ContextTokens: requirements.ContextTokens}, GeneratedAt: time.Now().UTC()}
	for _, target := range targets {
		if target.Adapter != req.Adapter {
			continue
		}
		candidate := domain.PlacementCandidate{TargetID: target.ID, AcceleratorID: target.AcceleratorID, Eligible: true, ContextLimit: target.ContextLimit, Slots: target.Slots, AvailableSlots: m.availableSlots(target), CapacitySource: target.CapacitySource, CapacityVerified: target.CapacityVerified, Resident: requirements.Model == "" || containsString(target.ResidentModels, requirements.Model)}
		if estimate := estimates[target.ID]; estimate != nil {
			candidate.EstimatedStart, candidate.EstimatedEnd, candidate.Confidence, candidate.Score = &estimate.start, &estimate.end, estimate.confidence, estimate.score
		}
		switch {
		case target.Quarantined:
			candidate.Blocker = "provider/model route is quarantined"
		case !target.Enabled:
			candidate.Blocker = "target is disabled"
		case target.Cloud && req.Egress == domain.EgressLocalOnly:
			candidate.Blocker = "data egress policy requires local execution"
		case boundTarget != "" && target.ID != boundTarget:
			candidate.Blocker = "sticky session is pinned to another target"
		case m.inventoryBlocker(ctx, target, requirements) != "":
			candidate.Blocker = m.inventoryBlocker(ctx, target, requirements)
		case requirements.Model != "" && !containsString(target.Models, requirements.Model):
			candidate.Blocker = "model unavailable"
		case requirements.ContextTokens > 0 && target.ContextLimit > 0 && requirements.ContextTokens > target.ContextLimit:
			candidate.Blocker = fmt.Sprintf("context limit %d is below required %d", target.ContextLimit, requirements.ContextTokens)
		}
		if candidate.Blocker == "" {
			for _, model := range requirements.RequiredModels {
				if !containsString(target.Models, model) {
					candidate.Blocker = "workflow model unavailable: " + model
					break
				}
			}
		}
		if candidate.Blocker == "" {
			for _, node := range requirements.CustomNodes {
				if len(target.CustomNodes) > 0 && !containsString(target.CustomNodes, node) {
					candidate.Blocker = "custom node unavailable: " + node
					break
				}
			}
		}
		if candidate.Blocker == "" && !candidate.Resident {
			if target.SupportsModelLifecycle {
				candidate.ResidencyAction = "load_from_disk"
			} else {
				candidate.Blocker = "model is not resident and target cannot load it"
			}
		}
		if candidate.Blocker == "" && len(req.Transformations) > 0 {
			candidate.Plan, err = m.prepareExecutionPlan(adapter, workload, target)
			if err != nil {
				candidate.Blocker = "transformation preview rejected: " + err.Error()
			}
		}
		candidate.Eligible = candidate.Blocker == ""
		preview.Candidates = append(preview.Candidates, candidate)
	}
	sort.SliceStable(preview.Candidates, func(i, j int) bool {
		if preview.Candidates[i].Eligible != preview.Candidates[j].Eligible {
			return preview.Candidates[i].Eligible
		}
		if preview.Candidates[i].Score != preview.Candidates[j].Score {
			return preview.Candidates[i].Score < preview.Candidates[j].Score
		}
		return preview.Candidates[i].TargetID < preview.Candidates[j].TargetID
	})
	for _, candidate := range preview.Candidates {
		if candidate.Eligible {
			preview.Recommended = candidate.TargetID
			break
		}
	}
	return preview, nil
}
