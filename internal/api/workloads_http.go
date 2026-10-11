package api

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"

	"vram-governor/internal/domain"
	"vram-governor/internal/store"
	"vram-governor/internal/workloads"
)

func (s *Server) workloadsUnavailable(w http.ResponseWriter) bool {
	if s.workloads == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "workload scheduler unavailable"})
		return true
	}
	return false
}

func (s *Server) prepareRequest(r *http.Request, p Principal, req *domain.WorkloadRequest) error {
	if !allowsAdapter(p, req.Adapter) {
		return fmt.Errorf("adapter %q is not allowed", req.Adapter)
	}
	if len(req.ArtifactRefs) > 0 && s.artifacts == nil {
		return fmt.Errorf("artifact store is unavailable")
	}
	for _, ref := range req.ArtifactRefs {
		artifact, reader, err := s.artifacts.Open(r.Context(), ref)
		if reader != nil {
			reader.Close()
		}
		if err != nil || (!hasScope(p, "admin") && artifact.OwnerID != p.OwnerID) {
			return fmt.Errorf("artifact %q is unavailable", ref)
		}
	}
	req.OwnerID = p.OwnerID
	req.PrincipalID = p.ID
	req.ConcurrencyLimit = p.ConcurrencyLimit
	req.BudgetLimitCents = p.BudgetCents
	requestedPreemptionBudget := req.PreemptionBudget
	if req.PreemptionBudget < 0 {
		return fmt.Errorf("preemption_budget exceeds the authenticated principal limit")
	}
	if p.PreemptionBudget > 0 && req.PreemptionBudget > p.PreemptionBudget {
		req.PreemptionBudget = p.PreemptionBudget
	}
	if req.PreemptionBudget == 0 {
		req.PreemptionBudget = p.PreemptionBudget
	}
	// Checkpointability is an all-controls opt-in. A generic caller, or a
	// partially specified governor extension, remains locked even if one field
	// happens to request checkpointing; this keeps every safe-default matrix
	// cell non-preemptible. Preserve the authenticated principal's ordinary
	// budget on generic requests: it is an accounting limit, not permission to
	// opt into interruption.
	if req.Disruption != domain.DisruptionCheckpointable {
		req.InterruptionConsent = false
		req.Recoverable = false
	} else if !req.InterruptionConsent || !req.Recoverable || requestedPreemptionBudget <= 0 || req.PreemptionBudget <= 0 {
		req.Disruption = domain.DisruptionLocked
		req.InterruptionConsent = false
		req.Recoverable = false
		req.PreemptionBudget = 0
	}
	if req.OwnerID == "" {
		req.OwnerID = p.ID
	}
	if req.Plane == "" {
		req.Plane = domain.PlaneAPI
	}
	if p.MaxPriority > 0 && req.Priority > p.MaxPriority {
		req.Priority = p.MaxPriority
	}
	if req.Priority < 0 {
		req.Priority = 0
	}
	if key := strings.TrimSpace(r.Header.Get("Idempotency-Key")); key != "" {
		req.IdempotencyKey = key
	}
	if p.EgressPolicy == string(domain.EgressLocalOnly) {
		req.Egress = domain.EgressLocalOnly
	} else if p.EgressPolicy == string(domain.EgressSanitized) && req.Egress == domain.EgressAllowed {
		req.Egress = domain.EgressSanitized
	}
	return nil
}

func (s *Server) handleSubmitWorkload(w http.ResponseWriter, r *http.Request) {
	if s.workloadsUnavailable(w) {
		return
	}
	p, ok := s.requirePrincipal(w, r, "workloads:submit")
	if !ok {
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, 16<<20))
	if err != nil || !json.Valid(raw) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON request"})
		return
	}
	var marker struct {
		Operation string `json:"operation"`
	}
	_ = json.Unmarshal(raw, &marker)
	var req domain.WorkloadRequest
	creatorRequest := marker.Operation != ""
	if creatorRequest {
		var body creatorStudioRequest
		if err := decodeStrictCreator(raw, &body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		var blocked *creatorBlockedResponse
		req, blocked, err = s.buildCreatorWorkload(r, p, body)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		if blocked != nil {
			writeJSON(w, http.StatusUnprocessableEntity, blocked)
			return
		}
	} else if err := json.Unmarshal(raw, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if req.InteractiveStream {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "interactive_stream is reserved for protocol streaming routes"})
		return
	}
	if !creatorRequest {
		req.Plane = domain.PlaneAPI
	}
	if err := s.prepareRequest(r, p, &req); err != nil {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": err.Error()})
		return
	}
	workload, created, err := s.workloads.Submit(r.Context(), req)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	status := http.StatusAccepted
	if created {
		status = http.StatusCreated
	}
	if creatorRequest {
		writeJSON(w, status, s.creatorResponse(r, workload))
		return
	}
	writeJSON(w, status, workload)
}

func (s *Server) handlePreviewWorkload(w http.ResponseWriter, r *http.Request) {
	if s.workloadsUnavailable(w) {
		return
	}
	p, ok := s.requirePrincipal(w, r, "workloads:submit")
	if !ok {
		return
	}
	var req domain.WorkloadRequest
	if err := decodeJSONLimit(r, &req, 16<<20); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	req.Plane = domain.PlaneAPI
	if err := s.prepareRequest(r, p, &req); err != nil {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": err.Error()})
		return
	}
	preview, err := s.workloads.Preview(r.Context(), req)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, preview)
}

func (s *Server) handleListWorkloads(w http.ResponseWriter, r *http.Request) {
	if s.workloadsUnavailable(w) {
		return
	}
	p, ok := s.requirePrincipal(w, r, "workloads:read")
	if !ok {
		return
	}
	rows, err := s.workloads.List(r.Context())
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	if !hasScope(p, "admin") {
		filtered := rows[:0]
		for _, row := range rows {
			if row.Request.OwnerID == p.OwnerID {
				filtered = append(filtered, row)
			}
		}
		rows = filtered
	}
	result := make([]any, 0, len(rows))
	for _, row := range rows {
		if row.Request.Plane == domain.PlaneCreatorStudio && !hasScope(p, "admin") {
			result = append(result, s.creatorResponse(r, row))
		} else {
			result = append(result, row)
		}
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) ownedWorkload(w http.ResponseWriter, r *http.Request, p Principal, id string) (*domain.Workload, bool) {
	row, err := s.workloads.Get(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) || (err == nil && !hasScope(p, "admin") && row.Request.OwnerID != p.OwnerID) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "workload not found"})
		return nil, false
	}
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return nil, false
	}
	return row, true
}

func (s *Server) handleGetWorkload(w http.ResponseWriter, r *http.Request) {
	if s.workloadsUnavailable(w) {
		return
	}
	p, ok := s.requirePrincipal(w, r, "workloads:read")
	if !ok {
		return
	}
	row, ok := s.ownedWorkload(w, r, p, r.PathValue("id"))
	if ok {
		if row.Request.Plane == domain.PlaneCreatorStudio && !hasScope(p, "admin") {
			writeJSON(w, http.StatusOK, s.creatorResponse(r, row))
			return
		}
		writeJSON(w, http.StatusOK, row)
	}
}

func (s *Server) handleCancelWorkload(w http.ResponseWriter, r *http.Request) {
	if s.workloadsUnavailable(w) {
		return
	}
	p, ok := s.requirePrincipal(w, r, "workloads:cancel")
	if !ok {
		return
	}
	if _, ok := s.ownedWorkload(w, r, p, r.PathValue("id")); !ok {
		return
	}
	if err := s.workloads.Cancel(r.Context(), r.PathValue("id"), p.OwnerID, hasScope(p, "admin")); err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "cancelled"})
}

func (s *Server) handleApproveWorkload(w http.ResponseWriter, r *http.Request) {
	if s.workloadsUnavailable(w) {
		return
	}
	var body struct {
		PlanHash string `json:"plan_hash"`
		Mode     string `json:"mode"`
	}
	if err := decodeJSONLimit(r, &body, 1<<20); err != nil || body.PlanHash == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "plan_hash is required"})
		return
	}
	requiredScope := "workloads:approve"
	if body.Mode == string(domain.TransformDelegateSafeReview) {
		requiredScope = "workloads:delegate_safe_review"
	}
	p, ok := s.requirePrincipal(w, r, requiredScope)
	if !ok {
		return
	}
	if _, ok := s.ownedWorkload(w, r, p, r.PathValue("id")); !ok {
		return
	}
	if body.Mode == "" {
		body.Mode = string(domain.TransformAsk)
	}
	row, err := s.workloads.ApproveTransformation(r.Context(), r.PathValue("id"), body.PlanHash, p.ID, body.Mode)
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, row)
}

func (s *Server) handleReprioritizeWorkload(w http.ResponseWriter, r *http.Request) {
	if s.workloadsUnavailable(w) {
		return
	}
	p, ok := s.requirePrincipal(w, r, "workloads:reprioritize")
	if !ok {
		return
	}
	if _, ok := s.ownedWorkload(w, r, p, r.PathValue("id")); !ok {
		return
	}
	var body struct {
		Priority int `json:"priority"`
	}
	if err := decodeJSONLimit(r, &body, 1<<20); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "priority is required"})
		return
	}
	if body.Priority < 0 {
		body.Priority = 0
	}
	if p.MaxPriority > 0 && body.Priority > p.MaxPriority {
		body.Priority = p.MaxPriority
	}
	row, err := s.workloads.Reprioritize(r.Context(), r.PathValue("id"), body.Priority, p.ID)
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, row)
}

func (s *Server) handleWorkloadArtifacts(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requirePrincipal(w, r, "artifacts:read")
	if !ok {
		return
	}
	row, ok := s.ownedWorkload(w, r, p, r.PathValue("id"))
	if !ok {
		return
	}
	if s.artifacts == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "artifact store unavailable"})
		return
	}
	if row.Request.Plane == domain.PlaneCreatorStudio && !hasScope(p, "admin") {
		outputs := make([]creatorArtifactResponse, 0, len(row.OutputRefs))
		for _, ref := range row.OutputRefs {
			artifact, reader, err := s.artifacts.Open(r.Context(), ref)
			if reader != nil {
				reader.Close()
			}
			if err == nil && artifact.OwnerID == p.OwnerID {
				outputs = append(outputs, publicArtifact(artifact))
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"outputs": outputs})
		return
	}
	refs := append(append([]string(nil), row.Request.ArtifactRefs...), row.OutputRefs...)
	result := []*domain.Artifact{}
	for _, ref := range refs {
		artifact, reader, err := s.artifacts.Open(r.Context(), ref)
		if reader != nil {
			reader.Close()
		}
		if err == nil && (hasScope(p, "admin") || artifact.OwnerID == p.OwnerID) {
			result = append(result, artifact)
		}
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleExplainWorkload(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requirePrincipal(w, r, "workloads:read")
	if !ok {
		return
	}
	row, ok := s.ownedWorkload(w, r, p, r.PathValue("id"))
	if !ok {
		return
	}
	if row.Request.Plane == domain.PlaneCreatorStudio && !hasScope(p, "admin") {
		writeJSON(w, http.StatusOK, map[string]any{"workload": s.creatorResponse(r, row)})
		return
	}
	approvals, _ := s.workloadStore.ListTransformationApprovals(r.Context(), row.Request.ID)
	plans, _ := s.workloadStore.ListTransitionPlans(r.Context(), row.Request.ID, 100)
	events, _ := s.workloadStore.ListAuditEvents(r.Context(), row.Request.OwnerID, 500)
	filtered := make([]*domain.AuditEvent, 0)
	for _, event := range events {
		if event.WorkloadID == row.Request.ID {
			filtered = append(filtered, event)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"workload": row, "transformation_approvals": jsonSlice(approvals), "transition_plans": jsonSlice(plans), "events": filtered})
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requirePrincipal(w, r, "events:read")
	if !ok {
		return
	}
	owner := p.OwnerID
	if hasScope(p, "admin") {
		owner = ""
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	events, err := s.workloadStore.ListAuditEvents(r.Context(), owner, limit)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, events)
}

func (s *Server) handleNotifications(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requirePrincipal(w, r, "workloads:read")
	if !ok {
		return
	}
	ownerID := p.OwnerID
	if hasScope(p, "admin") {
		ownerID = ""
	}
	rows, err := s.workloads.ListNotifications(r.Context(), ownerID, 100)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, rows)
}

func (s *Server) handleChatCompletions(w http.ResponseWriter, r *http.Request) {
	if s.workloadsUnavailable(w) {
		return
	}
	p, ok := s.requirePrincipal(w, r, "inference:submit")
	if !ok {
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 8<<20))
	if err != nil || !json.Valid(body) {
		writeJSON(w, 400, map[string]string{"error": "invalid JSON body"})
		return
	}
	var envelope struct {
		Model               string `json:"model"`
		Stream              bool   `json:"stream"`
		MaxTokens           int    `json:"max_tokens"`
		MaxCompletionTokens int    `json:"max_completion_tokens"`
		Governor            struct {
			Adapter         string                 `json:"adapter"`
			Egress          domain.EgressPolicy    `json:"egress"`
			ContextTokens   int                    `json:"context_tokens"`
			PlacementKey    string                 `json:"placement_key"`
			PlacementPolicy domain.PlacementPolicy `json:"placement_policy"`
			// These controls are an explicit, authenticated governor extension.
			// Their zero values intentionally keep ordinary OpenAI requests locked.
			Checkpointable      bool `json:"checkpointable"`
			InterruptionConsent bool `json:"interruption_consent"`
			Recoverable         bool `json:"recoverable"`
			PreemptionBudget    int  `json:"preemption_budget"`
		} `json:"governor"`
	}
	_ = json.Unmarshal(body, &envelope)
	adapter := envelope.Governor.Adapter
	if adapter == "" {
		adapter = "llamacpp"
	}
	maxOutput := envelope.MaxCompletionTokens
	if maxOutput == 0 {
		maxOutput = envelope.MaxTokens
	}
	placementKey := envelope.Governor.PlacementKey
	if placementKey == "" {
		placementKey = r.Header.Get("X-VRAM-Placement-Key")
	}
	placementPolicy := envelope.Governor.PlacementPolicy
	if placementPolicy == "" {
		placementPolicy = domain.PlacementPolicy(r.Header.Get("X-VRAM-Placement-Policy"))
	}
	disruption := domain.DisruptionLocked
	if envelope.Governor.Checkpointable && envelope.Governor.InterruptionConsent && envelope.Governor.Recoverable && envelope.Governor.PreemptionBudget > 0 {
		disruption = domain.DisruptionCheckpointable
	}
	queuePolicy := domain.QueueFailFast
	// A checkpointable stream must be able to remain queued while the higher
	// priority workload owns the target; otherwise admission would reject the
	// original HTTP session before its signed restore can deliver the suffix.
	if disruption == domain.DisruptionCheckpointable {
		queuePolicy = domain.QueueWait
	}
	req := domain.WorkloadRequest{Plane: domain.PlaneOpenAI, Adapter: adapter, WorkloadType: "llm.chat", Payload: body, QoS: domain.QoSInteractive, QueuePolicy: queuePolicy, Disruption: disruption, InterruptionConsent: envelope.Governor.InterruptionConsent, Egress: envelope.Governor.Egress, Bounds: domain.WorkloadBounds{ContextTokens: envelope.Governor.ContextTokens, MaxOutput: maxOutput}, PlacementKey: placementKey, PlacementPolicy: placementPolicy, InteractiveStream: envelope.Stream, Recoverable: envelope.Governor.Recoverable, PreemptionBudget: envelope.Governor.PreemptionBudget}
	if err := s.prepareRequest(r, p, &req); err != nil {
		writeJSON(w, 403, map[string]string{"error": err.Error()})
		return
	}
	row, _, err := s.workloads.Submit(r.Context(), req)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	if row.Status == domain.WorkloadWaiting || row.Status == domain.WorkloadRejected {
		retrySeconds := 1
		if row.Decision.EstimatedStart != nil {
			if seconds := int(time.Until(*row.Decision.EstimatedStart).Seconds()); seconds > retrySeconds {
				retrySeconds = seconds
			}
		}
		w.Header().Set("Retry-After", strconv.Itoa(retrySeconds))
		status := http.StatusServiceUnavailable
		errorType := "service_unavailable"
		blocker := strings.ToLower(strings.Join(append([]string{row.Decision.Blocker}, row.Decision.Alternatives...), " "))
		if strings.Contains(blocker, "busy") || strings.Contains(blocker, "concurrency") || strings.Contains(blocker, "budget") || strings.Contains(blocker, "cooldown") || strings.Contains(blocker, "circuit open") || strings.Contains(blocker, "reserved") {
			status = http.StatusTooManyRequests
			errorType = "capacity_unavailable"
		}
		message := row.Decision.Blocker
		if len(row.Decision.Alternatives) > 0 {
			message += ": " + strings.Join(row.Decision.Alternatives, "; ")
		}
		writeJSON(w, status, map[string]any{"error": map[string]any{"message": message, "type": errorType, "workload_id": row.Request.ID}, "admission": row.Decision})
		return
	}
	if envelope.Stream {
		flusher, ok := w.(http.Flusher)
		if !ok {
			_ = s.workloads.Cancel(context.Background(), row.Request.ID, row.Request.OwnerID, false)
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": map[string]string{"message": "streaming is unsupported by this HTTP writer", "type": "stream_error"}})
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("X-Accel-Buffering", "no")
		started := false
		_, streamErr := s.workloads.RunStream(r.Context(), row.Request.ID, func(chunk []byte) error {
			if !started {
				w.WriteHeader(http.StatusOK)
				started = true
			}
			written, err := w.Write(chunk)
			if err == nil && written != len(chunk) {
				err = io.ErrShortWrite
			}
			flusher.Flush()
			return err
		})
		if streamErr != nil {
			if !started && r.Context().Err() == nil {
				w.Header().Set("Content-Type", "application/json")
				writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": map[string]string{"message": streamErr.Error(), "type": "backend_stream_error"}})
			}
			return
		}
		if !started {
			w.WriteHeader(http.StatusOK)
		}
		return
	}
	row, err = s.workloads.Wait(r.Context(), row.Request.ID)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": map[string]string{"message": err.Error(), "type": "execution_error"}})
		return
	}
	if row.Status != domain.WorkloadSucceeded {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": map[string]string{"message": row.Error, "type": "backend_error"}})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(row.InlineOutput)
}

func (s *Server) handleOpenAIModels(w http.ResponseWriter, r *http.Request) {
	if s.workloadsUnavailable(w) {
		return
	}
	p, ok := s.requirePrincipal(w, r, "inference:submit")
	if !ok {
		return
	}
	type governorMetadata struct {
		MaxContextTokens        int                                `json:"max_context_tokens,omitempty"`
		AvailableContextLimits  []int                              `json:"available_context_limits,omitempty"`
		ActiveContextLimits     []int                              `json:"active_context_limits,omitempty"`
		CapacityProfiles        []workloads.RuntimeCapacityProfile `json:"capacity_profiles,omitempty"`
		CurrentSlots            int                                `json:"current_slots"`
		CurrentlyAvailableSlots int                                `json:"currently_available_slots"`
		MaximumParallelSlots    int                                `json:"maximum_parallel_slots"`
		MaxAccelerators         int                                `json:"max_accelerators"`
		TargetCount             int                                `json:"target_count"`
		Resident                bool                               `json:"resident"`
		LifecycleCapable        bool                               `json:"lifecycle_capable"`
		ProfileSwitchSupported  bool                               `json:"profile_switch_supported"`
	}
	type modelEntry struct {
		ID       string           `json:"id"`
		Object   string           `json:"object"`
		Created  int              `json:"created"`
		OwnedBy  string           `json:"owned_by"`
		Governor governorMetadata `json:"governor"`
	}
	byModel := make(map[string]*modelEntry)
	currentSlots := make(map[string]map[string]int)
	availableSlots := make(map[string]map[string]int)
	maximumSlots := make(map[string]map[string]int)
	for _, target := range s.workloads.Targets() {
		if !target.Enabled || target.Quarantined || (target.Adapter != "llamacpp" && target.Adapter != "openrouter") || !allowsAdapter(p, target.Adapter) || (target.Cloud && p.EgressPolicy == string(domain.EgressLocalOnly)) {
			continue
		}
		for _, model := range target.Models {
			if model == "" || model == "*" {
				continue
			}
			entry, exists := byModel[model]
			if !exists {
				entry = &modelEntry{ID: model, Object: "model", Created: 0, OwnedBy: "vram-governor"}
				entry.Governor.MaxAccelerators = s.workloads.MaxAcceleratorsForModel(model)
				byModel[model] = entry
				currentSlots[model] = make(map[string]int)
				availableSlots[model] = make(map[string]int)
				maximumSlots[model] = make(map[string]int)
			}
			capacityKey := target.AcceleratorID
			if capacityKey == "" {
				capacityKey = "target/" + target.ID
			}
			entry.Governor.TargetCount++
			entry.Governor.Resident = entry.Governor.Resident || stringPresent(target.ResidentModels, model)
			entry.Governor.LifecycleCapable = entry.Governor.LifecycleCapable || target.SupportsModelLifecycle
			if target.ContextLimit > 0 {
				if target.ContextLimit > entry.Governor.MaxContextTokens {
					entry.Governor.MaxContextTokens = target.ContextLimit
				}
				if !intPresent(entry.Governor.AvailableContextLimits, target.ContextLimit) {
					entry.Governor.AvailableContextLimits = append(entry.Governor.AvailableContextLimits, target.ContextLimit)
				}
				if !intPresent(entry.Governor.ActiveContextLimits, target.ContextLimit) {
					entry.Governor.ActiveContextLimits = append(entry.Governor.ActiveContextLimits, target.ContextLimit)
				}
			}
			if target.Slots > currentSlots[model][capacityKey] {
				currentSlots[model][capacityKey] = target.Slots
			}
			free := s.workloads.CurrentlyAvailableSlotsForModel(r.Context(), target, model)
			if free > availableSlots[model][capacityKey] {
				availableSlots[model][capacityKey] = free
			}
			if target.Slots > maximumSlots[model][capacityKey] {
				maximumSlots[model][capacityKey] = target.Slots
			}
			currentProfileID := target.ActiveRuntimeProfile
			if currentProfileID == "" {
				currentProfileID = target.ID
			}
			currentProfile := workloads.RuntimeCapacityProfile{ID: currentProfileID, ContextLimit: target.ContextLimit, Slots: target.Slots}
			if currentProfile.ContextLimit > 0 && currentProfile.Slots > 0 && !runtimeProfilePresent(entry.Governor.CapacityProfiles, currentProfile) {
				entry.Governor.CapacityProfiles = append(entry.Governor.CapacityProfiles, currentProfile)
			}
			entry.Governor.ProfileSwitchSupported = entry.Governor.ProfileSwitchSupported || target.SupportsRuntimeProfileSwitch
			for _, profile := range target.RuntimeProfiles {
				if !runtimeProfilePresent(entry.Governor.CapacityProfiles, profile) {
					entry.Governor.CapacityProfiles = append(entry.Governor.CapacityProfiles, profile)
				}
				if !intPresent(entry.Governor.AvailableContextLimits, profile.ContextLimit) {
					entry.Governor.AvailableContextLimits = append(entry.Governor.AvailableContextLimits, profile.ContextLimit)
				}
				if profile.ContextLimit > entry.Governor.MaxContextTokens {
					entry.Governor.MaxContextTokens = profile.ContextLimit
				}
				if profile.Slots > maximumSlots[model][capacityKey] {
					maximumSlots[model][capacityKey] = profile.Slots
				}
			}
		}
	}
	models := make([]modelEntry, 0, len(byModel))
	for _, entry := range byModel {
		sort.Ints(entry.Governor.AvailableContextLimits)
		sort.Ints(entry.Governor.ActiveContextLimits)
		sort.Slice(entry.Governor.CapacityProfiles, func(i, j int) bool {
			if entry.Governor.CapacityProfiles[i].ContextLimit != entry.Governor.CapacityProfiles[j].ContextLimit {
				return entry.Governor.CapacityProfiles[i].ContextLimit < entry.Governor.CapacityProfiles[j].ContextLimit
			}
			return entry.Governor.CapacityProfiles[i].Slots > entry.Governor.CapacityProfiles[j].Slots
		})
		entry.Governor.CurrentSlots = sumLargestCapacities(currentSlots[entry.ID], entry.Governor.MaxAccelerators)
		entry.Governor.CurrentlyAvailableSlots = sumLargestCapacities(availableSlots[entry.ID], entry.Governor.MaxAccelerators)
		entry.Governor.MaximumParallelSlots = sumLargestCapacities(maximumSlots[entry.ID], entry.Governor.MaxAccelerators)
		models = append(models, *entry)
	}
	sort.Slice(models, func(i, j int) bool { return models[i].ID < models[j].ID })
	writeJSON(w, http.StatusOK, map[string]any{"object": "list", "data": models})
}

func runtimeProfilePresent(values []workloads.RuntimeCapacityProfile, wanted workloads.RuntimeCapacityProfile) bool {
	for _, value := range values {
		if value.ContextLimit == wanted.ContextLimit && value.Slots == wanted.Slots {
			return true
		}
	}
	return false
}

func sumLargestCapacities(values map[string]int, limit int) int {
	capacities := make([]int, 0, len(values))
	for _, value := range values {
		capacities = append(capacities, value)
	}
	sort.Sort(sort.Reverse(sort.IntSlice(capacities)))
	if limit < 1 {
		limit = 1
	}
	if len(capacities) > limit {
		capacities = capacities[:limit]
	}
	total := 0
	for _, capacity := range capacities {
		total += capacity
	}
	return total
}

func stringPresent(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func intPresent(values []int, wanted int) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func openAIChunk(response json.RawMessage, requestedModel string) map[string]any {
	var completion struct {
		ID      string `json:"id"`
		Model   string `json:"model"`
		Choices []struct {
			Message struct {
				Content any `json:"content"`
			} `json:"message"`
			FinishReason any `json:"finish_reason"`
		} `json:"choices"`
	}
	_ = json.Unmarshal(response, &completion)
	if completion.ID == "" {
		completion.ID = "chatcmpl-governor"
	}
	if completion.Model == "" {
		completion.Model = requestedModel
	}
	var content any = ""
	var finish any = "stop"
	if len(completion.Choices) > 0 {
		content = completion.Choices[0].Message.Content
		if completion.Choices[0].FinishReason != nil {
			finish = completion.Choices[0].FinishReason
		}
	}
	return map[string]any{"id": completion.ID, "object": "chat.completion.chunk", "created": time.Now().Unix(), "model": completion.Model, "choices": []any{map[string]any{"index": 0, "delta": map[string]any{"role": "assistant", "content": content}, "finish_reason": finish}}}
}

func (s *Server) handleComfyPrompt(w http.ResponseWriter, r *http.Request) {
	if s.workloadsUnavailable(w) {
		return
	}
	p, ok := s.requirePrincipal(w, r, "comfy:submit")
	if !ok {
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 32<<20))
	if err != nil || !json.Valid(body) {
		writeJSON(w, 400, map[string]string{"error": "invalid JSON body"})
		return
	}
	publicID := newPublicID()
	var parsed struct {
		ClientID string `json:"client_id"`
	}
	_ = json.Unmarshal(body, &parsed)
	req := domain.WorkloadRequest{Plane: domain.PlaneComfy, Adapter: "comfy", WorkloadType: "comfy.workflow", Payload: body, ArtifactRefs: comfyArtifactRefs(body), ItemID: publicID, OperationVersion: "v1", IdempotencyKey: r.Header.Get("Idempotency-Key"), QoS: domain.QoSNormal, QueuePolicy: domain.QueueWait, Disruption: domain.DisruptionLocked, Egress: domain.EgressLocalOnly, Recoverable: true}
	if err := s.prepareRequest(r, p, &req); err != nil {
		writeJSON(w, 403, map[string]string{"error": err.Error()})
		return
	}
	row, _, err := s.workloads.Submit(r.Context(), req)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	mapping := &domain.PromptMapping{PublicPromptID: publicID, WorkloadID: row.Request.ID, ClientID: parsed.ClientID}
	if row.Plan != nil {
		mapping.TargetID = row.Plan.TargetID
	}
	if row.Execution != nil {
		mapping.BackendPromptID = row.Execution.ExternalID
	}
	if err := s.workloadStore.SavePromptMapping(r.Context(), mapping); err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"prompt_id": publicID, "number": 0, "node_errors": map[string]any{}})
}

func newPublicID() string {
	return strings.TrimPrefix(fmt.Sprintf("%d-%d", time.Now().UnixNano(), time.Now().UnixMilli()), "-")
}

func comfyArtifactRefs(body []byte) []string {
	var value any
	if json.Unmarshal(body, &value) != nil {
		return nil
	}
	seen := make(map[string]struct{})
	var visit func(any)
	visit = func(current any) {
		switch typed := current.(type) {
		case string:
			if len(typed) == 36 && strings.HasPrefix(typed, "art-") {
				if _, err := hex.DecodeString(strings.TrimPrefix(typed, "art-")); err == nil {
					seen[typed] = struct{}{}
				}
			}
		case []any:
			for _, item := range typed {
				visit(item)
			}
		case map[string]any:
			for _, item := range typed {
				visit(item)
			}
		}
	}
	visit(value)
	refs := make([]string, 0, len(seen))
	for ref := range seen {
		refs = append(refs, ref)
	}
	sort.Strings(refs)
	return refs
}

func (s *Server) comfyRow(w http.ResponseWriter, r *http.Request, p Principal, publicID string) (*domain.Workload, bool) {
	mapping, err := s.workloadStore.GetPromptMapping(r.Context(), publicID)
	if errors.Is(err, store.ErrNotFound) {
		writeJSON(w, 404, map[string]string{"error": "prompt not found"})
		return nil, false
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "history unavailable"})
		return nil, false
	}
	if mapping == nil || mapping.WorkloadID == "" {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "history unavailable"})
		return nil, false
	}
	row, err := s.workloads.Get(r.Context(), mapping.WorkloadID)
	if errors.Is(err, store.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "prompt not found"})
		return nil, false
	}
	if err != nil || row == nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "history unavailable"})
		return nil, false
	}
	if !hasScope(p, "admin") && row.Request.OwnerID != p.OwnerID {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "prompt not found"})
		return nil, false
	}
	if mapping.PublicPromptID != publicID || row.Request.ID != mapping.WorkloadID || row.Request.ItemID != publicID || row.Request.Plane != domain.PlaneComfy || row.Request.Adapter != "comfy" || (mapping.TargetID != "" && (row.Plan == nil || row.Plan.TargetID != mapping.TargetID)) || (mapping.BackendPromptID != "" && row.Execution != nil && row.Execution.ExternalID != "" && mapping.BackendPromptID != row.Execution.ExternalID) {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "history unavailable"})
		return nil, false
	}
	return row, true
}

const (
	comfyHistoryMaxInputBytes = 8 << 20
	comfyHistoryMaxOutputBytes = 16 << 20
	comfyHistoryMaxRows = 500
)

var errComfyHistoryTooLarge = errors.New("Comfy history exceeds public response bounds")

func duplicateFreeJSON(raw []byte) error {
	if !utf8.Valid(raw) {
		return errors.New("invalid UTF-8 JSON")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var scan func() error
	scan = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delim, isDelim := token.(json.Delim)
		if !isDelim {
			return nil
		}
		switch delim {
		case '{':
			seen := make(map[string]struct{})
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return errors.New("invalid object key")
				}
				if _, exists := seen[key]; exists {
					return errors.New("duplicate object key")
				}
				seen[key] = struct{}{}
				if err := scan(); err != nil {
					return err
				}
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim('}') {
				return errors.New("invalid object end")
			}
		case '[':
			for decoder.More() {
				if err := scan(); err != nil {
					return err
				}
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim(']') {
				return errors.New("invalid array end")
			}
		default:
			return errors.New("unexpected JSON delimiter")
		}
		return nil
	}
	if err := scan(); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return errors.New("trailing JSON value")
		}
		return err
	}
	return nil
}

func comfyExpectedGraphCount(payload json.RawMessage) (int, error) {
	if len(payload) == 0 || len(payload) > comfyHistoryMaxInputBytes || duplicateFreeJSON(payload) != nil {
		return 0, errors.New("invalid Comfy request payload")
	}
	var body map[string]json.RawMessage
	if err := json.Unmarshal(payload, &body); err != nil || body == nil {
		return 0, errors.New("invalid Comfy request payload")
	}
	if chunksRaw, exists := body["managed_chunks"]; exists {
		var chunks []json.RawMessage
		if json.Unmarshal(chunksRaw, &chunks) != nil {
			return 0, errors.New("invalid managed Comfy chunks")
		}
		if len(chunks) > 0 {
			for _, chunkRaw := range chunks {
				var chunk map[string]json.RawMessage
				if json.Unmarshal(chunkRaw, &chunk) != nil || chunk == nil {
					return 0, errors.New("invalid managed Comfy chunk")
				}
				var prompt map[string]json.RawMessage
				if json.Unmarshal(chunk["prompt"], &prompt) != nil || len(prompt) == 0 {
					return 0, errors.New("invalid managed Comfy prompt")
				}
			}
			return len(chunks), nil
		}
	}
	var prompt map[string]json.RawMessage
	if json.Unmarshal(body["prompt"], &prompt) != nil || len(prompt) == 0 {
		return 0, errors.New("invalid Comfy prompt")
	}
	return 1, nil
}

func normalizeComfyHistory(row *domain.Workload, publicID string) (json.RawMessage, error) {
	if row == nil || publicID == "" || row.Request.ItemID != publicID || row.Request.Plane != domain.PlaneComfy || row.Request.Adapter != "comfy" {
		return nil, errors.New("invalid Comfy workload identity")
	}
	if len(row.InlineOutput) > comfyHistoryMaxInputBytes {
		return nil, errComfyHistoryTooLarge
	}
	if len(row.InlineOutput) == 0 || duplicateFreeJSON(row.InlineOutput) != nil {
		return nil, errors.New("invalid Comfy history JSON")
	}
	graphCount, err := comfyExpectedGraphCount(row.Request.Payload)
	if err != nil {
		return nil, err
	}
	var backend map[string]json.RawMessage
	if err := json.Unmarshal(row.InlineOutput, &backend); err != nil || backend == nil || len(backend) == 0 {
		return nil, errors.New("invalid Comfy history object")
	}
	if graphCount == 1 && len(backend) != 1 || graphCount > 1 && len(backend) != graphCount {
		return nil, errors.New("Comfy history graph count mismatch")
	}
	managedExecution := row.Plan != nil && row.Plan.RuntimeProtocol == "managed_comfy_v1"
	if graphCount == 1 && !managedExecution && row.Execution != nil && row.Execution.ExternalID != "" {
		if _, exists := backend[row.Execution.ExternalID]; !exists {
			return nil, errors.New("Comfy execution identity mismatch")
		}
	}
	for backendID, rawRecord := range backend {
		if backendID == "" || len(rawRecord) == 0 || len(rawRecord) > comfyHistoryMaxInputBytes || duplicateFreeJSON(rawRecord) != nil {
			return nil, errors.New("invalid Comfy history record")
		}
		var record map[string]json.RawMessage
		if json.Unmarshal(rawRecord, &record) != nil || record == nil || len(record) == 0 {
			return nil, errors.New("invalid Comfy history record")
		}
		var outputs map[string]json.RawMessage
		if json.Unmarshal(record["outputs"], &outputs) != nil || outputs == nil {
			return nil, errors.New("invalid Comfy history outputs")
		}
		var status struct {
			StatusStr string `json:"status_str"`
			Completed bool   `json:"completed"`
		}
		if json.Unmarshal(record["status"], &status) != nil || status.StatusStr != "success" || !status.Completed {
			return nil, errors.New("invalid Comfy history status")
		}
		if promptRaw, present := record["prompt"]; present {
			var promptTuple []json.RawMessage
			if json.Unmarshal(promptRaw, &promptTuple) != nil || len(promptTuple) < 2 {
				return nil, errors.New("invalid Comfy history prompt tuple")
			}
			var tupleID string
			if json.Unmarshal(promptTuple[1], &tupleID) != nil || tupleID != backendID {
				return nil, errors.New("Comfy history prompt identity mismatch")
			}
			publicJSON, _ := json.Marshal(publicID)
			promptTuple[1] = publicJSON
			promptJSON, _ := json.Marshal(promptTuple)
			record["prompt"] = promptJSON
			rewritten, _ := json.Marshal(record)
			backend[backendID] = rewritten
		}
	}
	var normalized json.RawMessage
	if graphCount == 1 {
		for _, record := range backend {
			normalized = append([]byte(nil), record...)
		}
	} else {
		normalized, err = json.Marshal(backend)
		if err != nil {
			return nil, err
		}
	}
	publicOutput, err := json.Marshal(map[string]json.RawMessage{publicID: normalized})
	if err != nil {
		return nil, err
	}
	if len(publicOutput) > comfyHistoryMaxOutputBytes {
		return nil, errComfyHistoryTooLarge
	}
	return publicOutput, nil
}

func (s *Server) handleComfyHistory(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requirePrincipal(w, r, "comfy:read")
	if !ok {
		return
	}
	if !allowsAdapter(p, "comfy") {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "insufficient_scope"})
		return
	}
	id := r.PathValue("id")
	row, ok := s.comfyRow(w, r, p, id)
	if !ok {
		return
	}
	if row.Status != domain.WorkloadSucceeded {
		writeJSON(w, 200, map[string]any{})
		return
	}
	normalized, err := normalizeComfyHistory(row, id)
	if err != nil {
		if errors.Is(err, errComfyHistoryTooLarge) {
			writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "history limit exceeded"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "history unavailable"})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(normalized)
}

func (s *Server) handleComfyHistoryAll(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requirePrincipal(w, r, "comfy:read")
	if !ok {
		return
	}
	if !allowsAdapter(p, "comfy") {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "insufficient_scope"})
		return
	}
	if s.workloads == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "history unavailable"})
		return
	}
	rows, err := s.workloads.List(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "history unavailable"})
		return
	}
	out := make(map[string]json.RawMessage)
	outputBytes := 2
	ownedRows := 0
	seenIDs := make(map[string]struct{})
	for _, row := range rows {
		if row == nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "history unavailable"})
			return
		}
		if row.Request.Plane != domain.PlaneComfy || (!hasScope(p, "admin") && row.Request.OwnerID != p.OwnerID) {
			continue
		}
		ownedRows++
		if ownedRows > comfyHistoryMaxRows {
			writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "history limit exceeded"})
			return
		}
		if row.Request.Adapter != "comfy" || row.Request.ItemID == "" {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "history unavailable"})
			return
		}
		if _, duplicate := seenIDs[row.Request.ItemID]; duplicate {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "history unavailable"})
			return
		}
		seenIDs[row.Request.ItemID] = struct{}{}
		if row.Status != domain.WorkloadSucceeded {
			continue
		}
		if _, duplicate := out[row.Request.ItemID]; duplicate {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "history unavailable"})
			return
		}
		normalized, err := normalizeComfyHistory(row, row.Request.ItemID)
		if err != nil {
			if errors.Is(err, errComfyHistoryTooLarge) {
				writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "history limit exceeded"})
				return
			}
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "history unavailable"})
			return
		}
		publicKey, err := json.Marshal(row.Request.ItemID)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "history unavailable"})
			return
		}
		outputBytes += len(publicKey) + len(normalized) + 3
		if outputBytes > comfyHistoryMaxOutputBytes {
			writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "history limit exceeded"})
			return
		}
		var entry map[string]json.RawMessage
		if json.Unmarshal(normalized, &entry) != nil || len(entry) != 1 {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "history unavailable"})
			return
		}
		out[row.Request.ItemID] = entry[row.Request.ItemID]
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleComfyQueue(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requirePrincipal(w, r, "comfy:read")
	if !ok {
		return
	}
	rows, _ := s.workloads.List(r.Context())
	running := []any{}
	pending := []any{}
	for _, row := range rows {
		if row.Request.Plane != domain.PlaneComfy || (!hasScope(p, "admin") && row.Request.OwnerID != p.OwnerID) {
			continue
		}
		entry := []any{0, row.Request.ItemID, json.RawMessage(row.Request.Payload)}
		if row.Status == domain.WorkloadRunning {
			running = append(running, entry)
		} else if row.Status == domain.WorkloadQueued || row.Status == domain.WorkloadWaiting {
			pending = append(pending, entry)
		}
	}
	writeJSON(w, 200, map[string]any{"queue_running": running, "queue_pending": pending})
}

func (s *Server) handleComfyQueueMutation(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requirePrincipal(w, r, "comfy:cancel")
	if !ok {
		return
	}
	var body struct {
		Delete []string `json:"delete"`
	}
	if decodeJSONLimit(r, &body, 1<<20) != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid body"})
		return
	}
	for _, id := range body.Delete {
		if row, found := s.comfyRow(w, r, p, id); found {
			if err := s.workloads.Cancel(r.Context(), row.Request.ID, p.OwnerID, hasScope(p, "admin")); err != nil {
				writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error(), "prompt_id": id})
				return
			}
		}
	}
	writeJSON(w, 200, map[string]any{})
}

func (s *Server) handleComfyWS(w http.ResponseWriter, r *http.Request) {
	p, ok := s.authenticate(r)
	if !ok || !hasScope(p, "comfy:read") {
		http.Error(w, "unauthorized", 401)
		return
	}
	conn, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	defer conn.CloseNow()
	rows, _ := s.workloads.List(r.Context())
	queueRemaining := 0
	for _, row := range rows {
		if row.Request.Plane == domain.PlaneComfy && (hasScope(p, "admin") || row.Request.OwnerID == p.OwnerID) && (row.Status == domain.WorkloadQueued || row.Status == domain.WorkloadWaiting || row.Status == domain.WorkloadRunning) {
			queueRemaining++
		}
	}
	if err := wsjson.Write(r.Context(), conn, map[string]any{"type": "status", "data": map[string]any{"status": map[string]any{"exec_info": map[string]int{"queue_remaining": queueRemaining}}, "sid": r.URL.Query().Get("clientId")}}); err != nil {
		return
	}
	events, unsubscribe := s.workloads.Subscribe()
	defer unsubscribe()
	for {
		select {
		case <-r.Context().Done():
			return
		case event, open := <-events:
			if !open {
				return
			}
			if !hasScope(p, "admin") && event.OwnerID != p.OwnerID {
				continue
			}
			row, err := s.workloads.Get(r.Context(), event.WorkloadID)
			if err != nil || row.Request.Plane != domain.PlaneComfy {
				continue
			}
			messageType := event.Type
			data := map[string]any{"prompt_id": row.Request.ItemID, "workload_id": event.WorkloadID}
			switch event.Type {
			case "workload.admitted":
				messageType = "execution_start"
			case "workload.progress":
				messageType = "progress"
				data["value"] = row.Progress
				data["max"] = 1
			case "workload.succeeded":
				messageType = "executing"
				data["node"] = nil
			case "workload.failed":
				messageType = "execution_error"
				data["exception_message"] = row.Error
			case "workload.cancelled":
				messageType = "execution_interrupted"
			}
			message := map[string]any{"type": messageType, "data": data}
			if err := wsjson.Write(r.Context(), conn, message); err != nil {
				return
			}
		}
	}
}

func (s *Server) handleUploadImage(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requirePrincipal(w, r, "artifacts:write")
	if !ok {
		return
	}
	if s.artifacts == nil {
		writeJSON(w, 503, map[string]string{"error": "artifact store unavailable"})
		return
	}
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid multipart upload"})
		return
	}
	file, header, err := r.FormFile("image")
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": "image part is required"})
		return
	}
	defer file.Close()
	artifact, err := s.artifacts.Put(r.Context(), p.OwnerID, "", header.Filename, header.Header.Get("Content-Type"), file)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"name": artifact.ID, "subfolder": "", "type": "input", "artifact": artifact})
}

func (s *Server) handleViewArtifact(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requirePrincipal(w, r, "artifacts:read")
	if !ok {
		return
	}
	if s.artifacts == nil {
		writeJSON(w, 503, map[string]string{"error": "artifact store unavailable"})
		return
	}
	id := r.URL.Query().Get("artifact_id")
	if id == "" {
		id = r.URL.Query().Get("filename")
	}
	if id == "" {
		id = r.URL.Query().Get("filename")
	}
	artifact, reader, err := s.artifacts.Open(r.Context(), id)
	if err != nil || artifact == nil || reader == nil {
		if reader != nil {
			_ = reader.Close()
		}
		writeJSON(w, 404, map[string]string{"error": "artifact not found"})
		return
	}
	if !hasScope(p, "admin") && artifact.OwnerID != p.OwnerID {
		_ = reader.Close()
		writeJSON(w, 404, map[string]string{"error": "artifact not found"})
		return
	}
	defer reader.Close()
	if artifact.MediaType != "" {
		w.Header().Set("Content-Type", artifact.MediaType)
	}
	w.Header().Set("Content-Length", strconv.FormatInt(artifact.Size, 10))
	w.Header().Set("ETag", `"`+artifact.SHA256+`"`)
	_, _ = io.Copy(w, reader)
}

func decodeJSONLimit(r *http.Request, out any, limit int64) error {
	decoder := json.NewDecoder(io.LimitReader(r.Body, limit))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return fmt.Errorf("invalid request: %w", err)
	}
	return nil
}
