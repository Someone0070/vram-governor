package api

import (
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

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"

	"vram-governor/internal/domain"
	"vram-governor/internal/store"
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
	req.PreemptionBudget = p.PreemptionBudget
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
	var req domain.WorkloadRequest
	if err := decodeJSONLimit(r, &req, 16<<20); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if req.InteractiveStream {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "interactive_stream is reserved for protocol streaming routes"})
		return
	}
	req.Plane = domain.PlaneAPI
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
	writeJSON(w, http.StatusOK, rows)
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
	req := domain.WorkloadRequest{Plane: domain.PlaneOpenAI, Adapter: adapter, WorkloadType: "llm.chat", Payload: body, QoS: domain.QoSInteractive, QueuePolicy: domain.QueueFailFast, Disruption: domain.DisruptionLocked, Egress: envelope.Governor.Egress, Bounds: domain.WorkloadBounds{ContextTokens: envelope.Governor.ContextTokens, MaxOutput: maxOutput}, PlacementKey: placementKey, PlacementPolicy: placementPolicy, InteractiveStream: envelope.Stream, Recoverable: false}
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
		MaxContextTokens       int   `json:"max_context_tokens,omitempty"`
		AvailableContextLimits []int `json:"available_context_limits,omitempty"`
		TargetCount            int   `json:"target_count"`
		Resident               bool  `json:"resident"`
		LifecycleCapable       bool  `json:"lifecycle_capable"`
	}
	type modelEntry struct {
		ID       string           `json:"id"`
		Object   string           `json:"object"`
		Created  int              `json:"created"`
		OwnedBy  string           `json:"owned_by"`
		Governor governorMetadata `json:"governor"`
	}
	byModel := make(map[string]*modelEntry)
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
				byModel[model] = entry
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
			}
		}
	}
	models := make([]modelEntry, 0, len(byModel))
	for _, entry := range byModel {
		sort.Ints(entry.Governor.AvailableContextLimits)
		models = append(models, *entry)
	}
	sort.Slice(models, func(i, j int) bool { return models[i].ID < models[j].ID })
	writeJSON(w, http.StatusOK, map[string]any{"object": "list", "data": models})
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
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return nil, false
	}
	return s.ownedWorkload(w, r, p, mapping.WorkloadID)
}

func (s *Server) handleComfyHistory(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requirePrincipal(w, r, "comfy:read")
	if !ok {
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
	var backend any
	if len(row.InlineOutput) > 0 {
		_ = json.Unmarshal(row.InlineOutput, &backend)
	}
	writeJSON(w, 200, map[string]any{id: backend})
}

func (s *Server) handleComfyHistoryAll(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requirePrincipal(w, r, "comfy:read")
	if !ok {
		return
	}
	rows, _ := s.workloads.List(r.Context())
	out := map[string]any{}
	for _, row := range rows {
		if row.Request.Plane != domain.PlaneComfy || (!hasScope(p, "admin") && row.Request.OwnerID != p.OwnerID) || row.Status != domain.WorkloadSucceeded {
			continue
		}
		var value any
		_ = json.Unmarshal(row.InlineOutput, &value)
		out[row.Request.ItemID] = value
	}
	writeJSON(w, 200, out)
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
	if err != nil || (!hasScope(p, "admin") && artifact.OwnerID != p.OwnerID) {
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
