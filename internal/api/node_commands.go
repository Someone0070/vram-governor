package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"vram-governor/internal/domain"
	"vram-governor/internal/store"
	"vram-governor/internal/workloads"
	"vram-governor/internal/wsproto"
)

var runtimeProfileCommandGuard sync.Mutex

// ValidateLLMCheckpointEnvelope is shared by controller-side checkpoint
// integrations. It is intentionally additive to the existing residency
// command schema: checkpoint operations carry the same node/model/runtime
// fence plus generation/profile/context identity and cannot be replayed as a
// different owner's snapshot.
func ValidateLLMCheckpointEnvelope(args map[string]any) error {
	for _, key := range []string{"target_id", "model", "runtime_identity", "capability_version", "capability_revision", "profile_fingerprint", "context_fingerprint", "owner_id", "workload_id", "idempotency_key"} {
		value, ok := args[key].(string)
		if !ok || strings.TrimSpace(value) == "" {
			return fmt.Errorf("checkpoint argument %s is required", key)
		}
	}
	for _, key := range []string{"generation", "fencing_token", "context_limit"} {
		value, ok := args[key]
		if !ok {
			return fmt.Errorf("checkpoint argument %s is required", key)
		}
		switch n := value.(type) {
		case int:
			if n < 0 {
				return fmt.Errorf("checkpoint argument %s is invalid", key)
			}
		case int64:
			if n < 0 {
				return fmt.Errorf("checkpoint argument %s is invalid", key)
			}
		case float64:
			if n < 0 || n != float64(int64(n)) {
				return fmt.Errorf("checkpoint argument %s is invalid", key)
			}
		default:
			return fmt.Errorf("checkpoint argument %s is invalid", key)
		}
	}
	if snapshot, ok := args["snapshot_name"].(string); ok && (snapshot == "" || strings.ContainsAny(snapshot, "/\\") || strings.Contains(snapshot, "..")) {
		return fmt.Errorf("checkpoint snapshot name is unsafe")
	}
	return nil
}

func (s *Server) handleCreateNodeCommand(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	if len(s.commandSecret) < 16 {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "node command signing is not configured"})
		return
	}
	nodeID := r.PathValue("id")
	if _, err := s.nodes.GetNode(r.Context(), nodeID); err != nil {
		if err == store.ErrNotFound {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "node not found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	var body struct {
		Command    string         `json:"command"`
		Args       map[string]any `json:"args,omitempty"`
		TTLSeconds int            `json:"ttl_seconds,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON: " + err.Error()})
		return
	}
	if err := validateNodeCommand(body.Command, body.Args); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if body.Command == "query_model_state" {
		originalID, _ := body.Args["original_command_id"].(string)
		originalKey, _ := body.Args["original_idempotency_key"].(string)
		original, lookupErr := s.workloadStore.GetNodeCommand(r.Context(), originalID)
		if lookupErr != nil || original == nil || original.NodeID != r.PathValue("id") || original.IdempotencyKey != originalKey || original.Command == "query_model_state" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "query original command linkage is not a durable pending or completed command"})
			return
		}
		if err := validateControllerQueryArgs(original, body.Args); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
	}
	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Idempotency-Key is required"})
		return
	}
	if body.TTLSeconds <= 0 {
		body.TTLSeconds = 120
	}
	if body.TTLSeconds > 600 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "ttl_seconds may not exceed 600"})
		return
	}
	now := time.Now().UTC()
	command := &domain.NodeCommand{ID: newCommandID(), IdempotencyKey: idempotencyKey, NodeID: nodeID, Command: body.Command, Args: body.Args, IssuedBy: principal.ID, Status: domain.NodeCommandQueued, CreatedAt: now, ExpiresAt: now.Add(time.Duration(body.TTLSeconds) * time.Second), UpdatedAt: now}
	wire := nodeCommandPayload(command)
	signature, err := wsproto.SignCommand(wire, s.commandSecret)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	command.Signature = signature
	var stored *domain.NodeCommand
	var created bool
	if body.Command == "switch_runtime_profile" {
		runtimeProfileCommandGuard.Lock()
		releaseTicket, ticketErr := s.requireRuntimeProfileDispatchTicket(nodeID, body.Args, idempotencyKey)
		if ticketErr != nil {
			runtimeProfileCommandGuard.Unlock()
			writeJSON(w, http.StatusConflict, map[string]string{"error": ticketErr.Error()})
			return
		}
		if guardErr := s.rejectUnresolvedRuntimeProfileCommand(r.Context(), nodeID, body.Args, idempotencyKey); guardErr != nil {
			releaseTicket()
			runtimeProfileCommandGuard.Unlock()
			writeJSON(w, http.StatusConflict, map[string]string{"error": guardErr.Error()})
			return
		}
		stored, created, err = s.workloadStore.CreateNodeCommand(r.Context(), command)
		releaseTicket()
		runtimeProfileCommandGuard.Unlock()
	} else {
		stored, created, err = s.workloadStore.CreateNodeCommand(r.Context(), command)
	}
	if err != nil {
		if errors.Is(err, store.ErrNodeCommandConflict) {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "idempotency key conflicts with a different signed node command"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if !created && !nodeCommandReplayMatches(stored, command.NodeID, command.Command, command.Args) {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "idempotency key conflicts with a different signed node command"})
		return
	}
	if created {
		s.appendNodeCommandAudit(r.Context(), principal.ID, stored, "node.command.created", "info")
	}
	if stored.Uncertain {
		// HTTP idempotent replay is query-first as well. Never redispatch the
		// original mutation merely because the original waiter disappeared.
		s.scheduleNodeRecovery(stored.ID)
		writeJSON(w, http.StatusAccepted, stored)
		return
	}
	_ = s.sendNodeCommand(r.Context(), stored)
	latest, _ := s.workloadStore.GetNodeCommand(r.Context(), stored.ID)
	writeJSON(w, http.StatusAccepted, latest)
}

func (s *Server) handleListNodeCommands(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAdmin(w, r); !ok {
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	rows, err := s.workloadStore.ListNodeCommands(r.Context(), r.URL.Query().Get("node_id"), limit)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, rows)
}

func validateNodeCommand(command string, args map[string]any) error {
	switch command {
	case "checkpoint_slot_query", "checkpoint_slot_assign", "checkpoint_start", "checkpoint_pause", "checkpoint_save", "checkpoint_stop_confirm", "checkpoint_release", "checkpoint_reload", "checkpoint_restore", "checkpoint_reuse_verify", "checkpoint_resume", "checkpoint_rollback_resume", "checkpoint_cancel", "checkpoint_continue", "checkpoint_state_query":
		return wsproto.ValidateCheckpointCommandArgs(command, args)
	case "refresh_capabilities", "drain_runtimes":
		return nil
	case "load_model", "unload_model", "warm_model", "offload_model", "demote_model", "protect_warm_model", "cleanup_warm_model", "reverify_warm_model", "query_model_state":
		if err := wsproto.ValidateResidencyCommandArgs(command, args); err != nil {
			return err
		}
		if targetKind, _ := args["target_kind"].(string); targetKind != "llamacpp" {
			return fmt.Errorf("target_kind must be llamacpp")
		}
		for _, key := range []string{"target_id", "model", "runtime_identity", "capability_version", "capability_revision", "expected_tier"} {
			value, _ := args[key].(string)
			if strings.TrimSpace(value) == "" {
				return fmt.Errorf("%s is required", key)
			}
		}
		expectedTier := map[string]string{"load_model": "hot_vram", "unload_model": "cold_disk", "warm_model": "warm_ram", "offload_model": "warm_ram", "demote_model": "warm_ram", "protect_warm_model": "warm_ram", "cleanup_warm_model": "cold_disk", "reverify_warm_model": "warm_ram", "query_model_state": "query"}[command]
		if got, _ := args["expected_tier"].(string); got != expectedTier {
			return fmt.Errorf("expected_tier must be %s", expectedTier)
		}
		fence, err := observationFence(args["fencing_token"])
		if err != nil || fence < 0 {
			return fmt.Errorf("fencing_token must be a nonnegative integer")
		}
		return nil
	case "switch_runtime_profile":
		if target, _ := args["target_id"].(string); target == "" {
			return fmt.Errorf("target_id is required")
		}
		if profile, _ := args["profile_id"].(string); profile == "" {
			return fmt.Errorf("profile_id is required")
		}
		return nil
	case "reclaim_accelerator":
		if target, _ := args["target_id"].(string); target == "" {
			return fmt.Errorf("target_id is required")
		}
		return nil
	case "set_gpu_performance_profile":
		if accelerator, _ := args["accelerator_id"].(string); accelerator == "" {
			return fmt.Errorf("accelerator_id is required")
		}
		if profile, _ := args["profile"].(string); profile != "idle" && profile != "active" {
			return fmt.Errorf("profile must be idle or active")
		}
		return nil
	default:
		return fmt.Errorf("command is not allowlisted")
	}
}

// executeNodeCommand is the scheduler-facing half of the signed node control
// channel. It persists before delivery, waits for the node-confirmed result,
// and reuses the durable result for a repeated idempotency key.
func (s *Server) executeNodeCommand(ctx context.Context, nodeID, command string, args map[string]any, idempotencyKey string) (map[string]any, error) {
	if len(s.commandSecret) < 16 {
		return nil, fmt.Errorf("node command signing is not configured")
	}
	if idempotencyKey == "" {
		return nil, fmt.Errorf("node command idempotency key is required")
	}
	if command == "query_model_state" {
		args = cloneCommandArgs(args)
		if targetKind, ok := args["target_kind"].(string); !ok || targetKind != "llamacpp" {
			return nil, fmt.Errorf("query target_kind is required")
		}
		originalKey, _ := args["original_idempotency_key"].(string)
		originalID, _ := args["original_command_id"].(string)
		if originalID == "" && originalKey != "" {
			rows, listErr := s.workloadStore.ListNodeCommandRecovery(ctx, nodeID, "")
			if listErr != nil {
				return nil, listErr
			}
			for _, candidate := range rows {
				if candidate != nil && candidate.NodeID == nodeID && candidate.IdempotencyKey == originalKey {
					originalID = candidate.ID
					args["original_command_id"] = originalID
					break
				}
			}
		}
		if originalID == "" || originalKey == "" {
			return nil, fmt.Errorf("query original command linkage is required")
		}
		original, getErr := s.workloadStore.GetNodeCommand(ctx, originalID)
		if getErr != nil || original == nil || original.NodeID != nodeID || original.IdempotencyKey != originalKey {
			return nil, fmt.Errorf("query original command linkage is invalid")
		}
		if err := validateControllerQueryArgs(original, args); err != nil {
			return nil, err
		}
	}
	if err := validateNodeCommand(command, args); err != nil {
		return nil, err
	}
	if _, err := s.nodes.GetNode(ctx, nodeID); err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	// The controller's wait deadline is deliberately separate from the signed
	// command's reconciliation window. A caller may cancel while the node is
	// still authorized to finish and report the result for this idempotency key.
	expires := now.Add(10 * time.Minute)
	if s.nodeCommandExpiry > 0 {
		expires = now.Add(s.nodeCommandExpiry)
	}
	row := &domain.NodeCommand{ID: newCommandID(), IdempotencyKey: idempotencyKey, NodeID: nodeID, Command: command, Args: args, IssuedBy: "controller", Status: domain.NodeCommandQueued, CreatedAt: now, ExpiresAt: expires, UpdatedAt: now}
	wire := nodeCommandPayload(row)
	signature, err := wsproto.SignCommand(wire, s.commandSecret)
	if err != nil {
		return nil, err
	}
	row.Signature = signature
	if command == "switch_runtime_profile" {
		runtimeProfileCommandGuard.Lock()
		releaseTicket, err := s.requireRuntimeProfileDispatchTicket(nodeID, args, idempotencyKey)
		if err != nil {
			runtimeProfileCommandGuard.Unlock()
			return nil, err
		}
		if err := s.rejectUnresolvedRuntimeProfileCommand(ctx, nodeID, args, idempotencyKey); err != nil {
			releaseTicket()
			runtimeProfileCommandGuard.Unlock()
			return nil, err
		}
		stored, created, err := s.workloadStore.CreateNodeCommand(ctx, row)
		releaseTicket()
		runtimeProfileCommandGuard.Unlock()
		if err != nil {
			return nil, err
		}
		if !created && !nodeCommandReplayMatches(stored, nodeID, command, args) {
			return nil, fmt.Errorf("idempotency key conflicts with a different signed node command")
		}
		if created {
			s.appendNodeCommandAudit(ctx, "controller", stored, "node.command.created", "info")
		}
		return s.waitForNodeCommand(ctx, stored)
	}
	stored, created, err := s.workloadStore.CreateNodeCommand(ctx, row)
	if err != nil {
		return nil, err
	}
	if !created && !nodeCommandReplayMatches(stored, nodeID, command, args) {
		return nil, fmt.Errorf("idempotency key conflicts with a different signed node command")
	}
	if created {
		s.appendNodeCommandAudit(ctx, "controller", stored, "node.command.created", "info")
	}
	return s.waitForNodeCommand(ctx, stored)
}

func (s *Server) waitForNodeCommand(ctx context.Context, stored *domain.NodeCommand) (map[string]any, error) {
	if stored.Uncertain {
		// Durable uncertainty is query-first even for a fresh controller
		// waiter/recovery pass. Never send the original mutation again after
		// restart or reconnect.
		return s.reconcileUncertainNodeCommand(ctx, stored)
	}
	// Delivery is bounded by the command expiry, not by the caller's shorter
	// observation deadline. The wait below remains cancellable independently.
	if err := s.sendNodeCommand(ctx, stored); err != nil {
		// The durable row remains queued/sent and the caller receives the
		// delivery error; reconnect recovery owns the eventual retry.
		s.log.Warn("node command delivery failed", "command_id", stored.ID, "node_id", stored.NodeID, "command", stored.Command, "err", err)
		return nil, err
	}
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		current, getErr := s.workloadStore.GetNodeCommand(ctx, stored.ID)
		if getErr != nil {
			return nil, getErr
		}
		switch current.Status {
		case domain.NodeCommandSucceeded:
			var result map[string]any
			if len(current.Result) > 0 {
				_ = json.Unmarshal(current.Result, &result)
			}
			if err := s.projectRuntimeProfileResult(current, result); err != nil {
				return nil, fmt.Errorf("runtime profile observation was not projected before command success: %w", err)
			}
			return result, nil
		case domain.NodeCommandFailed, domain.NodeCommandExpired:
			return nil, fmt.Errorf("node command %s: %s", current.Status, current.Error)
		}
		if current.Uncertain {
			return s.reconcileUncertainNodeCommand(ctx, current)
		}
		if !current.ExpiresAt.IsZero() && !time.Now().UTC().Before(current.ExpiresAt) {
			// A connected-but-silent node is still an ambiguous side-effect
			// boundary. Promote the exact durable row to uncertainty at expiry and
			// hand it to the autonomous query/recovery loop; never wait forever on
			// the caller's context while the signed command window is over.
			recoveryCtx, recoveryCancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
			promoted, promoteErr := s.workloadStore.PromoteNodeCommandUncertain(recoveryCtx, current.ID, current.NodeID, nil, "unresolved: command expired before node result; authoritative recovery required")
			recoveryCancel()
			if promoteErr != nil && !errors.Is(promoteErr, store.ErrNodeCommandConflict) {
				return nil, fmt.Errorf("node command expiry could not be made durable: %w", promoteErr)
			}
			if promoted != nil && promoted.Uncertain {
				s.scheduleNodeRecovery(promoted.ID)
			}
			return nil, fmt.Errorf("node command %s expired; recovery is pending", current.ID)
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("node command did not complete: %w", ctx.Err())
		case <-ticker.C:
		}
	}
}

// rejectUnresolvedRuntimeProfileCommand prevents a new physical profile switch
// while an earlier switch on the node has no accepted result. The signed
// profile command lacks card identity, so guarding only one target alias would
// leave routes sharing that card exposed.
// The read and durable create are serialized so concurrent callers cannot
// both pass an empty-history check.
func (s *Server) rejectUnresolvedRuntimeProfileCommand(ctx context.Context, nodeID string, args map[string]any, idempotencyKey string) error {
	targetID, _ := args["target_id"].(string)
	rows, err := s.workloadStore.ListNodeCommandRecovery(ctx, nodeID, "")
	if err != nil {
		return err
	}
	if s.workloads == nil {
		return fmt.Errorf("runtime profile observation_unavailable; manager history scope is unavailable")
	}
	history := make([]*domain.NodeCommand, 0, len(rows))
	for _, prior := range rows {
		if prior == nil || prior.NodeID != nodeID || prior.Command != "switch_runtime_profile" {
			continue
		}
		if prior.IdempotencyKey == idempotencyKey {
			if !nodeCommandReplayMatches(prior, nodeID, "switch_runtime_profile", args) {
				return fmt.Errorf("idempotency key conflicts with a different signed node command")
			}
			continue
		}
		history = append(history, prior)
	}
	if reason := s.workloads.RuntimeProfileHistoryBlocker(nodeID, targetID, history); reason != "" {
		return fmt.Errorf("runtime profile observation_unavailable; %s", reason)
	}
	return nil
}

// requireRuntimeProfileDispatchTicket is the side-effect authorization gate
// for every physical switch gateway. Durable history and an accepted old
// observation are not dispatch authority; only the scheduler's exact current
// transition ticket may cross the API/websocket boundary. The raw admin HTTP
// endpoint currently has no public way to obtain such a ticket and therefore
// remains intentionally disabled for profile switches until that API exists.
func (s *Server) requireRuntimeProfileDispatchTicket(nodeID string, args map[string]any, idempotencyKey string) (func(), error) {
	if s.workloads == nil {
		return nil, fmt.Errorf("runtime profile observation_unavailable; no current manager transition ticket is available")
	}
	targetID, _ := args["target_id"].(string)
	release, err := s.workloads.ClaimRuntimeProfileDispatch(nodeID, targetID, args, idempotencyKey)
	if err != nil {
		return nil, fmt.Errorf("runtime profile observation_unavailable; switch requires the exact current manager transition ticket: %w", err)
	}
	return release, nil
}

// ExecuteNodeCommand is the narrow production hook used by restart
// reconciliation and the workload manager. It deliberately delegates to the
// durable signed command path rather than exposing a direct node HTTP seam.
func (s *Server) ExecuteNodeCommand(ctx context.Context, nodeID, command string, args map[string]any, idempotencyKey string) (map[string]any, error) {
	return s.executeNodeCommand(ctx, nodeID, command, args, idempotencyKey)
}

func cloneCommandArgs(args map[string]any) map[string]any {
	copyArgs := make(map[string]any, len(args)+4)
	for key, value := range args {
		copyArgs[key] = value
	}
	return copyArgs
}

func validateControllerQueryArgs(original *domain.NodeCommand, args map[string]any) error {
	if original == nil {
		return fmt.Errorf("query original command linkage is invalid")
	}
	for _, key := range []string{"target_id", "model", "runtime_identity", "capability_version", "capability_revision"} {
		want, _ := original.Args[key].(string)
		got, _ := args[key].(string)
		if want == "" || got != want {
			return fmt.Errorf("query %s does not match original command", key)
		}
	}
	wantFence, err := observationFence(original.Args["fencing_token"])
	if err != nil {
		return fmt.Errorf("original fencing_token: %w", err)
	}
	gotFence, err := observationFence(args["expected_fence"])
	if err != nil || gotFence != wantFence {
		return fmt.Errorf("query expected_fence does not match original command")
	}
	if reference, refErr := observationFence(args["observed_after_fence"]); refErr != nil || reference != wantFence {
		return fmt.Errorf("query observed_after_fence does not match original command")
	}
	return nil
}

// reconcileUncertainNodeCommand is the only path that resolves a node result
// marked uncertain. It issues a new, exact-resource read-only command through
// the same signed websocket boundary and leaves the original row Sent until
// authoritative truth settles it.
func (s *Server) reconcileUncertainNodeCommand(ctx context.Context, original *domain.NodeCommand) (map[string]any, error) {
	if original == nil {
		return nil, fmt.Errorf("uncertain node command is missing")
	}
	if !original.ExpiresAt.IsZero() && !time.Now().UTC().Before(original.ExpiresAt) {
		s.scheduleNodeRecovery(original.ID)
		return nil, fmt.Errorf("uncertain node command %s is outside its signed window; recovery is pending", original.ID)
	}
	// ComfyUI's native /free mutation has no authoritative model/cache state
	// query. Keep its durable command uncertain for recovery rather than
	// fabricating a query result or terminal failure.
	if original != nil && original.Command == "reclaim_accelerator" {
		return nil, fmt.Errorf("observation_unavailable: ComfyUI reclaim requires an authoritative status endpoint")
	}
	if original != nil && strings.HasPrefix(original.Command, "checkpoint_") {
		return s.reconcileUncertainCheckpointCommand(ctx, original)
	}
	query, err := s.issueAuthoritativeQuery(ctx, original)
	if err != nil {
		return nil, err
	}
	queryAttempts := 0
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		current, getErr := s.workloadStore.GetNodeCommand(ctx, query.ID)
		if getErr != nil {
			return nil, getErr
		}
		if !original.ExpiresAt.IsZero() && !time.Now().UTC().Before(original.ExpiresAt) {
			s.scheduleNodeRecovery(original.ID)
			return nil, fmt.Errorf("authoritative query exceeded command expiry; recovery is pending for %s", original.ID)
		}
		switch current.Status {
		case domain.NodeCommandSucceeded:
			var observed map[string]any
			if len(current.Result) > 0 {
				_ = json.Unmarshal(current.Result, &observed)
			}
			if validationErr := validateAuthoritativeObservation(original, query, observed); validationErr != nil {
				return nil, fmt.Errorf("authoritative query rejected: %w", validationErr)
			}
			return s.settleUncertainOriginal(ctx, original.ID, observed)
		case domain.NodeCommandFailed, domain.NodeCommandExpired:
			// A failed/expired query is not authoritative evidence. Retain the
			// original mutation and create a fresh linked query attempt; never
			// poison it with a terminal query failure.
			queryAttempts++
			if queryAttempts >= 3 {
				return nil, fmt.Errorf("unresolved: authoritative query %s: %s", current.Status, current.Error)
			}
			query, err = s.issueAuthoritativeQuery(ctx, original)
			if err != nil {
				return nil, fmt.Errorf("unresolved: authoritative query retry: %w", err)
			}
		}
		if !current.ExpiresAt.IsZero() && !time.Now().UTC().Before(current.ExpiresAt) {
			s.scheduleNodeRecovery(original.ID)
			return nil, fmt.Errorf("authoritative query window expired; recovery is pending for %s", original.ID)
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("authoritative query did not complete: %w", ctx.Err())
		case <-ticker.C:
		}
	}
}

// reconcileUncertainCheckpointCommand is query-first recovery for checkpoint
// mutations. It never replays a save/restore/stop after an ambiguous result;
// only a signed, operation-bound state query may provide evidence.
func (s *Server) reconcileUncertainCheckpointCommand(ctx context.Context, original *domain.NodeCommand) (map[string]any, error) {
	if original == nil {
		return nil, fmt.Errorf("uncertain checkpoint command is missing")
	}
	if !original.ExpiresAt.IsZero() && !time.Now().UTC().Before(original.ExpiresAt) {
		s.scheduleNodeRecovery(original.ID)
		return nil, fmt.Errorf("uncertain checkpoint command %s is outside its signed window; recovery is pending", original.ID)
	}
	query, err := s.issueAuthoritativeQuery(ctx, original)
	if err != nil {
		return nil, err
	}
	queryAttempts := 0
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		current, getErr := s.workloadStore.GetNodeCommand(ctx, query.ID)
		if getErr != nil {
			return nil, getErr
		}
		if !original.ExpiresAt.IsZero() && !time.Now().UTC().Before(original.ExpiresAt) {
			s.scheduleNodeRecovery(original.ID)
			return nil, fmt.Errorf("checkpoint query exceeded command expiry; recovery is pending for %s", original.ID)
		}
		switch current.Status {
		case domain.NodeCommandSucceeded:
			var observed map[string]any
			_ = json.Unmarshal(current.Result, &observed)
			if validationErr := validateAuthoritativeCheckpointObservation(original, query, observed); validationErr != nil {
				return nil, fmt.Errorf("checkpoint state query rejected: %w", validationErr)
			}
			// Keep the original uncertain row visible until the coordinator has
			// reconciled/compensated the physical slot. Returning validated
			// evidence is safe; terminalizing it here would lose recovery intent.
			return observed, nil
		case domain.NodeCommandFailed, domain.NodeCommandExpired:
			queryAttempts++
			if queryAttempts >= 3 {
				return nil, fmt.Errorf("unresolved: checkpoint state query %s: %s", current.Status, current.Error)
			}
			query, err = s.issueAuthoritativeQuery(ctx, original)
			if err != nil {
				return nil, err
			}
		}
		if !current.ExpiresAt.IsZero() && !time.Now().UTC().Before(current.ExpiresAt) {
			s.scheduleNodeRecovery(original.ID)
			return nil, fmt.Errorf("checkpoint state query window expired; recovery is pending for %s", original.ID)
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("checkpoint state query did not complete: %w", ctx.Err())
		case <-ticker.C:
		}
	}
}

func validateAuthoritativeCheckpointObservation(original, query *domain.NodeCommand, observed map[string]any) error {
	if original == nil || query == nil || observed == nil || query.Command != "checkpoint_state_query" || query.ReconcilesCommandID != original.ID {
		return fmt.Errorf("query linkage is not checkpoint-specific")
	}
	if observed["node_id"] != original.NodeID || observed["command_id"] != query.ID || observed["idempotency_key"] != query.IdempotencyKey || observed["action"] != "state_query" {
		return fmt.Errorf("checkpoint query envelope mismatch")
	}
	for _, key := range []string{"target_id", "checkpoint_operation_id", "generation", "fencing_token"} {
		if observed[key] == nil || query.Args[key] == nil || fmt.Sprint(observed[key]) != fmt.Sprint(query.Args[key]) {
			return fmt.Errorf("checkpoint query %s mismatch", key)
		}
	}
	if _, ok := observed["slots"]; !ok {
		return fmt.Errorf("checkpoint query omitted authoritative slots")
	}
	// The node phase journal is the source of truth for lifecycle evidence. A
	// result that contains only the signed query envelope is not evidence: it
	// could be produced by echoing the controller's expected arguments after a
	// node restart. Require every journal field and bind immutable identities to
	// the original signed operation while leaving phase/ordinal as observations
	// for the coordinator's exact DAG comparison.
	for _, key := range []string{"observed_phase", "observed_runtime_identity", "observed_model_fingerprint", "observed_profile_fingerprint", "observed_context_fingerprint", "observed_snapshot_name", "observed_snapshot_digest", "observed_conversation_id", "observed_continuation_conversation_id"} {
		value, ok := observed[key].(string)
		if !ok {
			return fmt.Errorf("checkpoint query omitted authoritative %s", key)
		}
		if key == "observed_phase" && strings.TrimSpace(value) == "" {
			return fmt.Errorf("checkpoint query observed phase is empty")
		}
	}
	phaseOrdinal, err := observationFence(observed["observed_phase_ordinal"])
	if err != nil || phaseOrdinal <= 0 {
		return fmt.Errorf("checkpoint query observed phase ordinal is invalid")
	}
	observedSlot, err := observationFence(observed["observed_slot_id"])
	if err != nil {
		return fmt.Errorf("checkpoint query observed slot is invalid")
	}
	if requestedSlot, requestedErr := observationFence(query.Args["slot_id"]); requestedErr == nil && observedSlot != requestedSlot {
		return fmt.Errorf("checkpoint query observed slot mismatch")
	}
	for _, binding := range []struct{ observed, expected string }{
		{"observed_runtime_identity", "runtime_identity"},
		{"observed_model_fingerprint", "model"},
		{"observed_profile_fingerprint", "profile_fingerprint"},
		{"observed_context_fingerprint", "context_fingerprint"},
		{"observed_snapshot_name", "snapshot_name"},
		{"observed_snapshot_digest", "snapshot_digest"},
		{"observed_conversation_id", "conversation_id"},
		{"observed_continuation_conversation_id", "continuation_conversation_id"},
	} {
		expected, _ := query.Args[binding.expected].(string)
		actual, _ := observed[binding.observed].(string)
		if expected != "" && actual != expected {
			return fmt.Errorf("checkpoint query observed %s mismatch", binding.observed)
		}
	}
	return nil
}

func observationString(observed map[string]any, key string) (string, error) {
	value, ok := observed[key].(string)
	if !ok || strings.TrimSpace(value) == "" {
		return "", fmt.Errorf("observation %s is required", key)
	}
	return value, nil
}

func observationFence(value any) (int64, error) {
	switch number := value.(type) {
	case int:
		return int64(number), nil
	case int64:
		return number, nil
	case int32:
		return int64(number), nil
	case uint64:
		if number > uint64(^uint64(0)>>1) {
			return 0, fmt.Errorf("fence exceeds integer range")
		}
		return int64(number), nil
	case float64:
		if number != float64(int64(number)) {
			return 0, fmt.Errorf("fence must be an integer")
		}
		return int64(number), nil
	case json.Number:
		parsed, err := strconv.ParseInt(string(number), 10, 64)
		if err != nil {
			return 0, fmt.Errorf("fence must be an integer")
		}
		return parsed, nil
	default:
		return 0, fmt.Errorf("fence is required")
	}
}

func validateAuthoritativeProofSchema(action string, observed map[string]any) error {
	allowed := map[string]bool{"action": true, "target_kind": true, "target_id": true, "model": true, "node_id": true, "runtime_identity": true, "capability_version": true, "capability_revision": true, "tier": true, "resident": true, "warm_ram": true, "changed": true, "reconciled": true, "command_id": true, "idempotency_key": true, "command_fingerprint": true, "fingerprint": true, "original_command_id": true, "original_idempotency_key": true, "expected_fence": true, "fencing_token": true, "observed_after_fence": true}
	for _, key := range []string{"cleaned", "warm_entry_absent", "warm_release_verified", "warm_model_bytes", "locked_bytes"} {
		allowed[key] = true
	}
	for _, key := range []string{"warm_model_bytes_verified", "oracle", "released_vram", "protected", "active_references"} {
		allowed[key] = true
	}
	for key := range observed {
		if !allowed[key] {
			return fmt.Errorf("authoritative evidence contains forbidden field %s", key)
		}
	}
	for _, key := range []string{"action", "target_kind", "target_id", "model", "runtime_identity", "capability_version", "capability_revision", "tier", "original_command_id", "original_idempotency_key"} {
		if _, err := observationString(observed, key); err != nil {
			return err
		}
	}
	for _, key := range []string{"node_id", "command_id", "idempotency_key", "command_fingerprint", "fingerprint"} {
		if value, present := observed[key]; present {
			if text, ok := value.(string); !ok || strings.TrimSpace(text) == "" {
				return fmt.Errorf("authoritative evidence %s must be a nonempty string", key)
			}
		}
	}
	if value, present := observed["reconciled"]; present {
		if _, ok := value.(bool); !ok {
			return fmt.Errorf("authoritative evidence reconciled must be a boolean")
		}
	}
	for _, key := range []string{"resident", "warm_ram", "changed", "cleaned", "warm_entry_absent", "warm_release_verified", "warm_model_bytes_verified", "released_vram", "protected"} {
		if value, present := observed[key]; present {
			if _, ok := value.(bool); !ok {
				return fmt.Errorf("authoritative evidence %s must be a boolean", key)
			}
		}
	}
	for _, key := range []string{"expected_fence", "fencing_token", "observed_after_fence", "warm_model_bytes", "locked_bytes", "active_references"} {
		if value, present := observed[key]; present {
			if _, err := observationFence(value); err != nil {
				return fmt.Errorf("authoritative evidence %s must be an integer", key)
			}
		}
	}
	if value, present := observed["oracle"]; present {
		if text, ok := value.(string); !ok || strings.TrimSpace(text) == "" {
			return fmt.Errorf("authoritative evidence oracle must be a string")
		}
	}
	changed, changedOK := observed["changed"].(bool)
	if !changedOK || changed {
		return fmt.Errorf("authoritative evidence changed must be typed false")
	}
	tier, _ := observed["tier"].(string)
	resident, _ := observed["resident"].(bool)
	warm, _ := observed["warm_ram"].(bool)
	cleaned, cleanedOK := observed["cleaned"].(bool)
	absolute, absentOK := observed["warm_entry_absent"].(bool)
	released, releasedOK := observed["warm_release_verified"].(bool)
	bytes, bytesErr := observationFence(observed["warm_model_bytes"])
	locked, lockedErr := observationFence(observed["locked_bytes"])
	warmVerified, warmVerifiedOK := observed["warm_model_bytes_verified"].(bool)
	warmReleased, warmReleasedOK := observed["released_vram"].(bool)
	oracle, oracleOK := observed["oracle"].(string)
	if tier == string(domain.ResidencyWarmRAM) {
		if cleanedOK || absentOK || releasedOK || !warm || resident || !warmVerifiedOK || !warmVerified || !warmReleasedOK || !warmReleased || !oracleOK || oracle != "mincore+mlock" || bytesErr != nil || lockedErr != nil || bytes <= 0 || locked < bytes {
			return fmt.Errorf("warm authoritative evidence lacks the exact warm proof or mixes cleanup fields")
		}
	} else {
		for _, key := range []string{"warm_model_bytes_verified", "released_vram", "oracle", "protected", "active_references"} {
			if _, present := observed[key]; present {
				return fmt.Errorf("non-warm authoritative evidence contains warm proof field %s", key)
			}
		}
		if tier == string(domain.ResidencyHotVRAM) {
			for _, key := range []string{"cleaned", "warm_entry_absent", "warm_release_verified", "warm_model_bytes", "locked_bytes"} {
				if _, present := observed[key]; present {
					return fmt.Errorf("hot authoritative evidence contains cold proof field %s", key)
				}
			}
			if !resident || warm {
				return fmt.Errorf("hot authoritative evidence state is invalid")
			}
		} else if tier == string(domain.ResidencyColdDisk) {
			if resident || warm || !cleanedOK || !cleaned || !absentOK || !absolute || !releasedOK || !released || bytesErr != nil || lockedErr != nil || bytes != 0 || locked != 0 {
				return fmt.Errorf("cold authoritative evidence lacks the exact cleanup proof")
			}
		} else {
			return fmt.Errorf("authoritative evidence tier is not canonical")
		}
	}
	valid := map[string]map[string]bool{
		"load_model":          {"hot_vram": true, "cold_disk": true},
		"unload_model":        {"cold_disk": true, "hot_vram": true},
		"warm_model":          {"warm_ram": true, "hot_vram": true},
		"offload_model":       {"warm_ram": true, "cold_disk": true},
		"demote_model":        {"warm_ram": true, "hot_vram": true},
		"protect_warm_model":  {"warm_ram": true, "cold_disk": true},
		"cleanup_warm_model":  {"cold_disk": true, "hot_vram": true},
		"reverify_warm_model": {"warm_ram": true, "cold_disk": true},
	}
	if !valid[action][tier] {
		return fmt.Errorf("authoritative evidence tier %s is not valid for %s", tier, action)
	}
	if action == "protect_warm_model" && tier == string(domain.ResidencyWarmRAM) {
		if _, ok := observed["protected"].(bool); !ok {
			return fmt.Errorf("protect authoritative evidence lacks protected proof")
		}
		if _, err := observationFence(observed["active_references"]); err != nil {
			return fmt.Errorf("protect authoritative evidence lacks active-reference proof")
		}
	}
	if action != "protect_warm_model" && (observed["protected"] != nil || observed["active_references"] != nil) {
		return fmt.Errorf("non-protect authoritative evidence contains protection fields")
	}
	return nil
}

func validateAuthoritativeObservation(original, query *domain.NodeCommand, observed map[string]any) error {
	if original == nil || query == nil || query.Command != "query_model_state" || query.ReconcilesCommandID != original.ID {
		return fmt.Errorf("query is not linked to the original mutation")
	}
	if original.IdempotencyKey == "" || !strings.HasPrefix(query.IdempotencyKey, original.IdempotencyKey+":authoritative-query") {
		return fmt.Errorf("query idempotency is not linked to the original mutation")
	}
	queryTargetKind, _ := query.Args["target_kind"].(string)
	originalID, _ := query.Args["original_command_id"].(string)
	originalKey, _ := query.Args["original_idempotency_key"].(string)
	if queryTargetKind == "" || queryTargetKind != "llamacpp" || originalID != original.ID || originalKey != original.IdempotencyKey {
		return fmt.Errorf("query linkage envelope does not match the original mutation")
	}
	if expectedTier, _ := query.Args["expected_tier"].(string); expectedTier != "query" {
		return fmt.Errorf("query expected_tier must be query")
	}
	for _, key := range []string{"target_id", "model", "runtime_identity", "capability_version", "capability_revision"} {
		want, _ := original.Args[key].(string)
		got, _ := query.Args[key].(string)
		if want == "" || got != want {
			return fmt.Errorf("query %s does not match the original mutation", key)
		}
	}
	originalFence, fenceErr := observationFence(original.Args["fencing_token"])
	if fenceErr != nil {
		return fmt.Errorf("original fencing_token: %w", fenceErr)
	}
	queryFence, fenceErr := observationFence(query.Args["expected_fence"])
	if fenceErr != nil || queryFence != originalFence {
		return fmt.Errorf("query expected_fence does not match the original mutation")
	}
	commandFence, fenceErr := observationFence(query.Args["fencing_token"])
	if fenceErr != nil || commandFence != queryFence {
		return fmt.Errorf("query fencing_token does not match expected_fence")
	}
	observedReference, fenceErr := observationFence(query.Args["observed_after_fence"])
	if fenceErr != nil || observedReference != queryFence {
		return fmt.Errorf("query observed_after_fence does not match expected_fence")
	}
	for _, key := range []string{"action", "target_kind", "target_id", "model", "runtime_identity", "capability_version", "capability_revision", "tier", "original_command_id", "original_idempotency_key"} {
		if _, err := observationString(observed, key); err != nil {
			return err
		}
	}
	switch observedTier, _ := observed["tier"].(string); observedTier {
	case string(domain.ResidencyHotVRAM), string(domain.ResidencyWarmRAM), string(domain.ResidencyColdDisk):
	default:
		return fmt.Errorf("observation tier is not canonical")
	}
	for _, key := range []string{"target_kind", "target_id", "model", "runtime_identity", "capability_version", "capability_revision"} {
		expected, ok := query.Args[key].(string)
		if !ok || expected == "" || observed[key] != expected {
			return fmt.Errorf("observation %s does not match query envelope", key)
		}
	}
	if observed["original_command_id"] != original.ID || observed["original_idempotency_key"] != original.IdempotencyKey {
		return fmt.Errorf("observation linkage does not match original mutation")
	}
	if observed["node_id"] != original.NodeID || observed["command_id"] != query.ID || observed["idempotency_key"] != query.IdempotencyKey {
		return fmt.Errorf("observation command envelope does not match the authoritative query")
	}
	queryFingerprint := wsproto.ResidencyCommandFingerprint(query.NodeID, query.Command, query.IdempotencyKey, query.Args)
	if observed["command_fingerprint"] != queryFingerprint || observed["fingerprint"] != queryFingerprint {
		return fmt.Errorf("observation command fingerprint does not match the authoritative query")
	}
	if observed["action"] != original.Command {
		return fmt.Errorf("observation action does not match original mutation")
	}
	if err := validateAuthoritativeProofSchema(original.Command, observed); err != nil {
		return err
	}
	expectedFence, err := observationFence(query.Args["expected_fence"])
	if err != nil {
		return fmt.Errorf("query expected_fence: %w", err)
	}
	observedAfter, err := observationFence(observed["observed_after_fence"])
	if err != nil || observedAfter != expectedFence {
		return fmt.Errorf("observation observed_after_fence does not equal query fence")
	}
	observedFence, err := observationFence(observed["fencing_token"])
	if err != nil || observedFence != expectedFence {
		return fmt.Errorf("observation fencing_token does not equal query fence")
	}
	observedExpected, err := observationFence(observed["expected_fence"])
	if err != nil || observedExpected != expectedFence {
		return fmt.Errorf("observation expected_fence does not equal query fence")
	}
	return nil
}

func validateResidencyMutationEvidence(original *domain.NodeCommand, observed map[string]any) error {
	if original == nil || original.Command == "query_model_state" {
		return fmt.Errorf("authoritative evidence is not bound to a mutation")
	}
	if err := validateNodeCommand(original.Command, original.Args); err != nil {
		return fmt.Errorf("original mutation envelope is invalid: %w", err)
	}
	canonicalFingerprint := wsproto.ResidencyCommandFingerprint(original.NodeID, original.Command, original.IdempotencyKey, original.Args)
	if original.Result != nil {
		var persisted map[string]any
		if json.Unmarshal(original.Result, &persisted) == nil {
			for _, key := range []string{"command_fingerprint", "fingerprint"} {
				if value, present := persisted[key]; present && value != canonicalFingerprint {
					return fmt.Errorf("original mutation %s drifted from its canonical manifest", key)
				}
			}
		}
	}
	if observed == nil {
		return fmt.Errorf("authoritative evidence is missing")
	}
	if err := validateAuthoritativeProofSchema(original.Command, observed); err != nil {
		return err
	}
	for _, key := range []string{"target_kind", "target_id", "model", "runtime_identity", "capability_version", "capability_revision"} {
		expected, ok := original.Args[key].(string)
		if !ok || expected == "" || observed[key] != expected {
			return fmt.Errorf("authoritative evidence %s does not match the original mutation", key)
		}
	}
	if observed["original_command_id"] != original.ID || observed["original_idempotency_key"] != original.IdempotencyKey {
		return fmt.Errorf("authoritative evidence linkage does not match the original mutation")
	}
	originalFence, fenceErr := observationFence(original.Args["fencing_token"])
	if fenceErr != nil {
		return fmt.Errorf("original mutation fencing_token: %w", fenceErr)
	}
	for _, key := range []string{"expected_fence", "fencing_token", "observed_after_fence"} {
		value, err := observationFence(observed[key])
		if err != nil || value != originalFence {
			return fmt.Errorf("authoritative evidence %s does not match the original fence", key)
		}
	}
	resident, residentOK := observed["resident"].(bool)
	warm, warmOK := observed["warm_ram"].(bool)
	tier, tierOK := observed["tier"].(string)
	if !residentOK || !warmOK || !tierOK {
		return fmt.Errorf("authoritative evidence lacks typed residency state")
	}
	if action, ok := observed["action"].(string); !ok || action != original.Command {
		return fmt.Errorf("authoritative evidence action does not match original mutation")
	}
	validateCold := func() error {
		cleaned, cleanedOK := observed["cleaned"].(bool)
		absent, absentOK := observed["warm_entry_absent"].(bool)
		released, releasedOK := observed["warm_release_verified"].(bool)
		bytes, bytesErr := observationFence(observed["warm_model_bytes"])
		locked, lockedErr := observationFence(observed["locked_bytes"])
		changed, changedOK := observed["changed"].(bool)
		if !cleanedOK || !cleaned || !absentOK || !absent || !releasedOK || !released || bytesErr != nil || lockedErr != nil || bytes != 0 || locked != 0 || !changedOK || changed {
			return fmt.Errorf("cold observation lacks exact cleanup proof")
		}
		if resident || warm || tier != string(domain.ResidencyColdDisk) {
			return fmt.Errorf("cold observation state is invalid")
		}
		return nil
	}
	validateHot := func() error {
		changed, changedOK := observed["changed"].(bool)
		if !resident || warm || tier != string(domain.ResidencyHotVRAM) || !changedOK || changed {
			return fmt.Errorf("hot observation state is invalid")
		}
		return nil
	}
	validateWarm := func(requireProtection bool) error {
		verified, verifiedOK := observed["warm_model_bytes_verified"].(bool)
		released, releasedOK := observed["released_vram"].(bool)
		oracle, oracleOK := observed["oracle"].(string)
		bytes, bytesErr := observationFence(observed["warm_model_bytes"])
		locked, lockedErr := observationFence(observed["locked_bytes"])
		if resident || !warm || tier != string(domain.ResidencyWarmRAM) || !verifiedOK || !verified || !releasedOK || !released || !oracleOK || oracle != "mincore+mlock" || bytesErr != nil || lockedErr != nil || bytes <= 0 || locked < bytes {
			return fmt.Errorf("warm observation lacks exact verified warm proof")
		}
		if requireProtection {
			protected, protectedOK := observed["protected"].(bool)
			refs, refsErr := observationFence(observed["active_references"])
			expectedProtected, expectedProtectedOK := original.Args["protected"].(bool)
			expectedRefs, expectedRefsErr := observationFence(original.Args["active_references"])
			if !protectedOK || !expectedProtectedOK || protected != expectedProtected || refsErr != nil || expectedRefsErr != nil || refs != expectedRefs {
				return fmt.Errorf("protect observation does not match signed protection fields")
			}
		}
		return nil
	}
	// The inverse state is action-specific.  Never infer it solely from the
	// signed expected_tier: several warm actions have different rollback
	// targets, and accepting the third canonical tier would make a stale
	// observation look authoritative.
	switch original.Command {
	case "load_model":
		if tier == "hot_vram" {
			return validateHot()
		}
		if tier == "cold_disk" {
			return validateCold()
		}
	case "unload_model":
		if tier == "cold_disk" {
			return validateCold()
		}
		if tier == "hot_vram" {
			return validateHot()
		}
	case "warm_model", "demote_model":
		if tier == "warm_ram" {
			return validateWarm(false)
		}
		if tier == "hot_vram" {
			return validateHot()
		}
	case "offload_model":
		if tier == "warm_ram" {
			return validateWarm(false)
		}
		if tier == "cold_disk" {
			return validateCold()
		}
	case "protect_warm_model":
		if tier == "warm_ram" {
			return validateWarm(true)
		}
		if tier == "cold_disk" {
			return validateCold()
		}
	case "cleanup_warm_model":
		if tier == "cold_disk" {
			return validateCold()
		}
		if tier == "hot_vram" {
			return validateHot()
		}
	case "reverify_warm_model":
		if tier == "warm_ram" {
			return validateWarm(false)
		}
		if tier == "cold_disk" {
			return validateCold()
		}
	}
	return fmt.Errorf("authoritative evidence tier is not the exact desired or inverse state for %s", original.Command)
}

type nodeRecoveryTimer struct {
	generation uint64
	timer      *time.Timer
}

func (s *Server) releaseNodeRecoveryTimer(commandID string, owner *nodeRecoveryTimer) bool {
	s.nodeRecoveryMu.Lock()
	defer s.nodeRecoveryMu.Unlock()
	if s.nodeRecoveryTimers[commandID] != owner {
		return false
	}
	delete(s.nodeRecoveryTimers, commandID)
	return true
}

func (s *Server) recoveryReadFailure(commandID string, reset bool) int {
	s.nodeRecoveryMu.Lock()
	defer s.nodeRecoveryMu.Unlock()
	if reset {
		delete(s.recoveryReadFailures, commandID)
		return 0
	}
	if s.recoveryReadFailures == nil {
		s.recoveryReadFailures = make(map[string]int)
	}
	s.recoveryReadFailures[commandID]++
	return s.recoveryReadFailures[commandID]
}

// scheduleNodeRecovery gives durable uncertain commands an autonomous,
// bounded recovery attempt even when no HTTP waiter, websocket reconnect, or
// workload-manager sweep is active. Timer ownership is identity based: a
// callback may only remove the timer it installed, so a replacement cannot be
// accidentally deleted by a late callback.
func (s *Server) scheduleNodeRecovery(commandID string) {
	s.scheduleNodeRecoveryWithDelay(commandID, 25*time.Millisecond)
}

func (s *Server) scheduleNodeRecoveryWithDelay(commandID string, fallback time.Duration) {
	if commandID == "" || s.recoveryCtx == nil || s.recoveryCtx.Err() != nil {
		return
	}
	delay := fallback
	if row, err := s.workloadStore.GetNodeCommand(s.recoveryCtx, commandID); err == nil {
		s.recoveryReadFailure(commandID, true)
		if row != nil && row.RecoveryNextAt != nil {
			delay = time.Until(*row.RecoveryNextAt)
			if delay < 0 {
				delay = 0
			}
		}
	} else {
		delay = recoveryBackoff(s.recoveryReadFailure(commandID, false))
	}
	if delay < 0 {
		delay = 0
	}
	s.recoveryLifecycleMu.Lock()
	if s.recoveryClosed {
		s.recoveryLifecycleMu.Unlock()
		return
	}
	s.nodeRecoveryMu.Lock()
	if _, exists := s.nodeRecoveryTimers[commandID]; exists {
		s.nodeRecoveryMu.Unlock()
		s.recoveryLifecycleMu.Unlock()
		return
	}
	entry := &nodeRecoveryTimer{generation: s.recoveryTimerSeq.Add(1)}
	s.recoveryWG.Add(1)
	entry.timer = time.AfterFunc(delay, func() {
		defer s.recoveryWG.Done()
		// Only this exact callback may release its slot. A replacement timer
		// installed by another path remains owned by that path.
		if !s.releaseNodeRecoveryTimer(commandID, entry) {
			return
		}
		row, err := s.workloadStore.GetNodeCommand(s.recoveryCtx, commandID)
		if err != nil {
			s.scheduleNodeRecoveryWithDelay(commandID, recoveryBackoff(s.recoveryReadFailure(commandID, false)))
			return
		}
		s.recoveryReadFailure(commandID, true)
		if row == nil || !row.Uncertain {
			return
		}
		if row.RecoveryNextAt != nil && row.RecoveryNextAt.After(time.Now().UTC()) {
			s.scheduleNodeRecoveryWithDelay(row.ID, time.Until(*row.RecoveryNextAt))
			return
		}
		updated, casErr := s.advanceNodeRecovery(s.recoveryCtx, row.ID)
		if casErr != nil {
			s.scheduleNodeRecoveryWithDelay(commandID, recoveryBackoff(row.RecoveryAttempts+1))
			return
		}
		// A concurrent authoritative result may have settled the row while the
		// recovery CAS was in flight.  The atomic store method returns that
		// latest row; never pass a terminal/nil snapshot into reconciliation or
		// schedule a stale retry from it.
		if updated == nil || !updated.Uncertain {
			return
		}
		row = updated
		ctx, cancel := context.WithTimeout(s.recoveryCtx, 2*time.Second)
		defer cancel()
		_, recoveryErr := s.reconcileUncertainNodeCommand(ctx, row)
		if recoveryErr == nil {
			return
		}
		latest, latestErr := s.workloadStore.GetNodeCommand(s.recoveryCtx, commandID)
		if latestErr != nil {
			s.scheduleNodeRecoveryWithDelay(commandID, recoveryBackoff(row.RecoveryAttempts))
			return
		}
		if latest == nil || !latest.Uncertain {
			return
		}
		next := time.Now().UTC().Add(recoveryBackoff(latest.RecoveryAttempts))
		latest.RecoveryNextAt = &next
		if _, retryErr := s.workloadStore.CompareAndSwapNodeCommandRevision(s.recoveryCtx, latest, latest.Revision, latest.Attempts, true, domain.NodeCommandSent); retryErr != nil {
			s.scheduleNodeRecoveryWithDelay(commandID, recoveryBackoff(latest.RecoveryAttempts))
			return
		}
		s.scheduleNodeRecoveryWithDelay(commandID, time.Until(next))
	})
	s.nodeRecoveryTimers[commandID] = entry
	s.nodeRecoveryMu.Unlock()
	s.recoveryLifecycleMu.Unlock()
}

// advanceNodeRecovery records retry progression before scheduling another
// attempt. A delivery/result race may invalidate the first snapshot; reload
// and retry the CAS so a conflict cannot erase the durable backoff state.
func (s *Server) advanceNodeRecovery(ctx context.Context, commandID string) (*domain.NodeCommand, error) {
	return s.workloadStore.AdvanceNodeCommandRecovery(ctx, commandID)
}

func recoveryBackoff(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	if attempt > 9 {
		attempt = 9
	}
	delay := 100 * time.Millisecond
	for i := 1; i < attempt; i++ {
		delay *= 2
	}
	if delay > 5*time.Second {
		return 5 * time.Second
	}
	return delay
}

// issueAuthoritativeQuery persists and delivers one exact-resource,
// read-only query for an uncertain mutation. Its durable linkage makes this
// safe to call from both an active waiter and reconnect recovery: a retry
// reuses the same query command instead of ever redispatching the mutation.
func (s *Server) issueAuthoritativeQuery(ctx context.Context, original *domain.NodeCommand) (*domain.NodeCommand, error) {
	if original != nil && original.Command == "switch_runtime_profile" {
		return nil, fmt.Errorf("runtime profile observation_unavailable; node protocol requires operator reconciliation")
	}
	target, _ := original.Args["target_id"].(string)
	model, _ := original.Args["model"].(string)
	runtimeIdentity, _ := original.Args["runtime_identity"].(string)
	capabilityVersion, _ := original.Args["capability_version"].(string)
	capabilityRevision, _ := original.Args["capability_revision"].(string)
	fence := original.Args["fencing_token"]
	if target == "" || model == "" || runtimeIdentity == "" || capabilityVersion == "" || capabilityRevision == "" || fence == nil {
		return nil, fmt.Errorf("uncertain node command lacks an exact reconciliation envelope")
	}
	fenceValue, fenceErr := observationFence(fence)
	if fenceErr != nil || fenceValue < 0 {
		return nil, fmt.Errorf("uncertain node command has an invalid fencing token")
	}
	checkpoint := strings.HasPrefix(original.Command, "checkpoint_")
	queryCommand := "query_model_state"
	queryArgs := wsproto.CanonicalResidencyCommandArgs(target, model, runtimeIdentity, capabilityVersion, capabilityRevision, "query", fenceValue)
	if checkpoint {
		// Preserve the complete checkpoint identity and change only the action to
		// a read-only state query. This keeps operation/slot/fence provenance
		// intact and prevents recovery from falling back to residency evidence.
		queryCommand = "checkpoint_state_query"
		queryArgs = make(map[string]any, len(original.Args)+4)
		for key, value := range original.Args {
			queryArgs[key] = value
		}
		queryArgs["checkpoint_action"] = "state_query"
		if operationID, ok := original.Args["checkpoint_operation_id"].(string); ok && operationID != "" {
			queryArgs["checkpoint_operation_id"] = operationID
		}
	}
	// Residency queries use the legacy controller-query linkage fields below.
	// Checkpoint queries are linked by ReconcilesCommandID and carry their full
	// signed checkpoint envelope; the residency-only fields are intentionally
	// not part of the checkpoint wire allowlist.
	if !checkpoint {
		queryArgs["expected_fence"] = fenceValue
		queryArgs["observed_after_fence"] = fenceValue
		queryArgs["original_command_id"] = original.ID
		queryArgs["original_idempotency_key"] = original.IdempotencyKey
	}
	rows, listErr := s.workloadStore.ListNodeCommandRecovery(ctx, original.NodeID, original.ID)
	if listErr != nil {
		return nil, listErr
	}
	queryKey := original.IdempotencyKey + ":authoritative-query"
	if checkpoint {
		queryKey = original.IdempotencyKey + ":checkpoint-state-query"
	}
	maxAttempt := 0
	for _, row := range rows {
		if row == nil || !nodeCommandReplayMatches(row, original.NodeID, queryCommand, queryArgs) || row.ReconcilesCommandID != original.ID {
			continue
		}
		if row.Status == domain.NodeCommandSucceeded || ((row.Status == domain.NodeCommandQueued || row.Status == domain.NodeCommandSent) && time.Now().UTC().Before(row.ExpiresAt)) {
			if row.Status != domain.NodeCommandSucceeded {
				if err := s.sendNodeCommand(ctx, row); err != nil {
					// Delivery failure is recoverable evidence, not a terminal
					// query failure. Keep the durable query queued/sent so the
					// bounded reconciliation wait or autonomous scheduler can
					// retry it after reconnect.
					_ = err
				}
			}
			return row, nil
		}
		if suffix := strings.TrimPrefix(row.IdempotencyKey, queryKey+":retry-"); suffix != row.IdempotencyKey {
			if n, parseErr := strconv.Atoi(suffix); parseErr == nil && n > maxAttempt {
				maxAttempt = n
			}
		} else if row.IdempotencyKey == queryKey {
			if maxAttempt < 0 {
				maxAttempt = 0
			}
		}
	}
	if len(rows) > 0 {
		if maxAttempt == 0 {
			queryKey += ":retry-1"
		} else {
			queryKey += ":retry-" + strconv.Itoa(maxAttempt+1)
		}
	}
	now := time.Now().UTC()
	queryExpires := now.Add(10 * time.Minute)
	if !original.ExpiresAt.IsZero() && original.ExpiresAt.Before(queryExpires) {
		// The read-only recovery query cannot extend the signed mutation's
		// reconciliation window. Otherwise a connected silent node could keep
		// this loop alive for a fresh ten-minute query after the original command
		// had already expired.
		queryExpires = original.ExpiresAt
	}
	query := &domain.NodeCommand{ID: newCommandID(), IdempotencyKey: queryKey, NodeID: original.NodeID, Command: queryCommand, Args: queryArgs, IssuedBy: "controller-reconciliation", Status: domain.NodeCommandQueued, CreatedAt: now, ExpiresAt: queryExpires, ReconcilesCommandID: original.ID, UpdatedAt: now}
	wire := nodeCommandPayload(query)
	signature, err := wsproto.SignCommand(wire, s.commandSecret)
	if err != nil {
		return nil, err
	}
	query.Signature = signature
	stored, created, err := s.workloadStore.CreateNodeCommand(ctx, query)
	if err != nil {
		return nil, err
	}
	if !created && (!nodeCommandReplayMatches(stored, query.NodeID, query.Command, query.Args) || stored.ReconcilesCommandID != original.ID) {
		return nil, fmt.Errorf("authoritative query idempotency conflict")
	}
	if created || (stored.Status != domain.NodeCommandSucceeded && stored.Status != domain.NodeCommandFailed && stored.Status != domain.NodeCommandExpired) {
		if err := s.sendNodeCommand(ctx, stored); err != nil {
			// Preserve the recoverable query row on offline/CAS delivery
			// failure; the caller must not terminalize the original mutation.
			_ = err
		}
	}
	return stored, nil
}

// settleUncertainOriginal atomically correlates an authoritative observation
// to the original mutation. A tier mismatch is a terminal rollback/failure
// with the observed evidence retained; it is never reported as success.
func (s *Server) settleUncertainOriginal(ctx context.Context, originalID string, observed map[string]any) (map[string]any, error) {
	original, err := s.workloadStore.GetNodeCommand(ctx, originalID)
	if err != nil {
		return nil, err
	}
	if original.Status == domain.NodeCommandSucceeded || original.Status == domain.NodeCommandFailed {
		var result map[string]any
		_ = json.Unmarshal(original.Result, &result)
		if original.Status == domain.NodeCommandSucceeded {
			if projectionErr := s.projectRuntimeProfileResult(original, result); projectionErr != nil {
				return nil, fmt.Errorf("runtime profile result was not projected: %w", projectionErr)
			}
		}
		if original.Status == domain.NodeCommandFailed {
			return result, fmt.Errorf("uncertain node command settled as failed: %s", original.Error)
		}
		return result, nil
	}
	if !original.Uncertain && original.Status != domain.NodeCommandSent {
		return nil, fmt.Errorf("uncertain node command %s is not pending reconciliation", originalID)
	}
	if !wsproto.VerifyCommand(nodeCommandPayload(original), s.commandSecret) {
		return nil, fmt.Errorf("original mutation signature is invalid")
	}
	// Bind the observation again at the terminal transition boundary. The
	// caller may have obtained the map from a different query/resource, so the
	// validator below is not allowed to be the sole source of original linkage.
	for _, key := range []string{"target_kind", "target_id", "model", "runtime_identity", "capability_version", "capability_revision"} {
		expected, ok := original.Args[key].(string)
		if !ok || expected == "" || observed[key] != expected {
			return nil, fmt.Errorf("authoritative observation %s is not bound to the original", key)
		}
	}
	if observed["action"] != original.Command || observed["original_command_id"] != original.ID || observed["original_idempotency_key"] != original.IdempotencyKey {
		return nil, fmt.Errorf("authoritative observation linkage is not bound to the original")
	}
	originalFence, fenceErr := observationFence(original.Args["fencing_token"])
	if fenceErr != nil {
		return nil, fmt.Errorf("original fencing_token: %w", fenceErr)
	}
	for _, key := range []string{"expected_fence", "fencing_token", "observed_after_fence"} {
		observedFence, err := observationFence(observed[key])
		if err != nil || observedFence != originalFence {
			return nil, fmt.Errorf("authoritative observation %s is not bound to the original fence", key)
		}
	}
	if err := validateResidencyMutationEvidence(original, observed); err != nil {
		return nil, fmt.Errorf("authoritative query cannot settle mutation: %w", err)
	}
	var profileResultClaim *workloads.RuntimeProfileResultClaim
	if original.Command == "switch_runtime_profile" {
		if s.workloads == nil {
			return nil, fmt.Errorf("runtime profile result cannot be settled without the workload manager")
		}
		var claimErr error
		profileResultClaim, claimErr = s.workloads.ClaimRuntimeProfileResult(original.IdempotencyKey, original.NodeID, observed)
		if claimErr != nil {
			return nil, fmt.Errorf("authoritative runtime profile observation was rejected: %w", claimErr)
		}
		defer func() {
			if profileResultClaim != nil {
				profileResultClaim.Release()
			}
		}()
		if err := s.validateRuntimeProfileResult(original, observed); err != nil {
			return nil, fmt.Errorf("authoritative runtime profile observation was rejected: %w", err)
		}
	}
	expectedRevision, expectedUncertain := original.Revision, original.Uncertain
	original.Result, _ = json.Marshal(observed)
	original.Uncertain = false
	original.EvidenceKind = "authoritative_observation"
	expectedTier, _ := original.Args["expected_tier"].(string)
	observedTier, _ := observed["tier"].(string)
	if expectedTier == "" || expectedTier == observedTier {
		original.Status = domain.NodeCommandSucceeded
		original.Error = ""
	} else {
		original.Status = domain.NodeCommandFailed
		original.Error = fmt.Sprintf("authoritative query observed tier=%s runtime_identity=%v observed_fence=%v; expected tier=%s", observedTier, observed["runtime_identity"], observed["observed_after_fence"], expectedTier)
	}
	now := time.Now().UTC()
	original.CompletedAt = &now
	original.UpdatedAt = now
	if _, casErr := s.workloadStore.CompareAndSwapNodeCommandRevision(ctx, original, expectedRevision, original.Attempts, expectedUncertain, domain.NodeCommandSent); casErr != nil {
		latest, reloadErr := s.workloadStore.GetNodeCommand(ctx, originalID)
		if reloadErr == nil && (latest.Status == domain.NodeCommandSucceeded || latest.Status == domain.NodeCommandFailed) {
			var result map[string]any
			_ = json.Unmarshal(latest.Result, &result)
			if latest.Status == domain.NodeCommandFailed {
				return result, fmt.Errorf("uncertain node command settled as failed: %s", latest.Error)
			}
			if profileResultClaim != nil {
				if projectionErr := profileResultClaim.Project(result); projectionErr != nil {
					return nil, fmt.Errorf("durable runtime profile result was not projected: %w", projectionErr)
				}
				profileResultClaim.Release()
				profileResultClaim = nil
			} else if projectionErr := s.projectRuntimeProfileResult(latest, result); projectionErr != nil {
				return nil, fmt.Errorf("durable runtime profile result was not projected: %w", projectionErr)
			}
			return result, nil
		}
		return nil, casErr
	}
	if original.Status == domain.NodeCommandFailed {
		return observed, fmt.Errorf("uncertain node command settled as failed: %s", original.Error)
	}
	if original.Status == domain.NodeCommandSucceeded {
		if profileResultClaim != nil {
			if projectionErr := profileResultClaim.Project(observed); projectionErr != nil {
				return nil, fmt.Errorf("durable runtime profile result was not projected: %w", projectionErr)
			}
			profileResultClaim.Release()
			profileResultClaim = nil
		} else if projectionErr := s.projectRuntimeProfileResult(original, observed); projectionErr != nil {
			return nil, fmt.Errorf("durable runtime profile result was not projected: %w", projectionErr)
		}
	}
	return observed, nil
}

func nodeCommandReplayMatches(stored *domain.NodeCommand, nodeID, command string, args map[string]any) bool {
	if stored == nil || stored.NodeID != nodeID || stored.Command != command {
		return false
	}
	left, leftErr := json.Marshal(stored.Args)
	right, rightErr := json.Marshal(args)
	return leftErr == nil && rightErr == nil && string(left) == string(right)
}

func nodeCommandPayload(command *domain.NodeCommand) wsproto.CommandPayload {
	return wsproto.CommandPayload{ID: command.ID, IdempotencyKey: command.IdempotencyKey, NodeID: command.NodeID, Command: command.Command, Args: command.Args, IssuedAt: command.CreatedAt, ExpiresAt: command.ExpiresAt, Signature: command.Signature}
}

func (s *Server) dispatchNodeCommands(ctx context.Context, nodeID string) {
	rows, err := s.workloadStore.ListNodeCommandRecovery(ctx, nodeID, "")
	if err != nil {
		return
	}
	for _, command := range rows {
		if command.Status != domain.NodeCommandQueued && command.Status != domain.NodeCommandSent {
			continue
		}
		if command.Uncertain {
			// An uncertain mutation crossed an external side-effect boundary.
			// Reconnect recovery is query-first and must never redispatch it.
			if _, queryErr := s.issueAuthoritativeQuery(ctx, command); queryErr != nil {
				s.scheduleNodeRecovery(command.ID)
			}
			continue
		}
		if time.Now().UTC().After(command.ExpiresAt) {
			expectedRevision, expectedUncertain := command.Revision, command.Uncertain
			now := time.Now().UTC()
			command.Status = domain.NodeCommandExpired
			command.Error = "unresolved: command expired before delivery; authoritative runtime reconciliation required"
			command.CompletedAt = &now
			command.UpdatedAt = now
			_, _ = s.workloadStore.CompareAndSwapNodeCommandRevision(ctx, command, expectedRevision, command.Attempts, expectedUncertain, domain.NodeCommandQueued, domain.NodeCommandSent)
			continue
		}
		if sendErr := s.sendNodeCommand(ctx, command); sendErr != nil && command.Uncertain {
			s.scheduleNodeRecovery(command.ID)
		}
	}
}

func (s *Server) sendNodeCommand(ctx context.Context, command *domain.NodeCommand) error {
	if command.Status != domain.NodeCommandQueued && command.Status != domain.NodeCommandSent {
		return fmt.Errorf("node command is not dispatchable: %s", command.Status)
	}
	profileDispatchGuard := command.Command == "switch_runtime_profile"
	var releaseTicket func()
	if profileDispatchGuard {
		runtimeProfileCommandGuard.Lock()
		var err error
		releaseTicket, err = s.requireRuntimeProfileDispatchTicket(command.NodeID, command.Args, command.IdempotencyKey)
		if err != nil {
			runtimeProfileCommandGuard.Unlock()
			return err
		}
		defer releaseTicket()
		if err := s.rejectUnresolvedRuntimeProfileCommand(ctx, command.NodeID, command.Args, command.IdempotencyKey); err != nil {
			runtimeProfileCommandGuard.Unlock()
			return err
		}
	}
	s.nodeConnMu.RLock()
	connection := s.nodeConnections[command.NodeID]
	s.nodeConnMu.RUnlock()
	if !s.isCurrentNodeConnection(command.NodeID, connection) {
		if profileDispatchGuard {
			runtimeProfileCommandGuard.Unlock()
		}
		return fmt.Errorf("node is offline")
	}
	// Mark the command sent before the node can reply. Updating this row after
	// delivery can race a fast result and incorrectly turn SUCCEEDED back into
	// SENT, causing the controller to wait until expiry.
	now := time.Now().UTC()
	expectedAttempts := command.Attempts
	expectedRevision, expectedUncertain := command.Revision, command.Uncertain
	command.Status = domain.NodeCommandSent
	command.SentAt = &now
	command.Attempts++
	command.LastSentAt = &now
	command.UpdatedAt = now
	var sent *domain.NodeCommand
	sent, err := s.workloadStore.CompareAndSwapNodeCommandRevision(ctx, command, expectedRevision, expectedAttempts, expectedUncertain, domain.NodeCommandQueued, domain.NodeCommandSent)
	if err != nil {
		if profileDispatchGuard {
			runtimeProfileCommandGuard.Unlock()
		}
		return err
	}
	command = sent
	if profileDispatchGuard {
		// The durable SENT row now fences every creator/reconnect path before
		// this physical write. Do not hold the global command mutex over I/O.
		runtimeProfileCommandGuard.Unlock()
	}
	payload, _ := json.Marshal(nodeCommandPayload(command))
	envelope := wsproto.Envelope{Type: wsproto.MsgCommand, Time: time.Now().UTC(), Payload: payload}
	writeDeadline := time.Now().UTC().Add(5 * time.Second)
	if command.ExpiresAt.Before(writeDeadline) {
		writeDeadline = command.ExpiresAt
	}
	writeCtx, cancel := context.WithDeadline(ctx, writeDeadline)
	err = s.writeCurrentNodeConnection(writeCtx, command.NodeID, connection, envelope)
	cancel()
	if err != nil {
		latest, getErr := s.workloadStore.GetNodeCommand(ctx, command.ID)
		if getErr == nil && latest.Status == domain.NodeCommandSent {
			// A result can race the websocket write failure. Once the node has
			// reported an uncertain side effect, the durable row must remain
			// sent/uncertain so reconnect recovery issues the linked query; it
			// must never be reopened for mutation redelivery.
			if latest.Uncertain {
				return err
			}
			latest.Status = domain.NodeCommandQueued
			latest.UpdatedAt = time.Now().UTC()
			_, _ = s.workloadStore.CompareAndSwapNodeCommandRevision(ctx, latest, latest.Revision, latest.Attempts, latest.Uncertain, domain.NodeCommandSent)
		}
		return err
	}
	return nil
}

func (s *Server) handleNodeCommandResult(ctx context.Context, result wsproto.CommandResultPayload) {
	command, err := s.workloadStore.GetNodeCommand(ctx, result.ID)
	if err != nil || command.NodeID != result.NodeID {
		return
	}
	if result.Uncertain && command.Command != "query_model_state" {
		// Uncertainty is monotonic evidence. A valid signed result must win over
		// an intervening send-failure requeue or ordinary terminal observation;
		// the store operation increments revision atomically so stale ordinary
		// results cannot subsequently clear it.
		resultBody, _ := json.Marshal(result.Result)
		promoted, promoteErr := s.workloadStore.PromoteNodeCommandUncertain(ctx, command.ID, result.NodeID, resultBody, result.Error)
		if promoteErr != nil {
			return
		}
		schedule := promoted != nil && promoted.Uncertain
		if schedule {
			s.scheduleNodeRecovery(promoted.ID)
		}
		return
	}
	if command.Status == domain.NodeCommandSucceeded || command.Status == domain.NodeCommandFailed || (command.Status == domain.NodeCommandExpired && len(command.Result) > 0) {
		return
	}
	if command.Uncertain && command.Command != "query_model_state" && !result.Uncertain {
		// This is a response from an accidental mutation redelivery (usually a
		// blocked/stale replay after reconnect). It cannot supersede the
		// retained side-effect evidence; only the linked authoritative query may
		// settle an uncertain mutation.
		return
	}
	if command.Command == "query_model_state" && result.OK && command.ReconcilesCommandID != "" {
		original, originalErr := s.workloadStore.GetNodeCommand(ctx, command.ReconcilesCommandID)
		if originalErr != nil {
			return
		}
		if observationErr := validateAuthoritativeObservation(original, command, result.Result); observationErr != nil {
			// Invalid query evidence is recoverable, never settlement. Mark
			// this query attempt failed so reconciliation creates a fresh,
			// exact-resource attempt while the original remains uncertain.
			now := time.Now().UTC()
			expectedRevision := command.Revision
			command.Status = domain.NodeCommandFailed
			command.Error = "unresolved: authoritative observation rejected: " + observationErr.Error()
			command.Result, _ = json.Marshal(result.Result)
			command.CompletedAt = &now
			command.UpdatedAt = now
			if _, updateErr := s.workloadStore.CompareAndSwapNodeCommandRevision(ctx, command, expectedRevision, command.Attempts, command.Uncertain, domain.NodeCommandQueued, domain.NodeCommandSent); updateErr == nil {
				s.scheduleNodeRecovery(original.ID)
			}
			return
		}
	}
	profileProjectionReady := false
	var profileResultClaim *workloads.RuntimeProfileResultClaim
	if command.Command == "switch_runtime_profile" && result.OK && !result.Uncertain {
		completedWithinWindow := !result.CompletedAt.IsZero() && !result.CompletedAt.After(command.ExpiresAt)
		if !time.Now().UTC().After(command.ExpiresAt) || completedWithinWindow {
			if s.workloads == nil {
				result.OK = false
				result.Error = "runtime profile observation rejected: workload manager is unavailable"
			} else if claim, validationErr := s.workloads.ClaimRuntimeProfileResult(command.IdempotencyKey, command.NodeID, result.Result); validationErr != nil {
				result.OK = false
				result.Error = "runtime profile observation rejected: " + validationErr.Error()
			} else {
				profileResultClaim = claim
				profileProjectionReady = true
			}
		}
	}
	if profileResultClaim != nil {
		defer func() {
			if profileResultClaim != nil {
				profileResultClaim.Release()
			}
		}()
	}
	now := time.Now().UTC()
	expectedRevision, expectedUncertain := command.Revision, command.Uncertain
	if now.After(command.ExpiresAt) {
		// A result generated before the signed window remains authoritative even
		// if the websocket delivered it after that window. Otherwise retain the
		// evidence as unresolved for an explicit runtime reconciliation.
		if !result.CompletedAt.IsZero() && !result.CompletedAt.After(command.ExpiresAt) {
			command.Result, _ = json.Marshal(result.Result)
			command.Error = result.Error
			command.Uncertain = result.Uncertain
			if result.OK {
				command.Status = domain.NodeCommandSucceeded
			} else {
				command.Status = domain.NodeCommandFailed
			}
		} else {
			command.Status = domain.NodeCommandExpired
			command.Result, _ = json.Marshal(result.Result)
			command.Error = "unresolved: late command result arrived after expiry; authoritative runtime reconciliation required"
			command.Uncertain = result.Uncertain
		}
	} else if result.Uncertain {
		// Retain the command in the sent state while the controller performs an
		// exact signed query. It is not a terminal failure and must not be aged
		// into one by a scheduler retry.
		command.Status = domain.NodeCommandSent
		command.Uncertain = true
		command.Result, _ = json.Marshal(result.Result)
		command.Error = result.Error
	} else if result.OK {
		command.Status = domain.NodeCommandSucceeded
		command.Result, _ = json.Marshal(result.Result)
	} else {
		command.Status = domain.NodeCommandFailed
		command.Error = result.Error
	}
	command.CompletedAt = &now
	command.UpdatedAt = now
	_, updateErr := s.workloadStore.CompareAndSwapNodeCommandRevision(ctx, command, expectedRevision, command.Attempts, expectedUncertain, domain.NodeCommandQueued, domain.NodeCommandSent, domain.NodeCommandExpired)
	if errors.Is(updateErr, store.ErrNodeCommandConflict) {
		return
	}
	if updateErr != nil {
		s.log.Warn("node command result was not durably accepted", "command_id", command.ID, "node_id", command.NodeID, "err", updateErr)
		return
	}
	if updateErr == nil && command.Status == domain.NodeCommandSucceeded && command.Command == "switch_runtime_profile" && profileProjectionReady {
		if projectionErr := profileResultClaim.Project(result.Result); projectionErr != nil {
			s.log.Warn("durable runtime profile result could not be projected", "command_id", command.ID, "node_id", command.NodeID, "err", projectionErr)
		}
		profileResultClaim.Release()
		profileResultClaim = nil
	}
	if updateErr == nil && command.Status == domain.NodeCommandSucceeded && command.Command == "refresh_capabilities" {
		body, marshalErr := json.Marshal(result.Result)
		if marshalErr == nil {
			var capabilities wsproto.CapabilitiesPayload
			if json.Unmarshal(body, &capabilities) == nil {
				s.registerAdapterAdvertisements(command.NodeID, capabilities.Adapters)
			}
		}
	}
	if updateErr == nil && command.Status == domain.NodeCommandSucceeded && command.Command == "query_model_state" && command.ReconcilesCommandID != "" {
		// Reconnect recovery has no active executeNodeCommand waiter. Correlate
		// the exact read-only result here so the original uncertain mutation and
		// its controller transition settle from the same durable observation.
		if _, settleErr := s.settleUncertainOriginal(ctx, command.ReconcilesCommandID, result.Result); settleErr != nil {
			s.log.Warn("authoritative query did not settle uncertain command", "query_id", command.ID, "original_id", command.ReconcilesCommandID, "err", settleErr)
		}
	}
	severity := "info"
	if command.Status != domain.NodeCommandSucceeded {
		severity = "error"
	}
	s.appendNodeCommandAudit(ctx, result.NodeID, command, "node.command.completed", severity)
}

func (s *Server) projectRuntimeProfileResult(command *domain.NodeCommand, result map[string]any) error {
	if command == nil || command.Command != "switch_runtime_profile" {
		return nil
	}
	if s.workloads == nil {
		return fmt.Errorf("workload manager is unavailable")
	}
	return s.workloads.ProjectRuntimeProfileCommandResult(command.IdempotencyKey, command.NodeID, result)
}

func (s *Server) validateRuntimeProfileResult(command *domain.NodeCommand, result map[string]any) error {
	if command == nil || command.Command != "switch_runtime_profile" {
		return nil
	}
	if s.workloads == nil {
		return fmt.Errorf("workload manager is unavailable")
	}
	return s.workloads.ValidateRuntimeProfileCommandResult(command.IdempotencyKey, command.NodeID, result)
}

func (s *Server) appendNodeCommandAudit(ctx context.Context, actor string, command *domain.NodeCommand, eventType, severity string) {
	payload, _ := json.Marshal(map[string]any{"command_id": command.ID, "node_id": command.NodeID, "command": command.Command, "status": command.Status, "error": command.Error})
	event := &domain.AuditEvent{ID: "evt-" + newCommandID(), Timestamp: time.Now().UTC(), ActorID: actor, Type: eventType, Severity: severity, Payload: payload}
	_ = s.workloadStore.AppendAuditEvent(ctx, event)
}

func newCommandID() string {
	var value [12]byte
	if _, err := rand.Read(value[:]); err != nil {
		return fmt.Sprintf("cmd-%d", time.Now().UnixNano())
	}
	return "cmd-" + hex.EncodeToString(value[:])
}
