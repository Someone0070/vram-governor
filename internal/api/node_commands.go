package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"vram-governor/internal/domain"
	"vram-governor/internal/store"
	"vram-governor/internal/wsproto"
)

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
	stored, created, err := s.workloadStore.CreateNodeCommand(r.Context(), command)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if created {
		s.appendNodeCommandAudit(r.Context(), principal.ID, stored, "node.command.created", "info")
	}
	s.sendNodeCommand(r.Context(), stored)
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
	case "refresh_capabilities", "drain_runtimes":
		return nil
	case "load_model", "unload_model":
		if target, _ := args["target_id"].(string); target == "" {
			return fmt.Errorf("target_id is required")
		}
		if model, _ := args["model"].(string); model == "" {
			return fmt.Errorf("model is required")
		}
		return nil
	case "reclaim_accelerator":
		if target, _ := args["target_id"].(string); target == "" {
			return fmt.Errorf("target_id is required")
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
	if err := validateNodeCommand(command, args); err != nil {
		return nil, err
	}
	if _, err := s.nodes.GetNode(ctx, nodeID); err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	expires := now.Add(10 * time.Minute)
	if deadline, ok := ctx.Deadline(); ok && deadline.Before(expires) {
		expires = deadline
	}
	row := &domain.NodeCommand{ID: newCommandID(), IdempotencyKey: idempotencyKey, NodeID: nodeID, Command: command, Args: args, IssuedBy: "controller", Status: domain.NodeCommandQueued, CreatedAt: now, ExpiresAt: expires, UpdatedAt: now}
	wire := nodeCommandPayload(row)
	signature, err := wsproto.SignCommand(wire, s.commandSecret)
	if err != nil {
		return nil, err
	}
	row.Signature = signature
	stored, created, err := s.workloadStore.CreateNodeCommand(ctx, row)
	if err != nil {
		return nil, err
	}
	if created {
		s.appendNodeCommandAudit(ctx, "controller", stored, "node.command.created", "info")
	}
	s.sendNodeCommand(ctx, stored)
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
			return result, nil
		case domain.NodeCommandFailed, domain.NodeCommandExpired:
			return nil, fmt.Errorf("node command %s: %s", current.Status, current.Error)
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("node command did not complete: %w", ctx.Err())
		case <-ticker.C:
		}
	}
}

func nodeCommandPayload(command *domain.NodeCommand) wsproto.CommandPayload {
	return wsproto.CommandPayload{ID: command.ID, IdempotencyKey: command.IdempotencyKey, NodeID: command.NodeID, Command: command.Command, Args: command.Args, IssuedAt: command.CreatedAt, ExpiresAt: command.ExpiresAt, Signature: command.Signature}
}

func (s *Server) dispatchNodeCommands(ctx context.Context, nodeID string) {
	rows, err := s.workloadStore.ListNodeCommands(ctx, nodeID, 100)
	if err != nil {
		return
	}
	for _, command := range rows {
		if command.Status != domain.NodeCommandQueued && command.Status != domain.NodeCommandSent {
			continue
		}
		if time.Now().UTC().After(command.ExpiresAt) {
			now := time.Now().UTC()
			command.Status = domain.NodeCommandExpired
			command.Error = "command expired before delivery"
			command.CompletedAt = &now
			command.UpdatedAt = now
			_, _ = s.workloadStore.UpdateNodeCommand(ctx, command)
			continue
		}
		s.sendNodeCommand(ctx, command)
	}
}

func (s *Server) sendNodeCommand(ctx context.Context, command *domain.NodeCommand) {
	if command.Status != domain.NodeCommandQueued && command.Status != domain.NodeCommandSent {
		return
	}
	s.nodeConnMu.RLock()
	connection := s.nodeConnections[command.NodeID]
	s.nodeConnMu.RUnlock()
	if connection == nil {
		return
	}
	// Mark the command sent before the node can reply. Updating this row after
	// delivery can race a fast result and incorrectly turn SUCCEEDED back into
	// SENT, causing the controller to wait until expiry.
	now := time.Now().UTC()
	command.Status = domain.NodeCommandSent
	command.SentAt = &now
	command.UpdatedAt = now
	if _, err := s.workloadStore.UpdateNodeCommand(context.Background(), command); err != nil {
		return
	}
	payload, _ := json.Marshal(nodeCommandPayload(command))
	envelope := wsproto.Envelope{Type: wsproto.MsgCommand, Time: time.Now().UTC(), Payload: payload}
	writeCtx, cancel := context.WithDeadline(ctx, command.ExpiresAt)
	err := connection.write(writeCtx, envelope)
	cancel()
	if err != nil {
		latest, getErr := s.workloadStore.GetNodeCommand(context.Background(), command.ID)
		if getErr == nil && latest.Status == domain.NodeCommandSent {
			latest.Status = domain.NodeCommandQueued
			latest.UpdatedAt = time.Now().UTC()
			_, _ = s.workloadStore.UpdateNodeCommand(context.Background(), latest)
		}
		return
	}
}

func (s *Server) handleNodeCommandResult(ctx context.Context, result wsproto.CommandResultPayload) {
	command, err := s.workloadStore.GetNodeCommand(ctx, result.ID)
	if err != nil || command.NodeID != result.NodeID || command.Status == domain.NodeCommandSucceeded || command.Status == domain.NodeCommandFailed || command.Status == domain.NodeCommandExpired {
		return
	}
	now := time.Now().UTC()
	if now.After(command.ExpiresAt) {
		command.Status = domain.NodeCommandExpired
		command.Error = "late command result ignored after expiry"
	} else if result.OK {
		command.Status = domain.NodeCommandSucceeded
		command.Result, _ = json.Marshal(result.Result)
	} else {
		command.Status = domain.NodeCommandFailed
		command.Error = result.Error
	}
	command.CompletedAt = &now
	command.UpdatedAt = now
	_, updateErr := s.workloadStore.UpdateNodeCommand(ctx, command)
	if updateErr == nil && command.Status == domain.NodeCommandSucceeded && command.Command == "refresh_capabilities" {
		body, marshalErr := json.Marshal(result.Result)
		if marshalErr == nil {
			var capabilities wsproto.CapabilitiesPayload
			if json.Unmarshal(body, &capabilities) == nil {
				s.registerAdapterAdvertisements(command.NodeID, capabilities.Adapters)
			}
		}
	}
	severity := "info"
	if command.Status != domain.NodeCommandSucceeded {
		severity = "error"
	}
	s.appendNodeCommandAudit(ctx, result.NodeID, command, "node.command.completed", severity)
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
