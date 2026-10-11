package store

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"vram-governor/internal/domain"
)

func TestMemoryNodeCommandDeliveryCASAttempts(t *testing.T) {
	backing := NewMemoryStore()
	now := time.Now().UTC()
	command := &domain.NodeCommand{ID: "command-cas", IdempotencyKey: "command-cas-key", NodeID: "node-a", Command: "load_model", Args: map[string]any{"target_id": "target", "model": "model"}, Signature: "signed", Status: domain.NodeCommandQueued, CreatedAt: now, ExpiresAt: now.Add(time.Minute), UpdatedAt: now}
	stored, created, err := backing.CreateNodeCommand(context.Background(), command)
	if err != nil || !created {
		t.Fatalf("create command: %+v created=%v err=%v", stored, created, err)
	}
	first := *stored
	first.Status = domain.NodeCommandSent
	first.Attempts = 1
	if _, err := backing.CompareAndSwapNodeCommand(context.Background(), &first, 0, domain.NodeCommandQueued); err != nil {
		t.Fatalf("first delivery CAS: %v", err)
	}
	duplicate := first
	duplicate.Attempts = 2
	if _, err := backing.CompareAndSwapNodeCommand(context.Background(), &duplicate, 0, domain.NodeCommandSent); !errors.Is(err, ErrNodeCommandConflict) {
		t.Fatalf("stale delivery attempt was accepted: %v", err)
	}
	replay := first
	replay.Attempts = 2
	if _, err := backing.CompareAndSwapNodeCommand(context.Background(), &replay, 1, domain.NodeCommandSent); err != nil {
		t.Fatalf("same-args redelivery CAS: %v", err)
	}
}

func TestMemoryNodeCommandUncertaintyDominatesTerminalAndStaleReplay(t *testing.T) {
	backing := NewMemoryStore()
	now := time.Now().UTC()
	command := &domain.NodeCommand{ID: "uncertain-dominates", IdempotencyKey: "uncertain-dominates-key", NodeID: "node-a", Command: "load_model", Args: map[string]any{"target_id": "target", "model": "model"}, Signature: "signed", Status: domain.NodeCommandSent, CreatedAt: now, ExpiresAt: now.Add(time.Minute), UpdatedAt: now}
	stored, _, err := backing.CreateNodeCommand(context.Background(), command)
	if err != nil {
		t.Fatal(err)
	}
	terminal := *stored
	terminal.Status = domain.NodeCommandFailed
	terminal.Error = "send failure"
	terminalResult, err := backing.CompareAndSwapNodeCommandRevision(context.Background(), &terminal, stored.Revision, stored.Attempts, false, domain.NodeCommandSent)
	if err != nil {
		t.Fatal(err)
	}
	terminal = *terminalResult
	observation, _ := json.Marshal(map[string]any{"tier": "hot_vram", "fence": 7})
	uncertain, err := backing.PromoteNodeCommandUncertain(context.Background(), terminal.ID, terminal.NodeID, observation, "post-side-effect uncertainty")
	if err != nil || !uncertain.Uncertain || uncertain.Status != domain.NodeCommandSent || uncertain.Revision <= terminal.Revision {
		t.Fatalf("uncertainty did not dominate terminal observation: row=%+v err=%v", uncertain, err)
	}
	stale := terminal
	stale.Status = domain.NodeCommandSucceeded
	if _, err := backing.CompareAndSwapNodeCommandRevision(context.Background(), &stale, terminal.Revision, terminal.Attempts, false, domain.NodeCommandFailed); !errors.Is(err, ErrNodeCommandConflict) {
		t.Fatalf("stale ordinary result overwrote promoted uncertainty: %v", err)
	}
	authoritative := *uncertain
	authoritative.Uncertain = false
	authoritative.Status = domain.NodeCommandSucceeded
	authoritative.EvidenceKind = "authoritative_observation"
	authoritative.Result = observation
	settled, err := backing.CompareAndSwapNodeCommandRevision(context.Background(), &authoritative, uncertain.Revision, uncertain.Attempts, true, domain.NodeCommandSent)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := backing.PromoteNodeCommandUncertain(context.Background(), settled.ID, settled.NodeID, observation, "late duplicate uncertainty"); !errors.Is(err, ErrNodeCommandConflict) {
		t.Fatalf("late uncertainty reopened authoritative settlement: %v", err)
	}
}

func TestMemoryNodeCommandRevisionUncertaintyCASAndExhaustiveRecovery(t *testing.T) {
	backing := NewMemoryStore()
	now := time.Now().UTC()
	command := &domain.NodeCommand{ID: "revision-cas", IdempotencyKey: "revision-cas-key", NodeID: "node-a", Command: "load_model", Args: map[string]any{"target_id": "target", "model": "model"}, Signature: "signed", Status: domain.NodeCommandQueued, CreatedAt: now, ExpiresAt: now.Add(time.Minute), UpdatedAt: now}
	stored, _, err := backing.CreateNodeCommand(context.Background(), command)
	if err != nil || stored.Revision != 1 {
		t.Fatalf("initial revision: %+v %v", stored, err)
	}
	sent := *stored
	sent.Status, sent.Attempts = domain.NodeCommandSent, 1
	sentResult, err := backing.CompareAndSwapNodeCommandRevision(context.Background(), &sent, stored.Revision, 0, false, domain.NodeCommandQueued)
	if err != nil || sentResult.Revision != 2 {
		t.Fatalf("sent revision CAS: %+v %v", sentResult, err)
	}
	uncertain := *sentResult
	uncertain.Uncertain = true
	uncertainResult, err := backing.CompareAndSwapNodeCommandRevision(context.Background(), &uncertain, sentResult.Revision, sentResult.Attempts, false, domain.NodeCommandSent)
	if err != nil || !uncertainResult.Uncertain || uncertainResult.Revision != 3 {
		t.Fatalf("uncertain revision CAS: %+v %v", uncertainResult, err)
	}
	blocked := *sentResult
	blocked.Status = domain.NodeCommandFailed
	if _, err := backing.CompareAndSwapNodeCommandRevision(context.Background(), &blocked, sentResult.Revision, sentResult.Attempts, false, domain.NodeCommandSent); !errors.Is(err, ErrNodeCommandConflict) {
		t.Fatalf("stale blocked result overwrote uncertainty: %v", err)
	}
	rows, err := backing.ListNodeCommandRecovery(context.Background(), "node-a", "")
	if err != nil || len(rows) != 1 || !rows[0].Uncertain {
		t.Fatalf("recovery query lost uncertain row: rows=%+v err=%v", rows, err)
	}
}

func TestMemoryNodeCommandRecoveryAdvancePersistsFutureDueAfterReload(t *testing.T) {
	backing := NewMemoryStore()
	now := time.Now().UTC()
	command := &domain.NodeCommand{ID: "recovery-advance", IdempotencyKey: "recovery-advance-key", NodeID: "node-a", Command: "load_model", Args: map[string]any{"target_id": "target", "model": "model"}, Signature: "signed", Status: domain.NodeCommandSent, Uncertain: true, CreatedAt: now, ExpiresAt: now.Add(time.Minute), UpdatedAt: now}
	stored, _, err := backing.CreateNodeCommand(context.Background(), command)
	if err != nil {
		t.Fatal(err)
	}
	advanced, err := backing.AdvanceNodeCommandRecovery(context.Background(), stored.ID)
	if err != nil || advanced.RecoveryAttempts != 1 || advanced.RecoveryNextAt == nil || !advanced.RecoveryNextAt.After(now) {
		t.Fatalf("recovery advance was not durable: row=%+v err=%v", advanced, err)
	}
	reloaded, err := backing.GetNodeCommand(context.Background(), stored.ID)
	if err != nil || reloaded.RecoveryAttempts != advanced.RecoveryAttempts || reloaded.RecoveryNextAt == nil || !reloaded.RecoveryNextAt.Equal(*advanced.RecoveryNextAt) {
		t.Fatalf("reloaded recovery progression changed: row=%+v err=%v", reloaded, err)
	}
	if _, err := backing.AdvanceNodeCommandRecovery(context.Background(), "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing recovery row returned wrong error: %v", err)
	}
}
