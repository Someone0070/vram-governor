package nodeagent

import (
	"context"
	"strings"
	"testing"
)

func TestCheckpointCustodyLifecycleRejectsUnsettledRelease(t *testing.T) {
	model := &CheckpointPreparedModel{store: &CheckpointCustodyStore{}, used: true}
	launch := &CheckpointControlledLaunch{store: model.store, model: model, started: true}
	if err := launch.ReleaseTerminal(context.Background()); err == nil || !strings.Contains(err.Error(), "terminal ownership") {
		t.Fatalf("lifecycle rejection assertion: active child without exact reap released its source: %v", err)
	}
	if err := model.Discard(context.Background()); err == nil || !strings.Contains(err.Error(), "consumed") {
		t.Fatalf("lifecycle rejection assertion: consumed source was discarded while launch ownership remained unsettled: %v", err)
	}
	unknown := &CheckpointControlledLaunch{store: model.store, model: model, permit: &struct{}{}, childCreated: true, waitStarted: true, waitErr: context.DeadlineExceeded}
	if err := unknown.Abort(); err == nil || !strings.Contains(err.Error(), "WaitContext") {
		t.Fatalf("lifecycle rejection assertion: ambiguous child state was treated as an unstarted Abort: %v", err)
	}
	if err := unknown.ReleaseTerminal(context.Background()); err == nil || !strings.Contains(err.Error(), "terminal ownership") {
		t.Fatalf("lifecycle rejection assertion: WaitContext error without confirmed reap released a source: %v", err)
	}
}

func TestCheckpointCustodyLifecycleFailedBeginIsSingleUse(t *testing.T) {
	model := &CheckpointPreparedModel{store: &CheckpointCustodyStore{}, used: true, beginFailed: true}
	if err := model.Discard(context.Background()); err == nil {
		t.Fatal("lifecycle rejection assertion: failed Begin reached platform cleanup without a source pin")
	}
	if !model.used {
		t.Fatal("lifecycle rejection assertion: failed Begin made the consumed source reusable")
	}
}
