package nodeagent

import (
	"strings"
	"testing"

	"vram-governor/internal/wsproto"
)

func TestPlanRelaunchSharesStopFenceAndRequiresTerminalPriorStep(t *testing.T) {
	const accelerator = "gpu-0"
	const operationID = "disp-01"
	const epoch = "epoch-01"
	stop := ownedStopOperationState{OperationID: operationID, AcceleratorID: accelerator, RecoveryEpoch: epoch, Fence: 8, Steps: map[string]ownedStopStepState{
		"victim_stop": {CommandID: "stop-v", IdempotencyKey: "idem-stop-v", ReceiptSHA256: strings.Repeat("a", 64), Status: "acknowledged"},
		"urgent_stop": {CommandID: "stop-u", IdempotencyKey: "idem-stop-u", ReceiptSHA256: strings.Repeat("b", 64), Status: "acknowledged"},
	}}
	processor := &commandProcessor{ownedStopOperations: map[string]ownedStopOperationState{accelerator: stop}, fences: map[string]int64{ownedStopFenceKey(accelerator): 8}}
	urgent := wsproto.CommandPayload{Command: checkpointPlanRelaunchUrgentCommand, Args: map[string]any{
		"operation_id": operationID, "target_kind": "llamacpp", "target_id": "node-a-server-0", "accelerator_id": accelerator,
		"workload_id": "workload-01", "workload_revision": int64(2), "recovery_epoch": epoch, "fencing_token": int64(8),
		"catalog_id": "urgent-v1", "linked_catalog_id": "victim-v1", "prior_command_id": "stop-v", "prior_idempotency_key": "idem-stop-v", "prior_receipt_sha256": strings.Repeat("a", 64),
	}}
	if err := processor.checkPlanRelaunchTransition(urgent); err != nil {
		t.Fatalf("first linked urgent step rejected: %v", err)
	}
	processor.planRelaunchOperations = map[string]checkpointPlanRelaunchOperation{accelerator: {OperationID: operationID, TargetID: "node-a-server-0", AcceleratorID: accelerator, WorkloadID: "workload-01", WorkloadRevision: 2, RecoveryEpoch: epoch, Fence: 8, VictimCatalogID: "victim-v1", UrgentCatalogID: "urgent-v1", Steps: map[string]checkpointPlanRelaunchStep{"urgent_load": {CommandID: "load-u", Status: "acknowledged"}}}}
	processor.fences[checkpointPlanRelaunchFenceKey(accelerator)] = 8
	victim := urgent
	victim.Command = checkpointPlanRelaunchVictimCommand
	victim.Args = map[string]any{
		"operation_id": operationID, "target_kind": "llamacpp", "target_id": "node-a-server-0", "accelerator_id": accelerator,
		"workload_id": "workload-01", "workload_revision": int64(2), "recovery_epoch": epoch, "fencing_token": int64(8),
		"catalog_id": "victim-v1", "prior_command_id": "stop-u", "prior_idempotency_key": "idem-stop-u", "prior_receipt_sha256": strings.Repeat("b", 64),
	}
	if err := processor.checkPlanRelaunchTransition(victim); err != nil {
		t.Fatalf("exact linked victim return rejected: %v", err)
	}
	victim.Args["catalog_id"] = "other-v1"
	if err := processor.checkPlanRelaunchTransition(victim); err == nil {
		t.Fatal("substituted victim catalog was accepted")
	}
}

func TestPlanRelaunchRecoveryNeverRepeatsAmbiguousStart(t *testing.T) {
	for _, step := range []string{"urgent_load", "victim_reload"} {
		for _, stage := range []string{step + "_prepared", step + "_published", step + "_start_requested", step + "_start_accepted", step + "_acknowledged", "unknown"} {
			wantDispatch := stage == step+"_published"
			wantJoin := stage == step+"_start_requested" || stage == step+"_start_accepted"
			if got := checkpointPlanRelaunchMayIssueFirstStart(step, stage); got != wantDispatch {
				t.Errorf("first-start authority for %s/%s = %t, want %t", step, stage, got, wantDispatch)
			}
			if got := checkpointPlanRelaunchMayJoinStartedProcess(step, stage); got != wantJoin {
				t.Errorf("live-process join authority for %s/%s = %t, want %t", step, stage, got, wantJoin)
			}
		}
	}
	for _, step := range []string{"", "query", "urgent_load/other"} {
		if checkpointPlanRelaunchMayIssueFirstStart(step, step+"_published") || checkpointPlanRelaunchMayJoinStartedProcess(step, step+"_start_requested") {
			t.Errorf("unsupported step %q gained recovery start authority", step)
		}
	}
}
