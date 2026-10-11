package nodeagent

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"vram-governor/internal/wsproto"
)

func signedPlanRelaunchFixture(t *testing.T) (wsproto.CommandPayload, []byte, string) {
	t.Helper()
	secret := strings.Repeat("s", 40)
	now := time.Now().UTC().Truncate(time.Second)
	command := wsproto.CommandPayload{
		ID: "command-urgent-01", IdempotencyKey: "idem-urgent-01", NodeID: "node-a", Command: checkpointPlanRelaunchUrgentCommand,
		Args:     map[string]any{"operation_id": "operation-01", "target_kind": "llamacpp", "target_id": "node-a-server-0", "accelerator_id": "gpu-0", "workload_id": "workload-01", "workload_revision": int64(2), "recovery_epoch": "epoch-01", "fencing_token": int64(8), "catalog_id": "urgent-v1", "linked_catalog_id": "victim-v1", "prior_command_id": "stop-victim", "prior_idempotency_key": "idem-stop-victim", "prior_receipt_sha256": strings.Repeat("a", 64)},
		IssuedAt: now.Add(-time.Second), ExpiresAt: now.Add(3 * time.Minute),
	}
	signature, err := wsproto.SignCommand(command, []byte(secret))
	if err != nil {
		t.Fatal(err)
	}
	command.Signature = signature
	wire, err := wsproto.CanonicalCommandEnvelope(command)
	if err != nil {
		t.Fatal(err)
	}
	material, err := wsproto.CommandSigningMaterialForPlanRelaunch(command)
	if err != nil {
		t.Fatal(err)
	}
	return command, wire, sha256Hex(material)
}

func TestPlanRelaunchReceiptRequiresExactOriginalAndFreshIdentity(t *testing.T) {
	command, wire, signingDigest := signedPlanRelaunchFixture(t)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	acceptedAt := time.Now().UTC().Add(-time.Second)
	receipt := checkpointPlanRelaunchReceipt{
		Version: 1, NodeID: command.NodeID, OperationID: "operation-01", Step: "urgent_load", CommandID: command.ID, IdempotencyKey: command.IdempotencyKey,
		OriginalEnvelopeSHA256: sha256Hex(wire), SigningMaterialSHA256: signingDigest, RecoveryEpoch: "epoch-01", AcceleratorID: "gpu-0", FencingToken: 8,
		TargetID: "node-a-server-0", WorkloadID: "workload-01", WorkloadRevision: 2, CatalogID: "urgent-v1", LinkedCatalogID: "victim-v1",
		CatalogSHA256: strings.Repeat("b", 64), PlanSHA256: strings.Repeat("c", 64), PriorReceiptSHA256: strings.Repeat("a", 64), PriorInvocationID: "invocation-before",
		AcceptedAt: acceptedAt.Format(time.RFC3339Nano), InvocationID: "invocation-after", MainPID: 1200, CurrentIncarnation: strings.Repeat("d", 64), CustodyBindingSHA256: strings.Repeat("e", 64), Alias: "urgent-model", SignedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
	unsigned, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	receipt.Signature = hex.EncodeToString(ed25519.Sign(private, checkpointPlanRelaunchSigningMaterial(unsigned)))
	raw, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifyCheckpointPlanRelaunchReceipt(raw, public, wire, strings.Repeat("s", 40)); err != nil {
		t.Fatalf("valid signed root receipt rejected: %v", err)
	}
	if _, err := verifyCheckpointPlanRelaunchReceipt(raw, public, wire, strings.Repeat("x", 40)); err == nil {
		t.Fatal("receipt with an original command signed under another secret was accepted")
	}
	mutated := receipt
	mutated.MainPID++
	mutant, _ := json.Marshal(mutated)
	if _, err := verifyCheckpointPlanRelaunchReceipt(mutant, public, wire, strings.Repeat("s", 40)); err == nil {
		t.Fatal("modified root receipt accepted")
	}
	wrongPublic, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := verifyCheckpointPlanRelaunchReceipt(raw, wrongPublic, wire, strings.Repeat("s", 40)); err == nil {
		t.Fatal("receipt signed by an unpinned root key accepted")
	}
	if _, err := verifyCheckpointPlanRelaunchReceipt(append(append([]byte(nil), raw...), ' '), public, wire, strings.Repeat("s", 40)); err == nil {
		t.Fatal("noncanonical signed receipt accepted")
	}
	duplicate := append([]byte("{\"version\":1,"), raw[1:]...)
	if _, err := verifyCheckpointPlanRelaunchReceipt(duplicate, public, wire, strings.Repeat("s", 40)); err == nil {
		t.Fatal("duplicate receipt field accepted")
	}
}

func TestPlanRelaunchReceiptReconcilesOnlyPreviouslyAcceptedExpiredIntent(t *testing.T) {
	command, _, _ := signedPlanRelaunchFixture(t)
	secret := strings.Repeat("s", 40)
	command.IssuedAt = time.Now().UTC().Add(-10 * time.Minute).Truncate(time.Second)
	command.ExpiresAt = command.IssuedAt.Add(time.Minute)
	command.Signature, _ = wsproto.SignCommand(command, []byte(secret))
	wire, err := wsproto.CanonicalCommandEnvelope(command)
	if err != nil {
		t.Fatal(err)
	}
	material, err := wsproto.CommandSigningMaterialForPlanRelaunch(command)
	if err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	acceptedAt := command.IssuedAt.Add(30 * time.Second)
	receipt := checkpointPlanRelaunchReceipt{Version: 1, NodeID: command.NodeID, OperationID: "operation-01", Step: "urgent_load", CommandID: command.ID, IdempotencyKey: command.IdempotencyKey, OriginalEnvelopeSHA256: sha256Hex(wire), SigningMaterialSHA256: sha256Hex(material), RecoveryEpoch: "epoch-01", AcceleratorID: "gpu-0", FencingToken: 8, TargetID: "node-a-server-0", WorkloadID: "workload-01", WorkloadRevision: 2, CatalogID: "urgent-v1", LinkedCatalogID: "victim-v1", CatalogSHA256: strings.Repeat("b", 64), PlanSHA256: strings.Repeat("c", 64), PriorReceiptSHA256: strings.Repeat("a", 64), PriorInvocationID: "invocation-before", AcceptedAt: acceptedAt.Format(time.RFC3339Nano), InvocationID: "invocation-after", MainPID: 1200, CurrentIncarnation: strings.Repeat("d", 64), CustodyBindingSHA256: strings.Repeat("e", 64), Alias: "urgent-model", SignedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	sign := func(value checkpointPlanRelaunchReceipt) []byte {
		unsigned, _ := json.Marshal(value)
		value.Signature = hex.EncodeToString(ed25519.Sign(private, checkpointPlanRelaunchSigningMaterial(unsigned)))
		raw, _ := json.Marshal(value)
		return raw
	}
	if _, err := verifyCheckpointPlanRelaunchReceipt(sign(receipt), public, wire, secret); err != nil {
		t.Fatalf("previously accepted intent could not be observed after expiry: %v", err)
	}
	lateAcceptance := receipt
	lateAcceptance.AcceptedAt = command.ExpiresAt.Add(time.Second).Format(time.RFC3339Nano)
	if _, err := verifyCheckpointPlanRelaunchReceipt(sign(lateAcceptance), public, wire, secret); err == nil {
		t.Fatal("root receipt accepted an intent first accepted after its signed expiry")
	}
}

func TestPlanRelaunchQueryTimeWindowIsBounded(t *testing.T) {
	command, _, _ := signedPlanRelaunchFixture(t)
	if err := validateCheckpointPlanRelaunchCommandTime(command, time.Now().UTC()); err != nil {
		t.Fatalf("current signed command rejected: %v", err)
	}
	command.ExpiresAt = command.IssuedAt.Add(checkpointPlanBrokerMaxTimeout + time.Second)
	if err := validateCheckpointPlanRelaunchCommandTime(command, time.Now().UTC()); err == nil {
		t.Fatal("overlong command validity window accepted")
	}
}
