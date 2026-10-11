package nodeagent

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"strings"
	"time"

	"vram-governor/internal/wsproto"
)

func ownedStopReceiptSigningMaterial(unsigned []byte) []byte {
	const domain = "vram-governor-owned-stop-root-ack-v1\x00"
	material := make([]byte, 0, len(domain)+len(unsigned))
	material = append(material, domain...)
	return append(material, unsigned...)
}

func verifyOwnedStopReceiptSignature(receipt ownedStopReceipt, publicKey ed25519.PublicKey) error {
	if len(publicKey) != ed25519.PublicKeySize {
		return errors.New("owned stop acknowledgement public key is invalid")
	}
	signature, err := hex.DecodeString(receipt.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize || hex.EncodeToString(signature) != receipt.Signature {
		return errors.New("owned stop acknowledgement signature is malformed")
	}
	unsigned := receipt
	unsigned.Signature = ""
	canonical, err := json.Marshal(unsigned)
	if err != nil || !ed25519.Verify(publicKey, ownedStopReceiptSigningMaterial(canonical), signature) {
		return errors.New("owned stop acknowledgement signature is invalid")
	}
	return nil
}

func verifyOwnedStopReceipt(raw []byte, publicKey ed25519.PublicKey, originalWire []byte, secret string) error {
	if len(raw) == 0 || len(raw) > 16<<10 || len(publicKey) != ed25519.PublicKeySize {
		return errors.New("owned stop receipt size or key is invalid")
	}
	var receipt ownedStopReceipt
	if err := json.Unmarshal(raw, &receipt); err != nil || receipt.Version != 1 || !receipt.SignalSent || !receipt.ReleaseTerminal || receipt.SupervisorPID <= 1 || receipt.SupervisorStartTicks == 0 || receipt.WorkerPID <= 1 || receipt.WorkerStartTicks == 0 || receipt.InvocationID == "" || receipt.ControlGroup == "" {
		return errors.New("owned stop receipt is incomplete")
	}
	if err := verifyOwnedStopReceiptSignature(receipt, publicKey); err != nil {
		return err
	}
	canonicalSigned, err := json.Marshal(receipt)
	if err != nil || !bytes.Equal(canonicalSigned, raw) {
		return errors.New("owned stop receipt bytes are not canonical")
	}
	var original wsproto.CommandPayload
	if rejectDuplicateJSONKeys(originalWire) != nil || json.Unmarshal(originalWire, &original) != nil || !wsproto.VerifyCommand(original, []byte(secret)) {
		return errors.New("owned stop original command is invalid")
	}
	canonicalOriginal, err := wsproto.CanonicalCommandEnvelope(original)
	if err != nil || !bytes.Equal(canonicalOriginal, originalWire) {
		return errors.New("owned stop original envelope is not canonical")
	}
	signedAt, err := time.Parse(time.RFC3339Nano, receipt.SignedAt)
	if err != nil || signedAt.Before(original.IssuedAt) || signedAt.After(original.ExpiresAt) {
		return errors.New("owned stop receipt timestamp is outside the signed command window")
	}
	if receipt.ManagedCurrentIncarnation != receipt.LocalCheckpointBinding || !checkpointSHA256RE.MatchString(receipt.ManagedCurrentIncarnation) || !checkpointSHA256RE.MatchString(receipt.ManagedPlanSHA256) || !checkpointSHA256RE.MatchString(receipt.CustodyBindingSHA256) {
		return errors.New("owned stop receipt managed binding or custody fingerprint is malformed")
	}
	envelopeDigest := sha256Hex(originalWire)
	material, err := wsproto.CommandSigningMaterialForOwnedStop(original)
	if err != nil || receipt.SigningMaterialSHA256 != sha256Hex(material) {
		return errors.New("owned stop receipt signing-material digest differs")
	}
	localBinding := strings.TrimPrefix(fmt.Sprint(original.Args["local_checkpoint_binding"]), "sha256:")
	if receipt.NodeID != original.NodeID || receipt.OperationID != original.Args["operation_id"] || receipt.StepID != original.Args["step_id"] || receipt.CommandID != original.ID || receipt.IdempotencyKey != original.IdempotencyKey || receipt.OriginalEnvelopeSHA256 != envelopeDigest || receipt.RecoveryEpoch != original.Args["recovery_epoch"] || receipt.AcceleratorID != original.Args["accelerator_id"] || receipt.FencingToken != int64FromArg(original.Args["fencing_token"]) || receipt.TargetID != original.Args["target_id"] || receipt.WorkloadID != original.Args["workload_id"] || receipt.WorkloadRevision != int64FromArg(original.Args["workload_revision"]) || receipt.Model != original.Args["model"] || receipt.ModelAlias != original.Args["model_alias"] || receipt.LocalCheckpointBinding != localBinding || receipt.SnapshotName != original.Args["snapshot_name"] || receipt.SnapshotDigest != original.Args["snapshot_digest"] {
		return errors.New("owned stop receipt identity differs from original intent")
	}
	return nil
}

type checkpointOwnedStopLifetimeObservation struct {
	ExitType                string
	ActiveState             string
	SubState                string
	MainPID                 int
	ExpectedWorkerPID       int
	ExpectedWorkerTicks     uint64
	SupervisorPID           int
	ExpectedSupervisorTicks uint64
	SupervisorInUnit        bool
	SupervisorAlive         bool
	WorkerExited            bool
	DurableAckObserved      bool
	UnitInactiveAfterAck    bool
	ControlGroup            string
}

func validateCheckpointOwnedStopLifetime(observation checkpointOwnedStopLifetimeObservation) error {
	if observation.ExitType != "cgroup" {
		return errors.New("fixed service does not retain its supervisor with ExitType=cgroup")
	}
	if observation.ExpectedWorkerPID <= 1 || observation.ExpectedWorkerTicks == 0 || observation.SupervisorPID <= 1 || observation.ExpectedSupervisorTicks == 0 || observation.MainPID != observation.ExpectedWorkerPID {
		return errors.New("fixed service MainPID or process incarnation differs from the worker")
	}
	if !observation.WorkerExited || !observation.SupervisorAlive || !observation.SupervisorInUnit || !validOwnedStopLifetimeCgroup(observation.ControlGroup) {
		return errors.New("fixed service did not retain the exact live supervisor in the worker unit cgroup")
	}
	if !observation.DurableAckObserved || !observation.UnitInactiveAfterAck || observation.ActiveState != "inactive" {
		return errors.New("fixed service lifetime lacks durable acknowledgement before unit exit")
	}
	return nil
}

func validOwnedStopLifetimeCgroup(value string) bool {
	if value == "" || !path.IsAbs(value) || path.Clean(value) != value || value == "/" || strings.ContainsAny(value, "\x00\r\n") || strings.Contains(value, "//") {
		return false
	}
	for _, component := range strings.Split(value, "/") {
		if component == "." || component == ".." {
			return false
		}
	}
	return true
}
