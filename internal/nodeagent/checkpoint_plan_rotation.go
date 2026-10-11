package nodeagent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"vram-governor/internal/wsproto"
)

const (
	checkpointPlanRelaunchUrgentCommand = "llm_displacement_plan_urgent_load"
	checkpointPlanRelaunchVictimCommand = "llm_displacement_plan_victim_reload"
	checkpointPlanRelaunchQueryCommand  = "llm_displacement_plan_query"
	checkpointPlanRelaunchMaxFrame      = 64 << 10
	checkpointPlanCatalogMaxBytes       = 4 << 20
	checkpointPlanBrokerMaxTimeout      = 4 * time.Minute
	checkpointPlanBrokerSocketPath      = "/run/vram-governor-plan/plan.sock"
	checkpointPlanBrokerRuntimeDir      = "/run/vram-governor-plan"
	checkpointPlanBrokerCatalogPath     = "/etc/vram-governor/checkpoint-plan-catalog.json"
	checkpointPlanBrokerPrivateDir      = "/var/lib/vram-governor-plan-private"
	checkpointPlanBrokerPublicDir       = "/var/lib/vram-governor-plan-public"
	checkpointPlanBrokerPrivateKeyPath  = checkpointPlanBrokerPrivateDir + "/ed25519.key"
	checkpointPlanBrokerPublicKeyPath   = checkpointPlanBrokerPublicDir + "/ed25519.pub"
	checkpointPlanBrokerJournalPath     = checkpointPlanBrokerPrivateDir + "/operations.json"
	checkpointPlanBrokerReceiptDir      = checkpointPlanBrokerPublicDir + "/receipts"
	checkpointPlanBrokerUnit            = checkpointIdentityServiceUnit
)

type checkpointPlanBrokerPaths struct {
	Socket, RuntimeDir                            string
	Catalog, ActivePlan                           string
	PrivateKey, PublicKey, Journal, ReceiptDir    string
	StopPrivateKey, StopPublicKey, StopReceiptDir string
	NodeConfig, NodeEnv, NodeState, NodeStateDir  string
	NodeUID, NodeGID                              uint32
	fixtureRoot, fixtureUnit                      string
	bindingObserver                               func(context.Context, CheckpointLaunchPlan, string, string) (CheckpointManagedBinding, error)
	faultInjector                                 func(string) bool
	privateFixture                                bool
}

func fixedCheckpointPlanBrokerPaths() checkpointPlanBrokerPaths {
	stop := fixedCheckpointOwnedStopPaths()
	return checkpointPlanBrokerPaths{
		Socket: checkpointPlanBrokerSocketPath, RuntimeDir: checkpointPlanBrokerRuntimeDir,
		Catalog: checkpointPlanBrokerCatalogPath, ActivePlan: checkpointFixedPlanPath,
		PrivateKey: checkpointPlanBrokerPrivateKeyPath, PublicKey: checkpointPlanBrokerPublicKeyPath,
		Journal: checkpointPlanBrokerJournalPath, ReceiptDir: checkpointPlanBrokerReceiptDir,
		StopPrivateKey: stop.PrivateKey, StopPublicKey: stop.PublicKey, StopReceiptDir: stop.ReceiptDir,
		NodeConfig: stop.NodeConfig, NodeEnv: stop.NodeEnv, NodeState: stop.NodeState, NodeStateDir: stop.StateDir,
	}
}

type checkpointPlanRelaunchStep struct {
	CommandID             string `json:"command_id"`
	IdempotencyKey        string `json:"idempotency_key"`
	EnvelopeSHA256        string `json:"envelope_sha256"`
	OriginalEnvelope      []byte `json:"original_envelope"`
	SigningMaterialSHA256 string `json:"signing_material_sha256"`
	AcceptedAt            string `json:"accepted_at,omitempty"`
	Status                string `json:"status"`
	ReceiptSHA256         string `json:"receipt_sha256,omitempty"`
	Receipt               []byte `json:"receipt,omitempty"`
	PinnedRootPublicKey   []byte `json:"pinned_root_public_key,omitempty"`
}

type checkpointPlanRelaunchOperation struct {
	OperationID      string                                `json:"operation_id"`
	TargetID         string                                `json:"target_id"`
	AcceleratorID    string                                `json:"accelerator_id"`
	WorkloadID       string                                `json:"workload_id"`
	WorkloadRevision int64                                 `json:"workload_revision"`
	RecoveryEpoch    string                                `json:"recovery_epoch"`
	Fence            int64                                 `json:"fence"`
	VictimCatalogID  string                                `json:"victim_catalog_id"`
	UrgentCatalogID  string                                `json:"urgent_catalog_id"`
	Steps            map[string]checkpointPlanRelaunchStep `json:"steps"`
}

type checkpointPlanCatalog struct {
	Version int                          `json:"version"`
	Entries []checkpointPlanCatalogEntry `json:"entries"`
}

type checkpointPlanCatalogEntry struct {
	CatalogID        string `json:"catalog_id"`
	ModelID          string `json:"model_id"`
	WorkloadID       string `json:"workload_id"`
	WorkloadRevision int64  `json:"workload_revision"`
	PlanSHA256       string `json:"plan_sha256"`
	PlanBase64       string `json:"plan_base64"`
}

type checkpointPlanRelaunchReceipt struct {
	Version                int    `json:"version"`
	NodeID                 string `json:"node_id"`
	OperationID            string `json:"operation_id"`
	Step                   string `json:"step"`
	CommandID              string `json:"command_id"`
	IdempotencyKey         string `json:"idempotency_key"`
	OriginalEnvelopeSHA256 string `json:"original_envelope_sha256"`
	SigningMaterialSHA256  string `json:"signing_material_sha256"`
	RecoveryEpoch          string `json:"recovery_epoch"`
	AcceleratorID          string `json:"accelerator_id"`
	FencingToken           int64  `json:"fencing_token"`
	TargetID               string `json:"target_id"`
	WorkloadID             string `json:"workload_id"`
	WorkloadRevision       int64  `json:"workload_revision"`
	CatalogID              string `json:"catalog_id"`
	LinkedCatalogID        string `json:"linked_catalog_id,omitempty"`
	CatalogSHA256          string `json:"catalog_sha256"`
	PlanSHA256             string `json:"plan_sha256"`
	PriorReceiptSHA256     string `json:"prior_receipt_sha256"`
	PriorInvocationID      string `json:"prior_invocation_id"`
	AcceptedAt             string `json:"accepted_at,omitempty"`
	InvocationID           string `json:"invocation_id"`
	MainPID                int    `json:"main_pid"`
	CurrentIncarnation     string `json:"current_incarnation"`
	CustodyBindingSHA256   string `json:"custody_binding_sha256"`
	Alias                  string `json:"alias"`
	SignedAt               string `json:"signed_at"`
	Signature              string `json:"signature"`
}

type checkpointPlanBrokerRequest struct {
	Command []byte `json:"command"`
}

type checkpointPlanBrokerResponse struct {
	Receipt []byte `json:"receipt,omitempty"`
	Error   string `json:"error,omitempty"`
	Pending bool   `json:"pending,omitempty"`
}

type checkpointPlanBrokerOperation struct {
	Operation         checkpointPlanRelaunchOperation       `json:"operation"`
	Stage             string                                `json:"stage"`
	VictimAlias       string                                `json:"victim_alias,omitempty"`
	UrgentAlias       string                                `json:"urgent_alias,omitempty"`
	UrgentModelSHA256 string                                `json:"urgent_model_sha256,omitempty"`
	VictimPlanSHA256  string                                `json:"victim_plan_sha256,omitempty"`
	PriorPlanSHA256   string                                `json:"prior_plan_sha256"`
	PriorInvocation   string                                `json:"prior_invocation"`
	CatalogSHA256     string                                `json:"catalog_sha256"`
	PlanSHA256        string                                `json:"plan_sha256"`
	Steps             map[string]checkpointPlanRelaunchStep `json:"steps"`
}

type checkpointPlanBrokerJournal struct {
	Version    int                                      `json:"version"`
	Sequence   uint64                                   `json:"sequence"`
	Operations map[string]checkpointPlanBrokerOperation `json:"operations"`
	Checksum   string                                   `json:"checksum"`
}

func checkpointPlanRelaunchStepForCommand(command string) (string, bool) {
	switch command {
	case checkpointPlanRelaunchUrgentCommand:
		return "urgent_load", true
	case checkpointPlanRelaunchVictimCommand:
		return "victim_reload", true
	default:
		return "", false
	}
}

// A durable published stage proves that no start request has yet been sent.
// Once start_requested is durable, a cold broker cannot distinguish a crash
// immediately before systemctl start from a lost reply or a completed process
// that has since exited; recovery must observe an exact live binding or remain
// pending rather than issuing a second start.
func checkpointPlanRelaunchMayIssueFirstStart(step, stage string) bool {
	if step != "urgent_load" && step != "victim_reload" {
		return false
	}
	return stage == step+"_published"
}

func checkpointPlanRelaunchMayJoinStartedProcess(step, stage string) bool {
	if step != "urgent_load" && step != "victim_reload" {
		return false
	}
	return stage == step+"_start_requested" || stage == step+"_start_accepted"
}

func checkpointPlanRelaunchIsCommand(command string) bool {
	return command == checkpointPlanRelaunchUrgentCommand || command == checkpointPlanRelaunchVictimCommand || command == checkpointPlanRelaunchQueryCommand
}

func checkpointPlanRelaunchFenceKey(accelerator string) string {
	return "plan-relaunch-accelerator:" + accelerator
}

func checkpointPlanRelaunchSigningMaterial(unsigned []byte) []byte {
	return append([]byte("vram-governor-plan-relaunch-root-ack-v1\x00"), unsigned...)
}

func checkpointPlanRelaunchReceiptDigest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func verifyCheckpointPlanRelaunchReceipt(raw []byte, public ed25519.PublicKey, command []byte, secret string) (checkpointPlanRelaunchReceipt, error) {
	var receipt checkpointPlanRelaunchReceipt
	if len(raw) == 0 || len(raw) > 32<<10 || len(public) != ed25519.PublicKeySize || rejectDuplicateJSONKeys(raw) != nil {
		return receipt, errors.New("plan relaunch receipt size or root key is invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&receipt) != nil || receipt.Version != 1 || receipt.MainPID <= 1 || receipt.OperationID == "" || receipt.InvocationID == "" || receipt.CurrentIncarnation == "" || receipt.CustodyBindingSHA256 == "" {
		return receipt, errors.New("plan relaunch receipt is incomplete")
	}
	var trailing any
	if decoder.Decode(&trailing) == nil {
		return receipt, errors.New("plan relaunch receipt has trailing JSON")
	}
	canonical, err := json.Marshal(receipt)
	if err != nil || !bytes.Equal(canonical, raw) {
		return receipt, errors.New("plan relaunch receipt is not canonical")
	}
	signature, err := hex.DecodeString(receipt.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize || hex.EncodeToString(signature) != receipt.Signature {
		return receipt, errors.New("plan relaunch receipt signature is malformed")
	}
	unsigned := receipt
	unsigned.Signature = ""
	unsignedRaw, err := json.Marshal(unsigned)
	if err != nil || !ed25519.Verify(public, checkpointPlanRelaunchSigningMaterial(unsignedRaw), signature) {
		return receipt, errors.New("plan relaunch receipt signature is invalid")
	}
	if rejectDuplicateJSONKeys(command) != nil {
		return receipt, errors.New("plan relaunch original command is malformed")
	}
	var original wsproto.CommandPayload
	if json.Unmarshal(command, &original) != nil || !checkpointPlanRelaunchIsCommand(original.Command) || original.Command == checkpointPlanRelaunchQueryCommand || !wsproto.VerifyCommand(original, []byte(secret)) {
		return receipt, errors.New("plan relaunch original command HMAC is invalid")
	}
	canonicalCommand, err := wsproto.CanonicalCommandEnvelope(original)
	material, materialErr := wsproto.CommandSigningMaterialForPlanRelaunch(original)
	if err != nil || materialErr != nil || !bytes.Equal(canonicalCommand, command) || receipt.SigningMaterialSHA256 != checkpointPlanRelaunchReceiptDigest(material) {
		return receipt, errors.New("plan relaunch original command is not canonical or its signing digest differs")
	}
	if original.ID != receipt.CommandID || original.IdempotencyKey != receipt.IdempotencyKey || original.NodeID != receipt.NodeID || original.Args["operation_id"] != receipt.OperationID || original.Args["recovery_epoch"] != receipt.RecoveryEpoch || original.Args["accelerator_id"] != receipt.AcceleratorID || original.Args["target_id"] != receipt.TargetID || original.Args["workload_id"] != receipt.WorkloadID || int64FromArg(original.Args["workload_revision"]) != receipt.WorkloadRevision || int64FromArg(original.Args["fencing_token"]) != receipt.FencingToken || original.Args["catalog_id"] != receipt.CatalogID || receipt.OriginalEnvelopeSHA256 != checkpointPlanRelaunchReceiptDigest(command) {
		return receipt, errors.New("plan relaunch receipt does not bind the original command")
	}
	if original.Command == checkpointPlanRelaunchUrgentCommand && original.Args["linked_catalog_id"] != receipt.LinkedCatalogID {
		return receipt, errors.New("plan relaunch receipt does not bind the linked victim catalog")
	}
	if original.Command == checkpointPlanRelaunchVictimCommand && receipt.LinkedCatalogID != "" {
		return receipt, errors.New("victim reload receipt contains an unexpected linked catalog")
	}
	if receipt.Step != "urgent_load" && receipt.Step != "victim_reload" || receipt.PlanSHA256 == "" || receipt.CatalogSHA256 == "" || receipt.PriorReceiptSHA256 != fmt.Sprint(original.Args["prior_receipt_sha256"]) {
		return receipt, errors.New("plan relaunch receipt linkage is incomplete")
	}
	var acceptedAt time.Time
	var acceptedErr error
	if receipt.AcceptedAt != "" {
		acceptedAt, acceptedErr = time.Parse(time.RFC3339Nano, receipt.AcceptedAt)
	}
	signedAt, err := time.Parse(time.RFC3339Nano, receipt.SignedAt)
	if acceptedErr != nil || err != nil || (receipt.AcceptedAt == "" && signedAt.After(original.ExpiresAt)) || (receipt.AcceptedAt != "" && (acceptedAt.Before(original.IssuedAt) || acceptedAt.After(original.ExpiresAt) || signedAt.Before(acceptedAt))) {
		return receipt, errors.New("plan relaunch receipt timestamp is malformed")
	}
	if !checkpointSHA256RE.MatchString(receipt.CatalogSHA256) || !checkpointSHA256RE.MatchString(receipt.PlanSHA256) || !checkpointSHA256RE.MatchString(receipt.CurrentIncarnation) || !checkpointSHA256RE.MatchString(receipt.CustodyBindingSHA256) || receipt.Alias == "" || receipt.PriorInvocationID == "" || receipt.InvocationID == receipt.PriorInvocationID {
		return receipt, errors.New("plan relaunch receipt identity or digest is invalid")
	}
	return receipt, nil
}

func decodeCheckpointPlanCatalog(raw []byte, fixturePaths ...checkpointPlanBrokerPaths) (checkpointPlanCatalog, map[string]checkpointPlanCatalogEntry, error) {
	var catalog checkpointPlanCatalog
	if len(raw) == 0 || len(raw) > checkpointPlanCatalogMaxBytes || rejectDuplicateJSONKeys(raw) != nil {
		return catalog, nil, errors.New("root plan catalog is malformed or oversized")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&catalog) != nil || catalog.Version != 1 || len(catalog.Entries) == 0 || len(catalog.Entries) > 256 {
		return catalog, nil, errors.New("root plan catalog schema is invalid")
	}
	var trailing any
	if decoder.Decode(&trailing) == nil {
		return catalog, nil, errors.New("root plan catalog has trailing JSON")
	}
	canonical, err := json.Marshal(catalog)
	if err != nil || !bytes.Equal(canonical, raw) {
		return catalog, nil, errors.New("root plan catalog is not canonical")
	}
	entries := make(map[string]checkpointPlanCatalogEntry, len(catalog.Entries))
	for _, entry := range catalog.Entries {
		if !canonicalPlanCatalogToken(entry.CatalogID) || !canonicalPlanCatalogToken(entry.ModelID) || !canonicalPlanCatalogToken(entry.WorkloadID) || entry.WorkloadRevision <= 0 || len(entry.PlanSHA256) != 64 || strings.ToLower(entry.PlanSHA256) != entry.PlanSHA256 {
			return catalog, nil, errors.New("root plan catalog entry identity is invalid")
		}
		if _, duplicate := entries[entry.CatalogID]; duplicate {
			return catalog, nil, errors.New("root plan catalog contains a duplicate catalog id")
		}
		planBytes, err := base64.StdEncoding.DecodeString(entry.PlanBase64)
		if err != nil || base64.StdEncoding.EncodeToString(planBytes) != entry.PlanBase64 || len(planBytes) == 0 || len(planBytes) > checkpointLaunchPlanMaxBytes || checkpointPlanRelaunchReceiptDigest(planBytes) != entry.PlanSHA256 {
			return catalog, nil, errors.New("root plan catalog plan bytes do not match their digest")
		}
		plan, err := ParseCheckpointLaunchPlan(planBytes)
		paths := fixedCheckpointPlanBrokerPaths()
		if len(fixturePaths) > 0 {
			paths = fixturePaths[0]
		}
		if err != nil || plan.Version != checkpointLaunchPlanVersion2 || validateCheckpointPlanBrokerPlan(paths, plan) != nil {
			return catalog, nil, errors.New("root plan catalog contains an unsupported fixed plan")
		}
		entries[entry.CatalogID] = entry
	}
	return catalog, entries, nil
}

func validateCheckpointPlanBrokerPlan(paths checkpointPlanBrokerPaths, plan CheckpointLaunchPlan) error {
	if plan.Version != checkpointLaunchPlanVersion2 {
		return errors.New("plan broker requires a v2 launch plan")
	}
	if !paths.privateFixture {
		return validateCheckpointFixedPlan(plan)
	}
	if !checkpointPlanBrokerPrivateFixturePathSet(paths) || plan.Custody.Root != filepath.Join(paths.fixtureRoot, "var", "custody") || plan.SnapshotRoot != filepath.Join(paths.fixtureRoot, "var", "snapshots") || filepath.Dir(plan.Model.Path) != filepath.Join(paths.fixtureRoot, "models") || filepath.Base(plan.Model.Path) != "victim.gguf" && filepath.Base(plan.Model.Path) != "urgent.gguf" || plan.Executable.Path != filepath.Join(paths.fixtureRoot, "worker") {
		return errors.New("private CPU fixture plan escapes its exact local roots")
	}
	return nil
}

func canonicalPlanCatalogToken(value string) bool {
	if value == "" || len(value) > 128 || strings.TrimSpace(value) != value || strings.ContainsAny(value, "/\\\x00\r\n\t") {
		return false
	}
	for _, r := range value {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("._:-", r)) {
			return false
		}
	}
	return true
}
