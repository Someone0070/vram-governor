package nodeagent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	goruntime "runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"vram-governor/internal/domain"
	checkpointRuntime "vram-governor/internal/runtime"
	"vram-governor/internal/runtime/llamacpp"
	"vram-governor/internal/safefile"
	"vram-governor/internal/wsproto"
)

type commandProcessor struct {
	cfg *Config
	log *slog.Logger
	// handleMu serializes independent signed command requests without being
	// held by the processor's state mutex during a runtime call.  A managed
	// checkpoint driver can synchronously re-enter Handle for the signed
	// command that implements one phase of a refresh; the context marker below
	// makes that deliberate same-owner re-entry safe while other callers wait.
	handleMu               sync.Mutex
	mu                     sync.Mutex
	results                map[string]wsproto.CommandResultPayload
	commandFingerprints    map[string]string
	fences                 map[string]int64
	pending                map[string]pendingCommand
	inflight               map[string]bool
	checkpointSlots        map[string]string
	checkpointDrivers      map[string]checkpointRuntime.SlotCheckpointDriver
	checkpointPhases       map[string]checkpointPhaseState
	ownedStopOperations    map[string]ownedStopOperationState
	planRelaunchOperations map[string]checkpointPlanRelaunchOperation
	stateBlocked           bool
	stateBlockReason       string
	recoveryEpoch          string
	recoveryGeneration     uint64
	usedRecoveryEpochs     map[string]struct{}
	recoveryAnchorHash     string
	journalSequence        uint64
	journalHash            string
	journalPrevHash        string
	recoveryMarker         *recoveryMarkerState
	inRecovery             bool
	initError              error
	ready                  atomic.Bool
	// externalWork counts command paths that have crossed (or are about to
	// cross) the runtime boundary.  A refresh_capabilities proof deliberately
	// drops p.mu while it performs discovery and re-enters Handle for each
	// signed phase; the outer refresh must keep this count non-zero for the
	// whole interval so a reentrant phase cannot publish a stale Ready=true.
	externalWork            atomic.Int32
	warmRAM                 *WarmRAMManager
	persistedWarm           []WarmRAMManifest
	runProfileCommand       func(context.Context, []string) error
	syncDir                 func(string) error
	readState               func(string) ([]byte, error)
	renameState             func(string, string) error
	mkdirAll                func(string, os.FileMode) error
	createTemp              func(string, string) (commandStateFile, error)
	removeState             func(string) error
	afterReconciledJournal  func() error
	markerMkdirAll          func(string, os.FileMode) error
	markerCreateTemp        func(string, string) (commandStateFile, error)
	markerRename            func(string, string) error
	markerSyncDir           func(string) error
	strictResidencyEnvelope bool
	ownedStopPaths          checkpointOwnedStopPaths
	ownedStopPlanPath       string
	openOwnedStopPlan       func(context.Context, string) (*PinnedCheckpointLaunchPlan, error)
	planBrokerPaths         checkpointPlanBrokerPaths
	// onExternalWork is a narrow deterministic test seam. Production leaves it
	// nil; tests use it to hold a proof callback at the live boundary and
	// observe the heartbeat readiness contract without replacing the runtime.
	onExternalWork func(wsproto.CommandPayload)
}

type commandProcessorContextKey struct{}

func commandProcessorReentry(ctx context.Context, processor *commandProcessor) bool {
	owner, _ := ctx.Value(commandProcessorContextKey{}).(*commandProcessor)
	return owner == processor
}

type commandStateFile interface {
	Name() string
	Chmod(os.FileMode) error
	Write([]byte) (int, error)
	Sync() error
	Close() error
}

type pendingCommand struct {
	TargetID, Model, Command                  string
	Token                                     int64
	CommandID, IdempotencyKey, Fingerprint    string
	OriginalEnvelope                          []byte `json:"original_envelope,omitempty"`
	SigningMaterialSHA256                     string `json:"signing_material_sha256,omitempty"`
	PinnedRootStopPublicKey                   []byte `json:"pinned_root_stop_public_key,omitempty"`
	StopRecoveryEpoch                         string `json:"stop_recovery_epoch,omitempty"`
	StopReceiptSHA256                         string `json:"stop_receipt_sha256,omitempty"`
	PlanRelaunchSigningMaterialSHA256         string `json:"plan_relaunch_signing_material_sha256,omitempty"`
	PinnedPlanBrokerPublicKey                 []byte `json:"pinned_plan_broker_public_key,omitempty"`
	RuntimeIdentity                           string `json:"runtime_identity,omitempty"`
	ManifestJSON                              string
	Path, FileFingerprint, RuntimeFingerprint string
	ActiveReferences                          int
	Protected                                 bool
}

type checkpointPhaseState struct {
	OperationID                string `json:"operation_id"`
	OwnerID                    string `json:"owner_id"`
	WorkloadID                 string `json:"workload_id"`
	TargetID                   string `json:"target_id"`
	AcceleratorID              string `json:"accelerator_id"`
	Generation                 uint64 `json:"generation"`
	Fence                      int64  `json:"fence"`
	SlotID                     int    `json:"slot_id"`
	Phase                      int    `json:"phase"`
	Action                     string `json:"action"`
	RuntimeIdentity            string `json:"runtime_identity,omitempty"`
	ModelFingerprint           string `json:"model_fingerprint,omitempty"`
	ProfileFingerprint         string `json:"profile_fingerprint,omitempty"`
	ContextFingerprint         string `json:"context_fingerprint,omitempty"`
	SnapshotName               string `json:"snapshot_name,omitempty"`
	SnapshotDigest             string `json:"snapshot_digest,omitempty"`
	ConversationID             string `json:"conversation_id,omitempty"`
	ContinuationConversationID string `json:"continuation_conversation_id,omitempty"`
}

type ownedStopStepState struct {
	CommandID               string `json:"command_id"`
	IdempotencyKey          string `json:"idempotency_key"`
	EnvelopeSHA256          string `json:"envelope_sha256"`
	PinnedRootStopPublicKey []byte `json:"pinned_root_stop_public_key,omitempty"`
	Status                  string `json:"status"`
	ReceiptSHA256           string `json:"receipt_sha256,omitempty"`
}

type ownedStopOperationState struct {
	OperationID      string                        `json:"operation_id"`
	AcceleratorID    string                        `json:"accelerator_id"`
	Fence            int64                         `json:"fence"`
	RecoveryEpoch    string                        `json:"recovery_epoch"`
	UsedOperationIDs map[string]bool               `json:"used_operation_ids"`
	Steps            map[string]ownedStopStepState `json:"steps"`
}

// pendingOperationManifest is the durable binding for a signed operation.
// ManifestJSON intentionally carries both the normalized argument map (which
// is covered by Fingerprint) and the fields used by reconciliation. Keeping
// the envelope explicit prevents a sparse target/model-only row from being
// mistaken for the original command after a restart.
type pendingOperationManifest struct {
	SchemaVersion      int            `json:"schema_version"`
	Action             string         `json:"action"`
	NodeID             string         `json:"node_id"`
	CommandID          string         `json:"command_id"`
	IdempotencyKey     string         `json:"idempotency_key"`
	Fingerprint        string         `json:"fingerprint"`
	TargetKind         string         `json:"target_kind"`
	TargetID           string         `json:"target_id"`
	Model              string         `json:"model"`
	RuntimeIdentity    string         `json:"runtime_identity"`
	CapabilityVersion  string         `json:"capability_version"`
	CapabilityRevision string         `json:"capability_revision"`
	ExpectedTier       string         `json:"expected_tier"`
	FencingToken       int64          `json:"fencing_token"`
	ActiveReferences   int            `json:"active_references"`
	Protected          bool           `json:"protected"`
	Args               map[string]any `json:"args"`
}

const pendingManifestVersion = 1

const commandStateVersion = 1

type commandStatePayload struct {
	Results                map[string]wsproto.CommandResultPayload    `json:"results"`
	CommandFingerprints    map[string]string                          `json:"command_fingerprints"`
	Fences                 map[string]int64                           `json:"fences"`
	Pending                map[string]pendingCommand                  `json:"pending"`
	Warm                   []WarmRAMManifest                          `json:"warm,omitempty"`
	BlockReason            string                                     `json:"block_reason,omitempty"`
	RecoveryEpoch          string                                     `json:"recovery_epoch,omitempty"`
	RecoveryGeneration     uint64                                     `json:"recovery_generation,omitempty"`
	UsedRecoveryEpochs     []string                                   `json:"used_recovery_epochs,omitempty"`
	RecoveryAnchorHash     string                                     `json:"recovery_anchor_hash,omitempty"`
	JournalSequence        uint64                                     `json:"journal_sequence,omitempty"`
	JournalPrevHash        string                                     `json:"journal_prev_hash,omitempty"`
	CheckpointPhases       map[string]checkpointPhaseState            `json:"checkpoint_phases,omitempty"`
	OwnedStopOperations    map[string]ownedStopOperationState         `json:"owned_stop_operations,omitempty"`
	PlanRelaunchOperations map[string]checkpointPlanRelaunchOperation `json:"plan_relaunch_operations,omitempty"`
}

const (
	blockReasonWarmTransient = "warm_reconciliation"
	blockReasonCorrupt       = "corrupt_state"
	blockReasonRead          = "state_read"
	blockReasonQuarantine    = "quarantine_failure"
	blockReasonDurability    = "durability_failure"
)

const recoveryMarkerVersion = 1
const recoveryMarkerPhasePrepared = "prepared"
const recoveryMarkerPhaseQuarantined = "quarantined"
const recoveryMarkerPhaseRecoveryPrepared = "recovery_prepared"
const recoveryMarkerPhaseRecoveryCommitted = "recovery_committed"

var errRecoveryMarkerNeedsAdmin = errors.New("recovery marker requires explicit admin recovery")

type recoveryFileIdentity struct {
	Exists bool   `json:"exists"`
	Size   int64  `json:"size,omitempty"`
	Mtime  int64  `json:"mtime,omitempty"`
	Dev    uint64 `json:"dev,omitempty"`
	Ino    uint64 `json:"ino,omitempty"`
}

type recoveryMarkerState struct {
	Phase               string               `json:"phase"`
	Version             int                  `json:"version"`
	Reason              string               `json:"reason"`
	Timestamp           time.Time            `json:"timestamp"`
	RecoveryEpoch       string               `json:"recovery_epoch,omitempty"`
	RecoveryEpochHash   string               `json:"recovery_epoch_hash,omitempty"`
	RecoveryGeneration  uint64               `json:"recovery_generation,omitempty"`
	RecoveryAnchorHash  string               `json:"recovery_anchor_hash,omitempty"`
	TargetStateChecksum string               `json:"target_state_checksum,omitempty"`
	FenceHighWater      int64                `json:"fence_high_water,omitempty"`
	ResultHighWater     int                  `json:"result_high_water,omitempty"`
	OriginalPathHash    string               `json:"original_path_hash"`
	QuarantinePathHash  string               `json:"quarantine_path_hash"`
	Original            recoveryFileIdentity `json:"original"`
	Quarantine          recoveryFileIdentity `json:"quarantine"`
}

type recoveryMarkerEnvelope struct {
	Version  int                 `json:"version"`
	Checksum string              `json:"checksum"`
	State    recoveryMarkerState `json:"state"`
}

type commandStateJournalRecord struct {
	Sequence  uint64 `json:"sequence"`
	PrevHash  string `json:"prev_hash,omitempty"`
	StateHash string `json:"state_hash"`
	Phase     string `json:"phase"`
	HMAC      string `json:"hmac"`
}

func blockReasonRank(reason string) int {
	switch reason {
	case blockReasonQuarantine, blockReasonDurability:
		return 4
	case blockReasonCorrupt, blockReasonRead:
		return 3
	case blockReasonWarmTransient:
		return 1
	default:
		return 2
	}
}

func (p *commandProcessor) recoveryMarkerPath() string { return p.cfg.CommandStatePath + ".recovery" }

func recoveryPathHash(path string) string {
	sum := sha256.Sum256([]byte(filepath.Clean(path)))
	return hex.EncodeToString(sum[:])
}

func recoveryEpochHash(epoch string) string {
	sum := sha256.Sum256([]byte(epoch))
	return hex.EncodeToString(sum[:])
}

func recoveryAnchorHash(previous string, generation uint64, epochHash string) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s|%d|%s", previous, generation, epochHash)))
	return hex.EncodeToString(sum[:])
}

func recoveryIdentity(path string) recoveryFileIdentity {
	info, err := os.Stat(path)
	if err != nil {
		return recoveryFileIdentity{}
	}
	return recoveryFileIdentity{Exists: true, Size: info.Size(), Mtime: info.ModTime().UnixNano()}
}

func (p *commandProcessor) block(reason string) {
	if reason == "" {
		return
	}
	// A reason of equal rank cannot replace an existing reason.  This makes
	// precedence deterministic and prevents a later transient error from
	// rewriting a stronger durable block.
	if !p.stateBlocked || blockReasonRank(reason) > blockReasonRank(p.stateBlockReason) {
		p.stateBlockReason = reason
	}
	p.stateBlocked = true
	p.ready.Store(false)
}

func (p *commandProcessor) writeRecoveryMarker(reason, phase string, original, quarantine recoveryFileIdentity) error {
	return p.writeRecoveryMarkerTarget(reason, phase, original, quarantine, p.stateFileChecksum(), p.recoveryGeneration, p.recoveryEpoch)
}

func (p *commandProcessor) writeRecoveryMarkerTarget(reason, phase string, original, quarantine recoveryFileIdentity, targetChecksum string, generation uint64, epoch string) error {
	if p.cfg.CommandStatePath == "" {
		return errors.New("recovery marker path is unavailable")
	}
	if phase != recoveryMarkerPhasePrepared && phase != recoveryMarkerPhaseQuarantined && phase != recoveryMarkerPhaseRecoveryPrepared && phase != recoveryMarkerPhaseRecoveryCommitted {
		return errors.New("recovery marker phase is invalid")
	}
	var fenceHighWater int64
	for _, fence := range p.fences {
		if fence > fenceHighWater {
			fenceHighWater = fence
		}
	}
	state := recoveryMarkerState{Phase: phase, Version: recoveryMarkerVersion, Reason: reason, Timestamp: time.Now().UTC(), RecoveryEpoch: epoch, RecoveryEpochHash: recoveryEpochHash(epoch), RecoveryGeneration: generation, RecoveryAnchorHash: p.recoveryAnchorHash, TargetStateChecksum: targetChecksum, FenceHighWater: fenceHighWater, ResultHighWater: len(p.results), OriginalPathHash: recoveryPathHash(p.cfg.CommandStatePath), QuarantinePathHash: recoveryPathHash(p.cfg.CommandStatePath + ".corrupt"), Original: original, Quarantine: quarantine}
	encoded, err := json.Marshal(state)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(encoded)
	body, err := json.MarshalIndent(recoveryMarkerEnvelope{Version: recoveryMarkerVersion, Checksum: hex.EncodeToString(sum[:]), State: state}, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(p.recoveryMarkerPath())
	mkdirAll := p.markerMkdirAll
	if mkdirAll == nil {
		mkdirAll = os.MkdirAll
	}
	if err := mkdirAll(dir, 0o700); err != nil {
		return err
	}
	createTemp := p.markerCreateTemp
	if createTemp == nil {
		createTemp = func(dir, pattern string) (commandStateFile, error) { return os.CreateTemp(dir, pattern) }
	}
	tmp, err := createTemp(dir, ".command-recovery-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if written, err := tmp.Write(body); err != nil {
		_ = tmp.Close()
		return err
	} else if written != len(body) {
		_ = tmp.Close()
		return errors.New("recovery marker write was incomplete")
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	rename := p.markerRename
	if rename == nil {
		rename = os.Rename
	}
	if err := rename(tmpName, p.recoveryMarkerPath()); err != nil {
		return err
	}
	syncDir := p.markerSyncDir
	if syncDir == nil {
		syncDir = syncCommandStateDir
	}
	return syncDir(dir)
}

func (p *commandProcessor) stateFileChecksum() string {
	if p.cfg == nil || p.cfg.CommandStatePath == "" {
		return ""
	}
	body, err := os.ReadFile(p.cfg.CommandStatePath)
	if err != nil {
		return ""
	}
	var envelope commandStateEnvelope
	if json.Unmarshal(body, &envelope) != nil || envelope.Version != commandStateVersion {
		return ""
	}
	return envelope.Checksum
}

func (p *commandProcessor) journalPath() string { return p.cfg.CommandStatePath + ".journal" }

func (p *commandProcessor) journalMAC(record commandStateJournalRecord) string {
	record.HMAC = ""
	body, _ := json.Marshal(record)
	mac := hmac.New(sha256.New, []byte("node-command-state-journal-v1:"+p.cfg.CommandSigningSecret))
	_, _ = mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

func journalDigest(record commandStateJournalRecord) string {
	record.HMAC = ""
	body, _ := json.Marshal(record)
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func (p *commandProcessor) appendJournal(record commandStateJournalRecord) error {
	record.HMAC = p.journalMAC(record)
	body, err := json.Marshal(record)
	if err != nil {
		return err
	}
	body = append(body, '\n')
	dir := filepath.Dir(p.journalPath())
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	file, err := os.OpenFile(p.journalPath(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	if written, writeErr := file.Write(body); writeErr != nil || written != len(body) {
		_ = file.Close()
		if writeErr != nil {
			return writeErr
		}
		return errors.New("state journal write was incomplete")
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := syncCommandStateDir(dir); err != nil {
		return err
	}
	return nil
}

func (p *commandProcessor) validateJournal(state commandStatePayload, stateHash string) error {
	if state.JournalSequence == 0 {
		return nil
	}
	body, err := os.ReadFile(p.journalPath())
	if err != nil {
		return errors.New("state journal is unavailable")
	}
	var expectedPrev string
	var prepared *commandStateJournalRecord
	var committed *commandStateJournalRecord
	for _, line := range bytes.Split(body, []byte{'\n'}) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var record commandStateJournalRecord
		if json.Unmarshal(line, &record) != nil || record.Sequence == 0 || record.StateHash == "" || (record.Phase != "prepared" && record.Phase != "committed") || record.HMAC == "" || !hmac.Equal([]byte(record.HMAC), []byte(p.journalMAC(record))) {
			return errors.New("state journal authentication failed")
		}
		if record.Phase == "prepared" {
			if record.PrevHash != expectedPrev {
				return errors.New("state journal chain is invalid")
			}
			prepared = &record
			continue
		}
		if record.PrevHash != expectedPrev || prepared == nil || prepared.Sequence != record.Sequence || prepared.StateHash != record.StateHash {
			return errors.New("state journal commit is invalid")
		}
		committed = &record
		expectedPrev = journalDigest(record)
		prepared = nil
	}
	if prepared != nil {
		if prepared.Sequence == state.JournalSequence && prepared.StateHash == stateHash && state.JournalPrevHash == prepared.PrevHash {
			if err := p.appendJournal(commandStateJournalRecord{Sequence: prepared.Sequence, PrevHash: prepared.PrevHash, StateHash: prepared.StateHash, Phase: "committed"}); err != nil {
				return errors.New("prepared state journal could not be finalized")
			}
			return nil
		}
		return errors.New("state journal has an unresolved prepared record")
	}
	if committed == nil || committed.Sequence != state.JournalSequence || committed.StateHash != stateHash || state.JournalPrevHash != committed.PrevHash {
		// A durable prepared record may be continued if the primary already
		// contains its target; otherwise this is a rollback or torn write.
		return errors.New("state journal does not anchor the primary")
	}
	return nil
}

func (p *commandProcessor) latestJournalHash() (string, error) {
	body, err := os.ReadFile(p.journalPath())
	if err != nil {
		return "", err
	}
	latest := ""
	for _, line := range bytes.Split(body, []byte{'\n'}) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var record commandStateJournalRecord
		if err := json.Unmarshal(line, &record); err != nil {
			return "", err
		}
		if record.Phase == "committed" {
			latest = journalDigest(record)
		}
	}
	if latest == "" {
		return "", errors.New("state journal has no committed record")
	}
	return latest, nil
}

func (p *commandProcessor) committedRecoveryStateValid(marker recoveryMarkerState) bool {
	body, err := os.ReadFile(p.cfg.CommandStatePath)
	if err != nil {
		return false
	}
	var envelope commandStateEnvelope
	if json.Unmarshal(body, &envelope) != nil || envelope.Version != commandStateVersion || envelope.Checksum == "" {
		return false
	}
	encoded, err := json.Marshal(envelope.State)
	if err != nil {
		return false
	}
	sum := sha256.Sum256(encoded)
	if !strings.EqualFold(envelope.Checksum, hex.EncodeToString(sum[:])) || envelope.State.RecoveryGeneration < marker.RecoveryGeneration || envelope.State.RecoveryAnchorHash != marker.RecoveryAnchorHash {
		return false
	}
	if marker.RecoveryEpochHash != "" {
		found := false
		for _, epochHash := range envelope.State.UsedRecoveryEpochs {
			if epochHash == marker.RecoveryEpochHash {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	var fenceHighWater int64
	for _, fence := range envelope.State.Fences {
		if fence > fenceHighWater {
			fenceHighWater = fence
		}
	}
	return fenceHighWater >= marker.FenceHighWater && len(envelope.State.Results) >= marker.ResultHighWater
}

func (p *commandProcessor) loadRecoveryMarker() error {
	if p.cfg.CommandStatePath == "" {
		return nil
	}
	p.recoveryMarker = nil
	body, err := os.ReadFile(p.recoveryMarkerPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		p.block(blockReasonQuarantine)
		return err
	}
	var envelope recoveryMarkerEnvelope
	if json.Unmarshal(body, &envelope) != nil || envelope.Version != recoveryMarkerVersion || envelope.Checksum == "" || envelope.State.Version != recoveryMarkerVersion || envelope.State.Reason == "" || (envelope.State.Reason != blockReasonWarmTransient && envelope.State.Reason != blockReasonCorrupt && envelope.State.Reason != blockReasonRead && envelope.State.Reason != blockReasonQuarantine && envelope.State.Reason != blockReasonDurability) || (envelope.State.Phase != recoveryMarkerPhasePrepared && envelope.State.Phase != recoveryMarkerPhaseQuarantined && envelope.State.Phase != recoveryMarkerPhaseRecoveryPrepared && envelope.State.Phase != recoveryMarkerPhaseRecoveryCommitted) || envelope.State.OriginalPathHash != recoveryPathHash(p.cfg.CommandStatePath) || envelope.State.QuarantinePathHash != recoveryPathHash(p.cfg.CommandStatePath+".corrupt") {
		p.block(blockReasonQuarantine)
		return errors.New("recovery marker is invalid")
	}
	encoded, err := json.Marshal(envelope.State)
	if err != nil {
		p.block(blockReasonQuarantine)
		return err
	}
	sum := sha256.Sum256(encoded)
	if !strings.EqualFold(envelope.Checksum, hex.EncodeToString(sum[:])) {
		p.block(blockReasonQuarantine)
		return errors.New("recovery marker checksum is invalid")
	}
	currentOriginal := recoveryIdentity(p.cfg.CommandStatePath)
	currentQuarantine := recoveryIdentity(p.cfg.CommandStatePath + ".corrupt")
	// A marker is bound to both file identities.  A prepared marker is valid
	// before the rename; a quarantined marker is valid after it, or for a
	// save failure where the old primary remains intact and no quarantine was
	// needed.  Any other identity change is treated as tampering/corruption.
	identityOK := false
	switch envelope.State.Phase {
	case recoveryMarkerPhasePrepared, recoveryMarkerPhaseRecoveryPrepared:
		identityOK = currentOriginal == envelope.State.Original && currentQuarantine == envelope.State.Quarantine
	case recoveryMarkerPhaseQuarantined, recoveryMarkerPhaseRecoveryCommitted:
		identityOK = (currentQuarantine == envelope.State.Quarantine && currentOriginal == (recoveryFileIdentity{})) || (currentOriginal == envelope.State.Original && currentQuarantine == envelope.State.Quarantine)
	}
	if envelope.State.Phase == recoveryMarkerPhaseRecoveryPrepared && envelope.State.TargetStateChecksum != "" && envelope.State.TargetStateChecksum == p.stateFileChecksum() && currentQuarantine == envelope.State.Quarantine {
		// The primary is expected to have a new identity after the prepared
		// recovery transaction replaces it; the target checksum is the binding
		// in this phase.
		identityOK = true
	}
	if envelope.State.Phase == recoveryMarkerPhaseRecoveryCommitted && p.committedRecoveryStateValid(envelope.State) {
		identityOK = true
	}
	if !identityOK {
		p.block(blockReasonQuarantine)
		return errors.New("quarantine identity changed")
	}
	if envelope.State.RecoveryEpoch != "" && envelope.State.RecoveryEpochHash != "" && envelope.State.RecoveryEpochHash != recoveryEpochHash(envelope.State.RecoveryEpoch) {
		p.block(blockReasonQuarantine)
		return errors.New("recovery epoch hash is invalid")
	}
	p.recoveryMarker = &envelope.State
	if envelope.State.Phase != recoveryMarkerPhaseRecoveryPrepared {
		if envelope.State.RecoveryGeneration > p.recoveryGeneration {
			p.recoveryGeneration = envelope.State.RecoveryGeneration
		}
		if envelope.State.RecoveryAnchorHash != "" {
			p.recoveryAnchorHash = envelope.State.RecoveryAnchorHash
		}
		if envelope.State.RecoveryEpoch != "" {
			p.recoveryEpoch = envelope.State.RecoveryEpoch
		}
		if envelope.State.RecoveryEpochHash != "" {
			if p.usedRecoveryEpochs == nil {
				p.usedRecoveryEpochs = make(map[string]struct{})
			}
			p.usedRecoveryEpochs[envelope.State.RecoveryEpochHash] = struct{}{}
		}
	}
	if envelope.State.Phase == recoveryMarkerPhaseRecoveryCommitted && p.committedRecoveryStateValid(envelope.State) {
		// A committed marker is retained as an audit record. A later valid
		// primary state may have a different inode/checksum after normal saves;
		// the recovery generation/epoch anchor is the durable binding.
		return nil
	}
	p.block(envelope.State.Reason)
	return errRecoveryMarkerNeedsAdmin
}

func (p *commandProcessor) clearWarmBlockIfClean(unresolved bool) {
	if unresolved {
		p.block(blockReasonWarmTransient)
		return
	}
	if p.stateBlockReason == blockReasonWarmTransient {
		p.stateBlocked = false
		p.stateBlockReason = ""
	}
}

type commandStateEnvelope struct {
	Version  int                 `json:"version"`
	Checksum string              `json:"checksum"`
	State    commandStatePayload `json:"state"`
}

func newCommandProcessor(cfg *Config, log *slog.Logger, strict ...bool) *commandProcessor {
	policy := WarmRAMPolicy{AllowedRoots: append([]string(nil), cfg.WarmRAM.ModelRoots...), RAMTotalBytes: cfg.WarmRAM.RAMTotalBytes, RAMReserveBytes: cfg.WarmRAM.RAMReserveBytes, RAMHardCapBytes: cfg.WarmRAM.RAMHardCapBytes, MaxWarmBytes: cfg.WarmRAM.MaxWarmBytes, MemlockLimitBytes: cfg.WarmRAM.MemlockLimitBytes, CgroupLimitBytes: cfg.WarmRAM.CgroupLimitBytes, UnifiedMemory: cfg.WarmRAM.UnifiedMemory, UnifiedMemoryBytes: cfg.WarmRAM.UnifiedMemoryBytes, PressureRefusalPercent: cfg.WarmRAM.PressureRefusalPercent, MemInfoPath: cfg.WarmRAM.MemInfoPath, PressurePath: cfg.WarmRAM.PressurePath, CgroupCurrentPath: cfg.WarmRAM.CgroupCurrentPath, CgroupMaxPath: cfg.WarmRAM.CgroupMaxPath, CgroupEventsPath: cfg.WarmRAM.CgroupEventsPath, OOMEventsPath: cfg.WarmRAM.OOMEventsPath}
	// The configured generation is a proposed startup transition, not the
	// persisted high-water mark. Load durable state first so a higher config
	// generation can be compared against the actual prior generation.
	processor := &commandProcessor{cfg: cfg, log: log, strictResidencyEnvelope: len(strict) > 0 && strict[0], usedRecoveryEpochs: make(map[string]struct{}), results: make(map[string]wsproto.CommandResultPayload), commandFingerprints: make(map[string]string), fences: make(map[string]int64), pending: make(map[string]pendingCommand), inflight: make(map[string]bool, 1), checkpointSlots: make(map[string]string), checkpointDrivers: make(map[string]checkpointRuntime.SlotCheckpointDriver), checkpointPhases: make(map[string]checkpointPhaseState), ownedStopOperations: make(map[string]ownedStopOperationState), planRelaunchOperations: make(map[string]checkpointPlanRelaunchOperation), warmRAM: NewWarmRAMManager(policy), runProfileCommand: executeFixedProfileCommand, syncDir: syncCommandStateDir, readState: os.ReadFile, renameState: os.Rename, mkdirAll: os.MkdirAll, createTemp: func(dir, pattern string) (commandStateFile, error) { return os.CreateTemp(dir, pattern) }, removeState: os.Remove, markerMkdirAll: os.MkdirAll, markerCreateTemp: func(dir, pattern string) (commandStateFile, error) { return os.CreateTemp(dir, pattern) }, markerRename: os.Rename, markerSyncDir: syncCommandStateDir}
	for _, server := range cfg.LlamaCPP.Servers {
		processor.checkpointDrivers[server.ID] = llamacpp.NewEndpointDriver(server.Endpoint, cfg.Checkpoint.Root)
	}
	processor.load()
	processor.rebuildCheckpointSlotOwners()
	processor.finalizePreparedRecovery()
	processor.startupRecovery()
	if processor.initError == nil && cfg.CommandRecoveryGeneration > 0 && processor.stateBlocked && processor.recoveryMarker == nil {
		processor.initError = errors.New("startup recovery state is invalid")
	}
	processor.restoreWarmManifests()
	processor.refreshReady()
	return processor
}

func (p *commandProcessor) rebuildCheckpointSlotOwners() {
	p.checkpointSlots = make(map[string]string)
	// The phase journal is authoritative.  Results retain every historical
	// idempotency attempt, so rebuilding ownership by simply iterating result
	// rows can resurrect a slot that a later release already freed.  Start with
	// the latest durable state per operation and only use legacy result rows for
	// operations that predate checkpoint_phases persistence.
	latest := make(map[string]checkpointPhaseState, len(p.checkpointPhases))
	for operation, state := range p.checkpointPhases {
		if strings.TrimSpace(operation) == "" || state.OperationID == "" {
			continue
		}
		latest[operation] = state
	}
	install := func(operation string, state checkpointPhaseState) {
		if operation == "" || state.SlotID < 0 || state.Action == "release" || state.Phase <= 0 {
			return
		}
		key := state.TargetID + ":" + strconv.Itoa(state.SlotID)
		if prior, exists := p.checkpointSlots[key]; exists && prior != operation {
			// The higher durable fence owns a reused slot.  Equal-fence conflicts
			// remain fenced by authorizeCheckpointPhase's complete phase scan;
			// retain the deterministic lexical owner here until that check runs.
			priorState := latest[prior]
			if priorState.Fence > state.Fence || (priorState.Fence == state.Fence && prior < operation) {
				return
			}
		}
		p.checkpointSlots[key] = operation
	}
	for operation, state := range latest {
		install(operation, state)
	}
	legacyLatest := make(map[string]checkpointPhaseState)
	for _, result := range p.results {
		if result.Result == nil {
			continue
		}
		action, _ := result.Result["action"].(string)
		if action == "" || action == "slot_query" || action == "state_query" {
			continue
		}
		target, _ := result.Result["target_id"].(string)
		operation, _ := result.Result["checkpoint_operation_id"].(string)
		if operation == "" {
			operation, _ = result.Result["original_command_id"].(string)
		}
		if target == "" || operation == "" {
			continue
		}
		slotID := -1
		switch value := result.Result["slot_id"].(type) {
		case string:
			slotID, _ = strconv.Atoi(value)
		case float64:
			slotID = int(value)
		case int:
			slotID = value
		}
		if slotID < 0 {
			continue
		}
		phaseOrdinal := 0
		if value, ok := result.Result["observed_phase_ordinal"]; ok {
			if n, err := exactFenceToken(value); err == nil {
				phaseOrdinal = int(n)
			}
		}
		if phaseOrdinal == 0 {
			phaseOrdinal = checkpointPhase(action)
		}
		candidate := checkpointPhaseState{OperationID: operation, TargetID: target, SlotID: slotID, Phase: phaseOrdinal, Action: action}
		if current, exists := legacyLatest[operation]; !exists || candidate.Phase > current.Phase {
			legacyLatest[operation] = candidate
		}
	}
	for operation, state := range legacyLatest {
		if _, durable := latest[operation]; !durable {
			install(operation, state)
		}
	}
}

// CommandHandler is the narrow node-agent command boundary used by an
// embedded agent or a product-backed protocol fixture. Handle performs the
// same signature, fence, idempotency, runtime-discovery, and durable-state
// checks as Run's websocket loop.
type CommandHandler interface {
	Handle(context.Context, wsproto.CommandPayload) wsproto.CommandResultPayload
}

func NewCommandHandler(cfg *Config, log *slog.Logger) CommandHandler {
	return newCommandProcessor(cfg, log, true)
}

// refreshReady is called while the processor is in a stable state.  The
// websocket heartbeat must not take p.mu: Handle deliberately serializes a
// potentially slow runtime transition while holding that mutex.  Keep a
// lock-free readiness snapshot for the heartbeat path instead.
func (p *commandProcessor) refreshReady() {
	if p.externalWork.Load() > 0 {
		p.ready.Store(false)
		return
	}
	p.ready.Store(p.initError == nil && !p.stateBlocked && len(p.pending) == 0)
}

func (p *commandProcessor) beginExternalWork() {
	// Increment first and make Ready consult the counter directly.  This
	// ordering leaves no observable ready window between admission and the
	// readiness publication, even when a heartbeat races this transition.
	p.externalWork.Add(1)
	p.ready.Store(false)
}

func (p *commandProcessor) endExternalWork() {
	if remaining := p.externalWork.Add(-1); remaining <= 0 {
		if remaining < 0 {
			p.externalWork.Store(0)
		}
		p.refreshReady()
	}
}

func (p *commandProcessor) startupRecovery() {
	if p.cfg == nil || p.cfg.CommandRecoveryGeneration == 0 || strings.TrimSpace(p.cfg.CommandRecoveryEpoch) == "" || p.recoveryMarker == nil {
		return
	}
	if p.cfg.CommandRecoveryGeneration <= p.recoveryGeneration {
		return
	}
	if p.usedRecoveryEpochs == nil {
		p.usedRecoveryEpochs = make(map[string]struct{})
	}
	hash := recoveryEpochHash(p.cfg.CommandRecoveryEpoch)
	if _, used := p.usedRecoveryEpochs[hash]; used {
		p.block(blockReasonDurability)
		return
	}
	if err := p.recoverCommandState(p.cfg.CommandRecoveryEpoch, p.cfg.CommandRecoveryGeneration); err != nil {
		p.initError = errors.New("startup recovery could not be completed")
		p.block(blockReasonDurability)
	}
}

func (p *commandProcessor) finalizePreparedRecovery() {
	marker := p.recoveryMarker
	if marker == nil || marker.Phase != recoveryMarkerPhaseRecoveryPrepared || marker.TargetStateChecksum == "" || p.stateFileChecksum() != marker.TargetStateChecksum {
		return
	}
	if err := p.writeRecoveryMarkerTarget(marker.Reason, recoveryMarkerPhaseRecoveryCommitted, recoveryIdentity(p.cfg.CommandStatePath), recoveryIdentity(p.cfg.CommandStatePath+".corrupt"), marker.TargetStateChecksum, marker.RecoveryGeneration, marker.RecoveryEpoch); err != nil {
		p.block(blockReasonDurability)
		p.initError = errors.New("startup recovery finalization could not be persisted")
		return
	}
	if p.stateBlockReason == marker.Reason || p.stateBlockReason == blockReasonDurability {
		p.stateBlocked = false
		p.stateBlockReason = ""
	}
}

func (p *commandProcessor) restoreWarmManifests() {
	// A durable cleanup intent wins over a completed warm manifest. Do not
	// restore (and therefore do not PinFile) an entry that the pending command
	// explicitly asked us to remove; ReconcilePending performs cleanup only.
	cleanupKeys := make(map[string]struct{})
	for _, intent := range p.pending {
		if intent.Command == "cleanup_warm_model" {
			cleanupKeys[warmEntryKey(intent.TargetID, intent.Model)] = struct{}{}
		}
	}
	manifests := make([]WarmRAMManifest, 0, len(p.persistedWarm))
	for _, manifest := range p.persistedWarm {
		if _, cleanup := cleanupKeys[warmEntryKey(manifest.TargetID, manifest.Model)]; cleanup {
			continue
		}
		manifests = append(manifests, manifest)
	}
	if len(manifests) > 0 {
		// Metadata-only and failed-cleanup claims are unresolved until the
		// startup/reconnect reconciliation proves runtime state and re-establishes
		// a live pin (or removes the claim). Registration must advertise Ready=false
		// during that window.
		p.block(blockReasonWarmTransient)
	}
	p.warmRAM.RestoreManifests(manifests)
}

func (p *commandProcessor) Handle(ctx context.Context, command wsproto.CommandPayload) wsproto.CommandResultPayload {
	if err := p.authenticateCommand(command); err != nil {
		return wsproto.CommandResultPayload{ID: command.ID, NodeID: p.cfg.NodeID, Error: err.Error(), CompletedAt: time.Now().UTC()}
	}
	var ownedStopEnvelope []byte
	var ownedStopDigest, ownedStopEpoch string
	var ownedStopPublicKey []byte
	var planRelaunchEnvelope []byte
	var planRelaunchDigest string
	var planRelaunchPublicKey []byte
	var planRelaunchEpoch string
	if command.Command == "llm_displacement_stop" || command.Command == "llm_displacement_stop_query" {
		if err := wsproto.ValidateOwnedStopCommandArgs(command.Command, command.Args); err != nil {
			return wsproto.CommandResultPayload{ID: command.ID, NodeID: p.cfg.NodeID, Error: err.Error(), CompletedAt: time.Now().UTC()}
		}
		var err error
		ownedStopEnvelope, err = wsproto.CanonicalCommandEnvelope(command)
		if err != nil {
			return wsproto.CommandResultPayload{ID: command.ID, NodeID: p.cfg.NodeID, Error: "owned stop envelope could not be canonicalized", CompletedAt: time.Now().UTC()}
		}
		material, err := wsproto.CommandSigningMaterialForOwnedStop(command)
		if err != nil {
			return wsproto.CommandResultPayload{ID: command.ID, NodeID: p.cfg.NodeID, Error: "owned stop signing material is invalid", CompletedAt: time.Now().UTC()}
		}
		sum := sha256.Sum256(material)
		ownedStopDigest = hex.EncodeToString(sum[:])
		ownedStopEpoch, _ = command.Args["recovery_epoch"].(string)
		if command.Command == "llm_displacement_stop" {
			ownedStopPublicKey, err = readPinnedRootStopPublicKeyAt(p.ownedStopPathSet().PublicKey, p.ownedStopPathSet())
			if err != nil {
				return wsproto.CommandResultPayload{ID: command.ID, NodeID: p.cfg.NodeID, Error: "root stop acknowledgement key is unavailable", CompletedAt: time.Now().UTC()}
			}
		}
	}
	if checkpointPlanRelaunchIsCommand(command.Command) {
		if err := wsproto.ValidatePlanRelaunchCommandArgs(command.Command, command.Args); err != nil {
			return wsproto.CommandResultPayload{ID: command.ID, NodeID: p.cfg.NodeID, Error: err.Error(), CompletedAt: time.Now().UTC()}
		}
		if command.Command != checkpointPlanRelaunchQueryCommand {
			var err error
			planRelaunchEnvelope, err = wsproto.CanonicalCommandEnvelope(command)
			if err != nil {
				return wsproto.CommandResultPayload{ID: command.ID, NodeID: p.cfg.NodeID, Error: "plan relaunch envelope could not be canonicalized", CompletedAt: time.Now().UTC()}
			}
			material, materialErr := wsproto.CommandSigningMaterialForPlanRelaunch(command)
			if materialErr != nil {
				return wsproto.CommandResultPayload{ID: command.ID, NodeID: p.cfg.NodeID, Error: "plan relaunch signing material is invalid", CompletedAt: time.Now().UTC()}
			}
			planRelaunchDigest = sha256Hex(material)
			planRelaunchEpoch, _ = command.Args["recovery_epoch"].(string)
			paths := p.planRelaunchPathSet()
			planRelaunchPublicKey, err = readPinnedPlanBrokerPublicKeyAt(paths.PublicKey, paths)
			if err != nil {
				return wsproto.CommandResultPayload{ID: command.ID, NodeID: p.cfg.NodeID, Error: "root plan broker acknowledgement key is unavailable", CompletedAt: time.Now().UTC()}
			}
		}
	}
	// Resolve the target alias before any cached-state check.  Fences,
	// warm-entry keys, and idempotent retries must all observe one canonical
	// advertised target even when the signed command used a short alias.
	command = p.normalizeCommandTarget(command)
	if strings.HasPrefix(command.Command, "checkpoint_") {
		if err := wsproto.ValidateCheckpointCommandArgs(command.Command, command.Args); err != nil {
			return wsproto.CommandResultPayload{ID: command.ID, NodeID: p.cfg.NodeID, Error: err.Error(), CompletedAt: time.Now().UTC()}
		}
	}
	reentrant := commandProcessorReentry(ctx, p)
	if !reentrant {
		p.handleMu.Lock()
		defer p.handleMu.Unlock()
	}
	p.mu.Lock()
	stateLocked := true
	defer func() {
		if stateLocked {
			p.mu.Unlock()
		}
	}()
	if time.Now().UTC().After(command.ExpiresAt) {
		return wsproto.CommandResultPayload{ID: command.ID, NodeID: p.cfg.NodeID, Error: "command expired before durable intent", CompletedAt: time.Now().UTC()}
	}
	if command.Command == "llm_displacement_stop" && command.IssuedAt.After(time.Now().UTC()) {
		return wsproto.CommandResultPayload{ID: command.ID, NodeID: p.cfg.NodeID, Error: "owned stop command is not yet valid", CompletedAt: time.Now().UTC()}
	}
	if command.Command == "llm_displacement_stop_query" && !p.ownedStopQueryMatchesPending(command) {
		return wsproto.CommandResultPayload{ID: command.ID, NodeID: p.cfg.NodeID, Error: "owned stop query has no exact durable original intent", CompletedAt: time.Now().UTC()}
	}
	if command.Command == checkpointPlanRelaunchQueryCommand && !p.planRelaunchQueryMatchesPending(command) {
		return wsproto.CommandResultPayload{ID: command.ID, NodeID: p.cfg.NodeID, Error: "plan relaunch query has no exact durable original intent", CompletedAt: time.Now().UTC()}
	}
	// Authentication is the only work permitted before durable-state gates.
	// A cached success is not evidence that the current node is safe after a
	// rollback, restart, or unresolved intent, so never replay it while the
	// processor is blocked.
	cleanupRetry := command.Command == "cleanup_warm_model" && p.stateBlockReason == blockReasonWarmTransient && p.pendingWarmCleanupRetryFor(command)
	queryKnown := p.queryOriginalCommandExists(command)
	if isReadOnlyResidencyCommand(command.Command) && !queryKnown {
		return wsproto.CommandResultPayload{ID: command.ID, NodeID: p.cfg.NodeID, Error: "query original command linkage is not a durable pending or completed command", CompletedAt: time.Now().UTC()}
	}
	stopQueryRecovery := command.Command == "llm_displacement_stop_query" && p.initError == nil &&
		((!p.stateBlocked && p.stateBlockReason == "") || (p.stateBlocked && p.stateBlockReason == blockReasonWarmTransient))
	planRelaunchQueryRecovery := command.Command == checkpointPlanRelaunchQueryCommand && p.initError == nil &&
		((!p.stateBlocked && p.stateBlockReason == "") || (p.stateBlocked && p.stateBlockReason == blockReasonWarmTransient))
	queryRecovery := isReadOnlyCheckpointCommand(command.Command) || stopQueryRecovery || planRelaunchQueryRecovery || (isReadOnlyResidencyCommand(command.Command) && (p.pendingQueryMatches(ctx, command) || p.completedQueryMatches(command)))
	absoluteBlocked := p.initError != nil || ((p.stateBlocked || len(p.pending) > 0) && p.stateBlockReason != blockReasonWarmTransient)
	// Durable, corruption, recovery, and quarantine blocks are absolute for
	// cached success replay. The only exceptions are an explicit warm cleanup
	// retry or a linked live query recovery; neither is allowed to return a
	// cached mutation/query success.
	if absoluteBlocked && !cleanupRetry && !queryRecovery {
		message := "command state requires reconciliation"
		if p.initError != nil {
			message = "command state initialization failed"
		} else if p.stateBlockReason != "" {
			message = "command state blocked: " + p.stateBlockReason
		}
		return wsproto.CommandResultPayload{ID: command.ID, NodeID: p.cfg.NodeID, Error: message, CompletedAt: time.Now().UTC()}
	}
	settledReplay := !absoluteBlocked && queryKnown && p.queryOriginalBindingMatches(command) && p.cachedAuthoritativeObservationContext(ctx, command)
	durableMutationReplay := !absoluteBlocked && p.cachedMutationReplayContext(ctx, command)
	// A residency result is an authoritative journal entry, not a hint.  If a
	// record exists for either durable alias but fails the complete replay
	// validator, never fall through to execute/query and manufacture a fresh
	// success.  Doing so would turn a single persisted field drift (runtime,
	// fence, alias, or proof) into an undetectable live replacement.
	if p.residencyCacheRecordPresent(command) && !durableMutationReplay && !settledReplay && !cleanupRetry {
		return wsproto.CommandResultPayload{ID: command.ID, NodeID: p.cfg.NodeID, Error: "command blocked: cached residency result failed closed validation", CompletedAt: time.Now().UTC()}
	}
	if (p.initError != nil || p.stateBlocked || len(p.pending) > 0) && isReadOnlyResidencyCommand(command.Command) && !queryRecovery && !settledReplay && !durableMutationReplay && p.strictResidencyEnvelope {
		// Read-only recovery queries still pass the complete authoritative
		// envelope admission while blocked. This gives wrong-resource and
		// runtime-identity drift a precise rejection without permitting any
		// mutation or fence change; only an exact pending-resource query may
		// cross the durable block below.
		if preflightErr := p.preflightResidencyEnvelope(ctx, command); preflightErr != nil {
			return wsproto.CommandResultPayload{ID: command.ID, NodeID: p.cfg.NodeID, Error: preflightErr.Error(), CompletedAt: time.Now().UTC()}
		}
	}
	if (p.initError != nil && !queryRecovery) || ((p.stateBlocked || len(p.pending) > 0) && !cleanupRetry && !queryRecovery && !settledReplay && !durableMutationReplay) {
		message := "command state requires reconciliation"
		if p.initError != nil {
			message = "command state initialization failed"
		} else if p.stateBlockReason != "" {
			message = "command state blocked: " + p.stateBlockReason
		}
		return wsproto.CommandResultPayload{ID: command.ID, NodeID: p.cfg.NodeID, Error: message, CompletedAt: time.Now().UTC()}
	}
	if cached, ok := p.results[command.ID]; ok && (durableMutationReplay || settledReplay) {
		if fingerprint := p.commandFingerprints["id:"+command.ID]; fingerprint == "" || fingerprint != p.semanticFingerprint(command) {
			return wsproto.CommandResultPayload{ID: command.ID, NodeID: p.cfg.NodeID, Error: "command ID was previously used for a different command", CompletedAt: time.Now().UTC()}
		}
		return cached
	}
	if cached, ok := p.results["key:"+command.IdempotencyKey]; ok && (durableMutationReplay || settledReplay) {
		if fingerprint := p.commandFingerprints[command.IdempotencyKey]; fingerprint == "" || fingerprint != p.semanticFingerprint(command) {
			return wsproto.CommandResultPayload{ID: command.ID, NodeID: p.cfg.NodeID, Error: "idempotency key was previously used for a different command", CompletedAt: time.Now().UTC()}
		}
		return cached
	}
	if isReadOnlyResidencyCommand(command.Command) && !queryRecovery && !settledReplay {
		if p.strictResidencyEnvelope {
			if preflightErr := p.preflightResidencyEnvelope(ctx, command); preflightErr != nil {
				return wsproto.CommandResultPayload{ID: command.ID, NodeID: p.cfg.NodeID, Error: preflightErr.Error(), CompletedAt: time.Now().UTC()}
			}
		}
		return wsproto.CommandResultPayload{ID: command.ID, NodeID: p.cfg.NodeID, Error: "query resource or identity does not match the durable original command", CompletedAt: time.Now().UTC()}
	}
	// Only a new, authenticated, non-cached mutation enters the in-flight
	// window.  Authentication failures, cache hits, and ID/idempotency
	// mismatches must leave the durable readiness snapshot untouched.
	if commandHasExternalSideEffect(command) {
		p.beginExternalWork()
		defer p.endExternalWork()
		if p.onExternalWork != nil {
			p.onExternalWork(command)
		}
	}
	result := wsproto.CommandResultPayload{ID: command.ID, NodeID: p.cfg.NodeID, CompletedAt: time.Now().UTC()}
	p.log.Info("node command received", "command_hash", safeCommandHash(command))
	var intent pendingCommand
	var hasIntent bool
	var intentErr error
	var intentFenceKey string
	var previousFence int64
	var previousFenceSet bool
	if p.strictResidencyEnvelope && isResidencyCommand(command.Command) {
		if preflightErr := p.preflightResidencyEnvelope(ctx, command); preflightErr != nil {
			intentErr = preflightErr
		} else if !isReadOnlyResidencyCommand(command.Command) && !isReadOnlyCheckpointCommand(command.Command) {
			intent, hasIntent, intentErr = p.commandIntent(command)
		}
	} else if !isReadOnlyResidencyCommand(command.Command) && !isReadOnlyCheckpointCommand(command.Command) {
		intent, hasIntent, intentErr = p.commandIntent(command)
	}
	if intentErr == nil && hasIntent && command.Command == "llm_displacement_stop" {
		intent.OriginalEnvelope = append([]byte(nil), ownedStopEnvelope...)
		intent.SigningMaterialSHA256 = ownedStopDigest
		intent.PinnedRootStopPublicKey = append([]byte(nil), ownedStopPublicKey...)
		intent.StopRecoveryEpoch = ownedStopEpoch
	}
	if intentErr == nil && hasIntent && (command.Command == checkpointPlanRelaunchUrgentCommand || command.Command == checkpointPlanRelaunchVictimCommand) {
		intent.OriginalEnvelope = append([]byte(nil), planRelaunchEnvelope...)
		intent.PlanRelaunchSigningMaterialSHA256 = planRelaunchDigest
		intent.PinnedPlanBrokerPublicKey = append([]byte(nil), planRelaunchPublicKey...)
		intent.StopRecoveryEpoch = planRelaunchEpoch
	}
	if intentErr != nil {
		result.Error = intentErr.Error()
	} else if hasIntent {
		transitionKey := fenceKey(intent.TargetID, intent.Model)
		if command.Command == "llm_displacement_stop" {
			transitionKey = ownedStopFenceKey(fmt.Sprint(command.Args["accelerator_id"]))
		} else if command.Command == checkpointPlanRelaunchUrgentCommand || command.Command == checkpointPlanRelaunchVictimCommand {
			transitionKey = checkpointPlanRelaunchFenceKey(fmt.Sprint(command.Args["accelerator_id"]))
		}
		// A restart reconstructs pending intents but intentionally does not
		// reconstruct the in-flight map.  An explicit cleanup retry therefore
		// replaces the matching uncertain warm intent before acquiring its own
		// write-ahead fence.
		if command.Command == "cleanup_warm_model" && p.pendingWarmCleanupRetryFor(command) {
			for id, existing := range p.pending {
				if existing.TargetID == intent.TargetID && existing.Model == intent.Model && (existing.Command == "warm_model" || existing.Command == "offload_model" || existing.Command == "demote_model" || existing.Command == "reverify_warm_model" || existing.Command == "protect_warm_model" || existing.Command == "cleanup_warm_model") {
					delete(p.pending, id)
				}
			}
			delete(p.inflight, transitionKey)
		}
		if p.inflight[transitionKey] {
			if command.Command == "cleanup_warm_model" && p.pendingWarmCleanupRetryFor(command) {
				for id, existing := range p.pending {
					if existing.TargetID == intent.TargetID && existing.Model == intent.Model && (existing.Command == "warm_model" || existing.Command == "offload_model" || existing.Command == "demote_model" || existing.Command == "reverify_warm_model" || existing.Command == "protect_warm_model" || existing.Command == "cleanup_warm_model") {
						delete(p.pending, id)
					}
				}
				delete(p.inflight, transitionKey)
			} else {
				result.Error = "model transition is already in progress"
			}
		}
		if result.Error == "" {
			fenceErr := error(nil)
			if command.Command == "llm_displacement_stop" {
				fenceErr = p.checkOwnedStopTransition(command)
			} else if command.Command == checkpointPlanRelaunchUrgentCommand || command.Command == checkpointPlanRelaunchVictimCommand {
				fenceErr = p.checkPlanRelaunchTransition(command)
			} else if !isCheckpointCommand(command.Command) {
				fenceErr = p.checkFence(command, intent.TargetID, intent.Model)
			}
			if fenceErr != nil {
				result.Error = fenceErr.Error()
			} else {
				intentFenceKey = transitionKey
				previousFence, previousFenceSet = p.fences[transitionKey]
				p.inflight[transitionKey] = true
				p.fences[transitionKey] = intent.Token
				p.pending[command.ID] = intent
				if command.Command == "llm_displacement_stop" {
					semanticFingerprint := p.semanticFingerprint(command)
					p.commandFingerprints["id:"+command.ID] = semanticFingerprint
					p.commandFingerprints[command.IdempotencyKey] = semanticFingerprint
					if err := p.recordOwnedStopStep(command, intent, "pending", ""); err != nil {
						result.Error = "owned stop intent could not be journaled"
						p.block(blockReasonDurability)
					}
				}
				if command.Command == checkpointPlanRelaunchUrgentCommand || command.Command == checkpointPlanRelaunchVictimCommand {
					semanticFingerprint := p.semanticFingerprint(command)
					p.commandFingerprints["id:"+command.ID] = semanticFingerprint
					p.commandFingerprints[command.IdempotencyKey] = semanticFingerprint
					if err := p.recordPlanRelaunchStep(command, intent, "pending", nil); err != nil {
						result.Error = "plan relaunch intent could not be journaled"
						p.block(blockReasonDurability)
					}
				}
				if result.Error != "" {
					delete(p.pending, command.ID)
					delete(p.inflight, transitionKey)
					if command.Command == checkpointPlanRelaunchUrgentCommand || command.Command == checkpointPlanRelaunchVictimCommand {
						p.dropPlanRelaunchStep(command)
					}
					if previousFenceSet {
						p.fences[transitionKey] = previousFence
					} else {
						delete(p.fences, transitionKey)
					}
				} else {
					if err := p.save(); err != nil {
						result.Error = "command state requires reconciliation"
						p.block(blockReasonDurability)
					}
				}
			}
		}
	}
	sideEffectStarted := false
	if result.Error == "" {
		if time.Now().UTC().After(command.ExpiresAt) {
			result.Error = "command expired before external mutation"
			// The write-ahead intent is removed below, so an expiry observed
			// before the external boundary must not consume a fencing token.
			if hasIntent && intentFenceKey != "" {
				if previousFenceSet {
					p.fences[intentFenceKey] = previousFence
				} else {
					delete(p.fences, intentFenceKey)
				}
				if command.Command == "llm_displacement_stop" {
					p.dropOwnedStopStep(command)
				} else if command.Command == checkpointPlanRelaunchUrgentCommand || command.Command == checkpointPlanRelaunchVictimCommand {
					p.dropPlanRelaunchStep(command)
				}
			}
		} else {
			// The intent save above is the write-ahead fence. Once an external
			// mutator is entered, any error is ambiguous until authoritative
			// reconciliation proves the prior or final state. Keep the intent and
			// its fence durable rather than classifying errors by their wording.
			commandCtxBase := ctx
			// refresh_capabilities performs live discovery and, when checkpoint
			// proof is enabled, its managed driver calls this handler for each
			// signed phase.  Release the state lock around that external work;
			// handleMu still excludes unrelated callers, while the context marker
			// permits the owned phase call to re-enter this processor.
			if command.Command == "refresh_capabilities" {
				commandCtxBase = context.WithValue(ctx, commandProcessorContextKey{}, p)
				p.mu.Unlock()
				stateLocked = false
			}
			commandCtx, cancel := context.WithDeadline(commandCtxBase, command.ExpiresAt)
			result.Result, result.Error = p.execute(commandCtx, command, func() { sideEffectStarted = true })
			cancel()
			if !stateLocked {
				p.mu.Lock()
				stateLocked = true
			}
			result.Error = sanitizeCommandError(result.Error)
			if result.Error == "" && command.Command == checkpointPlanRelaunchQueryCommand {
				if err := p.settlePlanRelaunchQuery(command, result.Result); err != nil {
					result.Result = nil
					result.Error = "root plan relaunch query could not be durably reconciled"
					p.block(blockReasonDurability)
				}
			}
			if result.Error == "" && (command.Command == checkpointPlanRelaunchUrgentCommand || command.Command == checkpointPlanRelaunchVictimCommand) {
				receiptText, _ := result.Result["receipt"].(string)
				receipt, decodeErr := base64.StdEncoding.DecodeString(receiptText)
				if decodeErr != nil || len(receipt) == 0 || p.recordPlanRelaunchStep(command, intent, "acknowledged", receipt) != nil {
					result.Result = nil
					result.Error = "root plan relaunch receipt could not be durably joined"
				}
			}
			capabilityArg, capabilityArgPresent := command.Args["capability_version"].(string)
			if result.Error == "" && result.Result != nil && isResidencyCommand(command.Command) && (p.strictResidencyEnvelope || (capabilityArgPresent && strings.TrimSpace(capabilityArg) != "")) {
				var envelopeErr error
				if command.Command == "query_model_state" {
					envelopeErr = p.completeQueryResultEnvelope(command, result.Result)
				} else {
					envelopeErr = p.completeResidencyResultEnvelope(command, result.Result)
				}
				if envelopeErr != nil {
					result.Result = nil
					result.Error = envelopeErr.Error()
				}
			}
			result.OK = result.Error == ""
		}
	}
	if result.Error == "" && isReadOnlyResidencyCommand(command.Command) {
		p.settlePendingFromQuery(command, result)
	}
	retainPending := hasIntent && result.Error != "" && sideEffectStarted
	result.Uncertain = retainPending
	if !retainPending {
		delete(p.pending, command.ID)
	} else {
		p.block(blockReasonWarmTransient)
	}
	if hasIntent && !retainPending {
		transitionKey := intentFenceKey
		if transitionKey == "" {
			transitionKey = fenceKey(intent.TargetID, intent.Model)
		}
		delete(p.inflight, transitionKey)
		if p.stateBlockReason == blockReasonWarmTransient && len(p.pending) == 0 {
			p.stateBlocked = false
			p.stateBlockReason = ""
		}
	}
	result.CompletedAt = time.Now().UTC()
	if result.OK {
		p.log.Info("node command completed", "command_hash", safeCommandHash(command))
	} else {
		p.log.Warn("node command failed", "command_hash", safeCommandHash(command), "error", result.Error)
	}
	p.results[command.ID] = result
	p.results["key:"+command.IdempotencyKey] = result
	p.commandFingerprints["id:"+command.ID] = p.semanticFingerprint(command)
	p.commandFingerprints[command.IdempotencyKey] = p.semanticFingerprint(command)
	if err := p.save(); err != nil {
		result.OK = false
		result.Error = "command state requires reconciliation"
		p.block(blockReasonDurability)
		if hasIntent {
			p.pending[command.ID] = intent
			transitionKey := intentFenceKey
			if transitionKey == "" {
				transitionKey = fenceKey(intent.TargetID, intent.Model)
			}
			p.inflight[transitionKey] = true
			p.stateBlocked = true
		}
		p.results[command.ID] = result
		p.results["key:"+command.IdempotencyKey] = result
	}
	p.refreshReady()
	return result
}

// residencyCacheRecordPresent reports whether this exact command identity has
// any durable result under either of its aliases.  A one-sided or malformed
// alias is itself evidence of corruption and must be rejected before the live
// boundary is reached.
func (p *commandProcessor) residencyCacheRecordPresent(command wsproto.CommandPayload) bool {
	if !isResidencyCommand(command.Command) && !isCheckpointCommand(command.Command) {
		return false
	}
	_, byID := p.results[command.ID]
	_, byKey := p.results["key:"+command.IdempotencyKey]
	return byID || byKey
}

func (p *commandProcessor) completeResidencyResultEnvelope(command wsproto.CommandPayload, result map[string]any) error {
	stringArg := func(key string) (string, error) {
		value, ok := command.Args[key].(string)
		if !ok || strings.TrimSpace(value) == "" {
			return "", fmt.Errorf("residency command argument %s is missing", key)
		}
		return value, nil
	}
	targetID, err := stringArg("target_id")
	if err != nil {
		return err
	}
	model, err := stringArg("model")
	if err != nil {
		return err
	}
	capabilityVersion, err := stringArg("capability_version")
	if err != nil {
		return err
	}
	capabilityRevision, err := stringArg("capability_revision")
	if err != nil {
		return err
	}
	for key, expected := range map[string]string{"target_kind": "llamacpp", "target_id": targetID, "model": model, "node_id": p.cfg.NodeID, "action": command.Command, "original_command_id": command.ID, "original_idempotency_key": command.IdempotencyKey, "idempotency_key": command.IdempotencyKey, "command_id": command.ID, "capability_version": capabilityVersion, "capability_revision": capabilityRevision} {
		if existing, present := result[key]; present {
			value, ok := existing.(string)
			if !ok || value != expected {
				return fmt.Errorf("authoritative residency result %s does not match the signed command", key)
			}
		} else {
			result[key] = expected
		}
	}
	runtimeIdentity, ok := result["runtime_identity"].(string)
	if !ok || strings.TrimSpace(runtimeIdentity) == "" {
		return errors.New("authoritative residency result runtime identity is missing")
	}
	for _, key := range []string{"fencing_token", "observed_after_fence", "tier"} {
		if _, present := result[key]; !present {
			return fmt.Errorf("authoritative residency result %s is missing", key)
		}
	}
	if existing, present := result["command_fingerprint"]; present {
		if value, ok := existing.(string); !ok || value != p.semanticFingerprint(command) {
			return errors.New("authoritative residency result command fingerprint drifted")
		}
	} else {
		result["command_fingerprint"] = p.semanticFingerprint(command)
	}
	if existing, present := result["fingerprint"]; present {
		if value, ok := existing.(string); !ok || value != p.semanticFingerprint(command) {
			return errors.New("authoritative residency result fingerprint drifted")
		}
	} else {
		result["fingerprint"] = p.semanticFingerprint(command)
	}
	if _, present := result["reconciled"]; !present {
		result["reconciled"] = false
	}
	if _, present := result["changed"]; !present {
		return errors.New("authoritative residency result changed proof is missing")
	}
	return validateLiveResidencyResult(command.Command, result)
}

// completeQueryResultEnvelope canonicalizes the live read result before it is
// journaled. Queries are replayable only when the stored payload has the same
// bindings and aliases as the signed query and the durable original action.
func (p *commandProcessor) completeQueryResultEnvelope(command wsproto.CommandPayload, result map[string]any) error {
	if result == nil || wsproto.ValidateResidencyCommandArgs(command.Command, command.Args) != nil {
		return errors.New("authoritative query envelope is invalid")
	}
	action, actionOK := result["action"].(string)
	originalAction, originalOK := p.queryOriginalAction(command)
	if !actionOK || !originalOK || action != originalAction || action == "query_model_state" {
		return errors.New("authoritative query action is not bound to the durable original")
	}
	bindString := func(key, expected string) error {
		if existing, present := result[key]; present {
			value, ok := existing.(string)
			if !ok || value != expected {
				return fmt.Errorf("authoritative query result %s does not match the signed envelope", key)
			}
		} else {
			result[key] = expected
		}
		return nil
	}
	for _, binding := range []struct{ key, value string }{
		{"target_kind", "llamacpp"}, {"target_id", fmt.Sprint(command.Args["target_id"])},
		{"model", fmt.Sprint(command.Args["model"])}, {"runtime_identity", fmt.Sprint(command.Args["runtime_identity"])},
		{"capability_version", fmt.Sprint(command.Args["capability_version"])}, {"capability_revision", fmt.Sprint(command.Args["capability_revision"])},
		{"node_id", p.cfg.NodeID}, {"action", action}, {"command_id", command.ID},
		{"idempotency_key", command.IdempotencyKey}, {"original_command_id", fmt.Sprint(command.Args["original_command_id"])},
		{"original_idempotency_key", fmt.Sprint(command.Args["original_idempotency_key"])},
	} {
		if strings.TrimSpace(binding.value) == "" {
			return fmt.Errorf("authoritative query result %s is missing", binding.key)
		}
		if err := bindString(binding.key, binding.value); err != nil {
			return err
		}
	}
	expectedFence, fenceErr := exactFenceToken(command.Args["expected_fence"])
	if fenceErr != nil {
		return errors.New("authoritative query expected_fence is invalid")
	}
	for _, key := range []string{"expected_fence", "fencing_token", "observed_after_fence"} {
		if existing, present := result[key]; present {
			value, err := exactFenceToken(existing)
			if err != nil || value != expectedFence {
				return fmt.Errorf("authoritative query result %s does not match the query fence", key)
			}
		} else {
			result[key] = expectedFence
		}
	}
	fingerprint := p.semanticFingerprint(command)
	for _, key := range []string{"command_fingerprint", "fingerprint"} {
		if existing, present := result[key]; present {
			value, ok := existing.(string)
			if !ok || value != fingerprint {
				return fmt.Errorf("authoritative query result %s drifted", key)
			}
		} else {
			result[key] = fingerprint
		}
	}
	if _, present := result["reconciled"]; !present {
		result["reconciled"] = false
	}
	allowed := cachedResidencyResultAllowedKeys(action)
	allowed["expected_fence"] = true
	for _, key := range []string{"cleaned", "warm_entry_absent", "warm_release_verified", "warm_model_bytes", "locked_bytes"} {
		allowed[key] = true
	}
	for key := range result {
		if !allowed[key] {
			return fmt.Errorf("authoritative query result contains unknown field %s", key)
		}
	}
	if !queryResultProvesAction(action, result, action) {
		return errors.New("authoritative query result lacks the exact action proof")
	}
	return nil
}

// cachedMutationReplay is the durable no-side-effect replay path used after a
// node restart. A persisted successful observation with an exact semantic
// fingerprint is authoritative for the same signed command; returning it
// before the warm-state gate prevents a duplicate runtime mutation while the
// restored warm journal is still being reconciled.
func (p *commandProcessor) cachedMutationReplay(command wsproto.CommandPayload) bool {
	return p.cachedMutationReplayWithLive(context.Background(), command, false)
}

func (p *commandProcessor) cachedMutationReplayContext(ctx context.Context, command wsproto.CommandPayload) bool {
	return p.cachedMutationReplayWithLive(ctx, command, true)
}

func (p *commandProcessor) cachedMutationReplayWithLive(ctx context.Context, command wsproto.CommandPayload, checkLive bool) bool {
	if isCheckpointCommand(command.Command) && command.Command != "checkpoint_slot_query" && command.Command != "checkpoint_state_query" {
		byID, idOK := p.results[command.ID]
		byKey, keyOK := p.results["key:"+command.IdempotencyKey]
		if !idOK || !keyOK || !reflect.DeepEqual(byID, byKey) || !byID.OK || byID.Result == nil {
			return false
		}
		fingerprint := p.semanticFingerprint(command)
		return p.commandFingerprints["id:"+command.ID] == fingerprint && p.commandFingerprints[command.IdempotencyKey] == fingerprint && byID.Result["command_fingerprint"] == fingerprint && byID.Result["fingerprint"] == fingerprint
	}
	if !isResidencyCommand(command.Command) || command.Command == "query_model_state" {
		return false
	}
	if wsproto.ValidateResidencyCommandArgs(command.Command, command.Args) != nil {
		return p.cachedLegacyMutationReplay(command)
	}
	if checkLive && !p.currentCacheRuntimeBindingsMatch(ctx, command) {
		return false
	}
	byID, idOK := p.results[command.ID]
	byKey, keyOK := p.results["key:"+command.IdempotencyKey]
	if !idOK || !keyOK || !reflect.DeepEqual(byID, byKey) {
		return false
	}
	cached := byID
	if cached.ID != command.ID || cached.NodeID != p.cfg.NodeID || cached.Uncertain || (cached.OK && cached.Error != "") || cached.Result == nil || (!cached.OK && (cached.Result["reconciled"] != true || cached.Error == "")) {
		return false
	}
	expectedFingerprint := p.semanticFingerprint(command)
	fingerprintByID, fingerprintIDOK := p.commandFingerprints["id:"+command.ID]
	fingerprintByKey, fingerprintKeyOK := p.commandFingerprints[command.IdempotencyKey]
	resultFingerprint, resultFingerprintOK := cached.Result["command_fingerprint"].(string)
	resultFingerprintAlias, resultFingerprintAliasOK := cached.Result["fingerprint"].(string)
	if !fingerprintIDOK || !fingerprintKeyOK || fingerprintByID == "" || fingerprintByID != expectedFingerprint || fingerprintByKey != expectedFingerprint || !resultFingerprintOK || !resultFingerprintAliasOK || resultFingerprint != expectedFingerprint || resultFingerprintAlias != expectedFingerprint {
		return false
	}
	if command.Command != "query_model_state" {
		allowed := cachedResidencyResultAllowedKeys(command.Command)
		if !cached.OK {
			for _, key := range []string{"cleaned", "warm_entry_absent", "warm_release_verified", "warm_model_bytes", "locked_bytes"} {
				allowed[key] = true
			}
		}
		for _, key := range []string{"target_kind", "target_id", "model", "runtime_identity", "capability_version", "capability_revision", "tier", "fencing_token", "observed_after_fence", "action", "command_id", "idempotency_key", "original_command_id", "original_idempotency_key", "command_fingerprint", "fingerprint"} {
			if cached.Result[key] == nil {
				return false
			}
		}
		for key := range cached.Result {
			if !allowed[key] && !((key == "rolled_back" || key == "expected_fence") && !cached.OK) {
				return false
			}
		}
		if cached.Result["node_id"] != p.cfg.NodeID || cached.Result["target_kind"] != command.Args["target_kind"] || cached.Result["target_id"] != command.Args["target_id"] || cached.Result["model"] != command.Args["model"] || cached.Result["runtime_identity"] != command.Args["runtime_identity"] || cached.Result["capability_version"] != command.Args["capability_version"] || cached.Result["capability_revision"] != command.Args["capability_revision"] || cached.Result["action"] != command.Command || cached.Result["command_id"] != command.ID || cached.Result["idempotency_key"] != command.IdempotencyKey || cached.Result["original_command_id"] != command.ID || cached.Result["original_idempotency_key"] != command.IdempotencyKey || cached.Result["command_fingerprint"] != resultFingerprint || cached.Result["fingerprint"] != resultFingerprint {
			return false
		}
		expectedFence, expectedFenceErr := exactFenceToken(command.Args["fencing_token"])
		resultFence, resultFenceErr := exactFenceToken(cached.Result["fencing_token"])
		observedFence, observedFenceErr := exactFenceToken(cached.Result["observed_after_fence"])
		if expectedFenceErr != nil || resultFenceErr != nil || observedFenceErr != nil || resultFence != expectedFence || observedFence != expectedFence {
			return false
		}
		if _, changedOK := cached.Result["changed"].(bool); !changedOK || !mutationResultProvesAction(command.Command, cached.Result, command.Command) {
			return false
		}
		resident, residentOK := cached.Result["resident"].(bool)
		warm, warmOK := cached.Result["warm_ram"].(bool)
		tier, tierOK := cached.Result["tier"].(string)
		if !residentOK || !warmOK || !tierOK {
			return false
		}
		if !residencyResultHasExactTierSchema(command.Command, cached.Result, tier) {
			return false
		}
		if _, reconciledOK := cached.Result["reconciled"].(bool); !reconciledOK {
			return false
		}
		if cached.OK && tier != expectedResidencyTier(command.Command) {
			return false
		}
		if cached.OK && (command.Command == "load_model" && (!resident || warm) || (command.Command == "unload_model" || command.Command == "cleanup_warm_model") && (resident || warm) || (command.Command == "warm_model" || command.Command == "offload_model" || command.Command == "demote_model" || command.Command == "protect_warm_model" || command.Command == "reverify_warm_model") && (resident || !warm)) {
			return false
		}
		if cached.OK && command.Command == "cleanup_warm_model" {
			cleaned, cleanedOK := cached.Result["cleaned"].(bool)
			absent, absentOK := cached.Result["warm_entry_absent"].(bool)
			released, releasedOK := cached.Result["warm_release_verified"].(bool)
			locked, lockedErr := exactFenceToken(cached.Result["locked_bytes"])
			bytes, bytesErr := exactFenceToken(cached.Result["warm_model_bytes"])
			if !cleanedOK || !cleaned || !absentOK || !absent || !releasedOK || !released || lockedErr != nil || bytesErr != nil || locked != 0 || bytes != 0 {
				return false
			}
		}
		if cached.OK && (command.Command == "warm_model" || command.Command == "offload_model" || command.Command == "demote_model" || command.Command == "protect_warm_model" || command.Command == "reverify_warm_model") {
			verified, verifiedOK := cached.Result["warm_model_bytes_verified"].(bool)
			released, releasedOK := cached.Result["released_vram"].(bool)
			oracle, oracleOK := cached.Result["oracle"].(string)
			bytes, bytesErr := exactFenceToken(cached.Result["warm_model_bytes"])
			locked, lockedErr := exactFenceToken(cached.Result["locked_bytes"])
			if !verifiedOK || !verified || !releasedOK || !released || !oracleOK || oracle != "mincore+mlock" || bytesErr != nil || lockedErr != nil || bytes <= 0 || locked < bytes {
				return false
			}
			if command.Command == "protect_warm_model" {
				protected, protectedOK := cached.Result["protected"].(bool)
				expectedProtected, expectedProtectedOK := command.Args["protected"].(bool)
				expectedRefs, expectedRefsErr := exactFenceToken(command.Args["active_references"])
				refs, refsErr := exactFenceToken(cached.Result["active_references"])
				if !protectedOK || !expectedProtectedOK || protected != expectedProtected || expectedRefsErr != nil || refsErr != nil || refs != expectedRefs {
					return false
				}
			}
		}
		if cached.OK {
			if tier, ok := cached.Result["tier"].(string); !ok || tier != expectedResidencyTier(command.Command) {
				return false
			}
		} else {
			rolledBack, rolledBackOK := cached.Result["rolled_back"].(bool)
			expectedFence, expectedFenceErr := exactFenceToken(command.Args["fencing_token"])
			resultExpectedFence, resultExpectedFenceErr := exactFenceToken(cached.Result["expected_fence"])
			if !rolledBackOK || !rolledBack || expectedFenceErr != nil || resultExpectedFenceErr != nil || resultExpectedFence != expectedFence {
				return false
			}
			if tier, ok := cached.Result["tier"].(string); !ok || tier != inverseResidencyTier(command.Command) {
				return false
			}
		}
	}
	return true
}

// cachedLegacyMutationReplay is a deliberately narrow compatibility reader
// for pre-residency-envelope journals. It is not a warm-state shortcut: only
// an exact hot/cold result with the durable command fingerprint and typed
// action proof may replay, and warm/rolled-back/ambiguous results fail closed.
func (p *commandProcessor) cachedLegacyMutationReplay(command wsproto.CommandPayload) bool {
	if command.Command != "load_model" && command.Command != "unload_model" && command.Command != "cleanup_warm_model" {
		return false
	}
	// Compatibility is only for a genuinely pre-envelope command.  A partially
	// populated current envelope must not be downgraded into the legacy reader
	// (that would silently guess missing capability/runtime bindings).
	for _, key := range []string{"target_kind", "capability_version", "capability_revision", "expected_tier", "runtime_identity"} {
		if p.strictResidencyEnvelope {
			if _, present := command.Args[key]; present {
				return false
			}
		}
	}
	byID, idOK := p.results[command.ID]
	byKey, keyOK := p.results["key:"+command.IdempotencyKey]
	if !idOK || !keyOK || !reflect.DeepEqual(byID, byKey) || !byID.OK || byID.Uncertain || byID.Error != "" || byID.Result == nil || byID.ID != command.ID || byID.NodeID != p.cfg.NodeID {
		return false
	}
	expectedFingerprint := p.semanticFingerprint(command)
	if expectedFingerprint == "" || p.commandFingerprints["id:"+command.ID] != expectedFingerprint || p.commandFingerprints[command.IdempotencyKey] != expectedFingerprint {
		return false
	}
	result := byID.Result
	// Compatibility records still need an explicit action binding. A missing
	// action is indistinguishable from a tier-only record and must not replay.
	action, actionOK := result["action"].(string)
	if !actionOK || action != command.Command {
		return false
	}
	if result["target_id"] != command.Args["target_id"] || result["model"] != command.Args["model"] {
		return false
	}
	// The old journal shape is intentionally finite. Do not allow a caller to
	// smuggle a warm proof, rolled-back marker, or arbitrary extension through
	// the compatibility path.
	allowed := map[string]bool{"action": true, "target_id": true, "model": true, "resident": true, "warm_ram": true, "changed": true, "runtime_identity": true, "capability_revision": true, "fencing_token": true, "observed_after_fence": true, "tier": true}
	// A result produced by the current executor may already be the complete
	// envelope even when the signed command predates the strict argument
	// schema. In that case use the same finite canonical allowlist; this is
	// still fail-closed and is not a generic cache shortcut.
	if _, canonical := result["target_kind"]; canonical {
		// A current result requires the current signed command envelope. The
		// legacy path has no safe way to reconstruct those bindings.
		if p.strictResidencyEnvelope {
			return false
		}
		allowed = cachedResidencyResultAllowedKeys(command.Command)
	}
	if command.Command == "unload_model" || command.Command == "cleanup_warm_model" {
		for _, key := range []string{"cleaned", "warm_entry_absent", "warm_release_verified", "warm_model_bytes", "locked_bytes"} {
			allowed[key] = true
		}
	}
	for key := range result {
		if !allowed[key] {
			return false
		}
	}
	if _, canonical := result["target_kind"]; canonical {
		if result["target_kind"] != "llamacpp" || result["node_id"] != p.cfg.NodeID || result["action"] != command.Command || result["command_id"] != command.ID || result["idempotency_key"] != command.IdempotencyKey || result["original_command_id"] != command.ID || result["original_idempotency_key"] != command.IdempotencyKey {
			return false
		}
		for _, key := range []string{"capability_version", "capability_revision", "runtime_identity"} {
			value, ok := result[key].(string)
			if !ok || strings.TrimSpace(value) == "" {
				return false
			}
		}
		resultFence, resultFenceErr := exactFenceToken(result["fencing_token"])
		observedFence, observedFenceErr := exactFenceToken(result["observed_after_fence"])
		if resultFenceErr != nil || observedFenceErr != nil || resultFence != observedFence {
			return false
		}
		if commandFence, err := exactFenceToken(command.Args["fencing_token"]); err == nil && resultFence != commandFence {
			return false
		}
		for _, key := range []string{"command_fingerprint", "fingerprint"} {
			if value, ok := result[key].(string); !ok || value != expectedFingerprint {
				return false
			}
		}
		if reconciled, ok := result["reconciled"].(bool); !ok || reconciled {
			return false
		}
	}
	for _, key := range []string{"target_id", "model", "runtime_identity", "tier"} {
		if value, ok := result[key].(string); !ok || strings.TrimSpace(value) == "" {
			return false
		}
	}
	legacyRevision, revisionOK := result["capability_revision"].(string)
	if p.strictResidencyEnvelope && (!revisionOK || strings.TrimSpace(legacyRevision) == "") {
		return false
	}
	resident, residentOK := result["resident"].(bool)
	warm, warmOK := result["warm_ram"].(bool)
	_, changedOK := result["changed"].(bool)
	tier, tierOK := result["tier"].(string)
	if !residentOK || !warmOK || !changedOK || !tierOK || tier == "warm_ram" {
		return false
	}
	resultFence, resultFenceErr := exactFenceToken(result["fencing_token"])
	observedFence, observedFenceErr := exactFenceToken(result["observed_after_fence"])
	commandFence, commandFenceErr := exactFenceToken(command.Args["fencing_token"])
	if resultFenceErr != nil || observedFenceErr != nil || commandFenceErr != nil || resultFence != observedFence || resultFence != commandFence {
		return false
	}
	if command.Command == "load_model" {
		return tier == "hot_vram" && resident && !warm
	}
	if resident || warm || tier != "cold_disk" {
		return false
	}
	cleaned, cleanedOK := result["cleaned"].(bool)
	absent, absentOK := result["warm_entry_absent"].(bool)
	released, releasedOK := result["warm_release_verified"].(bool)
	bytes, bytesErr := exactFenceToken(result["warm_model_bytes"])
	locked, lockedErr := exactFenceToken(result["locked_bytes"])
	return cleanedOK && cleaned && absentOK && absent && releasedOK && released && bytesErr == nil && lockedErr == nil && bytes == 0 && locked == 0
}

// currentCacheRuntimeBindingsMatch prevents a durable result from being
// replayed after the node's configured runtime capability changed.  The
// cache remains fail-closed: a mismatch is not permission to rediscover and
// replace the authoritative record with a live success.
func (p *commandProcessor) currentCacheRuntimeBindingsMatch(ctx context.Context, command wsproto.CommandPayload) bool {
	if configured := strings.TrimSpace(p.cfg.Capabilities.Version); configured != "" && configured != domain.CapabilityContractVersion {
		return false
	}
	targetID, targetOK := command.Args["target_id"].(string)
	model, modelOK := command.Args["model"].(string)
	capabilityVersion, versionOK := command.Args["capability_version"].(string)
	runtimeIdentity, identityOK := command.Args["runtime_identity"].(string)
	if !targetOK || !modelOK || !versionOK || !identityOK || strings.TrimSpace(targetID) == "" || strings.TrimSpace(model) == "" || strings.TrimSpace(capabilityVersion) == "" || strings.TrimSpace(runtimeIdentity) == "" {
		return false
	}
	server, found := p.routerTarget(targetID)
	if !found {
		return false
	}
	// A cache binding is authoritative only while the exact configured
	// lifecycle runtime remains enabled.  RouterManaged is the explicit
	// enablement bit for llama.cpp targets; an entry that remains in the
	// list but is no longer managed must not authorize replay.
	if !server.RouterManaged {
		return false
	}
	canonicalTarget := p.cfg.NodeID + "-" + server.ID
	if targetID != canonicalTarget {
		return false
	}
	discovery, err := DiscoverLlamaCPP(ctx, p.cfg.NodeID, server)
	if err != nil {
		return false
	}
	if !discovery.CapabilitiesVerified || discovery.CapacitySource != "runtime:/slots" {
		return false
	}
	if capabilityVersion != discovery.Version || runtimeIdentity != canonicalCommandRuntimeIdentity(canonicalTarget, discovery) {
		return false
	}
	if server.ContextLimit > 0 && discovery.ContextLimit != server.ContextLimit {
		return false
	}
	if server.Slots > 0 && discovery.Slots != server.Slots {
		return false
	}
	return discovery.ContextLimit > 0 && discovery.Slots > 0
}

func isResidencyCommand(command string) bool {
	switch command {
	case "load_model", "unload_model", "warm_model", "offload_model", "demote_model", "protect_warm_model", "cleanup_warm_model", "reverify_warm_model", "query_model_state":
		return true
	default:
		return false
	}
}

func isCheckpointCommand(command string) bool { return strings.HasPrefix(command, "checkpoint_") }

func checkpointPhase(action string) int {
	switch action {
	case "slot_assign":
		return 1
	case "start":
		return 2
	case "pause":
		return 3
	case "save":
		return 4
	case "stop_confirm":
		return 5
	case "release":
		return 6
	case "reload":
		return 9
	case "restore":
		return 10
	case "resume":
		return 11
	case "continue":
		return 12
	case "reuse_verify":
		return 13
	case "cancel":
		return 14
	default:
		return 0
	}
}

func checkpointPhaseFor(state checkpointPhaseState, action string) int {
	// Restore reacquires an idle slot after release. Keep that reassignment in
	// the same operation's monotonic phase history instead of resetting to 1.
	if state.Phase == checkpointPhase("release") && action == "slot_assign" {
		return 8
	}
	// Older agents could restart with a slot assignment already durable while
	// the controller's restore intent was still in flight.  Keep this narrow
	// compatibility edge; the shared controller store never permits an
	// assigned -> reloaded transition.
	if state.Phase == checkpointPhase("slot_assign") && state.Action == "slot_assign" && action == "reload" {
		return checkpointPhase("reload")
	}
	if state.Phase == 8 && state.Action == "slot_assign" && action == "slot_assign" {
		return 8
	}
	if state.Phase == 8 && state.Action == "slot_assign" && action == "reload" {
		// Compatibility path for a restored slot whose assignment was recorded
		// before the reload boundary; assignment and reload are one authorized
		// reacquisition sequence when the assignment result was already durable.
		return checkpointPhase("reload")
	}
	// Failed stream attachment can leave a slot assigned/paused before the
	// controller has a durable snapshot. It still needs an authenticated stop
	// observation before the ownership release; no save phase is fabricated.
	if state.Phase >= checkpointPhase("slot_assign") && state.Phase < checkpointPhase("stop_confirm") && action == "stop_confirm" {
		return checkpointPhase("stop_confirm")
	}
	if state.Phase == checkpointPhase("slot_assign") && action == "start" {
		return checkpointPhase("start")
	}
	if state.Phase == checkpointPhase("reload") && state.Action == "reload" && action == "restore" {
		return checkpointPhase("restore")
	}
	if state.Phase == checkpointPhase("restore") && state.Action == "restore" && action == "resume" {
		return checkpointPhase("resume")
	}
	// Compensation is a signed, explicitly linked resume.  It may complete
	// the same restore chain after a release (the release phase is ownership
	// cleanup, not a destructive fence reset), or recover directly from an
	// early checkpoint failure.  Keep it in the resumed phase so the following
	// continue/reuse/release transitions remain legal and idempotent.
	if action == "rollback_resume" && state.Phase >= checkpointPhase("slot_assign") && state.Phase < checkpointPhase("continue") {
		return checkpointPhase("resume")
	}
	if state.Phase == checkpointPhase("resume") && state.Action == "resume" && action == "continue" {
		return checkpointPhase("continue")
	}
	if state.Phase == checkpointPhase("continue") && state.Action == "continue" && action == "reuse_verify" {
		return checkpointPhase("reuse_verify")
	}
	// A resumed stream may be cancelled before its continuation/reuse
	// evidence arrives. Release is still legal from every live resumed state;
	// it is a terminal ownership transition, not a rewind to the initial slot
	// release phase.
	if state.Phase >= checkpointPhase("reload") && state.Phase < checkpointPhase("cancel") && action == "release" {
		return 15
	}
	if state.Phase >= checkpointPhase("resume") && state.Phase < checkpointPhase("cancel") && action == "cancel" {
		return checkpointPhase("cancel")
	}
	if state.Phase == checkpointPhase("reuse_verify") && state.Action == "reuse_verify" && action == "release" {
		return 15
	}
	if state.Phase == checkpointPhase("cancel") && state.Action == "cancel" && action == "release" {
		return 15
	}
	if state.Phase == 15 && state.Action == "release" && action == "release" {
		return 15
	}
	// A normally completed initial stream has already confirmed its backend
	// EOF through the signed state query. It may release its reserved slot
	// without replaying save/stop phases that belong to preemption.
	if state.Phase == checkpointPhase("slot_assign") && state.Action == "slot_assign" && action == "release" {
		return checkpointPhase("release")
	}
	// A pre-existing stream may have been started before the checkpoint
	// journal was introduced.  Its assigned slot can pause directly, but a
	// save still requires the durable pause phase below.
	if state.Phase == checkpointPhase("slot_assign") && state.Action == "slot_assign" && action == "pause" {
		return checkpointPhase("pause")
	}
	return checkpointPhase(action)
}

func checkpointArgUint(args map[string]any, key string) (uint64, error) {
	value, ok := args[key]
	if !ok {
		return 0, fmt.Errorf("checkpoint %s is required", key)
	}
	n, err := exactFenceToken(value)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("checkpoint %s must be positive", key)
	}
	return uint64(n), nil
}

func checkpointArgString(args map[string]any, key string) string {
	value, _ := args[key].(string)
	return strings.TrimSpace(value)
}

// enrichCheckpointPhaseState carries the immutable runtime/snapshot identity
// into the durable node phase journal.  Recovery state queries must report the
// facts accepted by the node, rather than echoing whatever a later controller
// query happened to request.
func enrichCheckpointPhaseState(state checkpointPhaseState, command wsproto.CommandPayload) checkpointPhaseState {
	if value := checkpointArgString(command.Args, "runtime_identity"); value != "" {
		state.RuntimeIdentity = value
	}
	if value := checkpointArgString(command.Args, "model"); value != "" {
		state.ModelFingerprint = value
	}
	if value := checkpointArgString(command.Args, "profile_fingerprint"); value != "" {
		state.ProfileFingerprint = value
	}
	if value := checkpointArgString(command.Args, "context_fingerprint"); value != "" {
		state.ContextFingerprint = value
	}
	if value := checkpointArgString(command.Args, "snapshot_name"); value != "" {
		state.SnapshotName = value
	}
	if value := checkpointArgString(command.Args, "snapshot_digest"); value != "" {
		state.SnapshotDigest = value
	}
	if value := checkpointArgString(command.Args, "conversation_id"); value != "" {
		state.ConversationID = value
	}
	if value := checkpointArgString(command.Args, "continuation_conversation_id"); value != "" {
		state.ContinuationConversationID = value
	}
	return state
}

func checkpointStateIdentityMatchesCommand(state checkpointPhaseState, command wsproto.CommandPayload) bool {
	checks := []struct {
		stored string
		key    string
	}{
		{state.RuntimeIdentity, "runtime_identity"},
		{state.ModelFingerprint, "model"},
		{state.ProfileFingerprint, "profile_fingerprint"},
		{state.ContextFingerprint, "context_fingerprint"},
		{state.SnapshotName, "snapshot_name"},
		{state.SnapshotDigest, "snapshot_digest"},
		{state.ConversationID, "conversation_id"},
		{state.ContinuationConversationID, "continuation_conversation_id"},
	}
	for _, check := range checks {
		if check.stored != "" {
			if requested := checkpointArgString(command.Args, check.key); requested != "" && requested != check.stored {
				return false
			}
		}
	}
	return true
}

func checkpointStateQueryMatchesCommand(state checkpointPhaseState, command wsproto.CommandPayload, requestedSlot int) bool {
	if !checkpointStateIdentityMatchesCommand(state, command) {
		return false
	}
	for _, check := range []struct {
		stored string
		key    string
	}{
		{state.RuntimeIdentity, "runtime_identity"},
		{state.ModelFingerprint, "model"},
		{state.ProfileFingerprint, "profile_fingerprint"},
		{state.ContextFingerprint, "context_fingerprint"},
		{state.SnapshotName, "snapshot_name"},
		{state.SnapshotDigest, "snapshot_digest"},
		{state.ConversationID, "conversation_id"},
		{state.ContinuationConversationID, "continuation_conversation_id"},
	} {
		if requested := checkpointArgString(command.Args, check.key); requested != "" && requested != check.stored {
			return false
		}
	}
	return requestedSlot == state.SlotID
}

func checkpointNodeTransitionAllowed(state checkpointPhaseState, action string, phase int) bool {
	if state.Phase == 0 {
		return action == "slot_assign" && phase == checkpointPhase("slot_assign")
	}
	if phase == state.Phase && action == state.Action {
		return true
	}
	if state.Phase == checkpointPhase("slot_assign") && state.Action == "slot_assign" && action == "start" && phase == checkpointPhase("start") {
		return true
	}
	// A stream may have been registered before this phase journal was added;
	// allow its first pause while still requiring the pause ordinal before save.
	if state.Phase == checkpointPhase("slot_assign") && state.Action == "slot_assign" && action == "pause" && phase == checkpointPhase("pause") {
		return true
	}
	if state.Phase >= checkpointPhase("slot_assign") && state.Phase < checkpointPhase("stop_confirm") && action == "stop_confirm" && phase == checkpointPhase("stop_confirm") {
		return true
	}
	if state.Phase >= checkpointPhase("slot_assign") && state.Phase <= checkpointPhase("start") && action == "release" && phase == checkpointPhase("release") {
		return true
	}
	if state.Phase == checkpointPhase("release") && action == "slot_assign" && phase == 8 {
		return true
	}
	if state.Phase == checkpointPhase("slot_assign") && state.Action == "slot_assign" && action == "reload" && phase == checkpointPhase("reload") {
		return true
	}
	if state.Phase == 8 && state.Action == "slot_assign" && action == "reload" && phase == checkpointPhase("reload") {
		return true
	}
	if state.Phase == checkpointPhase("reload") && action == "restore" && phase == checkpointPhase("restore") {
		return true
	}
	if state.Phase == checkpointPhase("restore") && action == "resume" && phase == checkpointPhase("resume") {
		return true
	}
	if action == "rollback_resume" && state.Phase >= checkpointPhase("slot_assign") && state.Phase < checkpointPhase("continue") && phase == checkpointPhase("resume") {
		return true
	}
	if state.Phase == checkpointPhase("resume") && action == "continue" && phase == checkpointPhase("continue") {
		return true
	}
	if state.Phase == checkpointPhase("continue") && action == "reuse_verify" && phase == checkpointPhase("reuse_verify") {
		return true
	}
	if state.Phase >= checkpointPhase("resume") && state.Phase < checkpointPhase("cancel") && action == "cancel" && phase == checkpointPhase("cancel") {
		return true
	}
	// A resumed conversation is drained by the signed cancel boundary before
	// the physical slot ownership is released. Keep that release explicit and
	// journaled so cancellation cannot strand the restored slot.
	if state.Phase == checkpointPhase("cancel") && action == "release" && phase == 15 {
		return true
	}
	if state.Phase >= checkpointPhase("reload") && state.Phase < checkpointPhase("cancel") && action == "release" && phase == 15 {
		return true
	}
	return phase == state.Phase+1 && ((state.Action == "start" && action == "pause") || (state.Action == "pause" && action == "save") || (state.Action == "save" && action == "stop_confirm") || (state.Action == "stop_confirm" && action == "release"))
}

func (p *commandProcessor) authorizeCheckpointPhase(command wsproto.CommandPayload, targetID, action string, requestedSlot int) (checkpointPhaseState, error) {
	operation, _ := command.Args["checkpoint_operation_id"].(string)
	owner, _ := command.Args["owner_id"].(string)
	workload, _ := command.Args["workload_id"].(string)
	acceleratorID, _ := command.Args["accelerator_id"].(string)
	if strings.TrimSpace(acceleratorID) == "" {
		return checkpointPhaseState{}, fmt.Errorf("checkpoint accelerator identity is required")
	}
	generation, err := checkpointArgUint(command.Args, "generation")
	if err != nil {
		return checkpointPhaseState{}, err
	}
	fence, err := exactFenceToken(command.Args["fencing_token"])
	if err != nil || fence <= 0 {
		return checkpointPhaseState{}, fmt.Errorf("checkpoint fencing_token is invalid")
	}
	phase := checkpointPhaseFor(p.checkpointPhases[operation], action)
	if operation == "" || owner == "" || workload == "" {
		return checkpointPhaseState{}, fmt.Errorf("checkpoint phase identity is incomplete")
	}
	// Slot/state queries are signed, read-only observations. They carry the
	// operation/resource scope but do not consume a lifecycle phase or require
	// an already-materialized phase record; this is what recovery uses when a
	// mutation result is uncertain after a restart.
	if action == "slot_query" {
		if state, exists := p.checkpointPhases[operation]; exists {
			if state.OwnerID != owner || state.WorkloadID != workload || state.TargetID != targetID || state.AcceleratorID != acceleratorID || state.Generation != generation || state.Fence != fence {
				return checkpointPhaseState{}, fmt.Errorf("checkpoint query identity or fence changed")
			}
			if !checkpointStateQueryMatchesCommand(state, command, requestedSlot) {
				return checkpointPhaseState{}, fmt.Errorf("checkpoint query runtime identity changed")
			}
			return state, nil
		}
		// A production proof begins with an authoritative slot inventory before
		// any slot is assigned.  This read-only observation is safe without a
		// phase journal; state_query remains recovery-only and still requires an
		// existing durable operation below.
		return enrichCheckpointPhaseState(checkpointPhaseState{OperationID: operation, OwnerID: owner, WorkloadID: workload, TargetID: targetID, AcceleratorID: acceleratorID, Generation: generation, Fence: fence, SlotID: requestedSlot, Phase: 0}, command), nil
	}
	if action == "state_query" {
		if state, exists := p.checkpointPhases[operation]; exists {
			if state.OwnerID != owner || state.WorkloadID != workload || state.TargetID != targetID || state.AcceleratorID != acceleratorID || state.Generation != generation || state.Fence != fence {
				return checkpointPhaseState{}, fmt.Errorf("checkpoint query identity or fence changed")
			}
			if !checkpointStateQueryMatchesCommand(state, command, requestedSlot) {
				return checkpointPhaseState{}, fmt.Errorf("checkpoint query runtime identity changed")
			}
			return state, nil
		}
		return checkpointPhaseState{}, fmt.Errorf("not_found: checkpoint operation has no durable phase journal")
	}
	if action == "start" || action == "continue" {
		state, exists := p.checkpointPhases[operation]
		if !exists || state.OwnerID != owner || state.WorkloadID != workload || state.TargetID != targetID || state.AcceleratorID != acceleratorID || state.Generation != generation || state.Fence != fence {
			return checkpointPhaseState{}, fmt.Errorf("checkpoint %s is not bound to the operation", action)
		}
		if action == "start" && state.Phase != checkpointPhase("slot_assign") {
			return checkpointPhaseState{}, fmt.Errorf("checkpoint start requires an assigned slot")
		}
		if action == "continue" && state.Phase != checkpointPhase("resume") {
			return checkpointPhaseState{}, fmt.Errorf("checkpoint continuation requires the resumed phase")
		}
		return enrichCheckpointPhaseState(state, command), nil
	}
	if action == "rollback_resume" {
		compensationOf, _ := command.Args["compensation_of"].(string)
		state, exists := p.checkpointPhases[operation]
		if !exists && compensationOf != "" {
			// A compensation is a separate durable operation linked to the
			// original.  Reuse the original node evidence only to authorize the
			// signed rollback, then journal the compensation under its own key.
			for _, candidate := range p.checkpointPhases {
				if candidate.OperationID == compensationOf {
					state, exists = candidate, true
					break
				}
			}
			state.OperationID = operation
		}
		if compensationOf == "" || !exists || state.OwnerID != owner || state.WorkloadID != workload || state.TargetID != targetID || state.AcceleratorID != acceleratorID || state.Generation != generation || state.Fence != fence || state.SlotID != requestedSlot {
			return checkpointPhaseState{}, fmt.Errorf("checkpoint rollback identity or fence is invalid")
		}
		if state.Phase < checkpointPhase("slot_assign") || state.Phase >= checkpointPhase("continue") {
			return checkpointPhaseState{}, fmt.Errorf("checkpoint rollback is not legal from phase %s", state.Action)
		}
		return enrichCheckpointPhaseState(state, command), nil
	}
	if action == "cancel" {
		compensationOf, _ := command.Args["compensation_of"].(string)
		state, exists := p.checkpointPhases[operation]
		if !exists && compensationOf != "" {
			for _, candidate := range p.checkpointPhases {
				if candidate.OperationID == compensationOf {
					state, exists = candidate, true
					break
				}
			}
			state.OperationID = operation
		}
		if compensationOf == "" || !exists || state.OwnerID != owner || state.WorkloadID != workload || state.TargetID != targetID || state.AcceleratorID != acceleratorID || state.Generation != generation || state.Fence != fence || state.SlotID != requestedSlot || state.Phase < checkpointPhase("resume") {
			return checkpointPhaseState{}, fmt.Errorf("checkpoint cancel identity or phase is invalid")
		}
		return enrichCheckpointPhaseState(state, command), nil
	}
	if phase == 0 {
		return checkpointPhaseState{}, fmt.Errorf("checkpoint phase is unknown")
	}
	if requestedSlot >= 0 {
		if existingOwner := p.checkpointSlots[targetID+":"+strconv.Itoa(requestedSlot)]; existingOwner != "" && existingOwner != operation {
			return checkpointPhaseState{}, fmt.Errorf("checkpoint slot is owned by another operation")
		}
	}
	for key, state := range p.checkpointPhases {
		if key == operation {
			continue
		}
		if state.TargetID == targetID && state.AcceleratorID == acceleratorID && state.SlotID >= 0 && (requestedSlot < 0 || requestedSlot == state.SlotID) && state.OperationID != operation {
			if fence <= state.Fence {
				return checkpointPhaseState{}, fmt.Errorf("checkpoint slot is owned by another operation")
			}
		}
	}
	state, exists := p.checkpointPhases[operation]
	if exists {
		if state.OwnerID != owner || state.WorkloadID != workload || state.TargetID != targetID || state.AcceleratorID != acceleratorID || state.Generation != generation || state.Fence != fence {
			return checkpointPhaseState{}, fmt.Errorf("checkpoint phase identity or fence changed")
		}
		if !checkpointStateIdentityMatchesCommand(state, command) {
			return checkpointPhaseState{}, fmt.Errorf("checkpoint phase runtime identity changed")
		}
		if !checkpointNodeTransitionAllowed(state, action, phase) {
			return checkpointPhaseState{}, fmt.Errorf("checkpoint phase %s is out of order after %s", action, state.Action)
		}
		if requestedSlot >= 0 && state.SlotID >= 0 && requestedSlot != state.SlotID {
			return checkpointPhaseState{}, fmt.Errorf("checkpoint slot changed within operation")
		}
		return enrichCheckpointPhaseState(state, command), nil
	}
	if phase != checkpointPhase("slot_assign") {
		return checkpointPhaseState{}, fmt.Errorf("checkpoint operation must begin with slot assignment")
	}
	return enrichCheckpointPhaseState(checkpointPhaseState{OperationID: operation, OwnerID: owner, WorkloadID: workload, TargetID: targetID, AcceleratorID: acceleratorID, Generation: generation, Fence: fence, SlotID: requestedSlot, Phase: 0}, command), nil
}

func (p *commandProcessor) commitCheckpointPhase(state checkpointPhaseState, action string, result map[string]any) {
	state.Phase = checkpointPhaseFor(state, action)
	state.Action = action
	if value, ok := result["snapshot_name"].(string); ok && strings.TrimSpace(value) != "" {
		state.SnapshotName = value
	}
	if value, ok := result["snapshot_digest"].(string); ok && strings.TrimSpace(value) != "" {
		state.SnapshotDigest = value
	}
	if value, ok := result["slot_id"]; ok {
		if n, err := exactFenceToken(value); err == nil {
			state.SlotID = int(n)
		}
	}
	p.checkpointPhases[state.OperationID] = state
	if state.SlotID >= 0 && action != "release" {
		p.checkpointSlots[state.TargetID+":"+strconv.Itoa(state.SlotID)] = state.OperationID
	}
	if action == "release" {
		delete(p.checkpointSlots, state.TargetID+":"+strconv.Itoa(state.SlotID))
	}
}

func isReadOnlyResidencyCommand(command string) bool {
	return command == "query_model_state"
}

func isReadOnlyCheckpointCommand(command string) bool {
	return command == "checkpoint_slot_query" || command == "checkpoint_state_query"
}

func pendingResidencyTier(command string) string {
	switch command {
	case "load_model":
		return "hot_vram"
	case "unload_model", "cleanup_warm_model":
		return "cold_disk"
	case "warm_model", "offload_model", "demote_model", "protect_warm_model", "reverify_warm_model":
		return "warm_ram"
	default:
		return ""
	}
}

func inverseResidencyTier(command string) string {
	switch command {
	case "load_model":
		return "cold_disk"
	case "unload_model":
		return "hot_vram"
	case "warm_model", "demote_model":
		return "hot_vram"
	case "offload_model", "protect_warm_model", "reverify_warm_model":
		return "cold_disk"
	case "cleanup_warm_model":
		return "hot_vram"
	default:
		return ""
	}
}

// queryOriginalBindingMatches prevents a signed query from becoming an
// invented read path. The original mutation must still be a durable pending
// intent, or have a complete durable result under both ID/idempotency aliases.
// Resource and identity checks are repeated here because this gate is used by
// both blocked recovery and the normal live/cached query paths.
func (p *commandProcessor) queryOriginalBindingMatches(command wsproto.CommandPayload) bool {
	if command.Command != "query_model_state" {
		return true
	}
	originalID, idOK := command.Args["original_command_id"].(string)
	originalKey, keyOK := command.Args["original_idempotency_key"].(string)
	targetKind, targetKindOK := command.Args["target_kind"].(string)
	targetID, targetOK := command.Args["target_id"].(string)
	model, modelOK := command.Args["model"].(string)
	runtimeIdentity, identityOK := command.Args["runtime_identity"].(string)
	if !idOK || !keyOK || !targetKindOK || !targetOK || !modelOK || !identityOK || strings.TrimSpace(originalID) == "" || strings.TrimSpace(originalKey) == "" || strings.TrimSpace(targetKind) == "" || strings.TrimSpace(targetID) == "" || strings.TrimSpace(model) == "" || strings.TrimSpace(runtimeIdentity) == "" {
		return false
	}
	for _, pending := range p.pending {
		if pending.Command != "query_model_state" && pending.CommandID == originalID && pending.IdempotencyKey == originalKey && pending.TargetID == targetID && pending.Model == model && pending.RuntimeIdentity == runtimeIdentity {
			return true
		}
	}
	original, byID := p.results[originalID]
	byKey, byKeyOK := p.results["key:"+originalKey]
	if !byID || !byKeyOK || !reflect.DeepEqual(original, byKey) || original.ID != originalID || original.NodeID != p.cfg.NodeID || original.Result == nil || (!original.OK && !original.Uncertain && (original.Status != "failed" || original.Error == "")) {
		return false
	}
	if action, ok := original.Result["action"].(string); !ok || action == "" || action == "query_model_state" {
		return false
	}
	if original.Result["target_kind"] != targetKind || original.Result["target_id"] != targetID || original.Result["model"] != model || original.Result["runtime_identity"] != runtimeIdentity || original.Result["original_command_id"] != originalID || original.Result["original_idempotency_key"] != originalKey {
		return false
	}
	resultFingerprint, resultFingerprintOK := original.Result["command_fingerprint"].(string)
	resultFingerprintAlias, resultAliasOK := original.Result["fingerprint"].(string)
	byIDFingerprint, idFingerprintOK := p.commandFingerprints["id:"+originalID]
	byKeyFingerprint, keyFingerprintOK := p.commandFingerprints[originalKey]
	originalFence, originalFenceErr := exactFenceToken(original.Result["observed_after_fence"])
	queryFence, queryFenceErr := exactFenceToken(command.Args["expected_fence"])
	resultCommandFence, resultCommandFenceErr := exactFenceToken(original.Result["fencing_token"])
	matched := resultFingerprintOK && resultAliasOK && resultFingerprint != "" && resultFingerprint == resultFingerprintAlias && idFingerprintOK && keyFingerprintOK && byIDFingerprint == resultFingerprint && byKeyFingerprint == resultFingerprint && originalFenceErr == nil && queryFenceErr == nil && resultCommandFenceErr == nil && originalFence == queryFence && resultCommandFence == queryFence
	return matched
}

// completedQueryMatches is the completed-original query fence. A query may
// inspect a completed mutation only when its named original has the exact
// canonical resource, semantic fingerprint, and committed fence. In
// particular, a later fence may not be used to replay an older original from
// the result cache.
func (p *commandProcessor) completedQueryMatches(command wsproto.CommandPayload) bool {
	if command.Command != "query_model_state" || !p.queryOriginalBindingMatches(command) {
		return false
	}
	originalID, _ := command.Args["original_command_id"].(string)
	original, ok := p.results[originalID]
	if !ok || original.Result == nil || original.Uncertain || (!original.OK && (original.Status != "failed" || original.Error == "")) {
		return false
	}
	action, actionOK := original.Result["action"].(string)
	if !actionOK || action == "" || action == "query_model_state" {
		return false
	}
	// The original result must itself be a complete, action-specific proof;
	// an old tier-only cache is not a valid anchor for a new query.
	if (original.OK && validateLiveResidencyResult(action, original.Result) != nil) || (!original.OK && (original.Result["rolled_back"] != true || !mutationResultProvesAction(action, original.Result, action))) {
		return false
	}
	want, wantErr := exactFenceToken(original.Result["fencing_token"])
	got, gotErr := exactFenceToken(command.Args["expected_fence"])
	targetID, targetOK := command.Args["target_id"].(string)
	model, modelOK := command.Args["model"].(string)
	currentFence, currentOK := p.fences[fenceKey(targetID, model)]
	return wantErr == nil && gotErr == nil && targetOK && modelOK && targetID != "" && model != "" && currentOK && currentFence == want && want == got
}

func residencyResultProvesAction(action string, result map[string]any, expectedAction string, requireUnchanged bool) bool {
	if result == nil || action == "" || action != expectedAction {
		return false
	}
	resident, residentOK := result["resident"].(bool)
	warm, warmOK := result["warm_ram"].(bool)
	tier, tierOK := result["tier"].(string)
	if !residentOK || !warmOK || !tierOK {
		return false
	}
	if !residencyResultHasExactTierSchema(action, result, tier) {
		return false
	}
	hot := func() bool {
		changed, changedOK := result["changed"].(bool)
		return tier == "hot_vram" && resident && !warm && changedOK && (!requireUnchanged || !changed)
	}
	cold := func() bool {
		cleaned, cleanedOK := result["cleaned"].(bool)
		absent, absentOK := result["warm_entry_absent"].(bool)
		released, releasedOK := result["warm_release_verified"].(bool)
		bytes, bytesErr := exactFenceToken(result["warm_model_bytes"])
		locked, lockedErr := exactFenceToken(result["locked_bytes"])
		changed, changedOK := result["changed"].(bool)
		return tier == "cold_disk" && !resident && !warm && cleanedOK && cleaned && absentOK && absent && releasedOK && released && bytesErr == nil && lockedErr == nil && bytes == 0 && locked == 0 && changedOK && (!requireUnchanged || !changed)
	}
	warmProof := func(requireProtection bool) bool {
		verified, verifiedOK := result["warm_model_bytes_verified"].(bool)
		released, releasedOK := result["released_vram"].(bool)
		oracle, oracleOK := result["oracle"].(string)
		bytes, bytesErr := exactFenceToken(result["warm_model_bytes"])
		locked, lockedErr := exactFenceToken(result["locked_bytes"])
		if tier != "warm_ram" || resident || !warm || !verifiedOK || !verified || !releasedOK || !released || !oracleOK || oracle != "mincore+mlock" || bytesErr != nil || lockedErr != nil || bytes <= 0 || locked < bytes {
			return false
		}
		if requireProtection {
			_, protectedOK := result["protected"].(bool)
			refs, refsErr := exactFenceToken(result["active_references"])
			return protectedOK && refsErr == nil && refs >= 0
		}
		return true
	}
	switch action {
	case "load_model":
		return hot() || cold()
	case "unload_model":
		return cold() || hot()
	case "warm_model", "demote_model":
		return warmProof(false) || hot()
	case "offload_model":
		return warmProof(false) || cold()
	case "protect_warm_model":
		return warmProof(true) || cold()
	case "cleanup_warm_model":
		return cold() || hot()
	case "reverify_warm_model":
		return warmProof(false) || cold()
	default:
		return false
	}
}

func residencyResultHasExactTierSchema(action string, result map[string]any, tier string) bool {
	if tier == "warm_ram" {
		for _, key := range []string{"cleaned", "warm_entry_absent", "warm_release_verified"} {
			if _, present := result[key]; present {
				return false
			}
		}
		return true
	}
	if tier == "hot_vram" {
		// Hot is a minimal proof. Cleanup/absence/release and zero-byte
		// counters belong exclusively to cold observations.
		for _, key := range []string{"cleaned", "warm_entry_absent", "warm_release_verified", "warm_model_bytes", "locked_bytes"} {
			if _, present := result[key]; present {
				return false
			}
		}
	}
	// Non-warm states cannot carry a warm proof (or protection claim) from
	// another state. Cold cleanup fields are checked by the action proof.
	for _, key := range []string{"warm_model_bytes_verified", "released_vram", "oracle", "protected", "active_references"} {
		if _, present := result[key]; present {
			return false
		}
	}
	return tier == "hot_vram" || tier == "cold_disk"
}

func queryResultProvesAction(action string, result map[string]any, expectedAction string) bool {
	return residencyResultProvesAction(action, result, expectedAction, true)
}

func mutationResultProvesAction(action string, result map[string]any, expectedAction string) bool {
	return residencyResultProvesAction(action, result, expectedAction, false)
}

func (p *commandProcessor) queryOriginalCommandExists(command wsproto.CommandPayload) bool {
	if command.Command != "query_model_state" {
		return true
	}
	originalID, idOK := command.Args["original_command_id"].(string)
	originalKey, keyOK := command.Args["original_idempotency_key"].(string)
	if !idOK || !keyOK || strings.TrimSpace(originalID) == "" || strings.TrimSpace(originalKey) == "" {
		return false
	}
	for _, pending := range p.pending {
		if pending.Command != "query_model_state" && pending.CommandID == originalID && pending.IdempotencyKey == originalKey {
			return true
		}
	}
	original, byID := p.results[originalID]
	byKey, byKeyOK := p.results["key:"+originalKey]
	matched := byID && byKeyOK && reflect.DeepEqual(original, byKey) && original.ID == originalID && original.NodeID == p.cfg.NodeID && original.Result != nil && (original.OK || original.Uncertain || (original.Status == "failed" && original.Error != ""))
	return matched
}

// pendingQueryMatches is deliberately narrow: a query can pass the blocked
// state gate only when it names the same canonical resource, runtime identity,
// and mutation fence as a durable pending intent.
func (p *commandProcessor) pendingQueryMatches(ctx context.Context, command wsproto.CommandPayload) bool {
	if !p.strictResidencyEnvelope || command.Command != "query_model_state" {
		return false
	}
	if !p.queryOriginalBindingMatches(command) {
		return false
	}
	targetID, _ := command.Args["target_id"].(string)
	model, _ := command.Args["model"].(string)
	reference, err := exactFenceToken(command.Args["expected_fence"])
	originalID, _ := command.Args["original_command_id"].(string)
	originalKey, _ := command.Args["original_idempotency_key"].(string)
	if err != nil || targetID == "" || model == "" || originalID == "" || originalKey == "" {
		return false
	}
	server, ok := p.routerTarget(targetID)
	if !ok {
		return false
	}
	discovery, err := DiscoverLlamaCPP(ctx, p.cfg.NodeID, server)
	if err != nil {
		return false
	}
	canonicalTarget := p.cfg.NodeID + "-" + server.ID
	identity, envelopeErr := p.validateResidencyCommandEnvelope(command, canonicalTarget, model, discovery)
	if envelopeErr != "" || identity != command.Args["runtime_identity"] {
		return false
	}
	for _, pending := range p.pending {
		if pending.CommandID == originalID && pending.IdempotencyKey == originalKey && pending.TargetID == canonicalTarget && pending.Model == model && pending.RuntimeIdentity != "" && pending.RuntimeIdentity == identity && pending.Token >= 0 && uint64(pending.Token) == uint64(reference) && p.fences[fenceKey(canonicalTarget, model)] == reference && pendingResidencyTier(pending.Command) != "" {
			return true
		}
	}
	return false
}

// queryOriginalAction validates the durable object named by a query before a
// cached observation is considered authoritative.  The observation's action
// is never allowed to define its own anchor: it must match this pending
// manifest or this completed original result under the same fence.
func (p *commandProcessor) queryOriginalAction(command wsproto.CommandPayload) (string, bool) {
	if command.Command != "query_model_state" || wsproto.ValidateResidencyCommandArgs(command.Command, command.Args) != nil {
		return "", false
	}
	originalID, _ := command.Args["original_command_id"].(string)
	originalKey, _ := command.Args["original_idempotency_key"].(string)
	targetID, _ := command.Args["target_id"].(string)
	model, _ := command.Args["model"].(string)
	expectedFence, err := exactFenceToken(command.Args["expected_fence"])
	if err != nil {
		return "", false
	}
	for _, pending := range p.pending {
		if pending.CommandID != originalID || pending.IdempotencyKey != originalKey || pending.TargetID != targetID || pending.Model != model {
			continue
		}
		manifest, manifestErr := p.validatePendingManifest(pending)
		if manifestErr != nil || manifest.Action == "query_model_state" || manifest.Action == "" || manifest.FencingToken != expectedFence || p.fences[fenceKey(targetID, model)] != expectedFence {
			continue
		}
		if manifest.TargetKind != command.Args["target_kind"] || manifest.RuntimeIdentity != command.Args["runtime_identity"] || manifest.CapabilityVersion != command.Args["capability_version"] || manifest.CapabilityRevision != command.Args["capability_revision"] {
			continue
		}
		return manifest.Action, true
	}
	original, byID := p.results[originalID]
	byKey, byKeyOK := p.results["key:"+originalKey]
	if !byID || !byKeyOK || !reflect.DeepEqual(original, byKey) || original.ID != originalID || original.NodeID != p.cfg.NodeID || original.Result == nil || original.Uncertain || (!original.OK && (original.Status != "failed" || original.Error == "")) {
		return "", false
	}
	action, actionOK := original.Result["action"].(string)
	if !actionOK || action == "" || action == "query_model_state" || (original.OK && validateLiveResidencyResult(action, original.Result) != nil) || (!original.OK && (original.Result["rolled_back"] != true || !mutationResultProvesAction(action, original.Result, action))) {
		return "", false
	}
	if original.Result["target_kind"] != command.Args["target_kind"] || original.Result["target_id"] != targetID || original.Result["model"] != model || original.Result["runtime_identity"] != command.Args["runtime_identity"] || original.Result["capability_version"] != command.Args["capability_version"] || original.Result["capability_revision"] != command.Args["capability_revision"] || original.Result["original_command_id"] != originalID || original.Result["original_idempotency_key"] != originalKey {
		return "", false
	}
	resultFingerprint, resultFingerprintOK := original.Result["command_fingerprint"].(string)
	resultFingerprintAlias, resultAliasOK := original.Result["fingerprint"].(string)
	if !resultFingerprintOK || !resultAliasOK || resultFingerprint == "" || resultFingerprint != resultFingerprintAlias || p.commandFingerprints["id:"+originalID] != resultFingerprint || p.commandFingerprints[originalKey] != resultFingerprint {
		return "", false
	}
	originalFence, originalFenceErr := exactFenceToken(original.Result["observed_after_fence"])
	resultCommandFence, resultCommandFenceErr := exactFenceToken(original.Result["fencing_token"])
	if originalFenceErr != nil || resultCommandFenceErr != nil || originalFence != expectedFence || resultCommandFence != expectedFence || p.fences[fenceKey(targetID, model)] != expectedFence {
		return "", false
	}
	return action, true
}

// cachedAuthoritativeObservation is a terminal result produced by a signed
// read-only reconciliation query. An exact replay is safe after restart even
// while an unrelated warm journal remains blocked.
func (p *commandProcessor) cachedAuthoritativeObservation(command wsproto.CommandPayload) bool {
	return p.cachedAuthoritativeObservationWithLive(context.Background(), command, false)
}

func (p *commandProcessor) cachedAuthoritativeObservationContext(ctx context.Context, command wsproto.CommandPayload) bool {
	return p.cachedAuthoritativeObservationWithLive(ctx, command, true)
}

func (p *commandProcessor) cachedAuthoritativeObservationWithLive(ctx context.Context, command wsproto.CommandPayload, checkLive bool) bool {
	if checkLive && !p.currentCacheRuntimeBindingsMatch(ctx, command) {
		return false
	}
	originalAction, originalOK := p.queryOriginalAction(command)
	if !originalOK {
		return false
	}
	result, byID := p.results[command.ID]
	byKeyResult, byKey := p.results["key:"+command.IdempotencyKey]
	if !byID || !byKey || !reflect.DeepEqual(result, byKeyResult) || result.ID != command.ID || result.NodeID != p.cfg.NodeID || !result.OK || result.Uncertain || result.Error != "" || result.Result == nil {
		return false
	}
	expectedFingerprint := p.semanticFingerprint(command)
	fingerprintByID, fingerprintIDOK := p.commandFingerprints["id:"+command.ID]
	fingerprintByKey, fingerprintKeyOK := p.commandFingerprints[command.IdempotencyKey]
	resultFingerprint, resultFingerprintOK := result.Result["command_fingerprint"].(string)
	resultFingerprintAlias, resultFingerprintAliasOK := result.Result["fingerprint"].(string)
	if !fingerprintIDOK || !fingerprintKeyOK || fingerprintByID != expectedFingerprint || fingerprintByKey != expectedFingerprint || !resultFingerprintOK || !resultFingerprintAliasOK || resultFingerprint != expectedFingerprint || resultFingerprintAlias != expectedFingerprint {
		return false
	}
	for _, field := range []string{"target_kind", "target_id", "model", "runtime_identity", "capability_version", "capability_revision", "tier", "original_command_id", "original_idempotency_key", "expected_fence", "fencing_token", "observed_after_fence"} {
		if result.Result[field] == nil {
			return false
		}
	}
	action, actionOK := result.Result["action"].(string)
	if !actionOK || !isResidencyCommand(action) || action == "query_model_state" || action != originalAction || result.Result["target_kind"] != "llamacpp" || result.Result["node_id"] != p.cfg.NodeID || result.Result["command_id"] != command.ID || result.Result["idempotency_key"] != command.IdempotencyKey || result.Result["original_command_id"] != command.Args["original_command_id"] || result.Result["original_idempotency_key"] != command.Args["original_idempotency_key"] || result.Result["target_id"] != command.Args["target_id"] || result.Result["model"] != command.Args["model"] || result.Result["runtime_identity"] != command.Args["runtime_identity"] || result.Result["capability_version"] != command.Args["capability_version"] || result.Result["capability_revision"] != command.Args["capability_revision"] {
		return false
	}
	allowed := cachedResidencyResultAllowedKeys(action)
	allowed["expected_fence"] = true
	for _, key := range []string{"cleaned", "warm_entry_absent", "warm_release_verified", "warm_model_bytes", "locked_bytes"} {
		allowed[key] = true
	}
	for key := range result.Result {
		if !allowed[key] {
			return false
		}
	}
	if !queryResultProvesAction(action, result.Result, action) {
		return false
	}
	tier, tierOK := result.Result["tier"].(string)
	if !tierOK || (tier != "hot_vram" && tier != "warm_ram" && tier != "cold_disk") {
		return false
	}
	if !residencyResultHasExactTierSchema(action, result.Result, tier) {
		return false
	}
	expectedFence, expectedErr := exactFenceToken(command.Args["expected_fence"])
	commandFence, commandFenceErr := exactFenceToken(command.Args["fencing_token"])
	observedFence, observedErr := exactFenceToken(command.Args["observed_after_fence"])
	resultExpected, resultExpectedErr := exactFenceToken(result.Result["expected_fence"])
	resultCommand, resultCommandErr := exactFenceToken(result.Result["fencing_token"])
	resultObserved, resultObservedErr := exactFenceToken(result.Result["observed_after_fence"])
	if expectedErr != nil || commandFenceErr != nil || observedErr != nil || resultExpectedErr != nil || resultCommandErr != nil || resultObservedErr != nil || expectedFence != commandFence || commandFence != observedFence || resultExpected != expectedFence || resultCommand != expectedFence || resultObserved != expectedFence {
		return false
	}
	return expectedFence == commandFence && commandFence == observedFence && resultExpected == expectedFence && resultCommand == expectedFence && resultObserved == expectedFence && p.fences[fenceKey(fmt.Sprint(command.Args["target_id"]), fmt.Sprint(command.Args["model"]))] == expectedFence
}

func queryResultProvesPendingAction(pending pendingCommand, result map[string]any) bool {
	if result == nil || result["action"] != pending.Command {
		return false
	}
	if !queryResultProvesAction(pending.Command, result, pending.Command) {
		return false
	}
	if pending.Command == "protect_warm_model" {
		if tier, _ := result["tier"].(string); tier == "warm_ram" {
			protected, protectedOK := result["protected"].(bool)
			refs, refsErr := exactFenceToken(result["active_references"])
			if !protectedOK || protected != pending.Protected || refsErr != nil || refs != int64(pending.ActiveReferences) {
				return false
			}
		}
	}
	return true
	/*
		resident, residentOK := result["resident"].(bool)
		warm, warmOK := result["warm_ram"].(bool)
		tier, tierOK := result["tier"].(string)
		if !residentOK || !warmOK || !tierOK {
			return false
		}
		switch pending.Command {
		case "load_model":
			return tier == "hot_vram" && resident && !warm
		case "unload_model":
			return tier == "cold_disk" && !resident && !warm
		case "cleanup_warm_model":
			cleaned, cleanedOK := result["cleaned"].(bool)
			absent, absentOK := result["warm_entry_absent"].(bool)
			released, releasedOK := result["warm_release_verified"].(bool)
			bytes, bytesErr := exactFenceToken(result["warm_model_bytes"])
			locked, lockedErr := exactFenceToken(result["locked_bytes"])
			return tier == "cold_disk" && !resident && !warm && cleanedOK && cleaned && absentOK && absent && releasedOK && released && bytesErr == nil && lockedErr == nil && bytes == 0 && locked == 0
		case "warm_model", "offload_model", "demote_model", "reverify_warm_model", "protect_warm_model":
			if tier == "hot_vram" {
				return resident && !warm
			}
			if tier == "cold_disk" {
				cleaned, cleanedOK := result["cleaned"].(bool)
				absent, absentOK := result["warm_entry_absent"].(bool)
				released, releasedOK := result["warm_release_verified"].(bool)
				bytes, bytesErr := exactFenceToken(result["warm_model_bytes"])
				locked, lockedErr := exactFenceToken(result["locked_bytes"])
				return !resident && !warm && cleanedOK && cleaned && absentOK && absent && releasedOK && released && bytesErr == nil && lockedErr == nil && bytes == 0 && locked == 0
			}
			verified, verifiedOK := result["warm_model_bytes_verified"].(bool)
			released, releasedOK := result["released_vram"].(bool)
			oracle, oracleOK := result["oracle"].(string)
			bytes, bytesErr := exactFenceToken(result["warm_model_bytes"])
			locked, lockedErr := exactFenceToken(result["locked_bytes"])
			if tier != "warm_ram" || resident || !warm || !verifiedOK || !verified || !releasedOK || !released || !oracleOK || oracle != "mincore+mlock" || bytesErr != nil || lockedErr != nil || bytes <= 0 || locked < bytes {
				return false
			}
			if pending.Command == "protect_warm_model" {
				protected, protectedOK := result["protected"].(bool)
				refs, refsErr := exactFenceToken(result["active_references"])
				return protectedOK && protected == pending.Protected && refsErr == nil && refs == int64(pending.ActiveReferences)
			}
			return true
		default:
			return false
		}
	*/
}

func (p *commandProcessor) settlePendingFromQuery(command wsproto.CommandPayload, queryResult wsproto.CommandResultPayload) {
	targetID, _ := command.Args["target_id"].(string)
	model, _ := command.Args["model"].(string)
	reference, err := exactFenceToken(command.Args["observed_after_fence"])
	if err != nil {
		return
	}
	if queryResult.Result == nil || queryResult.Result["target_kind"] != "llamacpp" || queryResult.Result["target_id"] != targetID || queryResult.Result["model"] != model || queryResult.Result["runtime_identity"] != command.Args["runtime_identity"] || queryResult.Result["capability_version"] != command.Args["capability_version"] || queryResult.Result["capability_revision"] != command.Args["capability_revision"] || queryResult.Result["original_command_id"] != command.Args["original_command_id"] || queryResult.Result["original_idempotency_key"] != command.Args["original_idempotency_key"] {
		return
	}
	expectedFence, expectedErr := exactFenceToken(command.Args["expected_fence"])
	commandFence, commandFenceErr := exactFenceToken(command.Args["fencing_token"])
	observedFence, observedErr := exactFenceToken(command.Args["observed_after_fence"])
	resultExpected, resultExpectedErr := exactFenceToken(queryResult.Result["expected_fence"])
	resultCommand, resultCommandErr := exactFenceToken(queryResult.Result["fencing_token"])
	resultObserved, resultObservedErr := exactFenceToken(queryResult.Result["observed_after_fence"])
	if expectedErr != nil || commandFenceErr != nil || observedErr != nil || resultExpectedErr != nil || resultCommandErr != nil || resultObservedErr != nil || expectedFence != commandFence || commandFence != observedFence || resultExpected != expectedFence || resultCommand != expectedFence || resultObserved != expectedFence {
		return
	}
	tier, _ := queryResult.Result["tier"].(string)
	for id, pending := range p.pending {
		queryIdentity, _ := command.Args["runtime_identity"].(string)
		if pending.CommandID != command.Args["original_command_id"] || pending.IdempotencyKey != command.Args["original_idempotency_key"] || pending.TargetID != targetID || pending.Model != model || pending.RuntimeIdentity == "" || queryIdentity == "" || pending.RuntimeIdentity != queryIdentity || pending.Token < 0 || uint64(pending.Token) != uint64(reference) || pending.Fingerprint == "" {
			continue
		}
		// Reconciliation is authorized only by the durable canonical original
		// manifest. A tier/proof-shaped query cannot stand in for a missing or
		// invalid manifest, because it is not bound to the signed arguments.
		if pending.ManifestJSON == "" {
			continue
		}
		if _, manifestErr := p.validatePendingManifest(pending); manifestErr != nil {
			continue
		}
		desired := pendingResidencyTier(pending.Command)
		if desired == "" || !queryResultProvesPendingAction(pending, queryResult.Result) {
			continue
		}
		correlatedResult := make(map[string]any, len(queryResult.Result)+10)
		for key, value := range queryResult.Result {
			correlatedResult[key] = value
		}
		correlatedResult["action"] = pending.Command
		correlatedResult["reconciled"] = true
		correlatedResult["rolled_back"] = tier != desired
		correlatedResult["command_id"] = pending.CommandID
		correlatedResult["idempotency_key"] = pending.IdempotencyKey
		correlatedResult["original_command_id"] = pending.CommandID
		correlatedResult["original_idempotency_key"] = pending.IdempotencyKey
		correlatedResult["command_fingerprint"] = pending.Fingerprint
		correlatedResult["fingerprint"] = pending.Fingerprint
		correlated := wsproto.CommandResultPayload{ID: pending.CommandID, NodeID: p.cfg.NodeID, Status: "succeeded", Result: correlatedResult, CompletedAt: queryResult.CompletedAt, OK: tier == desired}
		if !correlated.OK {
			correlated.Status = "failed"
			correlated.Error = "authoritative query proved the pending mutation was rolled back"
		}
		p.results[pending.CommandID] = correlated
		p.results["key:"+pending.IdempotencyKey] = correlated
		p.commandFingerprints["id:"+pending.CommandID] = pending.Fingerprint
		p.commandFingerprints[pending.IdempotencyKey] = pending.Fingerprint
		delete(p.pending, id)
		delete(p.inflight, fenceKey(targetID, model))
	}
	if len(p.pending) == 0 && p.stateBlockReason == blockReasonWarmTransient {
		p.stateBlocked = false
		p.stateBlockReason = ""
	}
	_ = p.save()
}

func (p *commandProcessor) preflightResidencyEnvelope(ctx context.Context, command wsproto.CommandPayload) error {
	targetID, _ := command.Args["target_id"].(string)
	server, ok := p.routerTarget(targetID)
	if !ok {
		return errors.New("target is not an allowlisted local inference server")
	}
	canonicalTarget := p.cfg.NodeID + "-" + server.ID
	model, _ := command.Args["model"].(string)
	discovery, err := DiscoverLlamaCPP(ctx, p.cfg.NodeID, server)
	if err != nil {
		return errors.New("router discovery failed: " + err.Error())
	}
	if !containsModel(discovery.Models, model) {
		return errors.New("model is not an allowlisted runtime model")
	}
	_, envelopeErr := p.validateResidencyCommandEnvelope(command, canonicalTarget, model, discovery)
	if envelopeErr != "" {
		return errors.New(envelopeErr)
	}
	return nil
}

func canonicalCommandRuntimeIdentity(targetID string, discovery wsproto.AdapterAdvertisement) string {
	return strings.Join([]string{targetID, "llamacpp", "", discovery.Version, discovery.ModelFingerprint}, "|")
}

func (p *commandProcessor) capabilityRevision() string {
	if strings.TrimSpace(p.cfg.Capabilities.Version) != "" {
		return p.cfg.Capabilities.Version
	}
	return p.cfg.CapabilityVersion
}

func (p *commandProcessor) validateResidencyCommandEnvelope(command wsproto.CommandPayload, targetID, model string, discovery wsproto.AdapterAdvertisement) (string, string) {
	identity := canonicalCommandRuntimeIdentity(targetID, discovery)
	if targetValue, ok := command.Args["target_id"].(string); !ok || targetValue != targetID || model == "" {
		return identity, "command target and model identity are required"
	}
	configuredRevision := strings.TrimSpace(p.cfg.Capabilities.Version)
	if configuredRevision == "" {
		configuredRevision = strings.TrimSpace(p.cfg.CapabilityVersion)
	}
	// Every enrolled node with a configured lifecycle schema must receive the
	// complete signed envelope. Legacy direct handlers with no advertised
	// schema remain unsupported for lifecycle promises and are kept only for
	// compatibility with the pre-contract command surface.
	if p.strictResidencyEnvelope {
		if p.cfg.Capabilities.Version != domain.CapabilityContractVersion || strings.TrimSpace(p.cfg.CapabilityVersion) == "" {
			return identity, "residency capability schema/runtime is not configured; lifecycle command is unsupported"
		}
		if err := wsproto.ValidateResidencyCommandArgs(command.Command, command.Args); err != nil {
			return identity, err.Error()
		}
	}
	if configuredRevision != "" {
		capabilityRevision, ok := command.Args["capability_revision"].(string)
		if !ok || capabilityRevision == "" || capabilityRevision != configuredRevision {
			return identity, "command capability revision is required and does not match node schema"
		}
		capabilityVersion, ok := command.Args["capability_version"].(string)
		if !ok || capabilityVersion == "" || capabilityVersion != discovery.Version {
			return identity, "command runtime capability identity is required and does not match discovery"
		}
		runtimeIdentity, ok := command.Args["runtime_identity"].(string)
		if !ok || runtimeIdentity == "" || runtimeIdentity != identity {
			return identity, "command runtime identity is required and does not match authoritative discovery"
		}
		expectedTier, ok := command.Args["expected_tier"].(string)
		if !ok || expectedTier == "" || expectedTier != expectedResidencyTier(command.Command) {
			return identity, "command expected residency tier is required and does not match operation"
		}
		if command.Command == "query_model_state" {
			if targetKind, ok := command.Args["target_kind"].(string); !ok || targetKind != "llamacpp" {
				return identity, "query target_kind is required"
			}
			originalID, idOK := command.Args["original_command_id"].(string)
			originalKey, keyOK := command.Args["original_idempotency_key"].(string)
			if !idOK || strings.TrimSpace(originalID) == "" || !keyOK || strings.TrimSpace(originalKey) == "" {
				return identity, "query original command linkage is required"
			}
			expected, expectedErr := exactFenceToken(command.Args["expected_fence"])
			reference, referenceErr := exactFenceToken(command.Args["observed_after_fence"])
			if expectedErr != nil || referenceErr != nil || expected < 0 || reference != expected {
				return identity, "query expected_fence is required and must match observed_after_fence"
			}
		}
	} else if p.strictResidencyEnvelope {
		return identity, "residency capability schema is not configured; lifecycle command is unsupported"
	}
	return identity, ""
}

func expectedResidencyTier(command string) string {
	switch command {
	case "load_model":
		return "hot_vram"
	case "unload_model", "cleanup_warm_model":
		return "cold_disk"
	case "warm_model", "offload_model", "demote_model", "protect_warm_model", "reverify_warm_model":
		return "warm_ram"
	case "query_model_state":
		return "query"
	default:
		return ""
	}
}

func (p *commandProcessor) normalizeCommandTarget(command wsproto.CommandPayload) wsproto.CommandPayload {
	target, ok := command.Args["target_id"].(string)
	if !ok || target == "" {
		return command
	}
	server, found := p.routerTarget(target)
	if !found {
		return command
	}
	args := make(map[string]any, len(command.Args)+1)
	for key, value := range command.Args {
		args[key] = value
	}
	args["target_id"] = p.cfg.NodeID + "-" + server.ID
	command.Args = args
	return command
}

// commandHasExternalSideEffect identifies commands whose execute path may
// have crossed the node/runtime boundary. It is deliberately conservative:
// retaining a retryable intent is safer than discarding a fence after an
// ambiguous or partial mutation.
func commandHasExternalSideEffect(command wsproto.CommandPayload) bool {
	switch command.Command {
	case "llm_displacement_stop", checkpointPlanRelaunchUrgentCommand, checkpointPlanRelaunchVictimCommand:
		return true
	case "llm_displacement_stop_query", checkpointPlanRelaunchQueryCommand:
		return false
	case "reclaim_accelerator", "drain_runtimes", "switch_runtime_profile", "set_gpu_performance_profile",
		"load_model", "unload_model", "warm_model", "offload_model", "demote_model",
		"protect_warm_model", "cleanup_warm_model", "reverify_warm_model", "refresh_capabilities":
		return true
	default:
		return isCheckpointCommand(command.Command) && command.Command != "checkpoint_slot_query" && command.Command != "checkpoint_state_query"
	}
}

func isWarmLifecycleCommand(command string) bool {
	switch command {
	case "warm_model", "offload_model", "demote_model", "protect_warm_model", "cleanup_warm_model", "reverify_warm_model":
		return true
	default:
		return false
	}
}

func (p *commandProcessor) pendingCleanupFor(command wsproto.CommandPayload) bool {
	target, _ := command.Args["target_id"].(string)
	model, _ := command.Args["model"].(string)
	if server, ok := p.routerTarget(target); ok {
		target = p.cfg.NodeID + "-" + server.ID
	}
	for _, pending := range p.pending {
		if pending.Command == "cleanup_warm_model" && pending.TargetID == target && pending.Model == model {
			return true
		}
	}
	return false
}

// pendingWarmCleanupRetryFor permits the explicit cleanup operation to replace
// an uncertain warm/offload intent.  It is deliberately narrower than the
// general block exception: there must be a matching retry handle, and that
// handle must not still advertise verified residency.
func (p *commandProcessor) pendingWarmCleanupRetryFor(command wsproto.CommandPayload) bool {
	target, _ := command.Args["target_id"].(string)
	model, _ := command.Args["model"].(string)
	if server, ok := p.routerTarget(target); ok {
		target = p.cfg.NodeID + "-" + server.ID
	}
	if p.warmRAM == nil || !p.warmRAM.HasEntryFor(target, model) || p.warmRAM.IsVerifiedFor(target, model) {
		return false
	}
	for _, pending := range p.pending {
		if pending.TargetID == target && isWarmLifecycleCommand(pending.Command) {
			return true
		}
	}
	return false
}

func safeCommandHash(command wsproto.CommandPayload) string {
	sum := sha256.Sum256([]byte(command.ID + ":" + command.Command))
	return hex.EncodeToString(sum[:])[:16]
}

func pendingManifestFor(command wsproto.CommandPayload, normalized map[string]any, target, model string, token int64, intent pendingCommand) ([]byte, error) {
	targetKind, _ := normalized["target_kind"].(string)
	if targetKind == "" {
		if isResourceCommand(command.Command) {
			targetKind = "resource"
		} else if model != "" {
			targetKind = "llamacpp"
		} else {
			targetKind = "resource"
		}
	}
	runtimeIdentity, _ := normalized["runtime_identity"].(string)
	capabilityVersion, _ := normalized["capability_version"].(string)
	capabilityRevision, _ := normalized["capability_revision"].(string)
	expectedTier, _ := normalized["expected_tier"].(string)
	if expectedTier == "" {
		expectedTier = expectedResidencyTier(command.Command)
	}
	manifest := pendingOperationManifest{
		SchemaVersion: pendingManifestVersion,
		Action:        command.Command, CommandID: command.ID, IdempotencyKey: command.IdempotencyKey,
		NodeID:      command.NodeID,
		Fingerprint: intent.Fingerprint, TargetKind: targetKind, TargetID: target, Model: model,
		RuntimeIdentity: runtimeIdentity, CapabilityVersion: capabilityVersion,
		CapabilityRevision: capabilityRevision, ExpectedTier: expectedTier, FencingToken: token,
		ActiveReferences: intent.ActiveReferences, Protected: intent.Protected, Args: normalized,
	}
	return json.Marshal(manifest)
}

func isResourceCommand(command string) bool {
	switch command {
	case "reclaim_accelerator", "drain_runtimes", "switch_runtime_profile", "set_gpu_performance_profile":
		return true
	default:
		return false
	}
}

func (p *commandProcessor) commandIntent(command wsproto.CommandPayload) (pendingCommand, bool, error) {
	if command.Command == checkpointPlanRelaunchUrgentCommand || command.Command == checkpointPlanRelaunchVictimCommand {
		return p.commandIntentPlanRelaunch(command)
	}
	if command.Command == checkpointPlanRelaunchQueryCommand {
		return pendingCommand{}, false, nil
	}
	planPath := p.ownedStopPlanPath
	if planPath == "" {
		planPath = checkpointFixedPlanPath
	}
	return p.commandIntentWithPlan(command, planPath)
}

func (p *commandProcessor) planRelaunchPathSet() checkpointPlanBrokerPaths {
	if p != nil && p.planBrokerPaths.Socket != "" {
		return p.planBrokerPaths
	}
	return fixedCheckpointPlanBrokerPaths()
}

func (p *commandProcessor) commandIntentPlanRelaunch(command wsproto.CommandPayload) (pendingCommand, bool, error) {
	if err := wsproto.ValidatePlanRelaunchCommandArgs(command.Command, command.Args); err != nil {
		return pendingCommand{}, true, err
	}
	if err := p.checkPlanRelaunchTransition(command); err != nil {
		return pendingCommand{}, true, err
	}
	target, _ := command.Args["target_id"].(string)
	server, ok := p.routerTarget(target)
	if !ok || target != p.cfg.NodeID+"-"+server.ID {
		return pendingCommand{}, true, errors.New("plan relaunch target is not the canonical local llama.cpp target")
	}
	accelerator, _ := command.Args["accelerator_id"].(string)
	operationID, _ := command.Args["operation_id"].(string)
	epoch, _ := command.Args["recovery_epoch"].(string)
	token, err := exactFenceToken(command.Args["fencing_token"])
	if err != nil || token <= 0 || accelerator == "" || operationID == "" || epoch == "" || epoch != p.recoveryEpoch {
		return pendingCommand{}, true, errors.New("plan relaunch fence or recovery epoch is invalid")
	}
	resource := "plan-relaunch:" + accelerator
	normalized := make(map[string]any, len(command.Args)+1)
	for key, value := range command.Args {
		normalized[key] = value
	}
	normalized["resource"] = resource
	normalizedCommand := command
	normalizedCommand.Args = normalized
	intent := pendingCommand{TargetID: target, Model: resource, Command: command.Command, Token: token, CommandID: command.ID, IdempotencyKey: command.IdempotencyKey, Fingerprint: commandFingerprint(normalizedCommand)}
	manifest, err := pendingManifestFor(command, normalized, target, resource, token, intent)
	if err != nil {
		return pendingCommand{}, true, errors.New("plan relaunch durable intent could not be encoded")
	}
	intent.ManifestJSON = string(manifest)
	return intent, true, nil
}

func (p *commandProcessor) checkPlanRelaunchTransition(command wsproto.CommandPayload) error {
	accelerator := fmt.Sprint(command.Args["accelerator_id"])
	operationID := fmt.Sprint(command.Args["operation_id"])
	epoch := fmt.Sprint(command.Args["recovery_epoch"])
	fence := int64FromArg(command.Args["fencing_token"])
	stop, exists := p.ownedStopOperations[accelerator]
	if !exists || stop.OperationID != operationID || stop.AcceleratorID != accelerator || stop.RecoveryEpoch != epoch || stop.Fence != fence || p.fences[ownedStopFenceKey(accelerator)] != fence {
		return errors.New("plan relaunch is not linked to the current durable accelerator operation fence")
	}
	step := "urgent_load"
	priorStopStep := "victim_stop"
	if command.Command == checkpointPlanRelaunchVictimCommand {
		step, priorStopStep = "victim_reload", "urgent_stop"
	}
	priorStop, stopOK := stop.Steps[priorStopStep]
	if !stopOK || priorStop.Status != "acknowledged" || priorStop.CommandID != command.Args["prior_command_id"] || priorStop.IdempotencyKey != command.Args["prior_idempotency_key"] || priorStop.ReceiptSHA256 != command.Args["prior_receipt_sha256"] {
		return errors.New("plan relaunch requires the exact acknowledged predecessor receipt")
	}
	operation, hasOperation := p.planRelaunchOperations[accelerator]
	if step == "urgent_load" {
		if previousFence := p.fences[checkpointPlanRelaunchFenceKey(accelerator)]; previousFence > 0 && fence <= previousFence {
			return errors.New("urgent-load fence does not advance the prior plan relaunch operation")
		}
		if hasOperation {
			previous, terminal := operation.Steps["victim_reload"]
			if operation.OperationID == operationID || !terminal || previous.Status != "acknowledged" || fence <= operation.Fence {
				return errors.New("urgent-load step is duplicate or the prior plan relaunch operation is unresolved")
			}
		}
		return nil
	}
	urgent, urgentOK := operation.Steps["urgent_load"]
	urgentCatalog := fmt.Sprint(command.Args["catalog_id"])
	if !hasOperation || operation.OperationID != operationID || operation.Fence != fence || operation.RecoveryEpoch != epoch || operation.TargetID != command.Args["target_id"] || operation.WorkloadID != command.Args["workload_id"] || operation.WorkloadRevision != int64FromArg(command.Args["workload_revision"]) || operation.VictimCatalogID != urgentCatalog {
		return errors.New("victim reload does not match the journaled operation and approved victim catalog")
	}
	if p.fences[checkpointPlanRelaunchFenceKey(accelerator)] != fence || !urgentOK || urgent.Status != "acknowledged" || urgent.CommandID == "" {
		return errors.New("victim reload requires an acknowledged urgent-load receipt")
	}
	if _, duplicate := operation.Steps[step]; duplicate {
		return errors.New("victim reload step was already used")
	}
	return nil
}

func (p *commandProcessor) planRelaunchQueryMatchesPending(command wsproto.CommandPayload) bool {
	accelerator, _ := command.Args["accelerator_id"].(string)
	operationID, _ := command.Args["operation_id"].(string)
	stepID, _ := command.Args["query_step"].(string)
	step := p.planRelaunchOperations[accelerator].Steps[stepID]
	if step.CommandID == "" || p.planRelaunchOperations[accelerator].OperationID != operationID || step.CommandID != command.Args["original_command_id"] || step.IdempotencyKey != command.Args["original_idempotency_key"] || step.EnvelopeSHA256 != command.Args["original_envelope_sha256"] || step.EnvelopeSHA256 == "" {
		return false
	}
	var original wsproto.CommandPayload
	if rejectDuplicateJSONKeys(step.OriginalEnvelope) != nil || json.Unmarshal(step.OriginalEnvelope, &original) != nil || original.ID != step.CommandID || original.IdempotencyKey != step.IdempotencyKey || original.Args["operation_id"] != operationID || original.Args["catalog_id"] != command.Args["catalog_id"] || original.Args["prior_receipt_sha256"] != command.Args["prior_receipt_sha256"] || original.Command != map[string]string{"urgent_load": checkpointPlanRelaunchUrgentCommand, "victim_reload": checkpointPlanRelaunchVictimCommand}[stepID] {
		return false
	}
	if original.Command == checkpointPlanRelaunchUrgentCommand && original.Args["linked_catalog_id"] != command.Args["linked_catalog_id"] {
		return false
	}
	for _, key := range []string{"target_id", "accelerator_id", "workload_id", "workload_revision", "recovery_epoch", "fencing_token", "prior_command_id", "prior_idempotency_key", "prior_receipt_sha256"} {
		if fmt.Sprint(command.Args[key]) != fmt.Sprint(original.Args[key]) {
			return false
		}
	}
	return true
}

// settlePlanRelaunchQuery moves only the exact pending step named by the
// signed query into acknowledged state. The broker receipt was independently
// checked against the saved original envelope before this method is reached.
func (p *commandProcessor) settlePlanRelaunchQuery(command wsproto.CommandPayload, result map[string]any) error {
	if result == nil {
		return errors.New("plan relaunch query result is missing")
	}
	encoded, ok := result["receipt"].(string)
	if !ok || encoded == "" {
		return nil // a still-pending root journal is not a terminal acknowledgement
	}
	receipt, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(receipt) == 0 || sha256Hex(receipt) != result["receipt_sha256"] {
		return errors.New("plan relaunch query receipt encoding or digest is invalid")
	}
	accelerator := fmt.Sprint(command.Args["accelerator_id"])
	stepID := fmt.Sprint(command.Args["query_step"])
	operation, exists := p.planRelaunchOperations[accelerator]
	if !exists || operation.OperationID != command.Args["operation_id"] {
		return errors.New("plan relaunch query operation disappeared")
	}
	step, exists := operation.Steps[stepID]
	if !exists || step.CommandID != command.Args["original_command_id"] || step.EnvelopeSHA256 != command.Args["original_envelope_sha256"] {
		return errors.New("plan relaunch query no longer matches a pending original")
	}
	if step.Status == "acknowledged" {
		if !bytes.Equal(step.Receipt, receipt) || step.ReceiptSHA256 != sha256Hex(receipt) {
			return errors.New("plan relaunch query receipt differs from the prior acknowledgement")
		}
		return nil
	}
	if step.Status != "pending" {
		return errors.New("plan relaunch query original is not pending")
	}
	verified, err := verifyCheckpointPlanRelaunchReceipt(receipt, ed25519.PublicKey(step.PinnedRootPublicKey), step.OriginalEnvelope, p.cfg.CommandSigningSecret)
	if err != nil || verified.Step != stepID || verified.OperationID != operation.OperationID || verified.AcceleratorID != accelerator || verified.FencingToken != operation.Fence {
		return errors.New("plan relaunch query receipt failed original-intent verification")
	}
	step.Status = "acknowledged"
	step.Receipt = append([]byte(nil), receipt...)
	step.ReceiptSHA256 = sha256Hex(receipt)
	operation.Steps[stepID] = step
	p.planRelaunchOperations[accelerator] = operation
	var original wsproto.CommandPayload
	if json.Unmarshal(step.OriginalEnvelope, &original) != nil || original.ID != step.CommandID || original.IdempotencyKey != step.IdempotencyKey {
		return errors.New("plan relaunch original cannot be reconstructed for terminal replay")
	}
	terminalResult := make(map[string]any, len(result)+2)
	for key, value := range result {
		terminalResult[key] = value
	}
	terminalResult["action"] = original.Command
	terminalResult["reconciled"] = true
	terminal := wsproto.CommandResultPayload{ID: original.ID, NodeID: p.cfg.NodeID, Status: "succeeded", Result: terminalResult, CompletedAt: time.Now().UTC(), OK: true}
	p.results[original.ID] = terminal
	p.results["key:"+original.IdempotencyKey] = terminal
	normalizedArgs := make(map[string]any, len(original.Args)+1)
	for key, value := range original.Args {
		normalizedArgs[key] = value
	}
	normalizedArgs["resource"] = "plan-relaunch:" + accelerator
	original.Args = normalizedArgs
	fingerprint := commandFingerprint(original)
	p.commandFingerprints["id:"+original.ID] = fingerprint
	p.commandFingerprints[original.IdempotencyKey] = fingerprint
	delete(p.pending, step.CommandID)
	delete(p.inflight, checkpointPlanRelaunchFenceKey(accelerator))
	if len(p.pending) == 0 && p.stateBlockReason == blockReasonWarmTransient {
		p.stateBlocked = false
		p.stateBlockReason = ""
	}
	return p.save()
}

func (p *commandProcessor) recordPlanRelaunchStep(command wsproto.CommandPayload, intent pendingCommand, status string, receipt []byte) error {
	accelerator := fmt.Sprint(command.Args["accelerator_id"])
	operationID := fmt.Sprint(command.Args["operation_id"])
	stepID, ok := checkpointPlanRelaunchStepForCommand(command.Command)
	if !ok || (status != "pending" && status != "acknowledged") {
		return errors.New("plan relaunch step state is invalid")
	}
	operation, exists := p.planRelaunchOperations[accelerator]
	if !exists {
		if stepID != "urgent_load" || status != "pending" {
			return errors.New("plan relaunch operation must begin with urgent load")
		}
		operation = checkpointPlanRelaunchOperation{
			OperationID: operationID, TargetID: fmt.Sprint(command.Args["target_id"]), AcceleratorID: accelerator,
			WorkloadID: fmt.Sprint(command.Args["workload_id"]), WorkloadRevision: int64FromArg(command.Args["workload_revision"]),
			RecoveryEpoch: fmt.Sprint(command.Args["recovery_epoch"]), Fence: intent.Token,
			VictimCatalogID: fmt.Sprint(command.Args["linked_catalog_id"]), UrgentCatalogID: fmt.Sprint(command.Args["catalog_id"]),
			Steps: make(map[string]checkpointPlanRelaunchStep),
		}
	}
	if stepID == "urgent_load" && exists && operation.OperationID != operationID {
		previous, terminal := operation.Steps["victim_reload"]
		if !terminal || previous.Status != "acknowledged" || intent.Token <= operation.Fence {
			return errors.New("new plan relaunch operation cannot replace an unresolved predecessor")
		}
		operation = checkpointPlanRelaunchOperation{OperationID: operationID, TargetID: fmt.Sprint(command.Args["target_id"]), AcceleratorID: accelerator, WorkloadID: fmt.Sprint(command.Args["workload_id"]), WorkloadRevision: int64FromArg(command.Args["workload_revision"]), RecoveryEpoch: fmt.Sprint(command.Args["recovery_epoch"]), Fence: intent.Token, VictimCatalogID: fmt.Sprint(command.Args["linked_catalog_id"]), UrgentCatalogID: fmt.Sprint(command.Args["catalog_id"]), Steps: make(map[string]checkpointPlanRelaunchStep)}
	}
	if operation.OperationID != operationID || operation.AcceleratorID != accelerator || operation.Fence != intent.Token || operation.RecoveryEpoch != fmt.Sprint(command.Args["recovery_epoch"]) || operation.TargetID != fmt.Sprint(command.Args["target_id"]) || operation.WorkloadID != fmt.Sprint(command.Args["workload_id"]) || operation.WorkloadRevision != int64FromArg(command.Args["workload_revision"]) {
		return errors.New("plan relaunch step changed its durable operation identity")
	}
	if stepID == "urgent_load" && (operation.UrgentCatalogID != command.Args["catalog_id"] || operation.VictimCatalogID != command.Args["linked_catalog_id"]) {
		return errors.New("urgent-load catalog linkage changed")
	}
	if stepID == "victim_reload" && operation.VictimCatalogID != command.Args["catalog_id"] {
		return errors.New("victim-reload catalog differs from the original victim catalog")
	}
	digest := sha256Hex(intent.OriginalEnvelope)
	prior, exists := operation.Steps[stepID]
	if exists && (prior.CommandID != command.ID || prior.IdempotencyKey != command.IdempotencyKey || prior.EnvelopeSHA256 != digest || !bytes.Equal(prior.OriginalEnvelope, intent.OriginalEnvelope)) {
		return errors.New("plan relaunch step identity was already bound")
	}
	step := checkpointPlanRelaunchStep{CommandID: command.ID, IdempotencyKey: command.IdempotencyKey, EnvelopeSHA256: digest, OriginalEnvelope: append([]byte(nil), intent.OriginalEnvelope...), SigningMaterialSHA256: intent.PlanRelaunchSigningMaterialSHA256, Status: status, PinnedRootPublicKey: append([]byte(nil), intent.PinnedPlanBrokerPublicKey...)}
	if len(receipt) != 0 {
		step.Receipt = append([]byte(nil), receipt...)
		step.ReceiptSHA256 = sha256Hex(receipt)
	}
	if operation.Steps == nil {
		operation.Steps = make(map[string]checkpointPlanRelaunchStep)
	}
	operation.Steps[stepID] = step
	if p.planRelaunchOperations == nil {
		p.planRelaunchOperations = make(map[string]checkpointPlanRelaunchOperation)
	}
	p.planRelaunchOperations[accelerator] = operation
	return nil
}

func (p *commandProcessor) dropPlanRelaunchStep(command wsproto.CommandPayload) {
	accelerator := fmt.Sprint(command.Args["accelerator_id"])
	operation, exists := p.planRelaunchOperations[accelerator]
	if !exists {
		return
	}
	stepID, ok := checkpointPlanRelaunchStepForCommand(command.Command)
	if !ok {
		return
	}
	step := operation.Steps[stepID]
	if step.CommandID != command.ID || step.Status != "pending" {
		return
	}
	delete(operation.Steps, stepID)
	if stepID == "urgent_load" && len(operation.Steps) == 0 {
		delete(p.planRelaunchOperations, accelerator)
		return
	}
	p.planRelaunchOperations[accelerator] = operation
}

func (p *commandProcessor) ownedStopPathSet() checkpointOwnedStopPaths {
	if p != nil && p.ownedStopPaths.Socket != "" {
		return p.ownedStopPaths
	}
	return fixedCheckpointOwnedStopPaths()
}

func (p *commandProcessor) commandIntentWithPlan(command wsproto.CommandPayload, planPath string) (pendingCommand, bool, error) {
	if command.Command == "llm_displacement_stop_query" {
		return pendingCommand{}, false, nil
	}
	if command.Command == "llm_displacement_stop" {
		if err := wsproto.ValidateOwnedStopCommandArgs(command.Command, command.Args); err != nil {
			return pendingCommand{}, true, err
		}
		target, _ := command.Args["target_id"].(string)
		server, ok := p.routerTarget(target)
		if !ok {
			return pendingCommand{}, true, errors.New("owned stop target is not locally allowlisted")
		}
		if target != p.cfg.NodeID+"-"+server.ID {
			return pendingCommand{}, true, errors.New("owned stop target must use its canonical node-qualified identity")
		}
		openPlan := p.openOwnedStopPlan
		if openPlan == nil {
			openPlan = OpenCheckpointLaunchPlan
		}
		plan, err := openPlan(context.Background(), planPath)
		if err != nil {
			return pendingCommand{}, true, errors.New("owned stop fixed plan is unavailable")
		}
		spec := plan.Spec()
		closeErr := plan.Close()
		if closeErr != nil {
			return pendingCommand{}, true, errors.New("owned stop fixed plan could not be released after inspection")
		}
		return p.commandIntentWithPlanSpec(command, spec)
	}
	return p.commandIntentAfterOwnedStop(command)
}

func (p *commandProcessor) commandIntentWithPlanSpec(command wsproto.CommandPayload, spec CheckpointLaunchPlan) (pendingCommand, bool, error) {
	if command.Command == "llm_displacement_stop" {
		if err := wsproto.ValidateOwnedStopCommandArgs(command.Command, command.Args); err != nil {
			return pendingCommand{}, true, err
		}
		target, _ := command.Args["target_id"].(string)
		accelerator, _ := command.Args["accelerator_id"].(string)
		server, ok := p.routerTarget(target)
		if !ok {
			return pendingCommand{}, true, errors.New("owned stop target is not locally allowlisted")
		}
		if target != p.cfg.NodeID+"-"+server.ID {
			return pendingCommand{}, true, errors.New("owned stop target must use its canonical node-qualified identity")
		}
		if spec.Version != checkpointLaunchPlanVersion2 || spec.Alias != command.Args["model_alias"] {
			return pendingCommand{}, true, errors.New("owned stop command differs from the pinned fixed plan")
		}
		if spec.Placement == nil || accelerator != spec.Placement.PhysicalIdentity {
			return pendingCommand{}, true, errors.New("owned stop accelerator differs from the pinned fixed plan")
		}
		if strings.TrimPrefix(target, p.cfg.NodeID+"-") != server.ID {
			return pendingCommand{}, true, errors.New("owned stop target normalization is ambiguous")
		}
		token, err := exactFenceToken(command.Args["fencing_token"])
		if err != nil || token <= 0 {
			return pendingCommand{}, true, errors.New("owned stop fencing_token must be positive")
		}
		recoveryEpoch, _ := command.Args["recovery_epoch"].(string)
		if recoveryEpoch == "" || recoveryEpoch != p.recoveryEpoch {
			return pendingCommand{}, true, errors.New("owned stop recovery epoch does not match durable node state")
		}
		resource := "owned-stop:" + accelerator
		canonicalTarget := p.cfg.NodeID + "-" + server.ID
		normalized := make(map[string]any, len(command.Args)+1)
		for key, value := range command.Args {
			normalized[key] = value
		}
		normalized["target_id"] = canonicalTarget
		normalized["resource"] = resource
		normalizedCommand := command
		normalizedCommand.Args = normalized
		intent := pendingCommand{TargetID: canonicalTarget, Model: resource, Command: command.Command, Token: token, CommandID: command.ID, IdempotencyKey: command.IdempotencyKey, Fingerprint: commandFingerprint(normalizedCommand), RuntimeIdentity: command.Args["model_alias"].(string)}
		manifest, manifestErr := pendingManifestFor(command, normalized, canonicalTarget, resource, token, intent)
		if manifestErr != nil {
			return pendingCommand{}, true, errors.New("owned stop durable intent could not be encoded")
		}
		intent.ManifestJSON = string(manifest)
		return intent, true, nil
	}
	return p.commandIntentAfterOwnedStop(command)
}

func (p *commandProcessor) commandIntentAfterOwnedStop(command wsproto.CommandPayload) (pendingCommand, bool, error) {
	if isCheckpointCommand(command.Command) && command.Command != "checkpoint_slot_query" && command.Command != "checkpoint_state_query" {
		target, _ := command.Args["target_id"].(string)
		server, ok := p.routerTarget(target)
		if !ok {
			return pendingCommand{}, true, errors.New("checkpoint target is not allowlisted")
		}
		canonicalTarget := p.cfg.NodeID + "-" + server.ID
		token, err := exactFenceToken(command.Args["fencing_token"])
		if err != nil || token <= 0 {
			return pendingCommand{}, true, errors.New("checkpoint fencing_token must be positive")
		}
		slot := "-1"
		if value, present := command.Args["slot_id"]; present {
			slot = fmt.Sprint(value)
		}
		resource := "checkpoint:" + slot
		normalized := make(map[string]any, len(command.Args)+2)
		for key, value := range command.Args {
			normalized[key] = value
		}
		normalized["target_id"] = canonicalTarget
		normalized["resource"] = resource
		normalizedCommand := command
		normalizedCommand.Args = normalized
		runtimeIdentity, _ := command.Args["runtime_identity"].(string)
		intent := pendingCommand{TargetID: canonicalTarget, Model: resource, Command: command.Command, Token: token, CommandID: command.ID, IdempotencyKey: command.IdempotencyKey, Fingerprint: commandFingerprint(normalizedCommand), RuntimeIdentity: runtimeIdentity}
		manifest, manifestErr := pendingManifestFor(command, normalized, canonicalTarget, resource, token, intent)
		if manifestErr != nil {
			return pendingCommand{}, true, errors.New("checkpoint intent manifest could not be encoded")
		}
		intent.ManifestJSON = string(manifest)
		return intent, true, nil
	}
	resourceMutation := command.Command == "reclaim_accelerator" || command.Command == "drain_runtimes" || command.Command == "switch_runtime_profile" || command.Command == "set_gpu_performance_profile"
	if !resourceMutation && command.Command != "load_model" && command.Command != "unload_model" && command.Command != "warm_model" && command.Command != "offload_model" && command.Command != "demote_model" && command.Command != "protect_warm_model" && command.Command != "cleanup_warm_model" && command.Command != "reverify_warm_model" {
		return pendingCommand{}, false, nil
	}
	target, _ := command.Args["target_id"].(string)
	model, _ := command.Args["model"].(string)
	if resourceMutation {
		var resourceKey string
		switch command.Command {
		case "reclaim_accelerator":
			if target != p.cfg.NodeID+"-comfy" {
				return pendingCommand{}, true, errors.New("target is not the allowlisted accelerator runtime")
			}
			resourceKey = "reclaim_accelerator"
		case "drain_runtimes":
			if target == "" {
				target = p.cfg.NodeID + "-runtimes"
			}
			if target != p.cfg.NodeID+"-runtimes" {
				return pendingCommand{}, true, errors.New("target is not the allowlisted runtime group")
			}
			resourceKey = "drain_runtimes"
		case "switch_runtime_profile":
			profile, _ := command.Args["profile_id"].(string)
			if target == "" || profile == "" {
				return pendingCommand{}, true, errors.New("target_id and profile_id are required")
			}
			server, ok := p.routerTarget(target)
			if !ok {
				return pendingCommand{}, true, errors.New("target is not an allowlisted local inference server")
			}
			profileAllowed := false
			for _, configured := range server.RuntimeProfiles {
				if configured.ID == profile {
					profileAllowed = true
					break
				}
			}
			if !profileAllowed {
				return pendingCommand{}, true, errors.New("runtime profile is not allowlisted for target")
			}
			target = p.cfg.NodeID + "-" + server.ID
			// The desired profile is mutable state, not the fenced resource.
			// Fence the canonical runtime so profile A/B cannot use separate
			// namespaces and bypass monotonic ordering.
			resourceKey = "runtime_profile"
		case "set_gpu_performance_profile":
			accelerator, _ := command.Args["accelerator_id"].(string)
			profile, _ := command.Args["profile"].(string)
			if accelerator == "" || (profile != "idle" && profile != "active") {
				return pendingCommand{}, true, errors.New("accelerator_id and an allowlisted profile are required")
			}
			if !strings.HasPrefix(accelerator, p.cfg.NodeID+"-gpu") {
				return pendingCommand{}, true, errors.New("accelerator is not owned by this node")
			}
			target, resourceKey = accelerator, "gpu_profile"
		}
		token, err := exactFenceToken(command.Args["fencing_token"])
		if err != nil || token < 0 {
			return pendingCommand{}, true, errors.New("fencing_token must be a nonnegative integer")
		}
		normalized := make(map[string]any, len(command.Args)+1)
		for key, value := range command.Args {
			normalized[key] = value
		}
		normalized["target_id"], normalized["resource"] = target, resourceKey
		normalizedCommand := command
		normalizedCommand.Args = normalized
		fingerprint := commandFingerprint(normalizedCommand)
		intent := pendingCommand{TargetID: target, Model: resourceKey, Command: command.Command, Token: token, CommandID: command.ID, IdempotencyKey: command.IdempotencyKey, Fingerprint: fingerprint}
		manifestBytes, manifestErr := pendingManifestFor(command, normalized, target, resourceKey, token, intent)
		if manifestErr != nil {
			return pendingCommand{}, true, errors.New("pending operation manifest could not be encoded")
		}
		intent.ManifestJSON = string(manifestBytes)
		return intent, true, nil
	}
	if target == "" || model == "" {
		return pendingCommand{}, true, errors.New("target_id and model are required")
	}
	token, err := exactFenceToken(command.Args["fencing_token"])
	if err != nil {
		return pendingCommand{}, true, err
	}
	server, ok := p.routerTarget(target)
	if !ok {
		return pendingCommand{}, true, errors.New("target is not an allowlisted local inference server")
	}
	canonicalTarget := p.cfg.NodeID + "-" + server.ID
	runtimeIdentity, _ := command.Args["runtime_identity"].(string)
	normalized := make(map[string]any, len(command.Args)+1)
	for key, value := range command.Args {
		normalized[key] = value
	}
	normalized["target_id"] = canonicalTarget
	normalizedCommand := command
	normalizedCommand.Args = normalized
	intent := pendingCommand{TargetID: canonicalTarget, Model: model, Command: command.Command, Token: token, CommandID: command.ID, IdempotencyKey: command.IdempotencyKey, Fingerprint: commandFingerprint(normalizedCommand), RuntimeIdentity: runtimeIdentity}
	if command.Command != "load_model" && command.Command != "unload_model" && command.Command != "cleanup_warm_model" {
		intent.Path = server.ModelPaths[model]
		intent.FileFingerprint = server.ModelFingerprints[model]
		intent.RuntimeFingerprint = server.RuntimeFingerprints[model]
	}
	if value, ok := command.Args["active_references"]; ok {
		if parsed, parseErr := exactFenceToken(value); parseErr == nil && parsed >= 0 && uint64(parsed) <= uint64(^uint(0)>>1) {
			intent.ActiveReferences = int(parsed)
		}
	}
	if value, ok := command.Args["protected"].(bool); ok {
		intent.Protected = value
	}
	manifestBytes, manifestErr := pendingManifestFor(command, normalized, canonicalTarget, model, token, intent)
	if manifestErr != nil {
		return pendingCommand{}, true, errors.New("pending operation manifest could not be encoded")
	}
	intent.ManifestJSON = string(manifestBytes)
	return intent, true, nil
}

func sanitizeCommandError(message string) string {
	if message == "" {
		return ""
	}
	// Stable blocker codes are safe to preserve even when their diagnostic
	// detail contains endpoint paths. The controller uses this code to retain
	// an uncertain intent instead of terminalizing a post-side-effect result.
	if strings.HasPrefix(message, "observation_unavailable:") {
		return "observation_unavailable"
	}
	if len(message) > 256 || strings.ContainsAny(message, "/\\") || strings.Contains(message, "://") {
		return "command failed"
	}
	return message
}

// recoveryCommittedAt is the durable time the current recovery epoch took
// effect, or zero when no committed recovery is recorded.
func (p *commandProcessor) recoveryCommittedAt() time.Time {
	if p.recoveryMarker == nil || p.recoveryMarker.Phase != recoveryMarkerPhaseRecoveryCommitted {
		return time.Time{}
	}
	return p.recoveryMarker.Timestamp
}

func (p *commandProcessor) authenticateCommand(command wsproto.CommandPayload) error {
	if len(p.cfg.CommandSigningSecret) < 16 {
		return errors.New("node command signing is not configured")
	}
	if command.ID == "" || command.IdempotencyKey == "" {
		return errors.New("command identity is required")
	}
	if command.NodeID != p.cfg.NodeID {
		return errors.New("command is bound to a different node")
	}
	if !wsproto.VerifyCommand(command, []byte(p.cfg.CommandSigningSecret)) {
		return errors.New("invalid command signature")
	}
	if p.recoveryEpoch != "" {
		// Recovery cleared result history, so a pre-recovery command must not
		// be replayed. Commands that name an epoch must match it exactly;
		// ordinary commands (the controller does not know local epochs) are
		// accepted only when signed after the recovery was committed.
		if epoch, ok := command.Args["recovery_epoch"].(string); ok && strings.TrimSpace(epoch) != "" {
			if epoch != p.recoveryEpoch {
				return errors.New("command recovery epoch is stale")
			}
		} else if cutoff := p.recoveryCommittedAt(); cutoff.IsZero() || !command.IssuedAt.After(cutoff) {
			return errors.New("command was issued before the current recovery epoch")
		}
	}
	now := time.Now().UTC()
	if now.After(command.ExpiresAt) {
		return errors.New("command expired")
	}
	if command.IssuedAt.After(now.Add(2 * time.Minute)) {
		return errors.New("command issue time is in the future")
	}
	return nil
}

func verifyCheckpointSnapshotDigest(root, name, want string) error {
	if root == "" || filepath.Clean(root) != root || !filepath.IsAbs(root) || filepath.Base(name) != name || strings.Contains(name, "..") || !strings.HasSuffix(name, ".kv") {
		return fmt.Errorf("checkpoint snapshot path is unsafe")
	}
	path := filepath.Join(root, name)
	// Open one descriptor without following a final-component symlink, then
	// validate and hash that same descriptor. The helper has no ordinary-open
	// fallback, so this boundary cannot silently weaken its policy.
	f, err := safefile.OpenReadOnlyNoFollow(path)
	if err != nil {
		return fmt.Errorf("checkpoint snapshot file is unavailable")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || !singleCheckpointLink(info) || (goruntime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0) || info.Size() <= 0 || info.Size() > 1<<34 {
		return fmt.Errorf("checkpoint snapshot file is unavailable")
	}
	hash := sha256.New()
	read, err := io.Copy(hash, io.LimitReader(f, 1<<34))
	if err != nil {
		return err
	}
	if read != info.Size() {
		return fmt.Errorf("checkpoint snapshot file changed during verification")
	}
	got := "sha256:" + hex.EncodeToString(hash.Sum(nil))
	if got != want {
		return fmt.Errorf("checkpoint snapshot digest mismatch")
	}
	return nil
}

func (p *commandProcessor) ownedStopOriginal(commandID, idempotencyKey string) (pendingCommand, map[string]any, bool) {
	if pending, ok := p.pending[commandID]; ok && pending.Command == "llm_displacement_stop" && pending.IdempotencyKey == idempotencyKey {
		return pending, nil, true
	}
	result, ok := p.results[commandID]
	if !ok || !result.OK || result.Result == nil || result.Result["idempotency_key"] != idempotencyKey {
		return pendingCommand{}, nil, false
	}
	return pendingCommand{}, result.Result, true
}

func (p *commandProcessor) ownedStopQueryMatchesPending(command wsproto.CommandPayload) bool {
	originalID, _ := command.Args["original_command_id"].(string)
	originalKey, _ := command.Args["original_idempotency_key"].(string)
	pending, completed, ok := p.ownedStopOriginal(originalID, originalKey)
	if !ok {
		return false
	}
	var raw []byte
	var publicKey []byte
	if completed != nil {
		envelope, _ := completed["original_envelope"].(string)
		key, _ := completed["pinned_root_public_key"].(string)
		raw, _ = base64.StdEncoding.DecodeString(envelope)
		publicKey, _ = base64.StdEncoding.DecodeString(key)
	} else {
		raw = pending.OriginalEnvelope
		publicKey = pending.PinnedRootStopPublicKey
	}
	if len(raw) == 0 || len(publicKey) != ed25519.PublicKeySize {
		return false
	}
	var original wsproto.CommandPayload
	if json.Unmarshal(raw, &original) != nil || original.Command != "llm_displacement_stop" || original.ID != originalID || original.IdempotencyKey != originalKey || !wsproto.VerifyCommand(original, []byte(p.cfg.CommandSigningSecret)) {
		return false
	}
	digest := sha256.Sum256(raw)
	argDigest, _ := command.Args["original_envelope_sha256"].(string)
	if hex.EncodeToString(digest[:]) != argDigest {
		return false
	}
	accelerator, _ := original.Args["accelerator_id"].(string)
	operationID, _ := original.Args["operation_id"].(string)
	stepID, _ := original.Args["step_id"].(string)
	state, exists := p.ownedStopOperations[accelerator]
	step, stepExists := state.Steps[stepID]
	if !exists || !stepExists || !state.UsedOperationIDs[operationID] || state.OperationID != operationID || state.Fence != int64FromArg(original.Args["fencing_token"]) || state.RecoveryEpoch != original.Args["recovery_epoch"] || step.CommandID != originalID || step.IdempotencyKey != originalKey || step.EnvelopeSHA256 != argDigest || p.commandFingerprints["id:"+originalID] != p.semanticFingerprint(original) || p.commandFingerprints[originalKey] != p.semanticFingerprint(original) {
		return false
	}
	if completed != nil {
		receiptDigest, _ := completed["receipt_sha256"].(string)
		if step.Status != "acknowledged" || receiptDigest == "" || receiptDigest != step.ReceiptSHA256 || !bytes.Equal(publicKey, step.PinnedRootStopPublicKey) {
			return false
		}
	} else if (step.Status != "pending" && step.Status != "acknowledged") || !bytes.Equal(publicKey, pending.PinnedRootStopPublicKey) {
		return false
	}
	for _, key := range []string{"operation_id", "step_id", "target_kind", "target_id", "accelerator_id", "workload_id", "workload_revision", "model", "model_alias", "local_checkpoint_binding", "snapshot_name", "snapshot_digest", "recovery_epoch", "fencing_token"} {
		if fmt.Sprint(command.Args[key]) != fmt.Sprint(original.Args[key]) {
			return false
		}
	}
	if command.NodeID != original.NodeID || command.Args["fencing_token"] != command.Args["expected_fence"] || command.Args["fencing_token"] != command.Args["observed_after_fence"] {
		return false
	}
	return true
}

func (p *commandProcessor) executeOwnedStop(ctx context.Context, command wsproto.CommandPayload, query bool) (map[string]any, string) {
	return p.executeOwnedStopAt(ctx, command, query, p.ownedStopPathSet())
}

func (p *commandProcessor) executeOwnedStopAt(ctx context.Context, command wsproto.CommandPayload, query bool, paths checkpointOwnedStopPaths) (map[string]any, string) {
	if ctx == nil || ctx.Err() != nil {
		return nil, "owned stop context is unavailable"
	}
	if query {
		originalID, _ := command.Args["original_command_id"].(string)
		originalKey, _ := command.Args["original_idempotency_key"].(string)
		pending, completed, ok := p.ownedStopOriginal(originalID, originalKey)
		if !ok {
			return nil, "owned stop original intent is unavailable"
		}
		var raw, publicKey []byte
		if completed != nil {
			envelope, _ := completed["original_envelope"].(string)
			key, _ := completed["pinned_root_public_key"].(string)
			raw, _ = base64.StdEncoding.DecodeString(envelope)
			publicKey, _ = base64.StdEncoding.DecodeString(key)
		} else {
			raw, publicKey = pending.OriginalEnvelope, pending.PinnedRootStopPublicKey
		}
		receipt, err := observeOwnedStopReceiptAt(ctx, paths.ReceiptDir, raw, publicKey, p.cfg.CommandSigningSecret, paths)
		if err != nil {
			return nil, "owned stop receipt remains unavailable"
		}
		receiptDigest := sha256Hex(receipt)
		if completed != nil {
			expected, _ := completed["receipt_sha256"].(string)
			if expected == "" || expected != receiptDigest {
				return nil, "durable completed receipt digest changed"
			}
		} else if pending.StopReceiptSHA256 != "" && pending.StopReceiptSHA256 != receiptDigest {
			return nil, "durable pending receipt digest changed"
		}
		if pending.CommandID != "" {
			pending.StopReceiptSHA256 = receiptDigest
			var original wsproto.CommandPayload
			if rejectDuplicateJSONKeys(raw) != nil || json.Unmarshal(raw, &original) != nil || original.ID != originalID || original.IdempotencyKey != originalKey || p.recordOwnedStopStep(original, pending, "acknowledged", pending.StopReceiptSHA256) != nil {
				return nil, "owned stop receipt could not be joined to the operation journal"
			}
			delete(p.pending, pending.CommandID)
			delete(p.inflight, ownedStopFenceKey(fmt.Sprint(original.Args["accelerator_id"])))
			completedOriginal := map[string]any{"action": original.Command, "command_id": original.ID, "idempotency_key": original.IdempotencyKey, "original_envelope": base64.StdEncoding.EncodeToString(raw), "pinned_root_public_key": base64.StdEncoding.EncodeToString(publicKey), "receipt": string(receipt), "receipt_sha256": receiptDigest}
			originalResult := wsproto.CommandResultPayload{ID: original.ID, NodeID: p.cfg.NodeID, OK: true, Result: completedOriginal, CompletedAt: time.Now().UTC()}
			p.results[original.ID] = originalResult
			p.results["key:"+original.IdempotencyKey] = originalResult
		}
		return map[string]any{"action": command.Command, "original_command_id": originalID, "original_idempotency_key": originalKey, "receipt": string(receipt), "receipt_sha256": receiptDigest}, ""
	}
	pending, ok := p.pending[command.ID]
	if !ok || pending.Command != "llm_displacement_stop" || pending.CommandID != command.ID || pending.IdempotencyKey != command.IdempotencyKey || pending.Fingerprint != p.semanticFingerprint(command) || len(pending.PinnedRootStopPublicKey) != ed25519.PublicKeySize {
		return nil, "owned stop durable intent is unavailable"
	}
	req := ownedStopRequest{Command: append([]byte(nil), pending.OriginalEnvelope...), SigningSHA256: pending.SigningMaterialSHA256, RecoveryEpoch: pending.StopRecoveryEpoch, PinnedPublicKey: append([]byte(nil), pending.PinnedRootStopPublicKey...)}
	receiptRaw, err := invokeOwnedStopSupervisorAt(ctx, req, paths.Socket)
	if err != nil {
		return nil, "owned stop supervisor outcome is uncertain"
	}
	if err := verifyOwnedStopReceipt(receiptRaw, ed25519.PublicKey(pending.PinnedRootStopPublicKey), pending.OriginalEnvelope, p.cfg.CommandSigningSecret); err != nil {
		return nil, "owned stop receipt failed signature or intent verification"
	}
	pending.StopReceiptSHA256 = sha256Hex(receiptRaw)
	p.pending[command.ID] = pending
	if err := p.recordOwnedStopStep(command, pending, "acknowledged", pending.StopReceiptSHA256); err != nil {
		return nil, "owned stop acknowledgement could not be joined to the operation journal"
	}
	return map[string]any{"action": command.Command, "command_id": command.ID, "idempotency_key": command.IdempotencyKey, "original_envelope": base64.StdEncoding.EncodeToString(pending.OriginalEnvelope), "pinned_root_public_key": base64.StdEncoding.EncodeToString(pending.PinnedRootStopPublicKey), "receipt": string(receiptRaw), "receipt_sha256": pending.StopReceiptSHA256}, ""
}

func sha256Hex(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func int64FromArg(value any) int64 {
	n, _ := exactFenceToken(value)
	return n
}

// finalizeCheckpointOwnership resolves the durable owner reference before
// invoking the terminal lifecycle seam.  A restore has a new operation ID,
// while the snapshot manifest may still be owned by the original checkpoint
// operation.  When the manifest has exactly one reference, that durable fact
// is safe to use; ambiguous shared snapshots fail closed instead of
// terminalizing another operation's resumable reference.
func finalizeCheckpointOwnership(cfg CheckpointConfig, owner, snapshotName, operationID string) error {
	manifest, err := readCheckpointOwnerManifest(cfg, owner)
	if err != nil {
		return err
	}
	entry, ok := manifest.Entries[snapshotName]
	if !ok {
		return FinalizeOwnedCheckpoint(cfg, owner, snapshotName, operationID)
	}
	if entry.References != nil {
		if _, exists := entry.References[operationID]; !exists {
			if len(entry.References) != 1 {
				return fmt.Errorf("checkpoint terminal lifecycle reference is ambiguous")
			}
			for referenceID := range entry.References {
				operationID = referenceID
			}
		}
	} else if entry.OperationID != "" && entry.OperationID != operationID {
		operationID = entry.OperationID
	}
	return FinalizeOwnedCheckpoint(cfg, owner, snapshotName, operationID)
}

func (p *commandProcessor) executeCheckpoint(ctx context.Context, command wsproto.CommandPayload, markSideEffect func()) (map[string]any, string) {
	if !p.cfg.Checkpoint.Enabled {
		return nil, "production checkpointing is disabled on this node"
	}
	if err := validateCheckpointRoot(p.cfg.Checkpoint); err != nil {
		return nil, err.Error()
	}
	cleanupCheckpointRoot(p.cfg.Checkpoint)
	if name, ok := command.Args["snapshot_name"].(string); ok && name != "" {
		if filepath.Base(name) != name || strings.Contains(name, "..") || !strings.HasSuffix(name, ".kv") {
			return nil, "checkpoint snapshot name is not an allowlisted production name"
		}
		owner, _ := command.Args["owner_id"].(string)
		if owner == "" || filepath.Base(owner) != owner || strings.Contains(owner, "..") {
			return nil, "checkpoint owner path is invalid"
		}
		ownerDir := filepath.Join(p.cfg.Checkpoint.Root, owner)
		canonicalRoot, rootErr := filepath.EvalSymlinks(p.cfg.Checkpoint.Root)
		if rootErr != nil {
			return nil, "checkpoint root is unavailable"
		}
		canonicalDir, dirErr := filepath.EvalSymlinks(ownerDir)
		if dirErr != nil && !os.IsNotExist(dirErr) {
			return nil, "checkpoint owner path is not canonical"
		}
		if dirErr == nil && canonicalDir != filepath.Join(canonicalRoot, owner) {
			return nil, "checkpoint owner path escaped root"
		}
	}
	targetID, _ := command.Args["target_id"].(string)
	server, ok := p.routerTarget(targetID)
	if !ok || targetID != p.cfg.NodeID+"-"+server.ID {
		return nil, "checkpoint target is not an allowlisted local llama.cpp target"
	}
	acceleratorID, _ := command.Args["accelerator_id"].(string)
	if acceleratorID != fmt.Sprintf("%s-gpu%d", p.cfg.NodeID, server.AcceleratorIndex) {
		return nil, "checkpoint accelerator is not authoritative for this target"
	}
	driver := p.checkpointDrivers[server.ID]
	if driver == nil {
		return nil, "checkpoint runtime driver is not configured for this target"
	}
	model, _ := command.Args["model"].(string)
	if len(server.ModelFingerprints) > 0 {
		modelOK := false
		for configuredModel, fingerprint := range server.ModelFingerprints {
			if model == configuredModel || model == fingerprint {
				modelOK = true
				break
			}
		}
		if !modelOK {
			return nil, "checkpoint model is not the authoritative configured model/fingerprint"
		}
	}
	runtimeIdentity, _ := command.Args["runtime_identity"].(string)
	if len(server.RuntimeFingerprints) > 0 {
		runtimeOK := false
		for configuredRuntime, fingerprint := range server.RuntimeFingerprints {
			if runtimeIdentity == configuredRuntime || runtimeIdentity == fingerprint {
				runtimeOK = true
				break
			}
		}
		if !runtimeOK {
			return nil, "checkpoint runtime identity is not the authoritative configured runtime"
		}
	}
	contextLimit, _ := command.Args["context_limit"].(float64)
	if contextLimit == 0 {
		if value, ok := command.Args["context_limit"].(int); ok {
			contextLimit = float64(value)
		}
	}
	if contextLimit == 0 {
		if value, ok := command.Args["context_limit"].(int64); ok {
			contextLimit = float64(value)
		}
	}
	if server.ContextLimit > 0 && int(contextLimit) != server.ContextLimit {
		profileOK := false
		for _, profile := range server.RuntimeProfiles {
			if profile.ContextLimit == int(contextLimit) {
				profileOK = true
				break
			}
		}
		if !profileOK {
			return nil, "checkpoint context does not match the authoritative runtime profile"
		}
	}
	action, _ := command.Args["checkpoint_action"].(string)
	if action == "" {
		return nil, "checkpoint action is required"
	}
	if action == "save" || action == "restore" {
		name, _ := command.Args["snapshot_name"].(string)
		if name == "" {
			return nil, "checkpoint snapshot_name is required"
		}
	}
	operationID, _ := command.Args["checkpoint_operation_id"].(string)
	requestedSlot := -1
	if slotValue, present := command.Args["slot_id"]; present {
		if n, convErr := exactFenceToken(slotValue); convErr == nil {
			requestedSlot = int(n)
		}
	}
	phaseState, phaseErr := p.authorizeCheckpointPhase(command, targetID, action, requestedSlot)
	if phaseErr != nil {
		return nil, phaseErr.Error()
	}
	phaseNumber := checkpointPhaseFor(phaseState, action)
	if phaseNumber > 0 && phaseState.Phase == phaseNumber && phaseState.Action == action {
		if cached, ok := p.results["key:"+command.IdempotencyKey]; ok && cached.Result != nil && p.commandFingerprints[command.IdempotencyKey] == p.semanticFingerprint(command) {
			return cached.Result, ""
		}
		// Release is the terminal ownership transition for a checkpoint
		// operation.  It is deliberately safe to replay after a controller
		// restart or a second terminal observer has already seen the durable
		// release phase: the phase journal proves that the slot was released,
		// while a new idempotency key must not invoke the runtime release a
		// second time.  Synthesize the same durable observation used by a fresh
		// release so callers can finish cleanup without requiring an exact-key
		// result row from the first owner.
		if action == "release" {
			return map[string]any{
				"released":                              true,
				"target_id":                             phaseState.TargetID,
				"action":                                action,
				"node_id":                               p.cfg.NodeID,
				"command_id":                            command.ID,
				"idempotency_key":                       command.IdempotencyKey,
				"original_command_id":                   command.ID,
				"original_idempotency_key":              command.IdempotencyKey,
				"checkpoint_operation_id":               phaseState.OperationID,
				"observed_phase":                        phaseState.Action,
				"observed_phase_ordinal":                phaseState.Phase,
				"observed_slot_id":                      phaseState.SlotID,
				"observed_snapshot_name":                phaseState.SnapshotName,
				"observed_snapshot_digest":              phaseState.SnapshotDigest,
				"observed_conversation_id":              phaseState.ConversationID,
				"observed_continuation_conversation_id": phaseState.ContinuationConversationID,
				"observed_runtime_identity":             phaseState.RuntimeIdentity,
				"observed_model_fingerprint":            phaseState.ModelFingerprint,
				"observed_profile_fingerprint":          phaseState.ProfileFingerprint,
				"observed_context_fingerprint":          phaseState.ContextFingerprint,
				"generation":                            phaseState.Generation,
				"fencing_token":                         phaseState.Fence,
			}, ""
		}
		return nil, "checkpoint phase replay lacks durable result evidence"
	}
	if markSideEffect != nil && action != "slot_query" && action != "state_query" {
		markSideEffect()
	}
	result := map[string]any{}
	conversationID, _ := command.Args["conversation_id"].(string)
	continuationConversationID, _ := command.Args["continuation_conversation_id"].(string)
	slot := -1
	if value, present := command.Args["slot_id"]; present {
		if n, convErr := exactFenceToken(value); convErr == nil {
			slot = int(n)
		}
	}
	if action == "slot_assign" || action == "slot_query" || action == "state_query" {
		inventory, callErr := driver.QuerySlots(ctx)
		if callErr != nil {
			return nil, callErr.Error()
		}
		rows := make([]map[string]any, 0, len(inventory.Slots))
		for _, row := range inventory.Slots {
			rows = append(rows, map[string]any{"id": row.ID, "n_ctx": row.ContextLimit, "is_processing": row.Processing, "n_prompt_tokens": row.PromptTokens, "n_prompt_tokens_cached": row.CachedPromptTokens, "n_past": row.PastTokens})
		}
		result["slots"] = rows
		if action == "slot_assign" {
			assignment, assignErr := driver.AssignSlot(ctx, slot)
			if assignErr != nil {
				return nil, assignErr.Error()
			}
			result["slot_id"], result["context_limit"] = assignment.SlotID, assignment.ContextLimit
		}
	} else {
		switch action {
		case "pause", "cancel":
			var boundary checkpointRuntime.SlotBoundary
			var callErr error
			if action == "cancel" {
				if conversationID == "" {
					return nil, "checkpoint cancel requires conversation id"
				}
				if compensationOf, _ := command.Args["compensation_of"].(string); compensationOf == "" || compensationOf != operationID {
					return nil, "checkpoint cancel compensation identity is required"
				}
			}
			if conversationDriver, ok := driver.(checkpointRuntime.ConversationSlotCheckpointDriver); ok {
				boundary, callErr = conversationDriver.PauseAtBoundaryWithConversation(ctx, slot, conversationID)
			} else if conversationID == "" {
				// Deterministic compatibility drivers may expose only the legacy
				// boundary seam. A live production command always carries a
				// conversation id and therefore cannot enter this branch.
				boundary, callErr = driver.PauseAtBoundary(ctx, slot)
			} else {
				callErr = fmt.Errorf("production checkpoint driver lacks conversation pause")
			}
			if callErr != nil {
				return nil, callErr.Error()
			}
			result["prefix"], result["token_count"] = boundary.Prefix, boundary.TokenCount
			if action == "cancel" {
				result["stopped"] = true
			}
		case "start":
			conversationID, _ := command.Args["conversation_id"].(string)
			if conversationID == "" {
				return nil, "production checkpoint driver lacks conversation start"
			}
			var callErr error
			if registrationDriver, ok := driver.(checkpointRuntime.ConversationSlotRegistrationDriver); ok && command.Args["managed_stream"] == true {
				callErr = registrationDriver.RegisterCheckpointConversation(ctx, slot, conversationID, model, int(contextLimit))
			} else if conversationDriver, ok := driver.(checkpointRuntime.ConversationSlotCheckpointDriver); ok {
				callErr = conversationDriver.StartCheckpointConversation(ctx, slot, conversationID, model, int(contextLimit))
			} else {
				return nil, "production checkpoint driver lacks conversation start"
			}
			if callErr != nil {
				return nil, callErr.Error()
			}
			result["conversation_id"] = conversationID
		case "save":
			name, _ := command.Args["snapshot_name"].(string)
			owner, _ := command.Args["owner_id"].(string)
			if err := checkpointQuotaAllowed(p.cfg.Checkpoint, owner, name, 0); err != nil {
				return nil, err.Error()
			}
			// A failed post-save quota/manifest commit may clean up only a
			// filename that this save created.  Preserve a pre-existing snapshot
			// even when a caller reuses an idempotency name across owners.
			preexistingSnapshot := false
			if info, statErr := os.Lstat(filepath.Join(p.cfg.Checkpoint.Root, name)); statErr == nil {
				preexistingSnapshot = info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0
			} else if !errors.Is(statErr, os.ErrNotExist) {
				return nil, "checkpoint snapshot preflight failed: " + statErr.Error()
			}
			saved, callErr := driver.SaveKV(ctx, slot, name)
			if callErr != nil {
				return nil, callErr.Error()
			}
			if saved.SizeBytes <= 0 || saved.SizeBytes > p.cfg.Checkpoint.MaxMetadataBytes+p.cfg.Checkpoint.MaxOutputBytes+p.cfg.Checkpoint.MaxBytes {
				return nil, "checkpoint snapshot exceeds configured size bounds"
			}
			// Re-scan after the runtime has committed the actual file. This catches
			// external KV snapshots whose logical size is larger than their
			// metadata and removes only the just-created owned bundle on overflow.
			if quotaErr := checkpointQuotaAllowed(p.cfg.Checkpoint, owner, name, 0); quotaErr != nil {
				if !preexistingSnapshot {
					_ = removeFreshCheckpointBundle(p.cfg.Checkpoint, name)
				}
				return nil, quotaErr.Error()
			}
			if err := recordOwnedCheckpoint(p.cfg.Checkpoint, owner, name, operationID, saved.SizeBytes); err != nil {
				if !preexistingSnapshot {
					_ = removeFreshCheckpointBundle(p.cfg.Checkpoint, name)
				}
				return nil, "checkpoint ownership manifest could not be committed: " + err.Error()
			}
			result["snapshot_name"], result["snapshot_ref"], result["snapshot_bytes"], result["snapshot_digest"], result["saved_tokens"] = name, saved.SnapshotRef, saved.SizeBytes, saved.Digest, saved.TokensSaved
		case "stop_confirm":
			stopped, callErr := driver.ConfirmStopped(ctx, slot)
			if callErr != nil || !stopped {
				if callErr == nil {
					callErr = errors.New("runtime did not confirm backend stop")
				}
				return nil, callErr.Error()
			}
			result["stopped"] = true
		case "release":
			if callErr := driver.ReleaseSlot(ctx, slot); callErr != nil {
				return nil, callErr.Error()
			}
			owner, _ := command.Args["owner_id"].(string)
			name, _ := command.Args["snapshot_name"].(string)
			if err := markOwnedCheckpointInactive(p.cfg.Checkpoint, owner, name, operationID); err != nil && !errors.Is(err, os.ErrNotExist) {
				return nil, "checkpoint ownership manifest release could not be committed: " + err.Error()
			}
			result["released"] = true
		case "reload":
			if callErr := driver.Reload(ctx, slot); callErr != nil {
				return nil, callErr.Error()
			}
			result["reloaded"] = true
		case "restore":
			name, _ := command.Args["snapshot_name"].(string)
			if digest, _ := command.Args["snapshot_digest"].(string); digest != "" {
				if err := verifyCheckpointSnapshotDigest(p.cfg.Checkpoint.Root, name, digest); err != nil {
					return nil, err.Error()
				}
			} else if p.cfg.Checkpoint.Enabled {
				if _, external := driver.(*llamacpp.Driver); external {
					return nil, "checkpoint restore requires snapshot_digest"
				}
			}
			restored, callErr := driver.RestoreKV(ctx, slot, name)
			if callErr != nil {
				return nil, callErr.Error()
			}
			result["restored_tokens"] = restored.TokensRestored
		case "reuse_verify":
			saved, savedErr := exactFenceToken(command.Args["saved_tokens"])
			if savedErr != nil || saved <= 0 {
				return nil, "checkpoint reuse verification requires positive saved_tokens"
			}
			reused, callErr := driver.VerifyReuse(ctx, slot, int(saved))
			if callErr != nil {
				return nil, callErr.Error()
			}
			result["reused_tokens"] = reused
		case "resume", "rollback_resume":
			hash, _ := command.Args["partial_output_hash"].(string)
			offset, offsetErr := exactFenceToken(command.Args["partial_output_offset"])
			if offsetErr != nil || offset < 0 {
				return nil, "checkpoint resume requires a non-negative partial_output_offset"
			}
			var externalID string
			var callErr error
			if compensationOf, _ := command.Args["compensation_of"].(string); action == "rollback_resume" && compensationOf == "" {
				return nil, "checkpoint rollback compensation identity is required"
			} else if conversationDriver, ok := driver.(checkpointRuntime.ConversationSlotCheckpointDriver); ok {
				externalID, callErr = conversationDriver.ResumeWithConversation(ctx, slot, continuationConversationID, hash, int(offset))
			} else if continuationConversationID == "" {
				externalID, callErr = driver.Resume(ctx, slot, hash, int(offset))
			} else {
				callErr = fmt.Errorf("production checkpoint driver lacks conversation resume")
			}
			if callErr != nil {
				return nil, callErr.Error()
			}
			result["external_id"] = externalID
		case "continue":
			conversationID, _ := command.Args["continuation_conversation_id"].(string)
			assistantPrefix, _ := command.Args["assistant_prefix"].(string)
			// The controller-owned stream is already the real upstream response.
			// This signed phase only binds that response to the restored slot; it
			// must not start a second generation or create a metadata-only seam.
			if controllerStream, _ := command.Args["controller_stream"].(bool); controllerStream {
				if conversationID == "" {
					return nil, "production continuation requires conversation id"
				}
				result["external_id"] = conversationID
				break
			}
			continuationDriver, ok := driver.(checkpointRuntime.CheckpointContinuationDriver)
			if !ok || conversationID == "" {
				return nil, "production checkpoint driver lacks conversation continuation"
			}
			if callErr := continuationDriver.ContinueCheckpointConversation(ctx, slot, conversationID, model, assistantPrefix); callErr != nil {
				return nil, callErr.Error()
			}
			result["external_id"] = conversationID
		default:
			return nil, "checkpoint action is not implemented by the llama.cpp driver"
		}
	}
	// Commit first, then report the post-action durable journal.  Returning the
	// pre-action phase made checkpoint_start and every later state query look as
	// if the node had not performed the command yet.
	result["command_fingerprint"] = p.semanticFingerprint(command)
	result["fingerprint"] = p.semanticFingerprint(command)
	if checkpointPhase(action) > 0 || action == "rollback_resume" {
		p.commitCheckpointPhase(phaseState, action, result)
		phaseState = p.checkpointPhases[operationID]
	}
	// A released slot is still resumable, so checkpoint_release intentionally
	// does not touch the owner manifest.  Once restore has produced attributable
	// reuse, or a resumed conversation has been cancelled successfully, the
	// snapshot reference is terminal and must be finalized durably on the node.
	// Keep this after the phase journal commit so a restart can distinguish a
	// terminalization failure from an unobserved runtime mutation.
	if action == "reuse_verify" || action == "cancel" {
		if snapshotName := phaseState.SnapshotName; snapshotName != "" {
			if err := finalizeCheckpointOwnership(p.cfg.Checkpoint, phaseState.OwnerID, snapshotName, phaseState.OperationID); err != nil {
				return nil, "checkpoint ownership terminalization failed: " + err.Error()
			}
		}
	}
	result["target_id"] = phaseState.TargetID
	result["action"] = action
	result["node_id"] = p.cfg.NodeID
	result["command_id"] = command.ID
	result["idempotency_key"] = command.IdempotencyKey
	result["original_command_id"] = command.ID
	result["original_idempotency_key"] = command.IdempotencyKey
	result["checkpoint_operation_id"] = phaseState.OperationID
	// Recovery consumes these authoritative observations rather than merely
	// treating a successful query response as proof that hardware matches the
	// durable operation. Every observed field is read from the node journal;
	// the signed request is never copied into the evidence payload.
	result["observed_phase"] = phaseState.Action
	result["observed_phase_ordinal"] = phaseState.Phase
	result["observed_slot_id"] = phaseState.SlotID
	result["observed_snapshot_name"] = phaseState.SnapshotName
	result["observed_snapshot_digest"] = phaseState.SnapshotDigest
	result["observed_conversation_id"] = phaseState.ConversationID
	result["observed_continuation_conversation_id"] = phaseState.ContinuationConversationID
	result["observed_runtime_identity"] = phaseState.RuntimeIdentity
	result["observed_model_fingerprint"] = phaseState.ModelFingerprint
	result["observed_profile_fingerprint"] = phaseState.ProfileFingerprint
	result["observed_context_fingerprint"] = phaseState.ContextFingerprint
	result["generation"] = phaseState.Generation
	result["fencing_token"] = phaseState.Fence
	return result, ""
}

func (p *commandProcessor) execute(ctx context.Context, command wsproto.CommandPayload, markSideEffect func()) (map[string]any, string) {
	if command.Command == "llm_displacement_stop" {
		if markSideEffect != nil {
			markSideEffect()
		}
		return p.executeOwnedStop(ctx, command, false)
	}
	if command.Command == "llm_displacement_stop_query" {
		return p.executeOwnedStop(ctx, command, true)
	}
	if command.Command == checkpointPlanRelaunchQueryCommand {
		return p.executePlanRelaunch(ctx, command, false, nil)
	}
	if command.Command == checkpointPlanRelaunchUrgentCommand || command.Command == checkpointPlanRelaunchVictimCommand {
		if markSideEffect != nil {
			markSideEffect()
		}
		return p.executePlanRelaunch(ctx, command, true, p.pending[command.ID].PinnedPlanBrokerPublicKey)
	}
	if strings.HasPrefix(command.Command, "checkpoint_") {
		return p.executeCheckpoint(ctx, command, markSideEffect)
	}
	switch command.Command {
	case "refresh_capabilities":
		advertisements := discoverAdapters(ctx, p.cfg, p.log, p)
		return map[string]any{"adapters": advertisements}, ""
	case "load_model", "unload_model":
		targetID, _ := command.Args["target_id"].(string)
		model, _ := command.Args["model"].(string)
		if targetID == "" || model == "" {
			return nil, "target_id and model are required"
		}
		server, ok := p.routerTarget(targetID)
		if !ok {
			return nil, "target is not an allowlisted local inference server"
		}
		targetID = p.cfg.NodeID + "-" + server.ID
		discovery, err := DiscoverLlamaCPP(ctx, p.cfg.NodeID, server)
		if err != nil {
			return nil, "router discovery failed: " + err.Error()
		}
		runtimeIdentity, envelopeErr := p.validateResidencyCommandEnvelope(command, targetID, model, discovery)
		if envelopeErr != "" {
			return nil, envelopeErr
		}
		available := false
		for _, candidate := range discovery.Models {
			if candidate == model {
				available = true
				break
			}
		}
		_, configuredModel := server.ModelPaths[model]
		if !available && !configuredModel {
			return nil, "model is not allowlisted by router discovery"
		}
		if !discovery.SupportsModelLifecycle {
			return nil, "target runtime does not expose lifecycle control"
		}
		if !runtimeMutationSupported(ctx, server) {
			return nil, "runtime lifecycle mutation protocol is not configured"
		}
		load := command.Command == "load_model"
		currentState, stateErr := waitLlamaModelState(ctx, server, model)
		if stateErr != nil {
			return nil, "router model state is indeterminate: " + stateErr.Error()
		}
		alreadyResident := currentState == llamaStateLoaded
		if alreadyResident == load {
			if p.warmRAM != nil {
				if err := p.warmRAM.ReleaseModelFor(targetID, model); err != nil {
					if load || p.warmRAM.HasEntryFor(targetID, model) {
						return nil, "warm residency cleanup failed"
					}
				}
			}
			p.commitFence(command, targetID, model)
			result := map[string]any{"action": command.Command, "target_id": targetID, "model": model, "resident": load, "warm_ram": false, "changed": false, "runtime_identity": canonicalCommandRuntimeIdentity(targetID, discovery), "capability_revision": p.capabilityRevision(), "fencing_token": p.fences[fenceKey(targetID, model)], "observed_after_fence": p.fences[fenceKey(targetID, model)], "tier": map[bool]string{true: "hot_vram", false: "cold_disk"}[load]}
			if !load {
				result["cleaned"], result["warm_entry_absent"], result["warm_release_verified"] = true, true, true
				result["warm_model_bytes"], result["locked_bytes"] = int64(0), int64(0)
			}
			return result, ""
		}
		if markSideEffect != nil {
			markSideEffect()
		}
		if err := mutateRuntimeModel(ctx, server, model, load); err != nil {
			rollbackStatus := p.rollbackRuntimeModel(server, model, load)
			if strings.Contains(rollbackStatus, "uncertain") {
				return nil, rollbackStatus
			}
			return nil, err.Error()
		}
		observedRuntimeIdentity := runtimeIdentity
		for {
			observedState, observeErr := discoverLlamaModelState(ctx, server, model)
			if observeErr != nil {
				return nil, "router model state discovery failed after mutation: " + observeErr.Error()
			}
			if observedState != llamaStateTransitional && (observedState == llamaStateLoaded) == load {
				if p.warmRAM != nil {
					if err := p.warmRAM.ReleaseModelFor(targetID, model); err != nil {
						if load || p.warmRAM.HasEntryFor(targetID, model) {
							return nil, "warm residency cleanup failed"
						}
					}
				}
				observedRuntimeIdentity = canonicalCommandRuntimeIdentity(targetID, discovery)
				break
			}
			select {
			case <-ctx.Done():
				return nil, p.rollbackRuntimeModel(server, model, load)
			case <-time.After(100 * time.Millisecond):
			}
		}
		p.commitFence(command, targetID, model)
		result := map[string]any{"action": command.Command, "target_id": targetID, "model": model, "resident": load, "warm_ram": false, "changed": true, "runtime_identity": observedRuntimeIdentity, "capability_revision": p.capabilityRevision(), "fencing_token": p.fences[fenceKey(targetID, model)], "observed_after_fence": p.fences[fenceKey(targetID, model)], "tier": map[bool]string{true: "hot_vram", false: "cold_disk"}[load]}
		if !load {
			result["cleaned"], result["warm_entry_absent"], result["warm_release_verified"] = true, true, true
			result["warm_model_bytes"], result["locked_bytes"] = int64(0), int64(0)
		}
		return result, ""
	case "query_model_state":
		return p.queryModelState(ctx, command)
	case "warm_model", "offload_model", "demote_model", "protect_warm_model", "cleanup_warm_model", "reverify_warm_model":
		return p.warmModel(ctx, command, markSideEffect)
	case "reclaim_accelerator":
		targetID, _ := command.Args["target_id"].(string)
		if targetID != p.cfg.NodeID+"-comfy" || p.cfg.ComfyUI.Endpoint == "" {
			return nil, "target is not the allowlisted local ComfyUI runtime"
		}
		if markSideEffect != nil {
			markSideEffect()
		}
		if err := reclaimComfy(ctx, p.cfg.ComfyUI.Endpoint); err != nil {
			return nil, err.Error()
		}
		// Native /free is only the mutation. It has no correlated authoritative
		// post-state, so retain the intent and require manual/managed-harness
		// reconciliation rather than fabricating a cold result.
		return nil, "observation_unavailable: native ComfyUI /free has no correlated post-state protocol"
	case "drain_runtimes":
		return p.drainRuntimes(ctx, markSideEffect)
	case "switch_runtime_profile":
		return p.switchRuntimeProfile(ctx, command.Args, markSideEffect)
	case "set_gpu_performance_profile":
		return p.setGPUPerformanceProfile(ctx, command.Args, markSideEffect)
	default:
		return nil, "command is not allowlisted"
	}
}

func (p *commandProcessor) queryModelState(ctx context.Context, command wsproto.CommandPayload) (map[string]any, string) {
	targetID, _ := command.Args["target_id"].(string)
	model, _ := command.Args["model"].(string)
	server, ok := p.routerTarget(targetID)
	if !ok || targetID != p.cfg.NodeID+"-"+server.ID || model == "" {
		return nil, "target is not an allowlisted local inference model"
	}
	discovery, err := DiscoverLlamaCPP(ctx, p.cfg.NodeID, server)
	if err != nil {
		return nil, "router discovery failed: " + err.Error()
	}
	runtimeIdentity, envelopeErr := p.validateResidencyCommandEnvelope(command, targetID, model, discovery)
	if envelopeErr != "" {
		return nil, envelopeErr
	}
	state, stateErr := discoverLlamaModelState(ctx, server, model)
	if stateErr != nil {
		return nil, "router model state is indeterminate: " + stateErr.Error()
	}
	if state == llamaStateTransitional {
		return nil, "router model state is indeterminate: transitional status"
	}
	resident := state == llamaStateLoaded
	warm := p.warmRAM != nil && p.warmRAM.IsVerifiedFor(targetID, model)
	tier := "cold_disk"
	if warm {
		tier = "warm_ram"
	} else if resident {
		tier = "hot_vram"
	}
	committedFence := p.fences[fenceKey(targetID, model)]
	referenceFence, referenceErr := exactFenceToken(command.Args["expected_fence"])
	if referenceErr != nil || committedFence != referenceFence {
		return nil, "authoritative state fence does not equal expected_fence"
	}
	originalID, _ := command.Args["original_command_id"].(string)
	originalKey, _ := command.Args["original_idempotency_key"].(string)
	result := map[string]any{"target_kind": "llamacpp", "target_id": targetID, "model": model, "resident": resident, "warm_ram": warm, "runtime_identity": runtimeIdentity, "capability_version": discovery.Version, "capability_revision": p.capabilityRevision(), "fencing_token": committedFence, "observed_after_fence": committedFence, "tier": tier, "original_command_id": originalID, "original_idempotency_key": originalKey, "expected_fence": committedFence}
	// Carry the named original action into the read proof. This prevents a
	// generic tier observation from being reused as evidence for another
	// lifecycle operation.
	action := ""
	if original, ok := p.results[originalID]; ok && original.Result != nil {
		action, _ = original.Result["action"].(string)
	}
	if action == "" {
		for _, pending := range p.pending {
			if pending.CommandID == originalID && pending.IdempotencyKey == originalKey {
				action = pending.Command
				break
			}
		}
	}
	if action != "" {
		result["action"] = action
		// A read observation did not itself mutate the runtime. The explicit
		// false marker is part of the exact state proof for hot/cold actions.
		result["changed"] = false
	}
	// A read-only query has one exact observed-tier proof. Hot state contains
	// no cleanup fields; cold state contains only the zero-byte cleanup proof;
	// warm state contains only the verified warm proof.
	if warm {
		for _, candidate := range p.warmRAM.Snapshot() {
			if candidate.Model == model {
				result["warm_model_bytes_verified"] = candidate.Verified
				result["warm_model_bytes"] = candidate.Bytes
				result["locked_bytes"] = candidate.LockedBytes
				result["oracle"] = candidate.Oracle
				result["released_vram"] = candidate.VRAMReleased
				break
			}
		}
		if action == "protect_warm_model" {
			for _, manifest := range p.warmRAM.ManifestSnapshot() {
				if manifest.TargetID == targetID && manifest.Model == model {
					result["protected"] = manifest.Protected
					result["active_references"] = int64(manifest.ActiveReferences)
					break
				}
			}
		}
	} else if !resident && (p.warmRAM == nil || !p.warmRAM.HasEntryFor(targetID, model)) {
		result["cleaned"] = true
		result["warm_entry_absent"] = true
		result["warm_release_verified"] = true
		result["warm_model_bytes"] = int64(0)
		result["locked_bytes"] = int64(0)
	}
	return result, ""
}

func (p *commandProcessor) rollbackRuntimeModel(server LlamaCPPServerConfig, model string, loaded bool) string {
	rollbackCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := mutateRuntimeModel(rollbackCtx, server, model, !loaded); err != nil {
		return "router model state is uncertain; rollback failed"
	}
	observed, err := waitLlamaModelState(rollbackCtx, server, model)
	if err != nil {
		return "router model state is uncertain; rollback confirmation failed"
	}
	if (observed == llamaStateLoaded) == !loaded {
		return "router transition expired; inverse state restored"
	}
	return "router model state is uncertain; reconciliation required"
}

func (p *commandProcessor) setGPUPerformanceProfile(ctx context.Context, args map[string]any, markSideEffect func()) (map[string]any, string) {
	acceleratorID, _ := args["accelerator_id"].(string)
	profile, _ := args["profile"].(string)
	if profile != "idle" && profile != "active" {
		return nil, "profile must be idle or active"
	}
	for _, configured := range p.cfg.GPUPerformance.Accelerators {
		if acceleratorID != fmt.Sprintf("%s-gpu%d", p.cfg.NodeID, configured.Index) {
			continue
		}
		fixed := configured.IdleCommand
		if profile == "active" {
			fixed = configured.ActiveCommand
		}
		if markSideEffect != nil {
			markSideEffect()
		}
		if err := p.runProfileCommand(ctx, fixed); err != nil {
			return nil, "fixed GPU profile command failed"
		}
		return map[string]any{"accelerator_id": acceleratorID, "profile": profile, "managed": true}, ""
	}
	if !strings.HasPrefix(acceleratorID, p.cfg.NodeID+"-gpu") {
		return nil, "accelerator is not owned by this node"
	}
	return map[string]any{"accelerator_id": acceleratorID, "profile": profile, "managed": false}, ""
}

func executeFixedProfileCommand(ctx context.Context, command []string) error {
	if len(command) == 0 {
		return fmt.Errorf("runtime profile command is empty")
	}
	process := exec.CommandContext(ctx, command[0], command[1:]...)
	process.Stdin = nil
	process.Stdout = io.Discard
	process.Stderr = io.Discard
	if err := process.Run(); err != nil {
		return errors.New("fixed runtime profile command failed")
	}
	return nil
}

func (p *commandProcessor) switchRuntimeProfile(ctx context.Context, args map[string]any, markSideEffect func()) (map[string]any, string) {
	targetID, _ := args["target_id"].(string)
	profileID, _ := args["profile_id"].(string)
	if targetID == "" || profileID == "" {
		return nil, "target_id and profile_id are required"
	}
	server, ok := p.routerTarget(targetID)
	if !ok {
		return nil, "target is not an allowlisted local inference server"
	}
	var selected *RuntimeProfileConfig
	for index := range server.RuntimeProfiles {
		if server.RuntimeProfiles[index].ID == profileID {
			selected = &server.RuntimeProfiles[index]
			break
		}
	}
	if selected == nil {
		return nil, "runtime profile is not allowlisted for target"
	}
	before, _ := DiscoverLlamaCPP(ctx, p.cfg.NodeID, server)
	if before.CapabilitiesVerified && before.ContextLimit == selected.ContextLimit && before.Slots == selected.Slots {
		return map[string]any{"target_id": targetID, "profile_id": profileID, "changed": false, "adapters": p.discoverAdaptersAfterProfileSwitch(ctx)}, ""
	}
	if markSideEffect != nil {
		markSideEffect()
	}
	if err := p.runProfileCommand(ctx, selected.SwitchCommand); err != nil {
		return nil, "runtime profile switch command failed"
	}
	selectedServer := server
	selectedServer.ContextLimit = selected.ContextLimit
	selectedServer.Slots = selected.Slots
	for {
		observed, err := DiscoverLlamaCPP(ctx, p.cfg.NodeID, selectedServer)
		if err == nil && observed.CapabilitiesVerified && observed.ContextLimit == selected.ContextLimit && observed.Slots == selected.Slots {
			return map[string]any{"target_id": targetID, "profile_id": profileID, "changed": true, "adapters": p.discoverAdaptersAfterProfileSwitch(ctx)}, ""
		}
		select {
		case <-ctx.Done():
			return nil, "runtime did not confirm selected profile before command expiry"
		case <-time.After(200 * time.Millisecond):
		}
	}
}

// switch_runtime_profile still owns its durable intent while collecting the
// post-switch advertisement. Do not start a managed checkpoint exercise from
// inside that command: discovery would re-enter Handle under the profile
// transition's pending state. The response carries current runtime facts and
// leaves changed checkpoint bindings false until the next serialized refresh.
func (p *commandProcessor) discoverAdaptersAfterProfileSwitch(ctx context.Context) []wsproto.AdapterAdvertisement {
	cfg := *p.cfg
	cfg.Checkpoint.ProofExerciseEnabled = false
	return discoverAdapters(ctx, &cfg, p.log, p)
}

func (p *commandProcessor) drainRuntimes(ctx context.Context, markSideEffect func()) (map[string]any, string) {
	unloaded := make([]string, 0)
	for _, server := range p.cfg.LlamaCPP.Servers {
		models, err := discoverLlamaRouterModels(ctx, server)
		if err != nil {
			return nil, "runtime discovery failed: " + err.Error()
		}
		loadedModels := make([]string, 0, len(models))
		for _, model := range models {
			if model.State == wsproto.RouterModelUnknown {
				return nil, "runtime model state is indeterminate"
			}
			if model.State == wsproto.RouterModelLoaded {
				loadedModels = append(loadedModels, model.ID)
			}
		}
		if len(loadedModels) > 0 && !runtimeMutationSupported(ctx, server) {
			return nil, "runtime lifecycle mutation protocol is not configured"
		}
		for _, model := range loadedModels {
			if markSideEffect != nil {
				markSideEffect()
			}
			if err := mutateRuntimeModel(ctx, server, model, false); err != nil {
				return nil, err.Error()
			}
			unloaded = append(unloaded, server.ID+":"+model)
		}
	}
	comfyReclaimed := false
	if p.cfg.ComfyUI.Endpoint != "" {
		if markSideEffect != nil {
			markSideEffect()
		}
		if err := reclaimComfy(ctx, p.cfg.ComfyUI.Endpoint); err != nil {
			return nil, err.Error()
		}
		comfyReclaimed = true
	}
	return map[string]any{"unloaded_models": unloaded, "comfy_reclaimed": comfyReclaimed}, ""
}

func (p *commandProcessor) warmModel(ctx context.Context, command wsproto.CommandPayload, markSideEffect func()) (map[string]any, string) {
	targetID, _ := command.Args["target_id"].(string)
	model, _ := command.Args["model"].(string)
	path, _ := command.Args["model_path"].(string)
	if path == "" {
		path, _ = command.Args["path"].(string)
	}
	if targetID == "" || model == "" {
		return nil, "target_id and model are required"
	}
	activeReferences := 0
	// Protection is an explicit signed policy input; omitted values remain
	// false and are never synthesized as a protection grant.
	protected := false
	if value, ok := command.Args["active_references"]; ok {
		parsed, err := exactFenceToken(value)
		if err != nil || parsed < 0 {
			return nil, "active_references must be a nonnegative integer"
		}
		if uint64(parsed) > uint64(^uint(0)>>1) {
			return nil, "active_references is out of range"
		}
		activeReferences = int(parsed)
		if explicitlyProtected, exists := command.Args["protected"].(bool); exists {
			protected = explicitlyProtected
		}
	}
	if value, ok := command.Args["protected"]; ok {
		parsed, valid := value.(bool)
		if !valid {
			return nil, "protected must be a boolean"
		}
		protected = parsed
	}
	server, serverOK := p.routerTarget(targetID)
	if !serverOK {
		return nil, "target is not an allowlisted local inference server"
	}
	targetID = p.cfg.NodeID + "-" + server.ID
	discovery, discoveryErr := DiscoverLlamaCPP(ctx, p.cfg.NodeID, server)
	runtimeIdentity := ""
	if discoveryErr == nil {
		var envelopeErr string
		runtimeIdentity, envelopeErr = p.validateResidencyCommandEnvelope(command, targetID, model, discovery)
		if envelopeErr != "" {
			return nil, envelopeErr
		}
	} else if discoveryErr != nil {
		return nil, "router discovery failed: " + discoveryErr.Error()
	}
	canonicalFence := p.fences[fenceKey(targetID, model)]
	if command.Command == "cleanup_warm_model" {
		if p.warmRAM == nil {
			return nil, ErrWarmRAMUnsupported.Error()
		}
		if !p.warmRAM.HasEntryFor(targetID, model) {
			if discoveryErr != nil {
				return nil, "runtime discovery failed: " + discoveryErr.Error()
			}
			state, stateErr := discoverLlamaModelState(ctx, server, model)
			if stateErr != nil || state != llamaStateUnloaded {
				return nil, "runtime did not provide exact unloaded confirmation"
			}
			return map[string]any{"target_id": targetID, "model": model, "resident": false, "warm_ram": false, "changed": false, "cleaned": true, "warm_entry_absent": true, "warm_release_verified": true, "warm_model_bytes": int64(0), "locked_bytes": int64(0), "runtime_identity": runtimeIdentity, "capability_version": discovery.Version, "capability_revision": p.capabilityRevision(), "fencing_token": canonicalFence, "observed_after_fence": canonicalFence, "tier": "cold_disk"}, ""
		}
		if markSideEffect != nil {
			markSideEffect()
		}
		if err := p.warmRAM.ReleaseModelFor(targetID, model); err != nil {
			return nil, err.Error()
		}
		state, stateErr := discoverLlamaModelState(ctx, server, model)
		if stateErr != nil || state != llamaStateUnloaded {
			return nil, "runtime did not provide exact unloaded confirmation"
		}
		if p.warmRAM.HasEntryFor(targetID, model) || p.warmRAM.IsVerifiedFor(targetID, model) {
			return nil, "warm residency cleanup lacks exact release confirmation"
		}
		// A failed admission may have retained an LRU victim rather than the
		// requested model. Only after both the runtime and local release proofs
		// succeed may the superseded warm intent be retired.
		if !p.warmRAM.HasUnverifiedEntries() {
			for id, pending := range p.pending {
				if pending.TargetID == targetID && isWarmLifecycleCommand(pending.Command) {
					delete(p.pending, id)
					delete(p.inflight, fenceKey(pending.TargetID, pending.Model))
				}
			}
			if p.stateBlockReason == blockReasonWarmTransient && len(p.pending) == 0 {
				p.stateBlocked = false
				p.stateBlockReason = ""
			}
		}
		return map[string]any{"target_id": targetID, "model": model, "resident": false, "warm_ram": false, "changed": true, "cleaned": true, "warm_entry_absent": true, "warm_release_verified": true, "warm_model_bytes": int64(0), "locked_bytes": int64(0), "runtime_identity": runtimeIdentity, "capability_version": discovery.Version, "capability_revision": p.capabilityRevision(), "fencing_token": canonicalFence, "observed_after_fence": canonicalFence, "tier": "cold_disk"}, ""
	}
	if command.Command == "protect_warm_model" {
		if p.warmRAM == nil {
			return nil, ErrWarmRAMUnsupported.Error()
		}
		if !p.warmRAM.HasEntryFor(targetID, model) {
			return nil, "warm model is not present"
		}
		state, stateErr := discoverLlamaModelState(ctx, server, model)
		if stateErr != nil || state != llamaStateUnloaded {
			return nil, "protect requires exact unloaded runtime confirmation"
		}
		result, err := p.warmRAM.UpdateProtectionFor(targetID, model, activeReferences, protected, markSideEffect)
		if err != nil {
			if markSideEffect != nil && p.warmRAM.HasEntryFor(targetID, model) && !p.warmRAM.IsVerifiedFor(targetID, model) {
				markSideEffect()
			}
			return nil, err.Error()
		}
		return map[string]any{"target_id": targetID, "model": model, "resident": false, "warm_ram": true, "changed": true, "warm_model_bytes_verified": result.Verified, "warm_model_bytes": result.Bytes, "locked_bytes": result.LockedBytes, "oracle": result.Oracle, "released_vram": result.VRAMReleased, "protected": protected, "active_references": activeReferences, "runtime_identity": runtimeIdentity, "capability_version": discovery.Version, "capability_revision": p.capabilityRevision(), "fencing_token": canonicalFence, "observed_after_fence": canonicalFence, "tier": "warm_ram"}, ""
	}
	configuredPath, mapped := server.ModelPaths[model]
	if !mapped || configuredPath == "" {
		return nil, "model has no configured local path"
	}
	if path != "" && path != configuredPath {
		return nil, "model path does not match configured model mapping"
	}
	path = configuredPath
	expectedFileFingerprint := server.ModelFingerprints[model]
	expectedRuntimeFingerprint := server.RuntimeFingerprints[model]
	if expectedFileFingerprint == "" || expectedRuntimeFingerprint == "" {
		return nil, "model fingerprints are not configured"
	}
	if !strings.EqualFold(discovery.ModelFingerprint, expectedRuntimeFingerprint) {
		return nil, "runtime manifest fingerprint did not match configured runtime"
	}
	if command.Command == "reverify_warm_model" {
		if p.warmRAM == nil {
			return nil, ErrWarmRAMUnsupported.Error()
		}
		// Reverification is only valid after discovery proves the model is
		// known but absent from the runtime, and the stable runtime manifest
		// matches the configured identity.  The proof is passed explicitly so
		// the manager cannot manufacture released-VRAM state.
		if !containsModel(discovery.Models, model) {
			return nil, "model is not an allowlisted runtime model"
		}
		state, stateErr := discoverLlamaModelState(ctx, server, model)
		if stateErr != nil || state == llamaStateTransitional || state == llamaStateLoaded {
			return nil, "model must be absent from runtime before reverification"
		}
		if state != llamaStateUnloaded {
			return nil, "runtime did not provide exact unloaded confirmation"
		}
		result, err := p.warmRAM.ReverifyModelWithCallback(targetID, model, path, expectedFileFingerprint, markSideEffect, true)
		if err != nil {
			return nil, err.Error()
		}
		if err := p.warmRAM.SetRuntimeManifest(targetID, model, discovery.ModelFingerprint, server.Endpoint, discovery.Version, discovery.ActiveRuntimeProfile); err != nil {
			return nil, err.Error()
		}
		return map[string]any{"target_id": targetID, "model": model, "resident": false, "warm_ram": true, "changed": true, "warm_model_bytes_verified": result.Verified, "warm_model_bytes": result.Bytes, "locked_bytes": result.LockedBytes, "oracle": result.Oracle, "released_vram": result.VRAMReleased, "runtime_identity": runtimeIdentity, "capability_version": discovery.Version, "capability_revision": p.capabilityRevision(), "fencing_token": canonicalFence, "observed_after_fence": canonicalFence, "tier": "warm_ram"}, ""
	}
	state, stateErr := discoverLlamaModelState(ctx, server, model)
	if stateErr != nil {
		return nil, "runtime model state could not be discovered"
	}
	if state == llamaStateTransitional {
		return nil, "runtime model state is indeterminate"
	}
	if !containsModel(discovery.Models, model) || state != llamaStateLoaded {
		return nil, "model is not an allowlisted resident model"
	}
	if p.warmRAM == nil || !p.warmRAM.Supported() {
		return nil, ErrWarmRAMUnsupported.Error()
	}
	result, err := p.warmRAM.OffloadModel(ctx, WarmRAMRequest{TargetID: targetID, Model: model, Path: path, ExpectedFingerprint: expectedFileFingerprint, RuntimeFingerprint: expectedRuntimeFingerprint, RuntimeEndpoint: server.Endpoint, RuntimeVersion: discovery.Version, RuntimeProfile: discovery.ActiveRuntimeProfile,
		ActiveReferences: activeReferences, Protected: protected,
		MarkSideEffect: markSideEffect,
		ReleaseVRAM: func(releaseCtx context.Context) error {
			if markSideEffect != nil {
				markSideEffect()
			}
			return mutateRuntimeModel(releaseCtx, server, model, false)
		},
		ConfirmReleased: func(confirmCtx context.Context) (bool, error) {
			for {
				state, e := discoverLlamaModelState(confirmCtx, server, model)
				if e == nil && state == llamaStateUnloaded {
					return true, nil
				}
				if e == nil && state != llamaStateTransitional {
					return false, errors.New("runtime did not provide exact unloaded confirmation")
				}
				select {
				case <-confirmCtx.Done():
					return false, confirmCtx.Err()
				case <-time.After(100 * time.Millisecond):
				}
			}
		},
		RestoreVRAM: func(restoreCtx context.Context) error {
			if markSideEffect != nil {
				markSideEffect()
			}
			return mutateRuntimeModel(restoreCtx, server, model, true)
		},
	})
	if err != nil {
		// A failed post-pin identity check or cleanup leaves a retry handle in
		// the manager.  Treat that local pin mutation as an uncertain side
		// effect so the signed intent remains durable and readiness stays false.
		if markSideEffect != nil && p.warmRAM.HasUnverifiedEntries() {
			markSideEffect()
		}
		return nil, err.Error()
	}
	observedState, observeErr := discoverLlamaModelState(ctx, server, model)
	if observeErr != nil || observedState == llamaStateTransitional || observedState != llamaStateUnloaded {
		return nil, "warm transition did not prove authoritative unloaded runtime state"
	}
	observed, observeErr := DiscoverLlamaCPP(ctx, p.cfg.NodeID, server)
	if observeErr != nil {
		return nil, "warm transition runtime identity could not be rediscovered"
	}
	p.commitFence(command, targetID, model)
	return map[string]any{"target_id": targetID, "model": model, "resident": false, "warm_ram": true, "changed": true, "warm_model_bytes_verified": result.Verified, "warm_model_bytes": result.Bytes, "locked_bytes": result.LockedBytes, "released_vram": result.VRAMReleased, "oracle": result.Oracle, "runtime_identity": canonicalCommandRuntimeIdentity(targetID, observed), "capability_revision": p.capabilityRevision(), "fencing_token": p.fences[fenceKey(targetID, model)], "observed_after_fence": p.fences[fenceKey(targetID, model)], "tier": "warm_ram"}, ""
}

func containsModel(models []string, wanted string) bool {
	for _, model := range models {
		if model == wanted {
			return true
		}
	}
	return false
}

func (p *commandProcessor) checkFence(command wsproto.CommandPayload, targetID, model string) error {
	value, present := command.Args["fencing_token"]
	if !present {
		return errors.New("fencing_token is required")
	}
	token, err := exactFenceToken(value)
	if err != nil {
		return err
	}
	if token < 0 {
		return errors.New("fencing_token must not be negative")
	}
	if previous, exists := p.fences[fenceKey(targetID, model)]; exists && token <= previous {
		return fmt.Errorf("stale fencing token: %d is not above %d", token, previous)
	}
	return nil
}
func (p *commandProcessor) commitFence(command wsproto.CommandPayload, targetID, model string) {
	if token, err := exactFenceToken(command.Args["fencing_token"]); err == nil {
		p.fences[fenceKey(targetID, model)] = token
	}
}

// fenceKey is a collision-free, length-prefixed tuple. Resource names are
// canonical stable resources (for example runtime_profile), never desired
// profile values, so every semantic mutation shares one monotonic fence.
func fenceKey(target, resource string) string {
	return fmt.Sprintf("%d:%s%d:%s", len(target), target, len(resource), resource)
}

func ownedStopFenceKey(accelerator string) string { return "owned-stop-accelerator:" + accelerator }

func (p *commandProcessor) checkOwnedStopTransition(command wsproto.CommandPayload) error {
	accelerator := fmt.Sprint(command.Args["accelerator_id"])
	operation := fmt.Sprint(command.Args["operation_id"])
	step := fmt.Sprint(command.Args["step_id"])
	epoch := fmt.Sprint(command.Args["recovery_epoch"])
	token, err := exactFenceToken(command.Args["fencing_token"])
	if err != nil || accelerator == "" || operation == "" || epoch == "" || token <= 0 {
		return errors.New("owned stop accelerator fence identity is incomplete")
	}
	state, exists := p.ownedStopOperations[accelerator]
	previous := p.fences[ownedStopFenceKey(accelerator)]
	if !exists {
		if token <= previous || step != "victim_stop" {
			return errors.New("owned stop operation must begin with a fresh victim fence")
		}
		return nil
	}
	if state.UsedOperationIDs[operation] && state.OperationID != operation {
		return errors.New("owned stop operation identity was already consumed on this accelerator")
	}
	if state.OperationID == operation && (state.Fence != token || state.RecoveryEpoch != epoch) {
		return errors.New("owned stop operation identity cannot change fence or recovery epoch")
	}
	allSettled := true
	for _, prior := range state.Steps {
		if prior.Status != "acknowledged" {
			allSettled = false
			break
		}
	}
	if state.OperationID == operation && state.Fence == token && state.RecoveryEpoch == epoch {
		if !allSettled {
			return errors.New("owned stop operation has an unresolved earlier step")
		}
		if _, duplicate := state.Steps[step]; duplicate {
			return errors.New("owned stop operation step was already used")
		}
		if step == "urgent_stop" && state.Steps["victim_stop"].Status != "acknowledged" {
			return errors.New("urgent stop requires the same-fence victim stop receipt")
		}
		return nil
	}
	if !allSettled || token <= previous || step != "victim_stop" {
		return errors.New("new owned stop operation must use a higher fence after prior terminal receipts")
	}
	return nil
}

func (p *commandProcessor) recordOwnedStopStep(command wsproto.CommandPayload, intent pendingCommand, status, receiptDigest string) error {
	accelerator := fmt.Sprint(command.Args["accelerator_id"])
	operation := fmt.Sprint(command.Args["operation_id"])
	step := fmt.Sprint(command.Args["step_id"])
	state := p.ownedStopOperations[accelerator]
	if state.OperationID != operation || state.Fence != intent.Token || state.RecoveryEpoch != intent.StopRecoveryEpoch {
		used := state.UsedOperationIDs
		if used == nil {
			used = make(map[string]bool)
		}
		state = ownedStopOperationState{OperationID: operation, AcceleratorID: accelerator, Fence: intent.Token, RecoveryEpoch: intent.StopRecoveryEpoch, UsedOperationIDs: used, Steps: make(map[string]ownedStopStepState)}
	}
	if state.UsedOperationIDs == nil {
		state.UsedOperationIDs = make(map[string]bool)
	}
	state.UsedOperationIDs[operation] = true
	if state.Steps == nil {
		state.Steps = make(map[string]ownedStopStepState)
	}
	digest := sha256Hex(intent.OriginalEnvelope)
	if prior, exists := state.Steps[step]; exists && (prior.CommandID != command.ID || prior.IdempotencyKey != command.IdempotencyKey || prior.EnvelopeSHA256 != digest) {
		return errors.New("owned stop step identity was already bound")
	}
	state.Steps[step] = ownedStopStepState{CommandID: command.ID, IdempotencyKey: command.IdempotencyKey, EnvelopeSHA256: digest, PinnedRootStopPublicKey: append([]byte(nil), intent.PinnedRootStopPublicKey...), Status: status, ReceiptSHA256: receiptDigest}
	p.ownedStopOperations[accelerator] = state
	return nil
}

func (p *commandProcessor) dropOwnedStopStep(command wsproto.CommandPayload) {
	accelerator := fmt.Sprint(command.Args["accelerator_id"])
	state, exists := p.ownedStopOperations[accelerator]
	if !exists {
		return
	}
	step := fmt.Sprint(command.Args["step_id"])
	if prior := state.Steps[step]; prior.CommandID == command.ID && prior.Status == "pending" {
		delete(state.Steps, step)
		p.ownedStopOperations[accelerator] = state
	}
}

func exactFenceToken(value any) (int64, error) {
	switch n := value.(type) {
	case int:
		return int64(n), nil
	case int64:
		return n, nil
	case json.Number:
		v, err := n.Int64()
		if err != nil {
			return 0, errors.New("fencing_token must be an integer")
		}
		return v, nil
	case float64:
		if math.IsNaN(n) || math.IsInf(n, 0) || n != float64(int64(n)) {
			return 0, errors.New("fencing_token must be an integer")
		}
		return int64(n), nil
	default:
		return 0, errors.New("fencing_token must be an integer")
	}
}

func commandFingerprint(command wsproto.CommandPayload) string {
	return wsproto.ResidencyCommandFingerprint(command.NodeID, command.Command, command.IdempotencyKey, command.Args)
}

func (p *commandProcessor) semanticFingerprint(command wsproto.CommandPayload) string {
	normalized := command
	var args map[string]any
	cloneArgs := func() map[string]any {
		if args == nil {
			args = make(map[string]any, len(command.Args)+1)
			for key, value := range command.Args {
				args[key] = value
			}
		}
		return args
	}
	if target, ok := command.Args["target_id"].(string); ok {
		if server, found := p.routerTarget(target); found {
			cloneArgs()["target_id"] = p.cfg.NodeID + "-" + server.ID
		}
	}
	// The resource is derived from the signed accelerator identity when the
	// intent is created. Recompute that same semantic field for all later
	// pending/cache/query comparisons; it is deliberately not accepted from
	// the wire and does not alter the original envelope or its HMAC.
	if command.Command == "llm_displacement_stop" {
		if accelerator, ok := command.Args["accelerator_id"].(string); ok && strings.TrimSpace(accelerator) != "" {
			cloneArgs()["resource"] = "owned-stop:" + accelerator
		}
	}
	if args != nil {
		normalized.Args = args
	}
	return commandFingerprint(normalized)
}

func (p *commandProcessor) routerTarget(targetID string) (LlamaCPPServerConfig, bool) {
	shortID := strings.TrimPrefix(targetID, p.cfg.NodeID+"-")
	for _, server := range p.cfg.LlamaCPP.Servers {
		if server.ID == targetID || server.ID == shortID {
			return server, true
		}
	}
	return LlamaCPPServerConfig{}, false
}

func mutateRouterModel(ctx context.Context, endpoint, model string, load bool) error {
	path := "/models/unload"
	if load {
		path = "/models/load"
	}
	body, _ := json.Marshal(map[string]string{"model": model})
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(endpoint, "/")+path, bytes.NewReader(body))
	if err != nil {
		return errors.New("router mutation request could not be created")
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return errors.New("router mutation request failed")
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("router mutation returned status %d", response.StatusCode)
	}
	return nil
}

func mutateRuntimeModel(ctx context.Context, server LlamaCPPServerConfig, model string, load bool) error {
	if isOllamaServer(ctx, server) {
		keepAlive := 0
		if load {
			keepAlive = -1
		}
		body, _ := json.Marshal(map[string]any{"model": model, "prompt": "", "stream": false, "keep_alive": keepAlive})
		if err := postRuntimeJSON(ctx, strings.TrimRight(server.Endpoint, "/")+"/api/generate", body, "Ollama model transition"); err != nil {
			return err
		}
		return nil
	}
	if !server.RouterManaged {
		return fmt.Errorf("runtime lifecycle was discovered but no allowlisted mutation protocol is configured")
	}
	return mutateRouterModel(ctx, server.Endpoint, model, load)
}

func isOllamaServer(ctx context.Context, server LlamaCPPServerConfig) bool {
	for _, argument := range server.RuntimeArgs {
		if strings.Contains(strings.ToLower(argument), "ollama") {
			return true
		}
	}
	_, err := getJSON(ctx, strings.TrimRight(server.Endpoint, "/")+"/api/ps")
	return err == nil
}

func runtimeMutationSupported(ctx context.Context, server LlamaCPPServerConfig) bool {
	return server.RouterManaged || isOllamaServer(ctx, server)
}

func reclaimComfy(ctx context.Context, endpoint string) error {
	body, _ := json.Marshal(map[string]bool{"unload_models": true, "free_memory": true})
	return postRuntimeJSON(ctx, strings.TrimRight(endpoint, "/")+"/free", body, "ComfyUI runtime drain")
}

func postRuntimeJSON(ctx context.Context, url string, body []byte, operation string) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("%s request could not be created", operation)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return fmt.Errorf("%s request failed", operation)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("%s returned status %d", operation, response.StatusCode)
	}
	return nil
}

func (p *commandProcessor) load() {
	if p.cfg.CommandStatePath == "" {
		return
	}
	markerErr := p.loadRecoveryMarker()
	if markerErr != nil && !errors.Is(markerErr, errRecoveryMarkerNeedsAdmin) {
		return
	}
	readState := p.readState
	if readState == nil {
		readState = os.ReadFile
	}
	body, err := readState(p.cfg.CommandStatePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// A missing primary is first boot only when no durable evidence of
			// prior state exists. Never let a torn/removed primary beside a
			// journal or recovery marker reset fences and idempotency history.
			p.blockIfDurableStateEvidence()
			return
		}
		p.block(blockReasonRead)
		return
	}
	var envelope commandStateEnvelope
	if json.Unmarshal(body, &envelope) != nil || envelope.Version != commandStateVersion || envelope.Checksum == "" || envelope.State.Results == nil {
		p.quarantineState()
		return
	}
	encoded, err := json.Marshal(envelope.State)
	if err != nil {
		p.block(blockReasonCorrupt)
		return
	}
	sum := sha256.Sum256(encoded)
	if !strings.EqualFold(envelope.Checksum, hex.EncodeToString(sum[:])) {
		p.quarantineState()
		return
	}
	p.results = envelope.State.Results
	p.commandFingerprints = envelope.State.CommandFingerprints
	if p.commandFingerprints == nil {
		p.commandFingerprints = make(map[string]string)
	}
	if envelope.State.Fences != nil {
		p.fences = envelope.State.Fences
	}
	if envelope.State.CheckpointPhases != nil {
		p.checkpointPhases = envelope.State.CheckpointPhases
	}
	if envelope.State.OwnedStopOperations != nil {
		p.ownedStopOperations = envelope.State.OwnedStopOperations
	}
	if envelope.State.PlanRelaunchOperations != nil {
		p.planRelaunchOperations = envelope.State.PlanRelaunchOperations
	}
	if p.checkpointPhases == nil {
		p.checkpointPhases = make(map[string]checkpointPhaseState)
	}
	if envelope.State.RecoveryEpoch != "" {
		p.recoveryEpoch = envelope.State.RecoveryEpoch
	}
	if envelope.State.RecoveryGeneration > p.recoveryGeneration {
		p.recoveryGeneration = envelope.State.RecoveryGeneration
	}
	if envelope.State.RecoveryAnchorHash != "" {
		p.recoveryAnchorHash = envelope.State.RecoveryAnchorHash
	}
	// A non-empty journal is authoritative evidence that this state has
	// participated in the anchored-save protocol. A sequence-zero primary
	// alongside it is therefore a rollback/legacy overwrite, never an
	// implicitly accepted legacy state. Legacy migration is only safe before
	// any journal exists and must create the initial anchor before mutation.
	journalBody, journalErr := os.ReadFile(p.journalPath())
	journalNonempty := journalErr == nil && len(bytes.TrimSpace(journalBody)) > 0
	if journalNonempty && envelope.State.JournalSequence == 0 {
		p.block(blockReasonDurability)
	}
	if journalErr != nil && !errors.Is(journalErr, os.ErrNotExist) && envelope.State.JournalSequence == 0 {
		p.block(blockReasonDurability)
	}
	if envelope.State.JournalSequence > 0 {
		if err := p.validateJournal(envelope.State, envelope.Checksum); err != nil {
			// Preserve the last complete primary so its pending intent/fences
			// remain available for operator recovery; an unresolved prepared
			// journal record still blocks all commands fail-closed.
			p.block(blockReasonDurability)
		}
		p.journalSequence = envelope.State.JournalSequence
		p.journalPrevHash = envelope.State.JournalPrevHash
		if latest, latestErr := p.latestJournalHash(); latestErr == nil {
			p.journalHash = latest
		}
	}
	if p.usedRecoveryEpochs == nil {
		p.usedRecoveryEpochs = make(map[string]struct{})
	}
	for _, epochHash := range envelope.State.UsedRecoveryEpochs {
		if len(epochHash) != sha256.Size*2 {
			p.quarantineState()
			return
		}
		if _, err := hex.DecodeString(epochHash); err != nil {
			p.quarantineState()
			return
		}
		p.usedRecoveryEpochs[epochHash] = struct{}{}
	}
	if p.recoveryEpoch != "" {
		p.usedRecoveryEpochs[recoveryEpochHash(p.recoveryEpoch)] = struct{}{}
	}
	p.persistedWarm = append([]WarmRAMManifest(nil), envelope.State.Warm...)
	if envelope.State.BlockReason != "" {
		switch envelope.State.BlockReason {
		case blockReasonWarmTransient, blockReasonCorrupt, blockReasonRead, blockReasonQuarantine, blockReasonDurability:
			// Restored state is untrusted until its journal has been validated.
			// Keep any stronger block found during validation instead of letting
			// a checksummed-but-unanchored primary downgrade it.
			p.block(envelope.State.BlockReason)
		default:
			p.quarantineState()
			return
		}
	}
	seenWarmKeys := make(map[string]struct{}, len(p.persistedWarm))
	for _, manifest := range p.persistedWarm {
		if manifest.TargetID == "" || manifest.Model == "" || manifest.CanonicalPath == "" || manifest.FileFingerprint == "" || manifest.Size <= 0 || manifest.LastUsed.IsZero() || manifest.LastUsed.After(time.Now().UTC().Add(5*time.Minute)) || manifest.LastUsed.Before(time.Unix(0, 0).UTC()) || (manifest.Verified && manifest.VRAMReleased && (manifest.RuntimeFingerprint == "" || manifest.RuntimeEndpoint == "" || manifest.RuntimeVersion == "" || !manifest.RuntimeProfilePresent)) {
			p.quarantineState()
			return
		}
		key := warmEntryKey(manifest.TargetID, manifest.Model)
		if _, duplicate := seenWarmKeys[key]; duplicate {
			p.quarantineState()
			return
		}
		seenWarmKeys[key] = struct{}{}
		if manifest.ActiveReferences < 0 || (manifest.Verified && !manifest.VRAMReleased && !manifest.MetadataOnly) {
			p.quarantineState()
			return
		}
	}
	if len(envelope.State.Pending) > 0 {
		for _, intent := range envelope.State.Pending {
			if intent.CommandID == "" || intent.Fingerprint == "" || intent.TargetID == "" || intent.Model == "" || intent.ManifestJSON == "" || !json.Valid([]byte(intent.ManifestJSON)) || intent.Token < 0 || intent.ActiveReferences < 0 {
				p.quarantineState()
				return
			}
		}
		p.pending = envelope.State.Pending
		p.block(blockReasonWarmTransient)
	}
}

func (p *commandProcessor) blockIfDurableStateEvidence() {
	if p.recoveryMarker != nil {
		p.block(blockReasonDurability)
		return
	}
	if _, err := os.Stat(p.journalPath()); err == nil {
		// Existence itself is evidence: an empty, whitespace-only, or
		// truncated journal can represent a crash between durable stages.
		p.block(blockReasonDurability)
		return
	} else if !errors.Is(err, os.ErrNotExist) {
		p.block(blockReasonRead)
	}
}

func (p *commandProcessor) quarantineState() {
	if p.cfg.CommandStatePath == "" {
		p.block(blockReasonQuarantine)
		return
	}
	renameState := p.renameState
	if renameState == nil {
		renameState = os.Rename
	}
	original := recoveryIdentity(p.cfg.CommandStatePath)
	quarantinePath := p.cfg.CommandStatePath + ".corrupt"
	if err := p.writeRecoveryMarker(blockReasonCorrupt, "prepared", original, recoveryFileIdentity{}); err != nil {
		p.block(blockReasonQuarantine)
		return
	}
	if err := renameState(p.cfg.CommandStatePath, quarantinePath); err == nil {
		p.block(blockReasonCorrupt)
		syncDir := p.syncDir
		if syncDir == nil {
			syncDir = syncCommandStateDir
		}
		if err := syncDir(filepath.Dir(p.cfg.CommandStatePath)); err != nil {
			p.block(blockReasonQuarantine)
		}
		if err := p.writeRecoveryMarker(p.stateBlockReason, "quarantined", original, recoveryIdentity(quarantinePath)); err != nil {
			p.block(blockReasonQuarantine)
		}
	} else {
		p.block(blockReasonQuarantine)
		if markerErr := p.writeRecoveryMarker(p.stateBlockReason, "quarantined", original, recoveryIdentity(quarantinePath)); markerErr != nil {
			p.block(blockReasonQuarantine)
		}
	}
}

// RecoverCommandState is an explicit local/admin recovery boundary. A fresh,
// non-empty recovery epoch is required; ordinary reconciliation and signed
// remote commands cannot clear a durable block. Fences, idempotency results,
// and completed command fingerprints are deliberately retained.
func (p *commandProcessor) RecoverCommandState(epochs ...string) error {
	if p.cfg.CommandStatePath == "" {
		return errors.New("command state recovery is not configured")
	}
	if len(epochs) != 1 || strings.TrimSpace(epochs[0]) == "" {
		return errors.New("a new recovery epoch is required")
	}
	newEpoch := strings.TrimSpace(epochs[0])
	if p.recoveryMarker == nil {
		if err := p.loadRecoveryMarker(); err != nil && !errors.Is(err, errRecoveryMarkerNeedsAdmin) {
			return errors.New("recovery marker could not be validated")
		}
	}
	return p.recoverCommandState(newEpoch, p.recoveryGeneration+1)
}

func (p *commandProcessor) recoverCommandState(newEpoch string, generation uint64) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.recoveryMarker == nil {
		return errors.New("recovery marker is required")
	}
	if p.recoveryMarker.Phase == recoveryMarkerPhaseRecoveryCommitted && p.recoveryMarker.TargetStateChecksum != "" && p.stateFileChecksum() != p.recoveryMarker.TargetStateChecksum {
		return errors.New("committed recovery target does not match durable state")
	}
	if p.recoveryMarker.Phase == recoveryMarkerPhaseRecoveryPrepared {
		if generation != p.recoveryMarker.RecoveryGeneration || recoveryEpochHash(newEpoch) != p.recoveryMarker.RecoveryEpochHash {
			return errors.New("prepared recovery requires the recorded generation and epoch")
		}
	}
	if generation == 0 || generation <= p.recoveryGeneration {
		return errors.New("recovery generation is not newer than the recorded generation")
	}
	hash := recoveryEpochHash(newEpoch)
	if p.usedRecoveryEpochs == nil {
		p.usedRecoveryEpochs = make(map[string]struct{})
	}
	if _, used := p.usedRecoveryEpochs[hash]; used {
		return errors.New("recovery epoch was already used")
	}
	if p.recoveryMarker.Phase != recoveryMarkerPhaseRecoveryCommitted {
		if _, err := os.Stat(p.cfg.CommandStatePath + ".corrupt"); err != nil && p.stateBlockReason != blockReasonDurability {
			p.block(blockReasonQuarantine)
			return errors.New("quarantine state is unavailable")
		}
	}
	// Compute the target checksum before changing the durable primary. The
	// target retains completed results/fingerprints/fences but clears uncertain
	// transitions and warm claims.
	oldEpoch, oldGeneration, oldAnchor := p.recoveryEpoch, p.recoveryGeneration, p.recoveryAnchorHash
	oldJournalSequence, oldJournalHash, oldJournalPrev := p.journalSequence, p.journalHash, p.journalPrevHash
	oldUsed := p.usedRecoveryEpochs
	oldPending, oldInflight, oldWarm := p.pending, p.inflight, p.persistedWarm
	oldBlocked, oldReason := p.stateBlocked, p.stateBlockReason
	p.recoveryEpoch, p.recoveryGeneration = newEpoch, generation
	newAnchor := recoveryAnchorHash(oldAnchor, generation, hash)
	p.recoveryAnchorHash = newAnchor
	p.journalSequence, p.journalPrevHash = oldJournalSequence+1, oldJournalHash
	p.usedRecoveryEpochs = make(map[string]struct{}, len(oldUsed)+1)
	for used := range oldUsed {
		p.usedRecoveryEpochs[used] = struct{}{}
	}
	p.usedRecoveryEpochs[hash] = struct{}{}
	p.pending, p.inflight, p.persistedWarm = make(map[string]pendingCommand), make(map[string]bool), nil
	p.stateBlocked, p.stateBlockReason = false, ""
	targetChecksum := checksumForStatePayload(p.commandStatePayload())
	p.recoveryEpoch, p.recoveryGeneration, p.recoveryAnchorHash = oldEpoch, oldGeneration, oldAnchor
	p.journalSequence, p.journalHash, p.journalPrevHash = oldJournalSequence, oldJournalHash, oldJournalPrev
	p.usedRecoveryEpochs = oldUsed
	p.pending, p.inflight, p.persistedWarm = oldPending, oldInflight, oldWarm
	p.stateBlocked, p.stateBlockReason = oldBlocked, oldReason
	if err := p.writeRecoveryMarkerTarget(blockReasonDurability, recoveryMarkerPhaseRecoveryPrepared, recoveryIdentity(p.cfg.CommandStatePath), recoveryIdentity(p.cfg.CommandStatePath+".corrupt"), targetChecksum, generation, newEpoch); err != nil {
		p.block(blockReasonDurability)
		return errors.New("recovery prepared marker could not be persisted")
	}
	p.recoveryEpoch, p.recoveryGeneration = newEpoch, generation
	p.recoveryAnchorHash = newAnchor
	p.journalSequence, p.journalHash, p.journalPrevHash = oldJournalSequence, oldJournalHash, oldJournalPrev
	p.usedRecoveryEpochs = make(map[string]struct{}, len(oldUsed)+1)
	for used := range oldUsed {
		p.usedRecoveryEpochs[used] = struct{}{}
	}
	p.usedRecoveryEpochs[hash] = struct{}{}
	p.pending, p.inflight, p.persistedWarm = make(map[string]pendingCommand), make(map[string]bool), nil
	p.stateBlocked, p.stateBlockReason = false, ""
	p.inRecovery = true
	err := p.save()
	p.inRecovery = false
	if err != nil {
		p.block(blockReasonDurability)
		return errors.New("rebuilt command state could not be persisted")
	}
	if err := p.writeRecoveryMarkerTarget(blockReasonDurability, recoveryMarkerPhaseRecoveryCommitted, recoveryIdentity(p.cfg.CommandStatePath), recoveryIdentity(p.cfg.CommandStatePath+".corrupt"), targetChecksum, generation, newEpoch); err != nil {
		p.block(blockReasonDurability)
		return errors.New("recovery commit marker could not be persisted")
	}
	p.stateBlocked, p.stateBlockReason = false, ""
	marker := *p.recoveryMarker
	marker.Phase, marker.RecoveryEpoch, marker.RecoveryEpochHash = recoveryMarkerPhaseRecoveryCommitted, newEpoch, hash
	marker.Timestamp = time.Now().UTC()
	marker.RecoveryGeneration, marker.RecoveryAnchorHash, marker.TargetStateChecksum = generation, newAnchor, targetChecksum
	p.recoveryMarker = &marker
	return nil
}

// ReconcilePending inspects runtime truth after a restart or uncertain
// transition. It clears an intent only when the runtime reports the intended
// final state; otherwise the durable intent remains blocked for operator or
// controller recovery.
func (p *commandProcessor) validatePendingManifest(intent pendingCommand) (pendingOperationManifest, error) {
	var manifest pendingOperationManifest
	if intent.ManifestJSON == "" || json.Unmarshal([]byte(intent.ManifestJSON), &manifest) != nil {
		return manifest, errors.New("pending transition manifest is invalid")
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(intent.ManifestJSON), &raw); err != nil {
		return manifest, errors.New("pending transition manifest is invalid")
	}
	allowedManifestKeys := map[string]bool{"schema_version": true, "action": true, "node_id": true, "command_id": true, "idempotency_key": true, "fingerprint": true, "target_kind": true, "target_id": true, "model": true, "runtime_identity": true, "capability_version": true, "capability_revision": true, "expected_tier": true, "fencing_token": true, "active_references": true, "protected": true, "args": true}
	for key := range raw {
		if !allowedManifestKeys[key] {
			return manifest, errors.New("pending transition manifest contains an unknown field")
		}
	}
	for key := range allowedManifestKeys {
		if _, present := raw[key]; !present {
			return manifest, errors.New("pending transition manifest is missing a required field")
		}
	}
	if manifest.SchemaVersion != pendingManifestVersion || manifest.NodeID != p.cfg.NodeID {
		return manifest, errors.New("pending transition manifest schema or node binding is invalid")
	}
	if manifest.Action != intent.Command || manifest.CommandID != intent.CommandID || manifest.IdempotencyKey != intent.IdempotencyKey || manifest.Fingerprint != intent.Fingerprint {
		return manifest, errors.New("pending transition manifest operation binding drifted")
	}
	if manifest.TargetID != intent.TargetID || manifest.Model != intent.Model || manifest.FencingToken != intent.Token {
		return manifest, errors.New("pending transition manifest identity or fence drifted")
	}
	if intent.RuntimeIdentity != "" && manifest.RuntimeIdentity != intent.RuntimeIdentity {
		return manifest, errors.New("pending transition manifest runtime identity binding drifted")
	}
	if manifest.TargetKind == "" || (!isResourceCommand(intent.Command) && manifest.ExpectedTier != expectedResidencyTier(intent.Command)) {
		return manifest, errors.New("pending transition manifest target kind or tier is invalid")
	}
	if manifest.Args == nil {
		return manifest, errors.New("pending transition manifest arguments are missing")
	}
	allowedArgs := map[string]bool{"target_kind": true, "target_id": true, "model": true, "runtime_identity": true, "capability_version": true, "capability_revision": true, "expected_tier": true, "fencing_token": true, "expected_fence": true, "observed_after_fence": true, "model_path": true, "path": true, "active_references": true, "protected": true, "resource": true, "profile_id": true, "accelerator_id": true, "original_command_id": true, "original_idempotency_key": true}
	for key := range manifest.Args {
		if !allowedArgs[key] {
			return manifest, errors.New("pending transition manifest arguments contain an unknown field")
		}
	}
	if p.strictResidencyEnvelope && !isResourceCommand(intent.Command) {
		if err := wsproto.ValidateResidencyCommandArgs(intent.Command, manifest.Args); err != nil {
			return manifest, err
		}
		requiredArgs := []string{"target_kind", "target_id", "fencing_token"}
		if !isResourceCommand(intent.Command) {
			requiredArgs = append(requiredArgs, "model", "runtime_identity", "capability_version", "capability_revision", "expected_tier")
		}
		for _, key := range requiredArgs {
			if _, present := manifest.Args[key]; !present {
				return manifest, fmt.Errorf("pending transition manifest argument %s is missing", key)
			}
		}
	}
	normalizedCommand := wsproto.CommandPayload{NodeID: manifest.NodeID, Command: manifest.Action, IdempotencyKey: manifest.IdempotencyKey, Args: manifest.Args}
	if recomputed := commandFingerprint(normalizedCommand); recomputed != manifest.Fingerprint || recomputed != intent.Fingerprint {
		return manifest, errors.New("pending transition manifest fingerprint drifted")
	}
	if targetKind, present := manifest.Args["target_kind"]; present {
		if value, ok := targetKind.(string); !ok || value != manifest.TargetKind {
			return manifest, errors.New("pending transition manifest target kind drifted")
		}
	} else if p.strictResidencyEnvelope {
		return manifest, errors.New("pending transition manifest target kind is missing")
	}
	if target, _ := manifest.Args["target_id"].(string); target != intent.TargetID {
		return manifest, errors.New("pending transition manifest argument target drifted")
	}
	if isResourceCommand(intent.Command) {
		if resource, _ := manifest.Args["resource"].(string); resource != intent.Model {
			return manifest, errors.New("pending transition manifest resource drifted")
		}
	} else if model, _ := manifest.Args["model"].(string); model != intent.Model {
		return manifest, errors.New("pending transition manifest argument model drifted")
	}
	if token, err := exactFenceToken(manifest.Args["fencing_token"]); err != nil || token != intent.Token {
		return manifest, errors.New("pending transition manifest argument fence drifted")
	}
	if runtimeIdentity, present := manifest.Args["runtime_identity"]; present {
		if value, ok := runtimeIdentity.(string); !ok || value != manifest.RuntimeIdentity {
			return manifest, errors.New("pending transition manifest runtime identity drifted")
		}
	} else if manifest.RuntimeIdentity != "" {
		return manifest, errors.New("pending transition manifest runtime identity is missing")
	}
	if capabilityVersion, present := manifest.Args["capability_version"]; present {
		if value, ok := capabilityVersion.(string); !ok || value != manifest.CapabilityVersion {
			return manifest, errors.New("pending transition manifest capability version drifted")
		}
	}
	if capabilityRevision, present := manifest.Args["capability_revision"]; present {
		if value, ok := capabilityRevision.(string); !ok || value != manifest.CapabilityRevision {
			return manifest, errors.New("pending transition manifest capability revision drifted")
		}
	}
	if expectedTier, present := manifest.Args["expected_tier"]; present {
		if value, ok := expectedTier.(string); !ok || value != manifest.ExpectedTier {
			return manifest, errors.New("pending transition manifest expected tier drifted")
		}
	}
	if value, present := manifest.Args["active_references"]; present {
		parsed, err := exactFenceToken(value)
		if err != nil || parsed < 0 || parsed != int64(intent.ActiveReferences) {
			return manifest, errors.New("pending transition manifest protection references drifted")
		}
	}
	if value, present := manifest.Args["protected"]; present {
		protected, ok := value.(bool)
		if !ok || protected != intent.Protected {
			return manifest, errors.New("pending transition manifest protection state drifted")
		}
	}
	if p.strictResidencyEnvelope && (manifest.TargetKind == "" || manifest.RuntimeIdentity == "" || manifest.CapabilityVersion == "" || manifest.CapabilityRevision == "") {
		return manifest, errors.New("pending transition manifest lacks the complete signed residency envelope")
	}
	return manifest, nil
}

func cachedResidencyResultAllowedKeys(command string) map[string]bool {
	allowed := map[string]bool{
		"action": true, "target_kind": true, "target_id": true, "model": true, "node_id": true,
		"resident": true, "warm_ram": true, "runtime_identity": true,
		"capability_version": true, "capability_revision": true,
		"fencing_token": true, "observed_after_fence": true, "tier": true,
		"reconciled": true, "original_command_id": true,
		"original_idempotency_key": true, "command_id": true,
		"idempotency_key": true, "command_fingerprint": true, "fingerprint": true,
		"changed": true,
	}
	switch command {
	case "unload_model":
		for _, key := range []string{"cleaned", "warm_entry_absent", "warm_release_verified", "warm_model_bytes", "locked_bytes"} {
			allowed[key] = true
		}
	case "cleanup_warm_model":
		for _, key := range []string{"cleaned", "warm_entry_absent", "warm_release_verified", "warm_model_bytes", "locked_bytes"} {
			allowed[key] = true
		}
	case "warm_model", "offload_model", "demote_model", "reverify_warm_model":
		for _, key := range []string{"warm_model_bytes_verified", "warm_model_bytes", "locked_bytes", "oracle", "released_vram"} {
			allowed[key] = true
		}
	case "protect_warm_model":
		for _, key := range []string{"warm_model_bytes_verified", "warm_model_bytes", "locked_bytes", "oracle", "released_vram", "protected", "active_references"} {
			allowed[key] = true
		}
	}
	return allowed
}

func validateLiveResidencyResult(command string, result map[string]any) error {
	if result == nil {
		return errors.New("authoritative residency result is missing")
	}
	allowed := cachedResidencyResultAllowedKeys(command)
	for key := range result {
		if !allowed[key] {
			return fmt.Errorf("authoritative residency result contains unknown field %s", key)
		}
	}
	resident, residentOK := result["resident"].(bool)
	warm, warmOK := result["warm_ram"].(bool)
	tier, tierOK := result["tier"].(string)
	if _, changedOK := result["changed"].(bool); !changedOK || !residentOK || !warmOK || !tierOK || tier != expectedResidencyTier(command) {
		return errors.New("authoritative residency result state or tier is invalid")
	}
	fence, fenceErr := exactFenceToken(result["fencing_token"])
	observed, observedErr := exactFenceToken(result["observed_after_fence"])
	if fenceErr != nil || observedErr != nil || fence != observed || fence < 0 {
		return errors.New("authoritative residency result fence is invalid")
	}
	switch command {
	case "load_model":
		_, ok := result["changed"].(bool)
		if !ok || !resident || warm {
			return errors.New("load result lacks the exact hot-vram proof")
		}
	case "unload_model":
		cleaned, cleanedOK := result["cleaned"].(bool)
		absent, absentOK := result["warm_entry_absent"].(bool)
		released, releasedOK := result["warm_release_verified"].(bool)
		bytes, bytesErr := exactFenceToken(result["warm_model_bytes"])
		locked, lockedErr := exactFenceToken(result["locked_bytes"])
		if resident || warm || !cleanedOK || !cleaned || !absentOK || !absent || !releasedOK || !released || bytesErr != nil || lockedErr != nil || bytes != 0 || locked != 0 {
			return errors.New("unload result lacks the exact cold-disk proof")
		}
	case "cleanup_warm_model":
		cleaned, cleanedOK := result["cleaned"].(bool)
		absent, absentOK := result["warm_entry_absent"].(bool)
		released, releasedOK := result["warm_release_verified"].(bool)
		bytes, bytesErr := exactFenceToken(result["warm_model_bytes"])
		locked, lockedErr := exactFenceToken(result["locked_bytes"])
		if resident || warm || !cleanedOK || !cleaned || !absentOK || !absent || !releasedOK || !released || bytesErr != nil || lockedErr != nil || bytes != 0 || locked != 0 {
			return errors.New("cleanup result lacks the exact released cold-disk proof")
		}
	case "warm_model", "offload_model", "demote_model", "protect_warm_model", "reverify_warm_model":
		verified, verifiedOK := result["warm_model_bytes_verified"].(bool)
		released, releasedOK := result["released_vram"].(bool)
		oracle, oracleOK := result["oracle"].(string)
		bytes, bytesErr := exactFenceToken(result["warm_model_bytes"])
		locked, lockedErr := exactFenceToken(result["locked_bytes"])
		if resident || !warm || !verifiedOK || !verified || !releasedOK || !released || !oracleOK || oracle != "mincore+mlock" || bytesErr != nil || lockedErr != nil || bytes <= 0 || locked < bytes {
			return errors.New("warm result lacks the exact verified warm-ram proof")
		}
		if command == "protect_warm_model" {
			if _, ok := result["protected"].(bool); !ok {
				return errors.New("protect result lacks protected proof")
			}
			if refs, err := exactFenceToken(result["active_references"]); err != nil || refs < 0 {
				return errors.New("protect result lacks active-reference proof")
			}
		}
	}
	return nil
}

func cachedReconciledResultMatches(intent pendingCommand, manifest pendingOperationManifest, cached wsproto.CommandResultPayload) bool {
	if cached.ID != intent.CommandID || cached.NodeID != manifest.NodeID || cached.Status != "succeeded" || !cached.OK || cached.Uncertain || cached.Error != "" || cached.CompletedAt.IsZero() || cached.Result == nil {
		return false
	}
	result := cached.Result
	// The fingerprint is recomputed from the complete persisted manifest, not
	// trusted from either result alias. This keeps a journaled success bound to
	// the exact signed operation that created the pending intent.
	normalized := wsproto.CommandPayload{NodeID: manifest.NodeID, Command: manifest.Action, IdempotencyKey: manifest.IdempotencyKey, Args: manifest.Args}
	expectedFingerprint := commandFingerprint(normalized)
	if expectedFingerprint == "" || intent.Fingerprint != expectedFingerprint || manifest.Fingerprint != expectedFingerprint {
		return false
	}
	stringField := func(key string) (string, bool) {
		value, ok := result[key].(string)
		return value, ok && value != ""
	}
	if targetKind, ok := stringField("target_kind"); !ok || targetKind != manifest.TargetKind {
		return false
	}
	if action, ok := stringField("action"); !ok || action != intent.Command {
		return false
	}
	if targetID, ok := stringField("target_id"); !ok || targetID != intent.TargetID {
		return false
	}
	if nodeID, ok := stringField("node_id"); !ok || nodeID != manifest.NodeID {
		return false
	}
	if commandID, ok := stringField("command_id"); !ok || commandID != intent.CommandID {
		return false
	}
	if idempotency, ok := stringField("idempotency_key"); !ok || idempotency != intent.IdempotencyKey {
		return false
	}
	if model, ok := stringField("model"); !ok || model != intent.Model {
		return false
	}
	if id, ok := stringField("original_command_id"); !ok || id != intent.CommandID {
		return false
	}
	if key, ok := stringField("original_idempotency_key"); !ok || key != intent.IdempotencyKey {
		return false
	}
	if fingerprint, ok := stringField("command_fingerprint"); !ok || fingerprint != intent.Fingerprint {
		return false
	}
	if fingerprint, ok := stringField("fingerprint"); !ok || fingerprint != intent.Fingerprint {
		return false
	}
	for key, expected := range map[string]string{"runtime_identity": manifest.RuntimeIdentity, "capability_version": manifest.CapabilityVersion, "capability_revision": manifest.CapabilityRevision} {
		if expected == "" {
			continue
		}
		value, ok := stringField(key)
		if !ok || value != expected {
			return false
		}
	}
	tier, ok := stringField("tier")
	if !ok || tier != manifest.ExpectedTier {
		return false
	}
	for key := range map[string]struct{}{"fencing_token": {}, "observed_after_fence": {}} {
		value, err := exactFenceToken(result[key])
		if err != nil || value != intent.Token {
			return false
		}
	}
	if reconciled, ok := result["reconciled"].(bool); !ok || !reconciled {
		return false
	}
	allowed := cachedResidencyResultAllowedKeys(intent.Command)
	required := map[string]bool{
		"action": true, "target_kind": true, "target_id": true, "model": true, "node_id": true,
		"resident": true, "warm_ram": true, "runtime_identity": true,
		"capability_version": true, "capability_revision": true,
		"fencing_token": true, "observed_after_fence": true, "tier": true,
		"reconciled": true, "original_command_id": true, "original_idempotency_key": true,
		"command_id": true, "idempotency_key": true, "command_fingerprint": true, "fingerprint": true,
	}
	switch intent.Command {
	case "unload_model":
		for _, key := range []string{"cleaned", "warm_entry_absent", "warm_release_verified", "warm_model_bytes", "locked_bytes"} {
			required[key] = true
		}
	case "cleanup_warm_model":
		for _, key := range []string{"cleaned", "warm_entry_absent", "warm_release_verified", "warm_model_bytes", "locked_bytes"} {
			required[key] = true
		}
	case "warm_model", "offload_model", "demote_model", "reverify_warm_model":
		for _, key := range []string{"warm_model_bytes_verified", "warm_model_bytes", "locked_bytes", "oracle", "released_vram"} {
			required[key] = true
		}
	case "protect_warm_model":
		for _, key := range []string{"warm_model_bytes_verified", "warm_model_bytes", "locked_bytes", "oracle", "released_vram", "protected", "active_references"} {
			required[key] = true
		}
	}
	for key := range result {
		if !allowed[key] {
			return false
		}
	}
	for key := range required {
		if _, present := result[key]; !present {
			return false
		}
	}
	for _, key := range []string{"resident", "warm_ram", "reconciled"} {
		if _, ok := result[key].(bool); !ok {
			return false
		}
	}
	if intent.Command == "load_model" {
		resident, ok := result["resident"].(bool)
		warm, warmOK := result["warm_ram"].(bool)
		if !ok || !resident || !warmOK || warm {
			return false
		}
	}
	if intent.Command == "unload_model" || intent.Command == "cleanup_warm_model" {
		resident, ok := result["resident"].(bool)
		warm, warmOK := result["warm_ram"].(bool)
		if !ok || resident || !warmOK || warm {
			return false
		}
		cleaned, cleanedOK := result["cleaned"].(bool)
		absent, absentOK := result["warm_entry_absent"].(bool)
		released, releasedOK := result["warm_release_verified"].(bool)
		bytes, bytesErr := exactFenceToken(result["warm_model_bytes"])
		locked, lockedErr := exactFenceToken(result["locked_bytes"])
		if !cleanedOK || !cleaned || !absentOK || !absent || !releasedOK || !released || bytesErr != nil || lockedErr != nil || bytes != 0 || locked != 0 {
			return false
		}
	}
	if intent.Command == "cleanup_warm_model" {
		if cleaned, ok := result["cleaned"].(bool); !ok || !cleaned {
			return false
		}
		if released, ok := result["warm_release_verified"].(bool); !ok || !released {
			return false
		}
		if absent, ok := result["warm_entry_absent"].(bool); !ok || !absent {
			return false
		}
		locked, err := exactFenceToken(result["locked_bytes"])
		bytes, bytesErr := exactFenceToken(result["warm_model_bytes"])
		if err != nil || bytesErr != nil || locked != 0 || bytes != 0 {
			return false
		}
	}
	if intent.Command == "warm_model" || intent.Command == "offload_model" || intent.Command == "demote_model" || intent.Command == "protect_warm_model" || intent.Command == "reverify_warm_model" {
		resident, residentOK := result["resident"].(bool)
		warm, warmOK := result["warm_ram"].(bool)
		verified, verifiedOK := result["warm_model_bytes_verified"].(bool)
		released, releasedOK := result["released_vram"].(bool)
		oracle, oracleOK := result["oracle"].(string)
		if !residentOK || resident || !warmOK || !warm || !verifiedOK || !verified || !releasedOK || !released || !oracleOK || oracle != "mincore+mlock" {
			return false
		}
		bytes, bytesErr := exactFenceToken(result["warm_model_bytes"])
		locked, lockedErr := exactFenceToken(result["locked_bytes"])
		if bytesErr != nil || lockedErr != nil || bytes <= 0 || locked < bytes {
			return false
		}
		if intent.Command == "protect_warm_model" {
			protected, ok := result["protected"].(bool)
			if !ok || protected != manifest.Protected {
				return false
			}
			refs, err := exactFenceToken(result["active_references"])
			if err != nil || refs != int64(intent.ActiveReferences) {
				return false
			}
		}
	}
	return true
}

func cachedReconciledResultAliasesMatch(intent pendingCommand, manifest pendingOperationManifest, byID, byKey wsproto.CommandResultPayload) bool {
	if intent.IdempotencyKey == "" || !reflect.DeepEqual(byID, byKey) {
		return false
	}
	return cachedReconciledResultMatches(intent, manifest, byID)
}

func (p *commandProcessor) durableCommandFingerprintAliasesMatch(intent pendingCommand, manifest pendingOperationManifest) bool {
	normalized := wsproto.CommandPayload{NodeID: manifest.NodeID, Command: manifest.Action, IdempotencyKey: manifest.IdempotencyKey, Args: manifest.Args}
	expected := commandFingerprint(normalized)
	if expected == "" || intent.Fingerprint != expected || manifest.Fingerprint != expected {
		return false
	}
	byID, idOK := p.commandFingerprints["id:"+intent.CommandID]
	byKey, keyOK := p.commandFingerprints[intent.IdempotencyKey]
	return idOK && keyOK && byID != "" && byID == expected && byKey == expected && byID == byKey
}

func (p *commandProcessor) ReconcilePending(ctx context.Context) error {
	if p.stateBlocked && p.stateBlockReason != "" && p.stateBlockReason != blockReasonWarmTransient {
		return errors.New("durable command state block requires explicit recovery")
	}
	p.mu.Lock()
	intents := make(map[string]pendingCommand, len(p.pending))
	for id, intent := range p.pending {
		intents[id] = intent
	}
	p.mu.Unlock()
	for id, intent := range intents {
		if intent.Command == "llm_displacement_stop" {
			// A stopped worker cannot be inferred from runtime/model state. Keep
			// the write-ahead intent and accelerator fence until the explicit
			// signed owned-stop query joins the original envelope to a root
			// terminal receipt. Never route this through generic residency
			// reconciliation, which has no owned-stop completion authority.
			return errors.New("pending owned stop requires an exact signed root receipt query")
		}
		manifest, err := p.validatePendingManifest(intent)
		if err != nil {
			return err
		}
		// A journaled result may coexist with its pending intent after a crash
		// between the result write and intent deletion. It is safe to retire the
		// intent without re-running a local pin or external runtime operation.
		p.mu.Lock()
		cachedByID, byIDOK := p.results[intent.CommandID]
		cachedByKey, byKeyOK := p.results["key:"+intent.IdempotencyKey]
		if byIDOK && byKeyOK && p.durableCommandFingerprintAliasesMatch(intent, manifest) && cachedReconciledResultAliasesMatch(intent, manifest, cachedByID, cachedByKey) {
			delete(p.pending, id)
			delete(p.inflight, fenceKey(intent.TargetID, intent.Model))
			p.mu.Unlock()
			continue
		}
		p.mu.Unlock()
		if intent.Command == "reclaim_accelerator" || intent.Command == "drain_runtimes" || intent.Command == "switch_runtime_profile" || intent.Command == "set_gpu_performance_profile" {
			return errors.New("pending resource transition requires explicit operator reconciliation")
		}
		server, ok := p.routerTarget(intent.TargetID)
		if !ok {
			return errors.New("pending transition target is not allowlisted")
		}
		discovery, err := DiscoverLlamaCPP(ctx, p.cfg.NodeID, server)
		if err != nil {
			return errors.New("pending transition runtime could not be reconciled")
		}
		if intent.RuntimeIdentity != "" && intent.RuntimeIdentity != canonicalCommandRuntimeIdentity(intent.TargetID, discovery) {
			return errors.New("pending transition runtime identity drifted")
		}
		if intent.Command == "cleanup_warm_model" {
			if p.warmRAM == nil {
				return errors.New("pending cleanup lacks a warm manager")
			}
			state, stateErr := discoverLlamaModelState(ctx, server, intent.Model)
			if stateErr != nil || state != llamaStateUnloaded {
				return errors.New("pending warm cleanup lacks exact unloaded runtime confirmation")
			}
			if err := p.warmRAM.ReleaseModelFor(intent.TargetID, intent.Model); err != nil {
				return errors.New("pending warm cleanup remains blocked")
			}
			if p.warmRAM.HasEntryFor(intent.TargetID, intent.Model) || p.warmRAM.IsVerifiedFor(intent.TargetID, intent.Model) {
				return errors.New("pending warm cleanup lacks exact release confirmation")
			}
			result := p.reconciledResidencyResult(intent, discovery, "cold_disk", false, nil, map[string]any{
				"cleaned": true, "warm_ram": false, "warm_entry_absent": true,
				"warm_release_verified": true, "warm_model_bytes": int64(0), "locked_bytes": int64(0),
			})
			if err := p.recordReconciledResult(intent, result, ""); err != nil {
				return errors.New("pending cleanup result could not be journaled")
			}
			p.mu.Lock()
			delete(p.pending, id)
			delete(p.inflight, fenceKey(intent.TargetID, intent.Model))
			p.mu.Unlock()
			continue
		}
		warmIntent := intent.Command == "warm_model" || intent.Command == "offload_model" || intent.Command == "demote_model" || intent.Command == "reverify_warm_model" || intent.Command == "protect_warm_model"
		if warmIntent {
			configuredPath := server.ModelPaths[intent.Model]
			expectedFileFingerprint := server.ModelFingerprints[intent.Model]
			expectedRuntimeFingerprint := server.RuntimeFingerprints[intent.Model]
			if configuredPath == "" || expectedFileFingerprint == "" || expectedRuntimeFingerprint == "" || p.warmRAM == nil {
				return errors.New("pending warm transition lacks a validated model binding")
			}
			if intent.Path != configuredPath || intent.FileFingerprint != expectedFileFingerprint || intent.RuntimeFingerprint != expectedRuntimeFingerprint {
				return errors.New("pending warm transition is blocked by configuration drift")
			}
			if !strings.EqualFold(discovery.ModelFingerprint, expectedRuntimeFingerprint) {
				return errors.New("pending warm transition lacks matching runtime fingerprint")
			}
			state, stateErr := discoverLlamaModelState(ctx, server, intent.Model)
			if stateErr != nil || state != llamaStateUnloaded {
				// Hot, transitional, unknown, and missing statuses are not a
				// warm proof. Keep the intent durable and retryable.
				return errors.New("pending warm transition lacks exact unloaded runtime confirmation")
			}
			result, reverifyErr := p.warmRAM.ReverifyModelPreserveLastUsed(intent.TargetID, intent.Model, configuredPath, expectedFileFingerprint, true)
			if reverifyErr != nil {
				return fmt.Errorf("pending warm transition could not re-establish a verified pin: %w", reverifyErr)
			}
			if intent.Command == "protect_warm_model" {
				if _, protectErr := p.warmRAM.UpdateProtectionFor(intent.TargetID, intent.Model, intent.ActiveReferences, intent.Protected); protectErr != nil {
					return errors.New("pending protection transition could not be restored")
				}
			}
			var extra map[string]any
			if intent.Command == "protect_warm_model" {
				extra = map[string]any{"protected": intent.Protected, "active_references": intent.ActiveReferences}
			}
			canonical := p.reconciledResidencyResult(intent, discovery, "warm_ram", false, &result, extra)
			if err := p.recordReconciledResult(intent, canonical, ""); err != nil {
				return errors.New("pending warm result could not be journaled")
			}
		} else {
			desiredResident := intent.Command == "load_model"
			state, stateErr := discoverLlamaModelState(ctx, server, intent.Model)
			if stateErr != nil {
				return errors.New("pending transition runtime state could not be discovered")
			}
			if state == llamaStateTransitional {
				return errors.New("pending transition remains indeterminate while runtime is transitional")
			}
			if (state == llamaStateLoaded) != desiredResident {
				return errors.New("pending transition remains uncertain")
			}
			tier := "cold_disk"
			if desiredResident {
				tier = "hot_vram"
			}
			canonical := p.reconciledResidencyResult(intent, discovery, tier, desiredResident, nil, nil)
			if err := p.recordReconciledResult(intent, canonical, ""); err != nil {
				return errors.New("pending lifecycle result could not be journaled")
			}
		}
		p.mu.Lock()
		delete(p.pending, id)
		delete(p.inflight, fenceKey(intent.TargetID, intent.Model))
		p.mu.Unlock()
	}
	p.mu.Lock()
	if len(p.pending) > 0 {
		p.block(blockReasonWarmTransient)
	} else if p.stateBlockReason == blockReasonWarmTransient {
		p.stateBlocked = false
		p.stateBlockReason = ""
	}
	err := p.save()
	p.mu.Unlock()
	if err != nil {
		p.mu.Lock()
		for id, intent := range intents {
			p.pending[id] = intent
			p.inflight[fenceKey(intent.TargetID, intent.Model)] = true
		}
		p.block(blockReasonDurability)
		p.mu.Unlock()
		return errors.New("pending transition state could not be persisted")
	}
	p.mu.Lock()
	p.refreshReady()
	p.mu.Unlock()
	return nil
}

func (p *commandProcessor) reconciledResidencyResult(intent pendingCommand, discovery wsproto.AdapterAdvertisement, tier string, resident bool, warm *WarmRAMResult, extra map[string]any) map[string]any {
	capabilityVersion := discovery.Version
	capabilityRevision := p.capabilityRevision()
	var manifest pendingOperationManifest
	if intent.ManifestJSON != "" && json.Unmarshal([]byte(intent.ManifestJSON), &manifest) == nil {
		if manifest.CapabilityVersion != "" {
			capabilityVersion = manifest.CapabilityVersion
		}
		if manifest.CapabilityRevision != "" {
			capabilityRevision = manifest.CapabilityRevision
		}
	}
	result := map[string]any{
		"target_kind": "llamacpp", "target_id": intent.TargetID, "model": intent.Model, "node_id": p.cfg.NodeID, "resident": resident,
		"warm_ram": tier == "warm_ram", "runtime_identity": canonicalCommandRuntimeIdentity(intent.TargetID, discovery),
		"capability_version": capabilityVersion, "capability_revision": capabilityRevision,
		"fencing_token": intent.Token, "observed_after_fence": intent.Token, "tier": tier,
		"changed": false,
		"action":  intent.Command, "reconciled": true, "original_command_id": intent.CommandID, "original_idempotency_key": intent.IdempotencyKey,
		"command_id": intent.CommandID, "idempotency_key": intent.IdempotencyKey,
		"command_fingerprint": intent.Fingerprint, "fingerprint": intent.Fingerprint,
	}
	if warm != nil {
		result["warm_model_bytes_verified"] = warm.Verified
		result["warm_model_bytes"] = warm.Bytes
		result["locked_bytes"] = warm.LockedBytes
		result["oracle"] = warm.Oracle
		result["released_vram"] = warm.VRAMReleased
	}
	if tier == "cold_disk" && intent.Command == "unload_model" {
		result["cleaned"], result["warm_entry_absent"], result["warm_release_verified"] = true, true, true
		result["warm_model_bytes"], result["locked_bytes"] = int64(0), int64(0)
	}
	for key, value := range extra {
		result[key] = value
	}
	return result
}

func (p *commandProcessor) recordReconciledResult(intent pendingCommand, result map[string]any, message string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	status := "failed"
	if message == "" {
		status = "succeeded"
	}
	completed := wsproto.CommandResultPayload{ID: intent.CommandID, NodeID: p.cfg.NodeID, Status: status, OK: message == "", Result: result, Error: message, CompletedAt: time.Now().UTC()}
	p.results[intent.CommandID] = completed
	if intent.IdempotencyKey != "" {
		p.results["key:"+intent.IdempotencyKey] = completed
		p.commandFingerprints[intent.IdempotencyKey] = intent.Fingerprint
	}
	p.commandFingerprints["id:"+intent.CommandID] = intent.Fingerprint
	// Journal the successful observation while the pending intent is still
	// present. A crash between this write and the later pending deletion can
	// therefore replay the exact result without issuing another mutation.
	if err := p.save(); err != nil {
		return err
	}
	if p.afterReconciledJournal != nil {
		return p.afterReconciledJournal()
	}
	return nil
}

func (p *commandProcessor) HasPending() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.pending) > 0
}

// Ready is deliberately false while a durable or retryable transition is
// unresolved. The websocket remains available for observability, but the
// controller must not schedule new work on a node whose state cannot safely
// accept mutating commands.
func (p *commandProcessor) Ready() bool {
	return p.externalWork.Load() == 0 && p.ready.Load()
}

// ReconcileWarmManifests validates completed warm claims restored from disk
// before accepting cached commands. A restored pin has no trusted VRAM proof;
// runtime discovery either proves the model is absent and permits repinning,
// or proves it is hot and the stale warm claim is removed.
func (p *commandProcessor) ReconcileWarmManifests(ctx context.Context) error {
	if p.warmRAM == nil {
		return nil
	}
	if p.stateBlocked && p.stateBlockReason != "" && p.stateBlockReason != blockReasonWarmTransient {
		return errors.New("durable command state block requires explicit recovery")
	}
	manifests := p.warmRAM.ManifestSnapshot()
	sort.Slice(manifests, func(i, j int) bool {
		if manifests[i].LastUsed.Equal(manifests[j].LastUsed) {
			return warmEntryKey(manifests[i].TargetID, manifests[i].Model) < warmEntryKey(manifests[j].TargetID, manifests[j].Model)
		}
		return manifests[i].LastUsed.Before(manifests[j].LastUsed)
	})
	for _, manifest := range manifests {
		if !manifest.Verified {
			// This is a durable failed-cleanup/retry handle.  Restart may
			// clean it up, but it must never turn an unverified manifest back
			// into a warm claim by repinning it.
			if err := p.warmRAM.ReleaseModelFor(manifest.TargetID, manifest.Model); err != nil {
				p.mu.Lock()
				p.block(blockReasonWarmTransient)
				p.mu.Unlock()
				return errors.New("restored warm cleanup remains blocked")
			}
			continue
		}
		server, ok := p.routerTarget(manifest.TargetID)
		if !ok {
			p.mu.Lock()
			p.block(blockReasonWarmTransient)
			p.mu.Unlock()
			return errors.New("restored warm manifest target is not allowlisted")
		}
		canonicalTarget := p.cfg.NodeID + "-" + server.ID
		configuredPath := server.ModelPaths[manifest.Model]
		configuredFileFingerprint := server.ModelFingerprints[manifest.Model]
		configuredRuntimeFingerprint := server.RuntimeFingerprints[manifest.Model]
		canonicalPath, canonicalErr := canonicalWarmModelPath(configuredPath, p.cfg.WarmRAM.ModelRoots)
		if manifest.TargetID != canonicalTarget || configuredPath == "" || canonicalErr != nil || manifest.CanonicalPath != canonicalPath || manifest.FileFingerprint == "" || manifest.FileFingerprint != configuredFileFingerprint || manifest.RuntimeFingerprint == "" || manifest.RuntimeFingerprint != configuredRuntimeFingerprint || manifest.RuntimeEndpoint == "" || manifest.RuntimeEndpoint != server.Endpoint || manifest.RuntimeVersion == "" || !manifest.RuntimeProfilePresent {
			p.mu.Lock()
			p.block(blockReasonWarmTransient)
			p.mu.Unlock()
			return errors.New("restored warm manifest identity is incomplete or drifted")
		}
		if err := p.warmRAM.ValidateManifestIdentity(manifest); err != nil {
			p.mu.Lock()
			p.block(blockReasonWarmTransient)
			p.mu.Unlock()
			return errors.New("restored warm manifest file identity drifted")
		}
		discovery, err := DiscoverLlamaCPP(ctx, p.cfg.NodeID, server)
		if err != nil {
			p.mu.Lock()
			p.block(blockReasonWarmTransient)
			p.mu.Unlock()
			return errors.New("restored warm manifest runtime could not be discovered")
		}
		if !strings.EqualFold(discovery.ModelFingerprint, configuredRuntimeFingerprint) || discovery.Version != manifest.RuntimeVersion || discovery.ActiveRuntimeProfile != manifest.RuntimeProfile {
			p.mu.Lock()
			p.block(blockReasonWarmTransient)
			p.mu.Unlock()
			return errors.New("restored warm manifest runtime fingerprint drifted")
		}
		if manifest.RuntimeFingerprint != "" && !strings.EqualFold(manifest.RuntimeFingerprint, discovery.ModelFingerprint) {
			p.mu.Lock()
			p.block(blockReasonWarmTransient)
			p.mu.Unlock()
			return errors.New("restored warm manifest identity drifted")
		}
		state, stateErr := discoverLlamaModelState(ctx, server, manifest.Model)
		if stateErr != nil || (state != llamaStateUnloaded && state != llamaStateLoaded) {
			p.mu.Lock()
			p.block(blockReasonWarmTransient)
			p.mu.Unlock()
			return errors.New("restored warm manifest lacks exact runtime status")
		}
		if state == llamaStateLoaded {
			if err := p.warmRAM.ReleaseModelFor(manifest.TargetID, manifest.Model); err != nil {
				p.mu.Lock()
				p.block(blockReasonWarmTransient)
				p.mu.Unlock()
				return errors.New("restored warm manifest cleanup remains blocked")
			}
			continue
		}
		if manifest.VRAMReleased {
			// The existing pin was fully revalidated against current runtime
			// and file identity; no duplicate admission is needed.
			continue
		}
		if _, err := p.warmRAM.ReverifyModelPreserveLastUsed(manifest.TargetID, manifest.Model, configuredPath, configuredFileFingerprint, true); err != nil {
			p.mu.Lock()
			p.block(blockReasonWarmTransient)
			p.mu.Unlock()
			return errors.New("restored warm manifest could not be repinned")
		}
		if err := p.warmRAM.SetRuntimeManifest(manifest.TargetID, manifest.Model, discovery.ModelFingerprint, server.Endpoint, discovery.Version, discovery.ActiveRuntimeProfile); err != nil {
			p.mu.Lock()
			p.block(blockReasonWarmTransient)
			p.mu.Unlock()
			return errors.New("restored warm manifest runtime identity could not be stored")
		}
	}
	p.mu.Lock()
	unresolvedManifest := false
	for _, manifest := range p.warmRAM.ManifestSnapshot() {
		if !manifest.VRAMReleased || !manifest.Verified {
			unresolvedManifest = true
			break
		}
	}
	p.clearWarmBlockIfClean(unresolvedManifest || len(p.pending) > 0 || len(p.inflight) > 0)
	err := p.save()
	if err != nil {
		p.block(blockReasonDurability)
	}
	p.mu.Unlock()
	if err != nil {
		return errors.New("restored warm manifest state could not be persisted")
	}
	p.mu.Lock()
	p.refreshReady()
	p.mu.Unlock()
	return nil
}

func (p *commandProcessor) save() (err error) {
	defer func() {
		if err != nil && !p.inRecovery {
			p.block(blockReasonDurability)
			// This path intentionally bypasses injected primary persistence ops:
			// a failed state write must still leave an independent durable block
			// marker for a fresh processor.
			_ = p.writeRecoveryMarker(blockReasonDurability, "quarantined", recoveryIdentity(p.cfg.CommandStatePath), recoveryIdentity(p.cfg.CommandStatePath+".corrupt"))
		}
	}()
	if p.cfg.CommandStatePath == "" {
		return nil
	}
	// Reserve the next authenticated journal sequence before constructing the
	// target state. The prepared journal record is durable before the primary
	// rename; a crash can therefore be finalized or rejected deterministically.
	nextSequence := p.journalSequence + 1
	p.journalSequence = nextSequence
	p.journalPrevHash = p.journalHash
	payload := p.commandStatePayload()
	encoded, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(encoded)
	body, err := json.MarshalIndent(commandStateEnvelope{Version: commandStateVersion, Checksum: hex.EncodeToString(sum[:]), State: payload}, "", "  ")
	if err != nil {
		return err
	}
	mkdirAll := p.mkdirAll
	if mkdirAll == nil {
		mkdirAll = os.MkdirAll
	}
	if err := mkdirAll(filepath.Dir(p.cfg.CommandStatePath), 0o700); err != nil {
		return err
	}
	createTemp := p.createTemp
	if createTemp == nil {
		createTemp = func(dir, pattern string) (commandStateFile, error) { return os.CreateTemp(dir, pattern) }
	}
	tmp, err := createTemp(filepath.Dir(p.cfg.CommandStatePath), ".command-state-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	removeState := p.removeState
	if removeState == nil {
		removeState = os.Remove
	}
	defer removeState(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if written, err := tmp.Write(body); err != nil {
		_ = tmp.Close()
		return err
	} else if written != len(body) {
		_ = tmp.Close()
		return errors.New("command state write was incomplete")
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	stateHash := hex.EncodeToString(sum[:])
	if err := p.appendJournal(commandStateJournalRecord{Sequence: nextSequence, PrevHash: p.journalPrevHash, StateHash: stateHash, Phase: "prepared"}); err != nil {
		return errors.New("state journal prepare could not be persisted")
	}
	renameState := p.renameState
	if renameState == nil {
		renameState = os.Rename
	}
	if err := renameState(tmpName, p.cfg.CommandStatePath); err != nil {
		return err
	}
	syncDir := p.syncDir
	if syncDir == nil {
		syncDir = syncCommandStateDir
	}
	if err := syncDir(filepath.Dir(p.cfg.CommandStatePath)); err != nil {
		return err
	}
	committed := commandStateJournalRecord{Sequence: nextSequence, PrevHash: p.journalPrevHash, StateHash: stateHash, Phase: "committed"}
	if err := p.appendJournal(committed); err != nil {
		return errors.New("state journal commit could not be persisted")
	}
	p.journalHash = journalDigest(committed)
	return nil
}

func (p *commandProcessor) commandStatePayload() commandStatePayload {
	var warm []WarmRAMManifest
	if p.warmRAM != nil {
		warm = p.warmRAM.ManifestSnapshot()
	}
	used := make([]string, 0, len(p.usedRecoveryEpochs))
	for epochHash := range p.usedRecoveryEpochs {
		used = append(used, epochHash)
	}
	sort.Strings(used)
	return commandStatePayload{Results: p.results, CommandFingerprints: p.commandFingerprints, Fences: p.fences, Pending: p.pending, Warm: warm, BlockReason: p.stateBlockReason, RecoveryEpoch: p.recoveryEpoch, RecoveryGeneration: p.recoveryGeneration, UsedRecoveryEpochs: used, RecoveryAnchorHash: p.recoveryAnchorHash, JournalSequence: p.journalSequence, JournalPrevHash: p.journalPrevHash, CheckpointPhases: p.checkpointPhases, OwnedStopOperations: p.ownedStopOperations, PlanRelaunchOperations: p.planRelaunchOperations}
}

func checksumForStatePayload(payload commandStatePayload) string {
	encoded, err := json.Marshal(payload)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}
