// Package runtime defines the driver interface between the node agent and a
// concrete inference runtime (llama.cpp, vLLM, ...), per architecture.md §6
// (Runtime Adapter Layer). A driver never lies about what it can do: every
// capability it reports is verified by trying it (measurement.md §2), and
// every driver here only ever manages processes it launched itself
// (decision #18) — it never touches a PID it didn't start.
package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"vram-governor/internal/domain"
)

// SleepMode is the two levers architecture.md §7 gives a runtime for
// reclaiming VRAM from a model that isn't currently needed. Not every
// runtime supports every mode — llama.cpp has no weight-sleep-to-RAM API
// (§7.3), so SleepRAM is expected to return ErrUnsupported from that driver.
type SleepMode string

const (
	// SleepModeRAM parks weights in host RAM without releasing the engine
	// process (vLLM sleep level 1, §7.3 SLEEP_RAM). Fast wake, no VRAM use.
	SleepModeRAM SleepMode = "sleep_ram"
	// SleepModeEvicted tears the engine process down entirely (§7.4
	// EVICTED). VRAM is fully released; wake means relaunching the process.
	SleepModeEvicted SleepMode = "evicted"
)

// WakeStage lets a caller ask for a partial wake (weights only) or a full
// wake (weights + KV restored), matching the two-stage restore budget from
// the KV spike (T_wake_weights, then KV restore/reprefill).
type WakeStage string

const (
	WakeStageWeights WakeStage = "weights" // engine up, health-checked, no KV restored
	WakeStageFull    WakeStage = "full"    // weights + best-effort KV/session restore
)

// LaunchSpec is everything a driver needs to start a managed engine for a
// domain.ServingProfile on a specific accelerator.
type LaunchSpec struct {
	Profile       domain.ServingProfile
	AcceleratorID string
	// WorkDir holds runtime-owned scratch (KV slot snapshots, logs, sockets).
	WorkDir string
	// Port is the local port to bind, if the runtime is HTTP-based. 0 means
	// "driver picks a free port."
	Port int
}

// HealthStatus is the driver's live view of a managed engine.
type HealthStatus struct {
	Healthy   bool      `json:"healthy"`
	Message   string    `json:"message,omitempty"`
	CheckedAt time.Time `json:"checked_at"`
}

// Metrics is runtime-reported telemetry for a managed engine (architecture
// §34 "report runtime telemetry"). Fields are best-effort and runtime-
// specific; a driver leaves a field zero-valued if its runtime doesn't
// expose it rather than guessing.
type Metrics struct {
	ActiveSlots     int       `json:"active_slots"`
	TotalSlots      int       `json:"total_slots"`
	PromptTokPerSec float64   `json:"prompt_tok_per_sec,omitempty"`
	DecodeTokPerSec float64   `json:"decode_tok_per_sec,omitempty"`
	SampledAt       time.Time `json:"sampled_at"`
}

// CheckpointResult describes a saved KV/session snapshot (§8A.3).
type CheckpointResult struct {
	SnapshotRef string        `json:"snapshot_ref"` // path/key the driver can restore from
	SizeBytes   int64         `json:"size_bytes"`
	Digest      string        `json:"snapshot_digest,omitempty"`
	Duration    time.Duration `json:"duration"`
	TokensSaved int           `json:"tokens_saved,omitempty"`
}

// RestoreResult describes a KV/session restore (§8A.4).
type RestoreResult struct {
	Duration       time.Duration `json:"duration"`
	TokensRestored int           `json:"tokens_restored,omitempty"`
}

// CheckpointIdentity binds a session snapshot to the exact execution that
// created it.  A snapshot is never portable across owners, generations,
// runtime builds, profiles, or context limits.
type CheckpointIdentity struct {
	NodeID             string `json:"node_id"`
	TargetID           string `json:"target_id"`
	AcceleratorID      string `json:"accelerator_id"`
	OwnerID            string `json:"owner_id"`
	WorkloadID         string `json:"workload_id"`
	Generation         uint64 `json:"generation"`
	RuntimeIdentity    string `json:"runtime_identity"`
	ModelFingerprint   string `json:"model_fingerprint"`
	ProfileFingerprint string `json:"profile_fingerprint"`
	ContextLimit       int    `json:"context_limit"`
	SlotID             int    `json:"slot_id"`
}

// CheckpointCapabilityProof is intentionally separate from the lightweight
// probe result.  ProbeCapabilities proves that save/restore endpoints exist;
// this proof is emitted only after the live production pause/stop/restore
// workflow has shown safe-boundary semantics and measured KV reuse.
type CheckpointCapabilityProof struct {
	ProofVersion           string    `json:"proof_version"`
	ModelAlias             string    `json:"model_alias"`
	LocalCheckpointBinding string    `json:"local_checkpoint_binding"`
	Verified               bool      `json:"verified"`
	ProbeOnly              bool      `json:"probe_only"`
	SlotAssignment         bool      `json:"slot_assignment"`
	SafeBoundaryPause      bool      `json:"safe_boundary_pause"`
	SnapshotSave           bool      `json:"snapshot_save"`
	BackendStopConfirmed   bool      `json:"backend_stop_confirmed"`
	SnapshotRestore        bool      `json:"snapshot_restore"`
	KVReused               bool      `json:"kv_reused"`
	ProvenAt               time.Time `json:"proven_at"`
	Reason                 string    `json:"reason"`
	NodeID                 string    `json:"node_id"`
	TargetID               string    `json:"target_id"`
	ModelFingerprint       string    `json:"model_fingerprint"`
	RuntimeIdentity        string    `json:"runtime_identity"`
	ProfileFingerprint     string    `json:"profile_fingerprint"`
	ContextLimit           int       `json:"context_limit"`
	SlotID                 int       `json:"slot_id"`
	Generation             uint64    `json:"generation"`
	OldFence               uint64    `json:"old_fence"`
	NewFence               uint64    `json:"new_fence"`
	SavedTokens            int       `json:"saved_tokens"`
	ReusedTokens           int       `json:"reused_tokens"`
	EvidenceID             string    `json:"evidence_id"`
	Signature              string    `json:"signature"`
	Digest                 string    `json:"digest"`
	SnapshotDigest         string    `json:"snapshot_digest"`
	SnapshotBytes          int64     `json:"snapshot_bytes"`
	AcceleratorID          string    `json:"accelerator_id"`
	ExpiresAt              time.Time `json:"expires_at"`
	Nonce                  string    `json:"nonce"`
}

const CheckpointCapabilityProofVersion = "checkpoint-capability-proof-v2"

// CheckpointProofIssuanceEpoch returns the durable epoch embedded in a v2
// issuance nonce. Legacy/noncanonical nonces deliberately have no epoch.
func CheckpointProofIssuanceEpoch(nonce string) (uint64, bool) {
	parts := strings.Split(nonce, "-")
	if len(parts) != 3 || len(parts[0]) != 20 || len(parts[1]) != 21 || parts[1][0] != 'e' || len(parts[2]) != 32 {
		return 0, false
	}
	for _, r := range parts[0] + parts[1][1:] {
		if r < '0' || r > '9' {
			return 0, false
		}
	}
	for _, r := range parts[2] {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return 0, false
		}
	}
	epoch, err := strconv.ParseUint(parts[1][1:], 10, 64)
	return epoch, err == nil && epoch > 0
}

func (p CheckpointCapabilityProof) hasV2Identity() bool {
	_, epochOK := CheckpointProofIssuanceEpoch(p.Nonce)
	return p.ProofVersion == CheckpointCapabilityProofVersion && p.ModelAlias != "" &&
		validCheckpointProofAlias(p.ModelAlias) &&
		checkpointProofSHA256(p.LocalCheckpointBinding) && epochOK
}

func validCheckpointProofAlias(alias string) bool {
	if len(alias) == 0 || len(alias) > 128 || !((alias[0] >= 'A' && alias[0] <= 'Z') || (alias[0] >= 'a' && alias[0] <= 'z') || (alias[0] >= '0' && alias[0] <= '9')) {
		return false
	}
	for _, r := range alias[1:] {
		if !((r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-') {
			return false
		}
	}
	return true
}

func checkpointProofSHA256(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, r := range value[len("sha256:"):] {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}

// SlotCheckpointDriver is the node-side runtime contract for an already
// running llama.cpp router.  It deliberately lives beside Driver so command
// processors cannot grow a second, ad-hoc /slots protocol.  Implementations
// must return measurements from the runtime response and must not echo
// controller arguments as evidence.
type SlotCheckpointDriver interface {
	QuerySlots(context.Context) (SlotInventory, error)
	AssignSlot(context.Context, int) (SlotAssignment, error)
	PauseAtBoundary(context.Context, int) (SlotBoundary, error)
	SaveKV(context.Context, int, string) (CheckpointResult, error)
	ConfirmStopped(context.Context, int) (bool, error)
	ReleaseSlot(context.Context, int) error
	Reload(context.Context, int) error
	RestoreKV(context.Context, int, string) (RestoreResult, error)
	VerifyReuse(context.Context, int, int) (int, error)
	Resume(context.Context, int, string, int) (string, error)
}

// ConversationSlotCheckpointDriver is the production llama.cpp extension.
// The legacy methods remain only for deterministic compatibility fakes; a
// live checkpoint must use the conversation-aware DELETE/stream protocol.
type ConversationSlotCheckpointDriver interface {
	SlotCheckpointDriver
	StartCheckpointConversation(context.Context, int, string, string, int) error
	PauseAtBoundaryWithConversation(context.Context, int, string) (SlotBoundary, error)
	ResumeWithConversation(context.Context, int, string, string, int) (string, error)
}

// ConversationSlotRegistrationDriver records the signed binding for a
// controller-owned client stream without starting a second generation.
type ConversationSlotRegistrationDriver interface {
	RegisterCheckpointConversation(context.Context, int, string, string, int) error
}

// CheckpointContinuationDriver is implemented by a production runtime that
// can issue the actual post-restore continuation request. It is deliberately
// separate from ResumeWithConversation: the latter authorizes/reconciles the
// slot, while this method drives the upstream stream protocol and waits for
// its real response to finish.
type CheckpointContinuationDriver interface {
	ContinueCheckpointConversation(context.Context, int, string, string, string) error
}

type SlotInventory struct {
	Slots []SlotState `json:"slots"`
}

type SlotState struct {
	ID                 int  `json:"id"`
	ContextLimit       int  `json:"context_limit"`
	Processing         bool `json:"processing"`
	PastTokens         int  `json:"past_tokens,omitempty"`
	PromptTokens       int  `json:"prompt_tokens,omitempty"`
	CachedPromptTokens int  `json:"cached_prompt_tokens,omitempty"`
}

type SlotAssignment struct {
	SlotID       int
	ContextLimit int
}

type SlotBoundary struct {
	Prefix     []byte
	TokenCount int
}

func (p CheckpointCapabilityProof) Complete() bool {
	return p.hasV2Identity() && p.Verified && !p.ProbeOnly && p.SlotAssignment && p.SafeBoundaryPause &&
		p.SnapshotSave && p.BackendStopConfirmed && p.SnapshotRestore && p.KVReused && p.NodeID != "" && p.TargetID != "" && p.ModelFingerprint != "" && p.RuntimeIdentity != "" && p.ProfileFingerprint != "" && p.ContextLimit > 0 && p.SlotID >= 0 && p.Generation > 0 && p.NewFence > p.OldFence && p.SavedTokens > 0 && p.ReusedTokens > 0 && p.ReusedTokens <= p.SavedTokens && p.SnapshotBytes > 0 && p.SnapshotDigest != "" && p.EvidenceID != "" && p.Signature != "" && p.Digest != "" && p.Nonce != "" && !p.ExpiresAt.IsZero() && time.Now().Before(p.ExpiresAt)
}

// ComponentsComplete is used while constructing a proof; Complete is the
// admission predicate and additionally requires the explicit Verified bit.
func (p CheckpointCapabilityProof) ComponentsComplete() bool {
	return p.hasV2Identity() && !p.ProbeOnly && p.SlotAssignment && p.SafeBoundaryPause && p.SnapshotSave &&
		p.BackendStopConfirmed && p.SnapshotRestore && p.KVReused &&
		p.NodeID != "" && p.TargetID != "" && p.ModelFingerprint != "" &&
		p.RuntimeIdentity != "" && p.ProfileFingerprint != "" && p.ContextLimit > 0 &&
		p.SlotID >= 0 && p.Generation > 0 && p.NewFence > p.OldFence &&
		p.SavedTokens > 0 && p.ReusedTokens > 0 && p.ReusedTokens <= p.SavedTokens && p.SnapshotBytes > 0 && p.SnapshotDigest != "" && p.EvidenceID != "" && p.Nonce != "" &&
		p.Signature != "" && p.Digest != ""
}

// CheckpointProofDigest is shared by node signing and controller admission;
// keeping the canonical material in the runtime package prevents a verifier
// from accepting a differently serialized proof.
func CheckpointProofDigest(proof CheckpointCapabilityProof) string {
	material, _ := json.Marshal(struct {
		ProofVersion, ModelAlias, LocalCheckpointBinding                                                                          string
		Verified, ProbeOnly, SlotAssignment, SafeBoundaryPause, SnapshotSave, BackendStopConfirmed, SnapshotRestore, KVReused     bool
		ProvenAt                                                                                                                  time.Time
		NodeID, TargetID, ModelFingerprint, RuntimeIdentity, ProfileFingerprint, EvidenceID, SnapshotDigest, AcceleratorID, Nonce string
		ContextLimit, SlotID                                                                                                      int
		Generation, OldFence, NewFence                                                                                            uint64
		SavedTokens, ReusedTokens                                                                                                 int
		SnapshotBytes                                                                                                             int64
		ExpiresAt                                                                                                                 time.Time
	}{proof.ProofVersion, proof.ModelAlias, proof.LocalCheckpointBinding, proof.Verified, proof.ProbeOnly, proof.SlotAssignment, proof.SafeBoundaryPause, proof.SnapshotSave, proof.BackendStopConfirmed, proof.SnapshotRestore, proof.KVReused, proof.ProvenAt, proof.NodeID, proof.TargetID, proof.ModelFingerprint, proof.RuntimeIdentity, proof.ProfileFingerprint, proof.EvidenceID, proof.SnapshotDigest, proof.AcceleratorID, proof.Nonce, proof.ContextLimit, proof.SlotID, proof.Generation, proof.OldFence, proof.NewFence, proof.SavedTokens, proof.ReusedTokens, proof.SnapshotBytes, proof.ExpiresAt})
	sum := sha256.Sum256(material)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Driver is the runtime adapter interface (architecture.md §6). Every
// method that reports a capability or a measurement must reflect what
// actually happened on this call, never a static claim.
type Driver interface {
	// Name identifies the runtime this driver adapts, e.g. "llamacpp".
	Name() string

	// ProbeRuntime detects the runtime's own version/build identity, used
	// as part of the §20 performance-profile key. Does not require a
	// running engine.
	ProbeRuntime(ctx context.Context) (RuntimeIdentity, error)

	// ProbeCapabilities empirically determines what this runtime/driver
	// combination can do (measurement.md §2) by trying each capability
	// against a short-lived engine instance for the given profile, not by
	// reading documentation or hardcoding assumptions. Safe to call
	// without a prior Launch.
	ProbeCapabilities(ctx context.Context, spec LaunchSpec) (domain.RuntimeCapabilities, error)

	// Launch starts a managed engine process for the given spec and blocks
	// until it is healthy or ctx expires. The returned EngineInstance's PID
	// is owned by this driver from this point on (decision #18).
	Launch(ctx context.Context, spec LaunchSpec) (*domain.EngineInstance, error)

	// Health reports whether the given managed engine is currently healthy.
	Health(ctx context.Context, engine *domain.EngineInstance) (HealthStatus, error)

	// Metrics reports current runtime telemetry for the given managed engine.
	Metrics(ctx context.Context, engine *domain.EngineInstance) (Metrics, error)

	// Drain asks the engine to stop accepting new work and waits (up to
	// ctx) for in-flight work to finish, without killing the process.
	Drain(ctx context.Context, engine *domain.EngineInstance) error

	// Sleep reclaims VRAM from the engine using the requested mode. Returns
	// ErrUnsupported if the runtime cannot do that mode (e.g. llama.cpp +
	// SleepModeRAM) — callers must not treat that as a hard failure of the
	// whole operation, only as "capability absent, fall back."
	Sleep(ctx context.Context, engine *domain.EngineInstance, mode SleepMode) error

	// Wake restores the engine after Sleep. WakeStageWeights only needs the
	// engine healthy again; WakeStageFull also restores KV/session state if
	// a snapshot ref is provided via RestoreSession.
	Wake(ctx context.Context, engine *domain.EngineInstance, stage WakeStage) error

	// CheckpointSession saves the given slot/session's KV to durable
	// storage (§8A.3). Returns ErrUnsupported if the runtime doesn't
	// support KV snapshotting.
	CheckpointSession(ctx context.Context, engine *domain.EngineInstance, slotID int, snapshotName string) (CheckpointResult, error)

	// RestoreSession restores a previously checkpointed KV/session into the
	// given slot (§8A.4). Returns ErrUnsupported if unsupported.
	RestoreSession(ctx context.Context, engine *domain.EngineInstance, slotID int, snapshotName string) (RestoreResult, error)

	// Stop terminates the managed engine unconditionally (SIGTERM then
	// SIGKILL) and waits until the OS reports the process gone. Drivers
	// must never call this on a PID they did not launch.
	Stop(ctx context.Context, engine *domain.EngineInstance) error
}

// RuntimeIdentity is the runtime half of the §20 performance-profile key.
type RuntimeIdentity struct {
	Name    string `json:"name"`    // e.g. "llamacpp"
	Version string `json:"version"` // e.g. "0.2.0-dev" or build hash
	Binary  string `json:"binary"`  // resolved path to the binary actually run
}

// ErrUnsupported is returned by Driver methods for a capability the
// runtime/driver genuinely does not have (measurement.md §6 honesty rule:
// never silently no-op or fake a result).
type ErrUnsupported struct {
	Capability string
	Reason     string
}

func (e *ErrUnsupported) Error() string {
	if e.Reason != "" {
		return "runtime: unsupported capability " + e.Capability + ": " + e.Reason
	}
	return "runtime: unsupported capability " + e.Capability
}
