// Package runtime defines the driver interface between the node agent and a
// concrete inference runtime (llama.cpp, vLLM, ...), per architecture.md §6
// (Runtime Adapter Layer). A driver never lies about what it can do: every
// capability it reports is verified by trying it (measurement.md §2), and
// every driver here only ever manages processes it launched itself
// (decision #18) — it never touches a PID it didn't start.
package runtime

import (
	"context"
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
	Duration    time.Duration `json:"duration"`
	TokensSaved int           `json:"tokens_saved,omitempty"`
}

// RestoreResult describes a KV/session restore (§8A.4).
type RestoreResult struct {
	Duration       time.Duration `json:"duration"`
	TokensRestored int           `json:"tokens_restored,omitempty"`
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
