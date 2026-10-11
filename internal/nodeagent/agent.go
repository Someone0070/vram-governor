// Package nodeagent implements the small persistent process that runs
// co-located with a GPU (or, on a GPU-less box, still registers and
// heartbeats with an empty accelerator list). It dials the controller's
// websocket endpoint outbound, authenticates, registers, and then reports
// heartbeat + GPU telemetry on a fixed interval, redialing on any drop.
// See architecture.md §34 (Node Agent) and §34A (control channel).
package nodeagent

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"

	"vram-governor/internal/logging"
	"vram-governor/internal/nodetransport"
	"vram-governor/internal/runtime"
	"vram-governor/internal/wsproto"
)

var checkpointProofExerciseAttempts sync.Map

// A failed proof exercise must not permanently poison a target for the life
// of the agent.  The exercise is intentionally one-shot while a claim is
// fresh (so concurrent discovery refreshes cannot start duplicate disruptive
// workflows), but the claim expires and may be renewed after a bounded delay.
// Keep this as a variable so deterministic tests can shorten the retry window
// without making production expiry policy mutable from configuration input.
var checkpointProofExerciseRetryInterval = 30 * time.Second

type checkpointProofExerciseAttempt struct {
	ClaimedAt time.Time
}

func claimCheckpointProofExercise(targetID string) bool {
	_, claimed := claimCheckpointProofExerciseLease(targetID)
	return claimed
}

func claimCheckpointProofExerciseLease(targetID string) (checkpointProofExerciseAttempt, bool) {
	if strings.TrimSpace(targetID) == "" {
		return checkpointProofExerciseAttempt{}, false
	}
	for {
		now := time.Now().UTC()
		candidate := checkpointProofExerciseAttempt{ClaimedAt: now}
		value, loaded := checkpointProofExerciseAttempts.LoadOrStore(targetID, candidate)
		if !loaded {
			return candidate, true
		}
		attempt, ok := value.(checkpointProofExerciseAttempt)
		if !ok {
			// Preserve compatibility with an older in-process value while giving
			// it a bounded lease instead of treating it as permanent truth.
			attempt = checkpointProofExerciseAttempt{ClaimedAt: now}
		}
		interval := checkpointProofExerciseRetryInterval
		if interval <= 0 {
			interval = time.Nanosecond
		}
		if retryAfter := attempt.ClaimedAt.Add(interval); now.Before(retryAfter) {
			return checkpointProofExerciseAttempt{}, false
		}
		if checkpointProofExerciseAttempts.CompareAndSwap(targetID, value, candidate) {
			return candidate, true
		}
	}
}

// checkpointProofSessionIssued tracks targets that have already advertised a
// proof in this agent process. A persisted proof is rotated on the first
// authenticated session after process restart and on every reconnect, but a
// same-session capability refresh remains idempotent.
var checkpointProofSessionIssued sync.Map
var nodeConnectionSequence atomic.Uint64

// Run dials the controller and services the control channel until ctx is
// cancelled, redialing with backoff on any disconnect (§34A "the node
// redials on drop").
func Run(ctx context.Context, cfg *Config, log *slog.Logger, logSnapshots ...func() []logging.Entry) {
	backoff := time.Duration(cfg.ReconnectMinSeconds) * time.Second
	maxBackoff := time.Duration(cfg.ReconnectMaxSeconds) * time.Second
	sampler := &SystemSampler{}
	var logs func() []logging.Entry
	if len(logSnapshots) > 0 {
		logs = logSnapshots[0]
	}
	// The command processor owns durable fences, idempotency results, pending
	// transitions, and warm pins.  It must outlive a websocket session; making
	// one per reconnect would allow a dropped connection to replay lifecycle
	// work or lose its retry/reconciliation handle.
	commands := newCommandProcessor(cfg, log, true)
	if commands.initError != nil {
		log.Error("node command recovery initialization failed; refusing controller connection", "error", "startup recovery could not be completed")
		return
	}

	for {
		if ctx.Err() != nil {
			return
		}
		lifetime, err := runOnce(ctx, cfg, log, sampler, logs, commands)
		if ctx.Err() != nil {
			return
		}
		stableFor := 3 * time.Duration(cfg.HeartbeatIntervalSeconds) * time.Second
		if stableFor < 5*time.Second {
			stableFor = 5 * time.Second
		}
		if lifetime >= stableFor {
			backoff = time.Duration(cfg.ReconnectMinSeconds) * time.Second
		}
		if err != nil {
			log.Warn("connection ended, will reconnect", "backoff", backoff)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

func runOnce(ctx context.Context, cfg *Config, log *slog.Logger, sampler *SystemSampler, logs func() []logging.Entry, processors ...*commandProcessor) (time.Duration, error) {
	if len(processors) > 0 && processors[0] != nil && processors[0].initError != nil {
		return 0, errors.New("node command recovery initialization failed")
	}
	header := http.Header{}
	if cfg.Token != "" {
		header.Set("Authorization", "Bearer "+cfg.Token)
	}

	var client *http.Client
	if cfg.ControllerCAFile != "" {
		pem, err := os.ReadFile(cfg.ControllerCAFile)
		if err != nil {
			return 0, errors.New("controller CA could not be read")
		}
		roots, err := x509.SystemCertPool()
		if err != nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(pem) {
			return 0, errors.New("controller CA file has no certificates")
		}
		client = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}}
	}
	conn, _, err := websocket.Dial(ctx, cfg.ControllerURL, &websocket.DialOptions{
		HTTPHeader: header,
		HTTPClient: client,
	})
	if err != nil {
		return 0, err
	}
	nodetransport.ApplyControlMessageLimit(conn)
	defer conn.CloseNow()
	commands := (*commandProcessor)(nil)
	if len(processors) > 0 && processors[0] != nil {
		commands = processors[0]
	} else {
		commands = newCommandProcessor(cfg, log, true)
	}
	if commands.initError != nil {
		return 0, errors.New("node command recovery initialization failed")
	}

	log.Info("connected to controller")

	// Reset backoff on successful connect by returning to caller via a
	// successful (nil-until-drop) run; caller resets backoff after a
	// connection has been alive for a while — kept simple in Phase 1 by
	// resetting backoff unconditionally on next attempt after any
	// successful register (see below flag).
	ready := commands.Ready()
	reg := registerPayloadForConfig(cfg, ready)
	for _, profile := range cfg.GPUPerformance.Accelerators {
		reg.GPUPerformanceIndices = append(reg.GPUPerformanceIndices, profile.Index)
	}
	connectionOrdinal := nodeConnectionSequence.Add(1)
	reg.Adapters = discoverAdaptersForSession(ctx, cfg, log, commands, connectionOrdinal > 1)
	if err := sendEnvelope(ctx, conn, wsproto.MsgRegister, reg); err != nil {
		return 0, err
	}

	// Read the register ack before starting heartbeat loop.
	var ackEnv wsproto.Envelope
	if err := wsjson.Read(ctx, conn, &ackEnv); err != nil {
		return 0, err
	}
	if ackEnv.Type != wsproto.MsgAck {
		log.Warn("expected ack after register, got unexpected message type")
	} else {
		log.Info("registered with controller")
	}
	establishedAt := time.Now()
	sessionCtx, cancelSession := context.WithCancel(ctx)
	defer cancelSession()
	if commands.HasPending() {
		if err := commands.ReconcilePending(sessionCtx); err != nil {
			log.Warn("pending command reconciliation remains blocked", "error", "runtime reconciliation unavailable")
		}
	}
	if err := commands.ReconcileWarmManifests(sessionCtx); err != nil {
		log.Warn("restored warm manifest reconciliation remains blocked", "error", "runtime reconciliation unavailable")
	}

	errCh := make(chan error, 2)
	capabilitiesCh := make(chan []wsproto.AdapterAdvertisement, 1)
	commandResultsCh := make(chan wsproto.CommandResultPayload, 8)
	telemetryCh := make(chan wsproto.TelemetryPayload, 1)
	go capabilityDiscoveryLoop(sessionCtx, cfg, log, capabilitiesCh, commands)
	go telemetrySamplingLoop(sessionCtx, cfg, log, sampler, logs, QueryGPUTelemetry, telemetryCh)

	// Reader goroutine verifies and executes only the node agent's fixed
	// command allowlist. Results go through the single writer goroutine.
	go func() {
		for {
			var env wsproto.Envelope
			if err := wsjson.Read(sessionCtx, conn, &env); err != nil {
				errCh <- err
				return
			}
			if env.Type == wsproto.MsgCommand {
				var command wsproto.CommandPayload
				if err := json.Unmarshal(env.Payload, &command); err != nil {
					log.Warn("invalid command payload")
					continue
				}
				result := commands.Handle(sessionCtx, command)
				select {
				case commandResultsCh <- result:
				case <-sessionCtx.Done():
					return
				}
			}
		}
	}()

	// Liveness is deliberately independent from GPU/system sampling. Driver
	// tools can stall while a model is loading; that must not make a healthy
	// node look disconnected or invalidate a running workload's lease.
	if err := sendHeartbeat(sessionCtx, conn, cfg.NodeID, commands.Ready()); err != nil {
		return time.Since(establishedAt), err
	}

	// Writer loop: heartbeat + telemetry on a fixed interval.
	go func() {
		interval := time.Duration(cfg.HeartbeatIntervalSeconds) * time.Second
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-sessionCtx.Done():
				errCh <- sessionCtx.Err()
				return
			case <-ticker.C:
				if err := sendHeartbeat(sessionCtx, conn, cfg.NodeID, commands.Ready()); err != nil {
					errCh <- err
					return
				}
			case telemetry := <-telemetryCh:
				if err := sendEnvelope(sessionCtx, conn, wsproto.MsgTelemetry, telemetry); err != nil {
					errCh <- err
					return
				}
			case advertisements := <-capabilitiesCh:
				payload := capabilitiesPayloadForConfig(cfg, advertisements)
				if err := sendEnvelope(sessionCtx, conn, wsproto.MsgCapabilities, payload); err != nil {
					errCh <- err
					return
				}
			case result := <-commandResultsCh:
				if err := sendEnvelope(sessionCtx, conn, wsproto.MsgCommandResult, result); err != nil {
					errCh <- err
					return
				}
			}
		}
	}()

	select {
	case <-ctx.Done():
		return time.Since(establishedAt), ctx.Err()
	case err := <-errCh:
		return time.Since(establishedAt), err
	}
}

func registerPayloadForConfig(cfg *Config, readiness ...bool) wsproto.RegisterPayload {
	var ready *bool
	if len(readiness) > 0 {
		value := readiness[0]
		ready = &value
	}
	return wsproto.RegisterPayload{
		NodeID: cfg.NodeID, NodeName: cfg.NodeName, LocationClass: cfg.LocationClass,
		PowerControlMode: cfg.PowerControlMode, AgentVersion: cfg.AgentVersion,
		Ready:             ready,
		CapabilityVersion: cfg.CapabilityVersion, Capabilities: cfg.Capabilities,
		Capacity: cfg.Capacity, MaxAcceleratorsPerWorkload: cfg.MaxAcceleratorsPerWorkload,
	}
}

func capabilitiesPayloadForConfig(cfg *Config, adapters []wsproto.AdapterAdvertisement) wsproto.CapabilitiesPayload {
	return wsproto.CapabilitiesPayload{
		NodeID: cfg.NodeID, CapabilityVersion: cfg.CapabilityVersion,
		Capabilities: cfg.Capabilities, Capacity: cfg.Capacity,
		MaxAcceleratorsPerWorkload: cfg.MaxAcceleratorsPerWorkload, Adapters: adapters,
	}
}

func discoverAdapters(ctx context.Context, cfg *Config, log *slog.Logger, commandHandler CommandHandler) []wsproto.AdapterAdvertisement {
	return discoverAdaptersForSession(ctx, cfg, log, commandHandler, false)
}

func discoverAdaptersForSession(ctx context.Context, cfg *Config, log *slog.Logger, commandHandler CommandHandler, reconnect bool) []wsproto.AdapterAdvertisement {
	advertisements := make([]wsproto.AdapterAdvertisement, 0, len(cfg.LlamaCPP.Servers)+1)
	for _, server := range cfg.LlamaCPP.Servers {
		discoveryCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		advertisement, err := DiscoverLlamaCPP(discoveryCtx, cfg.NodeID, server)
		cancel()
		if err != nil {
			// Runtime IDs, endpoints, and upstream response bodies are external
			// data.  Keep discovery diagnostics bounded and secret-free.
			log.Warn("llama.cpp discovery failed")
			continue
		}
		if advertisement.CapabilityGeneration == 0 {
			advertisement.CapabilityGeneration = cfg.CommandRecoveryGeneration
			if advertisement.CapabilityGeneration == 0 {
				advertisement.CapabilityGeneration = 1
			}
		}
		// Discovery/probe facts are never production proof. A node may re-enable
		// the capability only after a complete live exercise through the same
		// driver used by signed checkpoint commands. Failure is fail-closed.
		if cfg.Checkpoint.Enabled {
			// The authenticated launch-plan/unit join belongs to the later fixed
			// launcher integration. Until it exists locally, neither a persisted
			// legacy/v2 proof nor a disruptive probe may be reused or issued.
			clearCheckpointCapability(&advertisement)
			advertisements = append(advertisements, advertisement)
			continue
		}
		clearCheckpointCapability(&advertisement)
		advertisements = append(advertisements, advertisement)
	}
	if cfg.ComfyUI.Endpoint != "" {
		discoveryCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		advertisement, err := DiscoverComfyUI(discoveryCtx, cfg)
		cancel()
		if err != nil {
			log.Warn("ComfyUI discovery failed")
		} else {
			advertisements = append(advertisements, advertisement)
		}
	}
	return advertisements
}

func checkpointProofMatchesAdvertisement(proof runtime.CheckpointCapabilityProof, cfg *Config, server LlamaCPPServerConfig, advertisement wsproto.AdapterAdvertisement) bool {
	profile := advertisement.ActiveRuntimeProfile
	if profile == "" {
		profile = "default"
	}
	generation := advertisement.CapabilityGeneration
	if generation == 0 {
		generation = cfg.CommandRecoveryGeneration
		if generation == 0 {
			generation = 1
		}
	}
	return proof.NodeID == cfg.NodeID &&
		proof.TargetID == cfg.NodeID+"-"+advertisement.ID &&
		proof.ModelFingerprint == advertisement.ModelFingerprint &&
		proof.RuntimeIdentity == advertisement.Version &&
		proof.ProfileFingerprint == profile &&
		proof.ContextLimit == advertisement.ContextLimit &&
		proof.AcceleratorID == fmt.Sprintf("%s-gpu%d", cfg.NodeID, server.AcceleratorIndex) &&
		advertisement.AcceleratorIndex == server.AcceleratorIndex &&
		proof.Generation == generation
}

func checkpointProofPath(base, targetID string) string {
	if base == "" || targetID == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(targetID))
	return filepath.Join(filepath.Dir(base), filepath.Base(base)+"."+strings.ToLower(hex.EncodeToString(sum[:6]))+".json")
}

func capabilityDiscoveryLoop(ctx context.Context, cfg *Config, log *slog.Logger, out chan<- []wsproto.AdapterAdvertisement, commandHandler CommandHandler) {
	interval := time.Duration(cfg.CapabilityRefreshSeconds) * time.Second
	if interval <= 0 {
		interval = 30 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			advertisements := discoverAdapters(ctx, cfg, log, commandHandler)
			if len(advertisements) == 0 {
				continue
			}
			select {
			case out <- advertisements:
			default:
			}
		}
	}
}

func sendHeartbeat(ctx context.Context, conn *websocket.Conn, nodeID string, ready bool) error {
	return sendEnvelope(ctx, conn, wsproto.MsgHeartbeat, wsproto.HeartbeatPayload{NodeID: nodeID, Ready: ready})
}

func telemetrySamplingLoop(ctx context.Context, cfg *Config, log *slog.Logger, sampler *SystemSampler, logs func() []logging.Entry, query func(context.Context) ([]wsproto.AcceleratorTelemetry, error), out chan wsproto.TelemetryPayload) {
	interval := time.Duration(cfg.HeartbeatIntervalSeconds) * time.Second
	if interval <= 0 {
		interval = 2 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	var lastAccelerators []wsproto.AcceleratorTelemetry
	for {
		queryTimeout := 5 * time.Second
		if interval > queryTimeout {
			queryTimeout = interval
		}
		queryCtx, cancel := context.WithTimeout(ctx, queryTimeout)
		accelerators, err := query(queryCtx)
		cancel()
		if err != nil {
			log.Warn("gpu telemetry query failed (preserving last inventory)")
			accelerators = append([]wsproto.AcceleratorTelemetry(nil), lastAccelerators...)
		} else {
			lastAccelerators = append(lastAccelerators[:0], accelerators...)
		}
		telemetry := wsproto.TelemetryPayload{NodeID: cfg.NodeID, Accelerators: accelerators, System: sampler.Sample()}
		if logs != nil {
			for _, entry := range logs() {
				telemetry.AgentLogs = append(telemetry.AgentLogs, wsproto.LogEntry{Timestamp: entry.Timestamp, Level: entry.Level, Message: entry.Message, Attributes: entry.Attributes})
			}
		}
		select {
		case out <- telemetry:
		default:
			// Keep the freshest sample without ever blocking liveness.
			select {
			case <-out:
			default:
			}
			select {
			case out <- telemetry:
			default:
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func sendEnvelope(ctx context.Context, conn *websocket.Conn, t wsproto.MsgType, payload any) error {
	b, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	env := wsproto.Envelope{Type: t, Time: time.Now().UTC(), Payload: b}
	return wsjson.Write(ctx, conn, env)
}
