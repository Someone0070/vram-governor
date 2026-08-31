// Package nodeagent implements the small persistent process that runs
// co-located with a GPU (or, on a GPU-less box, still registers and
// heartbeats with an empty accelerator list). It dials the controller's
// websocket endpoint outbound, authenticates, registers, and then reports
// heartbeat + GPU telemetry on a fixed interval, redialing on any drop.
// See architecture.md §34 (Node Agent) and §34A (control channel).
package nodeagent

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"

	"vram-governor/internal/logging"
	"vram-governor/internal/wsproto"
)

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

	for {
		if ctx.Err() != nil {
			return
		}
		lifetime, err := runOnce(ctx, cfg, log, sampler, logs)
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
			log.Warn("connection ended, will reconnect", "err", err, "backoff", backoff)
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

func runOnce(ctx context.Context, cfg *Config, log *slog.Logger, sampler *SystemSampler, logs func() []logging.Entry) (time.Duration, error) {
	header := http.Header{}
	if cfg.Token != "" {
		header.Set("Authorization", "Bearer "+cfg.Token)
	}

	conn, _, err := websocket.Dial(ctx, cfg.ControllerURL, &websocket.DialOptions{
		HTTPHeader: header,
	})
	if err != nil {
		return 0, err
	}
	defer conn.CloseNow()

	log.Info("connected to controller", "url", cfg.ControllerURL)

	// Reset backoff on successful connect by returning to caller via a
	// successful (nil-until-drop) run; caller resets backoff after a
	// connection has been alive for a while — kept simple in Phase 1 by
	// resetting backoff unconditionally on next attempt after any
	// successful register (see below flag).
	reg := wsproto.RegisterPayload{
		NodeID:           cfg.NodeID,
		NodeName:         cfg.NodeName,
		LocationClass:    cfg.LocationClass,
		PowerControlMode: cfg.PowerControlMode,
		AgentVersion:     cfg.AgentVersion,
	}
	reg.Adapters = discoverAdapters(ctx, cfg, log)
	if err := sendEnvelope(ctx, conn, wsproto.MsgRegister, reg); err != nil {
		return 0, err
	}

	// Read the register ack before starting heartbeat loop.
	var ackEnv wsproto.Envelope
	if err := wsjson.Read(ctx, conn, &ackEnv); err != nil {
		return 0, err
	}
	if ackEnv.Type != wsproto.MsgAck {
		log.Warn("expected ack after register, got", "type", ackEnv.Type)
	} else {
		log.Info("registered with controller")
	}
	establishedAt := time.Now()
	sessionCtx, cancelSession := context.WithCancel(ctx)
	defer cancelSession()

	errCh := make(chan error, 2)
	capabilitiesCh := make(chan []wsproto.AdapterAdvertisement, 1)
	commandResultsCh := make(chan wsproto.CommandResultPayload, 8)
	telemetryCh := make(chan wsproto.TelemetryPayload, 1)
	commands := newCommandProcessor(cfg, log)
	go capabilityDiscoveryLoop(sessionCtx, cfg, log, capabilitiesCh)
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
					log.Warn("invalid command payload", "err", err)
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
	if err := sendHeartbeat(sessionCtx, conn, cfg.NodeID); err != nil {
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
				if err := sendHeartbeat(sessionCtx, conn, cfg.NodeID); err != nil {
					errCh <- err
					return
				}
			case telemetry := <-telemetryCh:
				if err := sendEnvelope(sessionCtx, conn, wsproto.MsgTelemetry, telemetry); err != nil {
					errCh <- err
					return
				}
			case advertisements := <-capabilitiesCh:
				payload := wsproto.CapabilitiesPayload{NodeID: cfg.NodeID, Adapters: advertisements}
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

func discoverAdapters(ctx context.Context, cfg *Config, log *slog.Logger) []wsproto.AdapterAdvertisement {
	advertisements := make([]wsproto.AdapterAdvertisement, 0, len(cfg.LlamaCPP.Servers)+1)
	for _, server := range cfg.LlamaCPP.Servers {
		discoveryCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		advertisement, err := DiscoverLlamaCPP(discoveryCtx, cfg.NodeID, server)
		cancel()
		if err != nil {
			log.Warn("llama.cpp discovery failed", "id", server.ID, "endpoint", server.Endpoint, "err", err)
			continue
		}
		advertisements = append(advertisements, advertisement)
	}
	if cfg.ComfyUI.Endpoint != "" {
		discoveryCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		advertisement, err := DiscoverComfyUI(discoveryCtx, cfg)
		cancel()
		if err != nil {
			log.Warn("ComfyUI discovery failed", "err", err)
		} else {
			advertisements = append(advertisements, advertisement)
		}
	}
	return advertisements
}

func capabilityDiscoveryLoop(ctx context.Context, cfg *Config, log *slog.Logger, out chan<- []wsproto.AdapterAdvertisement) {
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
			advertisements := discoverAdapters(ctx, cfg, log)
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

func sendHeartbeat(ctx context.Context, conn *websocket.Conn, nodeID string) error {
	return sendEnvelope(ctx, conn, wsproto.MsgHeartbeat, wsproto.HeartbeatPayload{NodeID: nodeID, Ready: true})
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
			log.Warn("gpu telemetry query failed (preserving last inventory)", "err", err)
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
