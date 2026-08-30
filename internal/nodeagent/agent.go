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

	errCh := make(chan error, 2)
	capabilitiesCh := make(chan []wsproto.AdapterAdvertisement, 1)
	commandResultsCh := make(chan wsproto.CommandResultPayload, 8)
	commands := newCommandProcessor(cfg, log)
	go capabilityDiscoveryLoop(ctx, cfg, log, capabilitiesCh)

	// Reader goroutine verifies and executes only the node agent's fixed
	// command allowlist. Results go through the single writer goroutine.
	go func() {
		for {
			var env wsproto.Envelope
			if err := wsjson.Read(ctx, conn, &env); err != nil {
				errCh <- err
				return
			}
			if env.Type == wsproto.MsgCommand {
				var command wsproto.CommandPayload
				if err := json.Unmarshal(env.Payload, &command); err != nil {
					log.Warn("invalid command payload", "err", err)
					continue
				}
				result := commands.Handle(ctx, command)
				select {
				case commandResultsCh <- result:
				case <-ctx.Done():
					return
				}
			}
		}
	}()

	// Send one immediately so the dashboard doesn't wait a full interval.
	// This happens on the main goroutine, strictly before the writer
	// goroutine below starts, so there is never more than one writer at a
	// time on the connection (coder/websocket requires a single writer).
	if err := sendHeartbeatAndTelemetry(ctx, conn, cfg, log, sampler, logs); err != nil {
		return time.Since(establishedAt), err
	}

	// Writer loop: heartbeat + telemetry on a fixed interval.
	go func() {
		interval := time.Duration(cfg.HeartbeatIntervalSeconds) * time.Second
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				errCh <- ctx.Err()
				return
			case <-ticker.C:
				if err := sendHeartbeatAndTelemetry(ctx, conn, cfg, log, sampler, logs); err != nil {
					errCh <- err
					return
				}
			case advertisements := <-capabilitiesCh:
				payload := wsproto.CapabilitiesPayload{NodeID: cfg.NodeID, Adapters: advertisements}
				if err := sendEnvelope(ctx, conn, wsproto.MsgCapabilities, payload); err != nil {
					errCh <- err
					return
				}
			case result := <-commandResultsCh:
				if err := sendEnvelope(ctx, conn, wsproto.MsgCommandResult, result); err != nil {
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

func sendHeartbeatAndTelemetry(ctx context.Context, conn *websocket.Conn, cfg *Config, log *slog.Logger, sampler *SystemSampler, logs func() []logging.Entry) error {
	// Liveness must never wait behind a slow driver query. Large model loads can
	// temporarily stall nvidia-smi; send the heartbeat first so the controller
	// does not fence a healthy node while telemetry catches up.
	hb := wsproto.HeartbeatPayload{NodeID: cfg.NodeID, Ready: true}
	if err := sendEnvelope(ctx, conn, wsproto.MsgHeartbeat, hb); err != nil {
		return err
	}

	accels, err := QueryGPUTelemetry(ctx)
	if err != nil {
		log.Warn("gpu telemetry query failed (preserving last inventory)", "err", err)
	}
	if err == nil {
		tel := wsproto.TelemetryPayload{NodeID: cfg.NodeID, Accelerators: accels, System: sampler.Sample()}
		if logs != nil {
			for _, entry := range logs() {
				tel.AgentLogs = append(tel.AgentLogs, wsproto.LogEntry{Timestamp: entry.Timestamp, Level: entry.Level, Message: entry.Message, Attributes: entry.Attributes})
			}
		}
		if err := sendEnvelope(ctx, conn, wsproto.MsgTelemetry, tel); err != nil {
			return err
		}
	}
	return nil
}

func sendEnvelope(ctx context.Context, conn *websocket.Conn, t wsproto.MsgType, payload any) error {
	b, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	env := wsproto.Envelope{Type: t, Time: time.Now().UTC(), Payload: b}
	return wsjson.Write(ctx, conn, env)
}
