package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"

	"vram-governor/internal/domain"
	"vram-governor/internal/workloads"
	"vram-governor/internal/wsproto"
)

type nodeConnection struct {
	conn *websocket.Conn
	mu   sync.Mutex
}

func (connection *nodeConnection) write(ctx context.Context, envelope wsproto.Envelope) error {
	connection.mu.Lock()
	defer connection.mu.Unlock()
	return wsjson.Write(ctx, connection.conn, envelope)
}

// handleNodeWS is the single control-channel endpoint a node agent dials
// outbound into (architecture.md §34A). The controller never dials the
// node. Authentication uses a node-plane credential bound to the registering
// node ID; the legacy shared token remains development-only compatibility.
func (s *Server) handleNodeWS(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	conn, err := websocket.Accept(w, r, nil)
	if err != nil {
		s.log.Error("ws accept failed", "err", err)
		return
	}
	defer conn.CloseNow()
	connection := &nodeConnection{conn: conn}

	ctx := r.Context()

	// First message must be a register envelope.
	var env wsproto.Envelope
	if err := wsjson.Read(ctx, conn, &env); err != nil {
		s.log.Warn("ws: failed reading register message", "err", err)
		return
	}
	if env.Type != wsproto.MsgRegister {
		s.log.Warn("ws: first message was not register", "type", env.Type)
		_ = conn.Close(websocket.StatusPolicyViolation, "expected register message")
		return
	}
	var reg wsproto.RegisterPayload
	if err := json.Unmarshal(env.Payload, &reg); err != nil {
		s.log.Warn("ws: bad register payload", "err", err)
		_ = conn.Close(websocket.StatusUnsupportedData, "bad register payload")
		return
	}
	if principal, authenticated := s.authenticate(r); authenticated && principal.ID != "legacy" {
		if principal.Plane != "node" || !hasScope(principal, "node:connect") || (principal.NodeID != "" && principal.NodeID != reg.NodeID) {
			_ = conn.Close(websocket.StatusPolicyViolation, "credential is not authorized for this node")
			return
		}
	}

	node := s.registerNode(ctx, reg)
	s.registerAdapterAdvertisements(reg.NodeID, reg.Adapters)
	s.nodeConnMu.Lock()
	s.nodeConnections[reg.NodeID] = connection
	s.nodeConnMu.Unlock()
	defer func() {
		s.nodeConnMu.Lock()
		if s.nodeConnections[reg.NodeID] == connection {
			delete(s.nodeConnections, reg.NodeID)
		}
		s.nodeConnMu.Unlock()
	}()
	s.log.Info("node registered", "node_id", node.ID, "name", node.Name, "location_class", node.LocationClass)

	if err := s.sendAck(ctx, connection, true, "registered"); err != nil {
		return
	}
	s.dispatchNodeCommands(ctx, reg.NodeID)

	for {
		var env wsproto.Envelope
		if err := wsjson.Read(ctx, conn, &env); err != nil {
			s.log.Info("node disconnected", "node_id", reg.NodeID, "err", err)
			return
		}
		switch env.Type {
		case wsproto.MsgHeartbeat:
			var hb wsproto.HeartbeatPayload
			if err := json.Unmarshal(env.Payload, &hb); err != nil {
				s.log.Warn("ws: bad heartbeat payload", "node_id", reg.NodeID, "err", err)
				continue
			}
			s.handleHeartbeat(ctx, reg.NodeID, hb)
			_ = s.sendAck(ctx, connection, true, "")

		case wsproto.MsgTelemetry:
			var tel wsproto.TelemetryPayload
			if err := json.Unmarshal(env.Payload, &tel); err != nil {
				s.log.Warn("ws: bad telemetry payload", "node_id", reg.NodeID, "err", err)
				continue
			}
			s.handleTelemetry(ctx, reg.NodeID, tel)
			_ = s.sendAck(ctx, connection, true, "")

		case wsproto.MsgCapabilities:
			var capabilities wsproto.CapabilitiesPayload
			if err := json.Unmarshal(env.Payload, &capabilities); err != nil || capabilities.NodeID != reg.NodeID {
				s.log.Warn("ws: bad capabilities payload", "node_id", reg.NodeID, "err", err)
				continue
			}
			s.registerAdapterAdvertisements(reg.NodeID, capabilities.Adapters)
			_ = s.sendAck(ctx, connection, true, "")

		case wsproto.MsgEvent:
			var ev wsproto.EventPayload
			if err := json.Unmarshal(env.Payload, &ev); err == nil {
				s.log.Info("node event", "node_id", reg.NodeID, "type", ev.Type, "severity", ev.Severity)
			}
			_ = s.sendAck(ctx, connection, true, "")

		case wsproto.MsgCommandResult:
			var result wsproto.CommandResultPayload
			if err := json.Unmarshal(env.Payload, &result); err != nil || result.NodeID != reg.NodeID {
				s.log.Warn("ws: bad command result", "node_id", reg.NodeID, "err", err)
				continue
			}
			s.handleNodeCommandResult(ctx, result)

		default:
			s.log.Warn("ws: unknown message type", "type", env.Type, "node_id", reg.NodeID)
		}
	}
}

func (s *Server) registerAdapterAdvertisements(nodeID string, advertisements []wsproto.AdapterAdvertisement) {
	if s.workloads == nil {
		return
	}
	registered := make(map[string]struct{}, len(advertisements))
	for _, advertised := range advertisements {
		if advertised.ID == "" || advertised.Adapter == "" || advertised.Endpoint == "" {
			continue
		}
		targetID := advertised.ID
		if !strings.HasPrefix(targetID, nodeID+"-") {
			targetID = nodeID + "-" + targetID
		}
		registered[targetID] = struct{}{}
		acceleratorID := fmt.Sprintf("%s-gpu%d", nodeID, advertised.AcceleratorIndex)
		var acceleratorVRAMMB int64
		if node, err := s.nodes.GetNode(context.Background(), nodeID); err == nil {
			for _, accelerator := range node.Accelerators {
				if accelerator.ID == acceleratorID {
					acceleratorVRAMMB = accelerator.VRAMTotalMB
					break
				}
			}
		}
		s.workloads.RegisterTarget(workloads.Target{
			ID: targetID, Adapter: advertised.Adapter, Endpoint: advertised.Endpoint,
			AcceleratorID: acceleratorID, AcceleratorVRAMMB: acceleratorVRAMMB,
			Models: advertised.Models, ResidentModels: advertised.ResidentModels, CustomNodes: advertised.CustomNodes,
			ContextLimit: advertised.ContextLimit, Slots: advertised.Slots,
			CapabilityVersion: advertised.Version, ModelFingerprint: advertised.ModelFingerprint,
			CapacitySource: advertised.CapacitySource, CapacityVerified: advertised.CapabilitiesVerified,
			RuntimeArgs: advertised.RuntimeArgs, SupportsModelLifecycle: advertised.SupportsModelLifecycle, SupportsAcceleratorReclaim: advertised.SupportsAcceleratorReclaim,
			MaxResidentModels: advertised.MaxResidentModels, WarmRAMSupported: advertised.WarmRAMSupported,
			QueueRunning: advertised.QueueRunning, QueuePending: advertised.QueuePending,
			StandaloneVRAMMB: advertised.StandaloneVRAMMB, StandaloneVRAMSource: advertised.StandaloneVRAMSource, StandaloneVRAMVerified: advertised.StandaloneVRAMVerified,
			ResidencyPolicy: domain.ResidencyAuto, Enabled: true,
		})
	}
	s.workloads.ReconcileNodeTargets(nodeID, registered)
}

func (s *Server) checkAuth(r *http.Request) bool {
	_, ok := s.authenticate(r)
	return ok
}

func (s *Server) sendAck(ctx context.Context, conn *nodeConnection, ok bool, msg string) error {
	ack := wsproto.Envelope{
		Type: wsproto.MsgAck,
		Time: time.Now().UTC(),
	}
	payload, _ := json.Marshal(wsproto.AckPayload{OK: ok, Message: msg, ServerTime: time.Now().UTC()})
	ack.Payload = payload
	return conn.write(ctx, ack)
}

func (s *Server) registerNode(ctx context.Context, reg wsproto.RegisterPayload) *domain.Node {
	now := time.Now().UTC()
	previousConnectivity := domain.ConnectivityLost
	n := &domain.Node{
		ID:              reg.NodeID,
		Name:            reg.NodeName,
		LocationClass:   domain.LocationClass(reg.LocationClass),
		PriorityTier:    priorityFor(domain.LocationClass(reg.LocationClass)),
		SchedulingState: domain.SchedulingEnabled,
		Desired: domain.Desired{
			SchedulingEnabled: true,
			Power:             domain.DesiredPowerOn,
			AutoReconcile:     true,
			PowerControlMode:  domain.PowerControlMode(reg.PowerControlMode),
		},
		Observed: domain.Observed{
			Connectivity:  domain.ConnectivityConnected,
			Lifecycle:     domain.LifecycleConnected,
			Power:         domain.DesiredPowerOn,
			Ready:         true,
			LastHeartbeat: now,
			LastSeenAt:    now,
			AgentVersion:  reg.AgentVersion,
		},
	}
	if existing, err := s.nodes.GetNode(ctx, reg.NodeID); err == nil {
		previousConnectivity = existing.Observed.Connectivity
		// A reconnect reports observed facts. It must not erase durable
		// operator intent such as draining, disabled scheduling, or power
		// policy.
		n.SchedulingState = existing.SchedulingState
		n.Desired = existing.Desired
		n.PriorityTier = existing.PriorityTier
	}
	stored, err := s.nodes.UpsertNode(ctx, n)
	if err != nil {
		s.log.Error("failed to upsert node on register", "node_id", reg.NodeID, "err", err)
		return n
	}
	s.reconcileNodeConnectivityIncident(ctx, stored, previousConnectivity, domain.ConnectivityConnected)
	return stored
}

func priorityFor(lc domain.LocationClass) domain.PriorityTier {
	if lc == domain.LocationRemote {
		return domain.PriorityP0
	}
	return domain.PriorityP1
}

func (s *Server) handleHeartbeat(ctx context.Context, nodeID string, hb wsproto.HeartbeatPayload) {
	now := time.Now().UTC()
	err := s.nodes.UpdateObserved(ctx, nodeID, func(o *domain.Observed, _ *[]domain.Accelerator) {
		o.LastHeartbeat = now
		o.LastSeenAt = now
		o.Ready = hb.Ready
		o.Connectivity = domain.ConnectivityConnected
		if o.Lifecycle == domain.LifecycleOffline || o.Lifecycle == "" {
			o.Lifecycle = domain.LifecycleConnected
		}
		if hb.Ready {
			o.Lifecycle = domain.LifecycleReady
		}
	})
	if err != nil {
		s.log.Warn("heartbeat for unknown node", "node_id", nodeID, "err", err)
	}
}

func (s *Server) handleTelemetry(ctx context.Context, nodeID string, tel wsproto.TelemetryPayload) {
	accels := make([]domain.Accelerator, 0, len(tel.Accelerators))
	for _, a := range tel.Accelerators {
		accels = append(accels, domain.Accelerator{
			ID:             fmt.Sprintf("%s-gpu%d", nodeID, a.Index),
			NodeID:         nodeID,
			Vendor:         "nvidia",
			Model:          a.Name,
			VRAMTotalMB:    a.VRAMTotalMB,
			VRAMUsedMB:     a.VRAMUsedMB,
			VRAMFreeMB:     a.VRAMFreeMB,
			UtilizationPct: a.UtilizationPct,
			TemperatureC:   a.TemperatureC,
			Driver:         a.Driver, PowerDrawW: a.PowerDrawW, PowerLimitW: a.PowerLimitW, FanSpeedPct: a.FanSpeedPct,
			GraphicsClockMHz: a.GraphicsClockMHz, MemoryClockMHz: a.MemoryClockMHz, PCIeGeneration: a.PCIeGeneration, PCIeWidth: a.PCIeWidth, PerformanceState: a.PerformanceState,
		})
	}
	err := s.nodes.UpdateObserved(ctx, nodeID, func(o *domain.Observed, out *[]domain.Accelerator) {
		*out = accels
		o.System = systemTelemetryFromWire(tel.System)
		o.AgentLogs = make([]domain.LogEntry, 0, len(tel.AgentLogs))
		for _, entry := range tel.AgentLogs {
			o.AgentLogs = append(o.AgentLogs, domain.LogEntry{Timestamp: entry.Timestamp, Level: entry.Level, Message: entry.Message, Attributes: entry.Attributes})
		}
		o.LastSeenAt = time.Now().UTC()
	})
	if err != nil {
		s.log.Warn("telemetry for unknown node", "node_id", nodeID, "err", err)
		return
	}
	if s.workloads != nil {
		for _, accelerator := range accels {
			s.workloads.UpdateAcceleratorCapacity(accelerator.ID, accelerator.VRAMTotalMB)
		}
	}
	now := time.Now().UTC()
	s.telemetryMu.Lock()
	rows := append(s.telemetryHistory[nodeID], telemetrySnapshot{Timestamp: now, System: systemTelemetryFromWire(tel.System), Accelerators: accels})
	cutoff := now.Add(-24 * time.Hour)
	first := 0
	for first < len(rows) && rows[first].Timestamp.Before(cutoff) {
		first++
	}
	if first > 0 {
		rows = append([]telemetrySnapshot(nil), rows[first:]...)
	}
	s.telemetryHistory[nodeID] = rows
	s.telemetryMu.Unlock()
}

func systemTelemetryFromWire(system wsproto.SystemTelemetry) domain.SystemTelemetry {
	return domain.SystemTelemetry{
		Hostname: system.Hostname, OS: system.OS, Kernel: system.Kernel, Architecture: system.Architecture,
		CPUModel: system.CPUModel, CPULogical: system.CPULogical, CPUUtilizationPct: system.CPUUtilizationPct,
		Load1: system.Load1, Load5: system.Load5, Load15: system.Load15,
		RAMTotalMB: system.RAMTotalMB, RAMUsedMB: system.RAMUsedMB, RAMAvailableMB: system.RAMAvailableMB,
		SwapTotalMB: system.SwapTotalMB, SwapUsedMB: system.SwapUsedMB,
		RootDiskTotalMB: system.RootDiskTotalMB, RootDiskUsedMB: system.RootDiskUsedMB, RootDiskFreeMB: system.RootDiskFreeMB,
		NetworkAddresses: append([]string(nil), system.NetworkAddresses...), NetworkRXBPS: system.NetworkRXBPS, NetworkTXBPS: system.NetworkTXBPS,
		UptimeSeconds: system.UptimeSeconds, SampledAt: system.SampledAt,
	}
}
