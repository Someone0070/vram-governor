package api

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"

	"vram-governor/internal/domain"
	"vram-governor/internal/nodetransport"
	checkpointRuntime "vram-governor/internal/runtime"
	"vram-governor/internal/store"
	"vram-governor/internal/workloads"
	"vram-governor/internal/wsproto"
)

// checkpointProofIssuance reads the durable node-issued epoch embedded in a
// nonce. Older proofs used an unstructured nonce and remain protected by the
// durable nonce journal, but cannot advance the issuance high-water.
func checkpointProofIssuance(nonce string) (uint64, bool) {
	return checkpointRuntime.CheckpointProofIssuanceEpoch(nonce)
}

func (s *Server) validateCheckpointAdvertisementProof(nodeID string, advertised wsproto.AdapterAdvertisement) error {
	return s.validateCheckpointAdvertisementProofSession(nodeID, advertised, true, "")
}

// validateCheckpointAdvertisementProofSession verifies identity, digest and
// HMAC for every advertisement. A repeated capabilities refresh is
// idempotent only when it presents the same digest/nonce in the same
// authenticated websocket session; a new connection still hits the durable
// replay journal.
func (s *Server) validateCheckpointAdvertisementProofSession(nodeID string, advertised wsproto.AdapterAdvertisement, consumeNonce bool, sessionKey string) error {
	proof := advertised.CheckpointProof
	if proof == (checkpointRuntime.CheckpointCapabilityProof{}) {
		if advertised.Capabilities.SupportsSessionCheckpoint || advertised.Capabilities.SessionCheckpointVerified {
			return fmt.Errorf("checkpoint capability requires a completed proof")
		}
		return nil
	}
	if !proof.Complete() {
		return fmt.Errorf("checkpoint proof is incomplete")
	}
	if !hasUniqueCheckpointModelAlias(advertised.Models, proof.ModelAlias) || !hasUniqueCheckpointModelAlias(advertised.ResidentModels, proof.ModelAlias) {
		return fmt.Errorf("checkpoint proof model alias is not advertised as currently resident")
	}
	issuance, issuanceOK := checkpointProofIssuance(proof.Nonce)
	if !issuanceOK || issuance == 0 {
		return fmt.Errorf("checkpoint proof has no durable issuance epoch")
	}
	targetID := nodeID + "-" + advertised.ID
	if proof.TargetID != targetID || proof.NodeID != nodeID || proof.AcceleratorID != fmt.Sprintf("%s-gpu%d", nodeID, advertised.AcceleratorIndex) || proof.RuntimeIdentity != advertised.Version || proof.ContextLimit != advertised.ContextLimit {
		return fmt.Errorf("checkpoint proof identity does not match authenticated advertisement")
	}
	model := advertised.ModelFingerprint
	if model == "" || proof.ModelFingerprint != model || proof.ProfileFingerprint == "" || advertised.CapabilityGeneration == 0 || proof.Generation != advertised.CapabilityGeneration || proof.NewFence <= proof.OldFence || time.Now().After(proof.ExpiresAt) || proof.ProvenAt.After(time.Now().Add(2*time.Minute)) {
		return fmt.Errorf("checkpoint proof is stale or not bound to current capability facts")
	}
	if advertised.ActiveRuntimeProfile != "" && proof.ProfileFingerprint != advertised.ActiveRuntimeProfile {
		return fmt.Errorf("checkpoint proof profile does not match current advertisement")
	}
	if proof.Digest == "" || proof.Digest != checkpointRuntime.CheckpointProofDigest(proof) {
		return fmt.Errorf("checkpoint proof digest mismatch")
	}
	mac := hmac.New(sha256.New, s.commandSecret)
	_, _ = mac.Write([]byte(proof.Digest))
	want := hex.EncodeToString(mac.Sum(nil))
	if len(s.commandSecret) < 16 || !hmac.Equal([]byte(want), []byte(proof.Signature)) {
		return fmt.Errorf("checkpoint proof signature mismatch")
	}
	if !consumeNonce {
		return nil
	}
	s.checkpointProofMu.Lock()
	defer s.checkpointProofMu.Unlock()
	s.compactCheckpointProofJournalLocked(time.Now().UTC())
	if s.checkpointProofNoncePath == "" {
		return fmt.Errorf("checkpoint proof replay journal is not configured")
	}
	if s.checkpointProofNonceErr != nil {
		return fmt.Errorf("checkpoint proof replay journal unavailable: %w", s.checkpointProofNonceErr)
	}
	key := targetID + "|" + proof.Nonce
	if proof.Nonce == "" {
		return fmt.Errorf("checkpoint proof nonce is required")
	}
	if prior, exists := s.checkpointProofNonces[key]; exists {
		// A capabilities heartbeat in the same authenticated websocket session
		// is an idempotent refresh of the exact signed proof. A different session
		// (including a controller restart) cannot replay that nonce.
		if sessionKey == "" || s.checkpointProofSessions[sessionKey+"|"+key] != prior {
			return fmt.Errorf("checkpoint proof nonce replay")
		}
		return nil
	}
	if s.checkpointProofHighWater == nil {
		s.checkpointProofHighWater = make(map[string]uint64)
	}
	if s.checkpointProofFences == nil {
		s.checkpointProofFences = make(map[string]uint64)
	}
	if s.checkpointProofGenerations == nil {
		s.checkpointProofGenerations = make(map[string]uint64)
	}
	highWaterKey := nodeID + "|" + targetID
	priorIssuance, priorIssuanceExists := s.checkpointProofHighWater[highWaterKey]
	priorFence, priorFenceExists := s.checkpointProofFences[highWaterKey]
	priorGeneration, priorGenerationExists := s.checkpointProofGenerations[highWaterKey]
	if prior := s.checkpointProofHighWater[highWaterKey]; prior >= issuance {
		return fmt.Errorf("checkpoint proof issuance rollback or replay")
	}
	if prior := s.checkpointProofFences[highWaterKey]; prior > proof.NewFence {
		return fmt.Errorf("checkpoint proof fence rollback")
	}
	if prior := s.checkpointProofGenerations[highWaterKey]; prior > proof.Generation {
		return fmt.Errorf("checkpoint proof generation rollback")
	}
	if s.checkpointProofNonces == nil {
		s.checkpointProofNonces = make(map[string]string)
	}
	if s.checkpointProofSessions == nil {
		s.checkpointProofSessions = make(map[string]string)
	}
	s.checkpointProofNonces[key] = proof.Digest
	if s.checkpointProofIssuedAt == nil {
		s.checkpointProofIssuedAt = make(map[string]time.Time)
	}
	s.checkpointProofIssuedAt[key] = time.Now().UTC()
	s.checkpointProofHighWater[highWaterKey] = issuance
	if proof.NewFence > s.checkpointProofFences[highWaterKey] {
		s.checkpointProofFences[highWaterKey] = proof.NewFence
	}
	if proof.Generation > s.checkpointProofGenerations[highWaterKey] {
		s.checkpointProofGenerations[highWaterKey] = proof.Generation
	}
	if sessionKey != "" {
		s.checkpointProofSessions[sessionKey+"|"+key] = proof.Digest
	}
	if err := s.persistCheckpointProofNoncesLocked(); err != nil {
		delete(s.checkpointProofNonces, key)
		delete(s.checkpointProofIssuedAt, key)
		if priorIssuanceExists {
			s.checkpointProofHighWater[highWaterKey] = priorIssuance
		} else {
			delete(s.checkpointProofHighWater, highWaterKey)
		}
		if priorFenceExists {
			s.checkpointProofFences[highWaterKey] = priorFence
		} else {
			delete(s.checkpointProofFences, highWaterKey)
		}
		if priorGenerationExists {
			s.checkpointProofGenerations[highWaterKey] = priorGeneration
		} else {
			delete(s.checkpointProofGenerations, highWaterKey)
		}
		return fmt.Errorf("checkpoint proof replay journal: %w", err)
	}
	return nil
}

func hasUniqueCheckpointModelAlias(aliases []string, alias string) bool {
	count := 0
	for _, candidate := range aliases {
		if candidate == alias {
			count++
		}
	}
	return count == 1
}

type nodeConnection struct {
	conn       *websocket.Conn
	nodeID     string
	generation uint64
	writeInit  sync.Once
	writeGate  chan struct{}
	done       chan struct{}
	closeOnce  sync.Once
	// writeHook is nil in production. Tests may inject a blocking transport
	// boundary while still exercising the real gate/Close lifecycle.
	writeHook func(context.Context, wsproto.Envelope) error
	// writeStartHook only observes that the gate was acquired; the production
	// websocket transport remains responsible for the actual I/O.
	writeStartHook func()
}

func (connection *nodeConnection) write(ctx context.Context, envelope wsproto.Envelope) error {
	connection.writeInit.Do(func() {
		connection.writeGate = make(chan struct{}, 1)
		connection.writeGate <- struct{}{}
		if connection.done == nil {
			connection.done = make(chan struct{})
		}
	})
	if connection.conn == nil {
		return fmt.Errorf("node websocket is unavailable")
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-connection.done:
		return fmt.Errorf("node websocket is closed")
	case <-connection.writeGate:
	}
	defer func() { connection.writeGate <- struct{}{} }()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-connection.done:
		return fmt.Errorf("node websocket is closed")
	default:
	}
	if connection.writeStartHook != nil {
		connection.writeStartHook()
	}
	if connection.writeHook != nil {
		return connection.writeHook(ctx, envelope)
	}
	return wsjson.Write(ctx, connection.conn, envelope)
}

func (connection *nodeConnection) close() {
	if connection == nil {
		return
	}
	connection.writeInit.Do(func() {
		connection.writeGate = make(chan struct{}, 1)
		connection.writeGate <- struct{}{}
		if connection.done == nil {
			connection.done = make(chan struct{})
		}
	})
	connection.closeOnce.Do(func() {
		close(connection.done)
		if connection.conn != nil {
			connection.conn.CloseNow()
		}
	})
}

func (s *Server) isCurrentNodeConnection(nodeID string, connection *nodeConnection) bool {
	if connection == nil || nodeID == "" {
		return false
	}
	s.nodeConnMu.RLock()
	current := s.nodeConnections[nodeID]
	ok := current == connection && current.generation == connection.generation
	s.nodeConnMu.RUnlock()
	return ok
}

func (s *Server) writeCurrentNodeConnection(ctx context.Context, nodeID string, connection *nodeConnection, envelope wsproto.Envelope) error {
	if s.isConnectionsClosed() {
		return fmt.Errorf("server is closed")
	}
	s.nodeConnMu.RLock()
	current := s.nodeConnections[nodeID]
	generation := uint64(0)
	if current == connection && connection != nil {
		generation = connection.generation
	}
	s.nodeConnMu.RUnlock()
	if connection == nil || current != connection || generation == 0 {
		return fmt.Errorf("node session superseded")
	}
	// Bound both time spent waiting for the per-connection writer gate and the
	// socket write itself.  A caller's long-lived context must not turn a
	// stalled peer into an unbounded controller operation.
	writeDeadline := time.Now().Add(5 * time.Second)
	if deadline, ok := ctx.Deadline(); ok && deadline.Before(writeDeadline) {
		writeDeadline = deadline
	}
	writeCtx, cancel := context.WithDeadline(ctx, writeDeadline)
	err := connection.write(writeCtx, envelope)
	cancel()
	if err != nil {
		return err
	}
	if !s.isCurrentNodeConnection(nodeID, connection) {
		return fmt.Errorf("node session superseded during write")
	}
	return nil
}

// withCurrentNodeSession serializes validation and mutation with session
// replacement without holding nodeConnMu across store/recovery work. This
// establishes one lock order and prevents reentrant registry reads.
func (s *Server) withCurrentNodeSession(nodeID string, connection *nodeConnection, fn func()) bool {
	s.sessionMutationMu.Lock()
	defer s.sessionMutationMu.Unlock()
	if s.isConnectionsClosed() {
		return false
	}
	if !s.isCurrentNodeConnection(nodeID, connection) {
		return false
	}
	fn()
	return true
}

// trackNodeConnection runs before the register frame is read. A node can be
// connected, but not yet present in nodeConnections, and must still be closed
// and waited by Server.Close.
func (s *Server) trackNodeConnection(connection *nodeConnection) bool {
	s.connectionLifecycleMu.Lock()
	defer s.connectionLifecycleMu.Unlock()
	if s.connectionsClosed {
		return false
	}
	s.activeConnections[connection] = struct{}{}
	s.connectionWG.Add(1)
	return true
}

func (s *Server) releaseNodeConnection(connection *nodeConnection) {
	s.connectionLifecycleMu.Lock()
	if _, tracked := s.activeConnections[connection]; tracked {
		delete(s.activeConnections, connection)
		s.connectionWG.Done()
	}
	s.connectionLifecycleMu.Unlock()
}

func (s *Server) isConnectionsClosed() bool {
	s.connectionLifecycleMu.Lock()
	closed := s.connectionsClosed
	s.connectionLifecycleMu.Unlock()
	return closed
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
	nodetransport.ApplyControlMessageLimit(conn)
	defer conn.CloseNow()
	connection := &nodeConnection{conn: conn, generation: s.nodeSessionSeq.Add(1), done: make(chan struct{})}
	if !s.trackNodeConnection(connection) {
		conn.CloseNow()
		return
	}
	defer s.releaseNodeConnection(connection)

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
	// Bind the authenticated node principal before consuming any durable proof
	// nonce/high-water. Otherwise a valid command credential could submit a
	// proof under another node ID and poison that target's replay journal even
	// though registration would be rejected below.
	if principal, authenticated := s.authenticate(r); authenticated && principal.ID != "legacy" {
		if principal.Plane != "node" || !hasScope(principal, "node:connect") || (principal.NodeID != "" && principal.NodeID != reg.NodeID) {
			_ = conn.Close(websocket.StatusPolicyViolation, "credential is not authorized for this node")
			return
		}
	}
	registrationPlan, err := buildRegistrationPlan(reg)
	if err != nil {
		s.log.Warn("ws: invalid register capability contract", "err", err)
		_ = conn.Close(websocket.StatusPolicyViolation, "invalid capability contract")
		return
	}
	reg = registrationPlan.reg
	// Validate target-scoped checkpoint evidence before persisting the node or
	// applying any adapter target. Otherwise an invalid proof can transiently
	// enable a target during initial registration. The registration itself
	// consumes the nonce for this authenticated session; a later capabilities
	// heartbeat is idempotent for the same session.
	for i := range reg.Adapters {
		if err := s.validateCheckpointAdvertisementProofSession(reg.NodeID, reg.Adapters[i], true, fmt.Sprintf("%s:%d", reg.NodeID, connection.generation)); err != nil {
			reg.Adapters[i].CheckpointProof = checkpointRuntime.CheckpointCapabilityProof{}
			reg.Adapters[i].Capabilities.SupportsSessionCheckpoint = false
			reg.Adapters[i].Capabilities.SessionCheckpointVerified = false
			reg.Adapters[i].Capabilities.SessionCheckpointProof = ""
		}
	}
	registrationPlan.reg = reg
	if principal, authenticated := s.authenticate(r); authenticated && principal.ID != "legacy" {
		if principal.Plane != "node" || !hasScope(principal, "node:connect") || (principal.NodeID != "" && principal.NodeID != reg.NodeID) {
			_ = conn.Close(websocket.StatusPolicyViolation, "credential is not authorized for this node")
			return
		}
	}
	if s.isConnectionsClosed() {
		conn.CloseNow()
		return
	}

	s.sessionMutationMu.Lock()
	if s.isConnectionsClosed() {
		s.sessionMutationMu.Unlock()
		conn.CloseNow()
		return
	}
	s.nodeConnMu.Lock()
	connection.nodeID = reg.NodeID
	oldConnection := s.nodeConnections[reg.NodeID]
	if oldConnection != nil && oldConnection.generation > connection.generation {
		s.nodeConnMu.Unlock()
		s.sessionMutationMu.Unlock()
		connection.close()
		return
	}
	s.nodeConnections[reg.NodeID] = connection
	// Keep the session-mutation lease through registration persistence so a
	// delayed lower-generation handler cannot publish node/target state after a
	// newer session is arbitrated.
	s.nodeConnMu.Unlock()
	node, registerErr := s.registerNodeWithPlan(ctx, registrationPlan)
	if registerErr != nil {
		s.nodeConnMu.Lock()
		if s.nodeConnections[reg.NodeID] == connection {
			delete(s.nodeConnections, reg.NodeID)
		}
		s.nodeConnMu.Unlock()
		s.sessionMutationMu.Unlock()
		s.log.Error("ws: node registration persistence failed", "node_id", reg.NodeID, "err", "registration unavailable")
		_ = conn.Close(websocket.StatusInternalError, "registration unavailable")
		return
	}
	if s.workloads != nil {
		s.workloads.SetManagedGPUPerformance(reg.NodeID, reg.GPUPerformanceIndices)
		s.workloads.NotifyResidencyRecovery()
	}
	s.sessionMutationMu.Unlock()
	if oldConnection != nil && oldConnection != connection {
		// A node reconnect supersedes the prior session before any recovery
		// dispatch. Durable command revision/uncertainty CAS rejects any late
		// result that old session may still race into the store.
		oldConnection.close()
	}
	var targetErr error
	if !s.withCurrentNodeSession(reg.NodeID, connection, func() {
		targetErr = s.applyRegistrationTargets(registrationPlan, node)
	}) {
		return
	}
	if targetErr != nil {
		s.log.Warn("ws: node capacity observations rejected", "node_id", reg.NodeID, "err", targetErr)
		_ = conn.Close(websocket.StatusPolicyViolation, "invalid model capacity observation")
		return
	}
	if s.checkpointRecovery != nil {
		go func(reconcile func() error) {
			backoff := 100 * time.Millisecond
			for attempt := 0; attempt < 5; attempt++ {
				if err := reconcile(); err == nil {
					return
				}
				time.Sleep(backoff)
				backoff *= 2
			}
		}(s.checkpointRecovery)
	}
	defer func() {
		s.nodeConnMu.Lock()
		if s.nodeConnections[reg.NodeID] == connection {
			delete(s.nodeConnections, reg.NodeID)
			if s.workloads != nil {
				s.workloads.SetManagedGPUPerformance(reg.NodeID, nil)
			}
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
			if s.isCurrentNodeConnection(reg.NodeID, connection) {
				s.log.Info("node disconnected", "node_id", reg.NodeID, "err", err)
			}
			return
		}
		if !s.isCurrentNodeConnection(reg.NodeID, connection) {
			return
		}
		switch env.Type {
		case wsproto.MsgHeartbeat:
			var hb wsproto.HeartbeatPayload
			if err := json.Unmarshal(env.Payload, &hb); err != nil {
				s.log.Warn("ws: bad heartbeat payload", "node_id", reg.NodeID, "err", err)
				continue
			}
			var heartbeatErr error
			if !s.withCurrentNodeSession(reg.NodeID, connection, func() {
				heartbeatErr = s.handleHeartbeat(ctx, reg.NodeID, hb)
			}) {
				return
			}
			if heartbeatErr != nil {
				s.log.Error("ws: heartbeat persistence failed", "node_id", reg.NodeID, "err", "observed state unavailable")
				_ = conn.Close(websocket.StatusInternalError, "heartbeat persistence unavailable")
				return
			}
			if err := s.sendAck(ctx, connection, true, ""); err != nil {
				return
			}

		case wsproto.MsgTelemetry:
			var tel wsproto.TelemetryPayload
			if err := json.Unmarshal(env.Payload, &tel); err != nil {
				s.log.Warn("ws: bad telemetry payload", "node_id", reg.NodeID, "err", err)
				continue
			}
			if !s.withCurrentNodeSession(reg.NodeID, connection, func() {
				s.handleTelemetry(ctx, reg.NodeID, tel)
			}) {
				return
			}
			_ = s.sendAck(ctx, connection, true, "")

		case wsproto.MsgCapabilities:
			var capabilities wsproto.CapabilitiesPayload
			if err := json.Unmarshal(env.Payload, &capabilities); err != nil || capabilities.NodeID != reg.NodeID {
				s.log.Warn("ws: bad capabilities payload", "node_id", reg.NodeID, "err", err)
				continue
			}
			for i := range capabilities.Adapters {
				advertised := capabilities.Adapters[i]
				if err := s.validateCheckpointAdvertisementProofSession(reg.NodeID, advertised, true, fmt.Sprintf("%s:%d", reg.NodeID, connection.generation)); err != nil {
					s.log.Warn("ws: checkpoint proof rejected", "node_id", reg.NodeID, "target_id", advertised.ID, "err", err)
					// Revoke only this target. Other adapters in the same refresh
					// remain eligible when their independently bound proof is valid.
					capabilities.Adapters[i].CheckpointProof = checkpointRuntime.CheckpointCapabilityProof{}
					capabilities.Adapters[i].Capabilities.SupportsSessionCheckpoint = false
					capabilities.Adapters[i].Capabilities.SessionCheckpointVerified = false
					capabilities.Adapters[i].Capabilities.SessionCheckpointProof = ""
				}
			}
			var refreshErr error
			if !s.withCurrentNodeSession(reg.NodeID, connection, func() {
				storedNode, _ := s.nodes.GetNode(ctx, reg.NodeID)
				var refreshVersion string
				var refreshCapabilities domain.ResidencyCapabilities
				var refreshCapacity domain.CapacityBudget
				var normalizedMax int
				refreshVersion, refreshCapabilities, refreshCapacity, normalizedMax, refreshErr = mergeNodeCapabilityRefresh(storedNode, capabilities)
				if refreshErr == nil {
					_, refreshErr = buildAdapterPlans(reg.NodeID, capabilities.Adapters, refreshVersion, refreshCapabilities, refreshCapacity, normalizedMax)
				}
				if refreshErr == nil && storedNode != nil {
					storedNode.CapabilityVersion = refreshVersion
					storedNode.Capabilities = refreshCapabilities
					storedNode.Capacity = refreshCapacity
					storedNode.MaxAcceleratorsPerWorkload = normalizedMax
					_, refreshErr = s.nodes.UpsertNode(ctx, storedNode)
				}
				if refreshErr == nil {
					refreshErr = s.registerAdapterAdvertisementsWithDefaults(reg.NodeID, capabilities.Adapters, refreshVersion, refreshCapabilities, refreshCapacity, normalizedMax)
				}
			}) {
				return
			}
			if refreshErr != nil {
				s.log.Warn("ws: capability refresh failed", "node_id", reg.NodeID, "err", refreshErr)
				continue
			}
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
			if !s.withCurrentNodeSession(reg.NodeID, connection, func() {
				s.handleNodeCommandResult(ctx, result)
			}) {
				return
			}

		default:
			s.log.Warn("ws: unknown message type", "type", env.Type, "node_id", reg.NodeID)
		}
	}
}

func normalizeAuthoritativeNodeRefresh(incoming wsproto.CapabilitiesPayload) (string, domain.ResidencyCapabilities, domain.CapacityBudget, int, error) {
	version := incoming.CapabilityVersion
	if version == "" {
		version = domain.CapabilityContractVersion
	}
	capabilities := incoming.Capabilities
	if capabilities.Version == "" {
		capabilities.Version = version
	}
	normalizedMax, err := validateNodeCapabilityEnvelope(version, capabilities, incoming.Capacity, incoming.MaxAcceleratorsPerWorkload)
	if err != nil {
		return "", domain.ResidencyCapabilities{}, domain.CapacityBudget{}, 0, err
	}
	capabilities.MaxAcceleratorsPerWorkload = normalizedMax
	return version, capabilities, incoming.Capacity, normalizedMax, nil
}

func (s *Server) registerAdapterAdvertisements(nodeID string, advertisements []wsproto.AdapterAdvertisement) {
	version := ""
	capabilities := domain.ResidencyCapabilities{}
	capacity := domain.CapacityBudget{}
	maxAccelerators := 0
	if node, err := s.nodes.GetNode(context.Background(), nodeID); err == nil {
		version = node.CapabilityVersion
		capabilities = node.Capabilities
		capacity = node.Capacity
		maxAccelerators = node.MaxAcceleratorsPerWorkload
	}
	if err := s.registerAdapterAdvertisementsWithDefaults(nodeID, advertisements, version, capabilities, capacity, maxAccelerators); err != nil {
		s.log.Warn("ws: rejecting adapter capability refresh", "node_id", nodeID, "err", err)
	}
}

func (s *Server) registerAdapterAdvertisementsWithDefaults(nodeID string, advertisements []wsproto.AdapterAdvertisement, defaultVersion string, defaultCapabilities domain.ResidencyCapabilities, defaultCapacity domain.CapacityBudget, defaultMaxAccelerators int) error {
	if s.workloads == nil {
		return nil
	}
	plans, err := buildAdapterPlans(nodeID, advertisements, defaultVersion, defaultCapabilities, defaultCapacity, defaultMaxAccelerators)
	if err != nil {
		return err
	}
	node, err := s.nodes.GetNode(context.Background(), nodeID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	return s.applyAdapterPlans(nodeID, plans, node)
}

type registrationAdapterPlan struct {
	advertised         wsproto.AdapterAdvertisement
	capabilityRevision string
	capabilities       domain.ResidencyCapabilities
	maxAccelerators    int
	runtimeIdentity    string
}

type registrationPlan struct {
	reg               wsproto.RegisterPayload
	capabilityVersion string
	capabilities      domain.ResidencyCapabilities
	capacity          domain.CapacityBudget
	maxAccelerators   int
	adapters          []registrationAdapterPlan
}

func buildRegistrationPlan(reg wsproto.RegisterPayload) (*registrationPlan, error) {
	maxAccelerators, err := validateNodeCapabilityEnvelope(reg.CapabilityVersion, reg.Capabilities, reg.Capacity, reg.MaxAcceleratorsPerWorkload)
	if err != nil {
		return nil, err
	}
	version := reg.CapabilityVersion
	if version == "" {
		version = domain.CapabilityContractVersion
	}
	capabilities := reg.Capabilities
	if capabilities.Version == "" {
		capabilities.Version = version
	}
	if capabilities.MaxAcceleratorsPerWorkload == 0 {
		capabilities.MaxAcceleratorsPerWorkload = maxAccelerators
	}
	adapters, err := buildAdapterPlans(reg.NodeID, reg.Adapters, version, capabilities, reg.Capacity, maxAccelerators)
	if err != nil {
		return nil, err
	}
	reg.CapabilityVersion = version
	reg.Capabilities = capabilities
	reg.MaxAcceleratorsPerWorkload = maxAccelerators
	return &registrationPlan{reg: reg, capabilityVersion: version, capabilities: capabilities, capacity: reg.Capacity, maxAccelerators: maxAccelerators, adapters: adapters}, nil
}

func buildAdapterPlans(nodeID string, advertisements []wsproto.AdapterAdvertisement, defaultVersion string, defaultCapabilities domain.ResidencyCapabilities, defaultCapacity domain.CapacityBudget, defaultMaxAccelerators int) ([]registrationAdapterPlan, error) {
	if defaultVersion == "" {
		defaultVersion = domain.CapabilityContractVersion
	}
	if defaultCapabilities.Version == "" {
		defaultCapabilities.Version = defaultVersion
	}
	if defaultMaxAccelerators == 0 {
		defaultMaxAccelerators = 1
	}
	if defaultCapabilities.MaxAcceleratorsPerWorkload == 0 {
		defaultCapabilities.MaxAcceleratorsPerWorkload = defaultMaxAccelerators
	}
	plans := make([]registrationAdapterPlan, 0, len(advertisements))
	for _, advertised := range advertisements {
		if advertised.ID == "" || advertised.Adapter == "" || advertised.Endpoint == "" {
			return nil, fmt.Errorf("adapter %q is missing id, adapter, or endpoint", advertised.ID)
		}
		if err := advertised.Capacity.Validate(); err != nil {
			return nil, fmt.Errorf("adapter %q capacity: %w", advertised.ID, err)
		}
		if err := domain.ValidateCapacityOverride(defaultCapacity, advertised.Capacity); err != nil {
			return nil, fmt.Errorf("adapter %q capacity: %w", advertised.ID, err)
		}
		for profileIndex, profile := range advertised.RuntimeProfiles {
			if strings.TrimSpace(profile.ID) == "" || profile.ContextLimit <= 0 || profile.Slots <= 0 {
				return nil, fmt.Errorf("adapter %q runtime profile %d is invalid", advertised.ID, profileIndex)
			}
		}
		targetDocumentComplete := adapterCapabilitiesDocumentComplete(advertised)
		normalized := mergeAdapterDefaults(advertised, defaultVersion, defaultCapabilities, defaultCapacity, defaultMaxAccelerators)
		capabilityRevision, capabilities, maxAccelerators, runtimeIdentity, err := normalizeAdapterCapabilitiesWithSource(normalized, defaultCapabilities, targetDocumentComplete)
		if err != nil {
			return nil, fmt.Errorf("adapter %q capability contract: %w", advertised.ID, err)
		}
		if err := validateModelCapacityObservations(nodeID, normalized, runtimeIdentity, capabilityRevision); err != nil {
			return nil, fmt.Errorf("adapter %q model capacity observations: %w", advertised.ID, err)
		}
		plans = append(plans, registrationAdapterPlan{advertised: cloneAdapterAdvertisement(normalized), capabilityRevision: capabilityRevision, capabilities: capabilities, maxAccelerators: maxAccelerators, runtimeIdentity: runtimeIdentity})
	}
	return plans, nil
}

func cloneAdapterAdvertisement(advertised wsproto.AdapterAdvertisement) wsproto.AdapterAdvertisement {
	advertised.Models = append([]string(nil), advertised.Models...)
	advertised.ResidentModels = append([]string(nil), advertised.ResidentModels...)
	advertised.CustomNodes = append([]string(nil), advertised.CustomNodes...)
	advertised.RuntimeArgs = append([]string(nil), advertised.RuntimeArgs...)
	advertised.RuntimeProfiles = append([]wsproto.RuntimeProfileAdvertisement(nil), advertised.RuntimeProfiles...)
	advertised.ModelCapacityObservations = append([]wsproto.ModelCapacityObservationAdvertisement(nil), advertised.ModelCapacityObservations...)
	return advertised
}

func validateModelCapacityObservations(nodeID string, advertised wsproto.AdapterAdvertisement, runtimeIdentity, capabilityRevision string) error {
	if len(advertised.ModelCapacityObservations) == 0 {
		return nil
	}
	if len(advertised.ModelCapacityObservations) != 1 {
		return fmt.Errorf("exactly one authoritative model capacity observation is required per target")
	}
	targetID := advertised.ID
	if !strings.HasPrefix(targetID, nodeID+"-") {
		targetID = nodeID + "-" + targetID
	}
	acceleratorID := fmt.Sprintf("%s-gpu%d", nodeID, advertised.AcceleratorIndex)
	expectedRuntime := strings.Join([]string{targetID, advertised.Adapter, "", runtimeIdentity, advertised.ModelFingerprint}, "|")
	now := time.Now().UTC()
	seen := make(map[string]struct{}, len(advertised.ModelCapacityObservations))
	for _, observation := range advertised.ModelCapacityObservations {
		if !observation.Verified || observation.Source != "runtime:/api/ps:size_vram" || observation.AcceleratorID != acceleratorID || observation.Model == "" || !containsString(advertised.Models, observation.Model) || !containsString(advertised.ResidentModels, observation.Model) {
			return fmt.Errorf("observation for %q is incomplete or not attributable to the advertised loaded model", observation.Model)
		}
		if observation.ProfileID != advertised.ActiveRuntimeProfile || observation.ModelFingerprint == "" || observation.ModelFingerprint != advertised.ModelFingerprint || observation.RuntimeIdentity != expectedRuntime || observation.CapabilityVersion != runtimeIdentity || observation.CapabilityRevision != capabilityRevision {
			return fmt.Errorf("observation for %q has mismatched runtime/profile identity", observation.Model)
		}
		if observation.ModelBytes <= 0 || observation.ModelBytes > math.MaxInt64-observation.ProfileBytes || observation.ProfileBytes < 0 || observation.VRAMReserveBytes < 0 || observation.RuntimeHardCapBytes < 0 || observation.RAMBytes < 0 || observation.RAMReserveBytes < 0 || observation.VRAMTotalBytes < 0 || observation.RAMTotalBytes < 0 {
			return fmt.Errorf("observation for %q has invalid byte measurements", observation.Model)
		}
		if observation.ObservedAt.IsZero() || now.Sub(observation.ObservedAt) > 24*time.Hour || observation.ObservedAt.After(now.Add(5*time.Minute)) {
			return fmt.Errorf("observation for %q is stale", observation.Model)
		}
		key := observation.Model + "\x00" + observation.ProfileID
		if _, exists := seen[key]; exists {
			return fmt.Errorf("duplicate observation for %q profile %q", observation.Model, observation.ProfileID)
		}
		seen[key] = struct{}{}
	}
	return nil
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func (s *Server) applyRegistrationTargets(plan *registrationPlan, node *domain.Node) error {
	if s.workloads == nil || plan == nil || node == nil {
		return nil
	}
	return s.applyAdapterPlans(plan.reg.NodeID, plan.adapters, node)
}

func (s *Server) applyAdapterPlans(nodeID string, plans []registrationAdapterPlan, node *domain.Node) error {
	if s.workloads == nil {
		return nil
	}
	registered := make(map[string]struct{}, len(plans))
	for _, plan := range plans {
		advertised := plan.advertised
		targetID := advertised.ID
		if !strings.HasPrefix(targetID, nodeID+"-") {
			targetID = nodeID + "-" + targetID
		}
		registered[targetID] = struct{}{}
		acceleratorID := fmt.Sprintf("%s-gpu%d", nodeID, advertised.AcceleratorIndex)
		var acceleratorVRAMMB int64
		if node != nil {
			for _, accelerator := range node.Accelerators {
				if accelerator.ID == acceleratorID {
					acceleratorVRAMMB = accelerator.VRAMTotalMB
					break
				}
			}
		}
		target := workloads.Target{
			ID: targetID, NodeID: nodeID, Adapter: advertised.Adapter, Endpoint: advertised.Endpoint,
			AcceleratorID: acceleratorID, AcceleratorVRAMMB: acceleratorVRAMMB,
			Models: advertised.Models, ResidentModels: advertised.ResidentModels, CustomNodes: advertised.CustomNodes,
			ModelPools:   advertisedModelPools(advertised.ModelPools),
			ContextLimit: advertised.ContextLimit, Slots: advertised.Slots, CapabilityGeneration: advertised.CapabilityGeneration,
			CapabilityVersion: plan.runtimeIdentity, RuntimeIdentity: plan.runtimeIdentity, CapabilityRevision: plan.capabilityRevision, Capabilities: plan.capabilities, Capacity: advertised.Capacity, MaxAcceleratorsPerWorkload: plan.maxAccelerators, ModelFingerprint: advertised.ModelFingerprint,
			CapacitySource: advertised.CapacitySource, CapacityVerified: advertised.CapabilitiesVerified,
			RuntimeArgs: advertised.RuntimeArgs, SupportsModelLifecycle: plan.capabilities.SupportsModelLifecycle, SupportsAcceleratorReclaim: plan.capabilities.SupportsAcceleratorReclaim,
			MaxResidentModels: plan.capabilities.MaxResidentModels, WarmRAMSupported: plan.capabilities.SupportsWarmRAM,
			QueueRunning: advertised.QueueRunning, QueuePending: advertised.QueuePending,
			StandaloneVRAMMB: advertised.StandaloneVRAMMB, StandaloneVRAMSource: advertised.StandaloneVRAMSource, StandaloneVRAMVerified: advertised.StandaloneVRAMVerified,
			ResidencyPolicy: domain.ResidencyAuto, Enabled: true,
			RuntimeProfiles: runtimeCapacityProfiles(advertised.RuntimeProfiles), ActiveRuntimeProfile: advertised.ActiveRuntimeProfile, SupportsRuntimeProfileSwitch: advertised.SupportsRuntimeProfileSwitch,
			CheckpointProof: advertised.CheckpointProof,
		}
		s.workloads.RegisterTarget(target)
		for _, observation := range advertised.ModelCapacityObservations {
			capacity := store.ModelCapacity{
				TargetID: targetID, AcceleratorID: observation.AcceleratorID, Model: observation.Model, ProfileID: observation.ProfileID,
				ModelFingerprint: observation.ModelFingerprint, RuntimeIdentity: observation.RuntimeIdentity,
				CapabilityVersion: observation.CapabilityVersion, CapabilityRevision: observation.CapabilityRevision,
				ModelBytes: observation.ModelBytes, ProfileBytes: observation.ProfileBytes, VRAMReserveBytes: observation.VRAMReserveBytes,
				RuntimeHardCapBytes: observation.RuntimeHardCapBytes, RAMBytes: observation.RAMBytes, RAMReserveBytes: observation.RAMReserveBytes,
				VRAMTotalBytes: observation.VRAMTotalBytes, RAMTotalBytes: observation.RAMTotalBytes, UnifiedMemory: observation.UnifiedMemory,
				CapacitySource: observation.Source, Verified: observation.Verified, ObservedAt: observation.ObservedAt, UpdatedAt: observation.ObservedAt,
			}
			if capacity.VRAMTotalBytes == 0 && capacity.RAMTotalBytes == 0 {
				capacity.VRAMTotalBytes = target.Capacity.VRAMTotalBytes
				capacity.RAMTotalBytes = target.Capacity.RAMTotalBytes
				capacity.UnifiedMemory = capacity.VRAMTotalBytes <= 0 && capacity.RAMTotalBytes > 0
			}
			if capacity.VRAMReserveBytes == 0 && capacity.RAMReserveBytes == 0 {
				capacity.VRAMReserveBytes = target.Capacity.VRAMReserveBytes
				capacity.RAMReserveBytes = target.Capacity.RAMReserveBytes
			}
			if capacity.RuntimeHardCapBytes == 0 {
				capacity.RuntimeHardCapBytes = target.Capacity.VRAMHardCapBytes
				if capacity.RuntimeHardCapBytes == 0 {
					capacity.RuntimeHardCapBytes = target.Capacity.RAMHardCapBytes
				}
			}
			if _, err := s.workloads.SetModelCapacity(context.Background(), capacity); err != nil {
				return fmt.Errorf("persist model capacity for %s/%s: %w", target.ID, observation.Model, err)
			}
		}
	}
	s.workloads.ReconcileNodeTargets(nodeID, registered)
	return nil
}

func validateNodeCapabilityEnvelope(version string, capabilities domain.ResidencyCapabilities, capacity domain.CapacityBudget, maxAccelerators int) (int, error) {
	if version == "" {
		version = domain.CapabilityContractVersion
	}
	if err := domain.ValidateCapabilityVersion(version); err != nil {
		return 0, err
	}
	normalizedMax, err := validatePlacementCeiling(maxAccelerators, capabilities.MaxAcceleratorsPerWorkload)
	if err != nil {
		return 0, err
	}
	if capabilities.Version == "" {
		capabilities.Version = version
	}
	if capabilities.Version != version {
		return 0, fmt.Errorf("capability version %q does not match capabilities version %q", version, capabilities.Version)
	}
	if err := capabilities.Validate(); err != nil {
		return 0, err
	}
	if err := capacity.Validate(); err != nil {
		return 0, err
	}
	return normalizedMax, nil
}

// validateRegisterPayloadEnvelope validates the complete registration before
// any node, incident, or target state is touched. Adapter advertisements are
// one atomic contract: a malformed nested adapter/profile rejects the whole
// registration instead of being silently skipped during target projection.
func validateRegisterPayloadEnvelope(reg wsproto.RegisterPayload) (int, error) {
	plan, err := buildRegistrationPlan(reg)
	if err != nil {
		return 0, err
	}
	return plan.maxAccelerators, nil
}

// mergeNodeCapabilityRefresh treats the registered node envelope as the
// authoritative default when a legacy refresh sends adapters only. Partial
// refreshes may narrow capacity or placement, but may not erase or raise the
// stored node protections.
func mergeNodeCapabilityRefresh(stored *domain.Node, incoming wsproto.CapabilitiesPayload) (string, domain.ResidencyCapabilities, domain.CapacityBudget, int, error) {
	version := domain.CapabilityContractVersion
	baseCapabilities := domain.ResidencyCapabilities{Version: version}
	baseCapacity := domain.CapacityBudget{}
	inheritedMax := 1
	if stored != nil {
		if stored.CapabilityVersion != "" {
			version = stored.CapabilityVersion
		}
		baseCapabilities = stored.Capabilities
		if baseCapabilities.Version == "" {
			baseCapabilities.Version = version
		}
		baseCapacity = stored.Capacity
		if stored.MaxAcceleratorsPerWorkload > 0 {
			inheritedMax = stored.MaxAcceleratorsPerWorkload
		} else if baseCapabilities.MaxAcceleratorsPerWorkload > 0 {
			inheritedMax = baseCapabilities.MaxAcceleratorsPerWorkload
		}
	}
	versionPresent := incoming.CapabilityVersionPresent || incoming.CapabilityVersion != ""
	capabilitiesPresent := incoming.CapabilitiesPresent || incoming.Capabilities != (domain.ResidencyCapabilities{})
	capacityPresent := incoming.CapacityPresent || incoming.Capacity != (domain.CapacityBudget{})
	maxPresent := incoming.MaxAcceleratorsPerWorkloadPresent || incoming.MaxAcceleratorsPerWorkload != 0
	if versionPresent {
		version = incoming.CapabilityVersion
	}
	if capacityPresent {
		if err := incoming.Capacity.Validate(); err != nil {
			return "", domain.ResidencyCapabilities{}, domain.CapacityBudget{}, 0, err
		}
	}
	if err := domain.ValidateCapabilityVersion(version); err != nil {
		return "", domain.ResidencyCapabilities{}, domain.CapacityBudget{}, 0, err
	}
	capabilities := baseCapabilities
	if capabilitiesPresent {
		capabilities = incoming.Capabilities
		if capabilities.Version == "" {
			capabilities.Version = version
		}
	} else {
		if capabilities.Version == "" {
			capabilities.Version = version
		}
		if versionPresent {
			capabilities.Version = version
		}
	}
	if err := capabilities.Validate(); err != nil {
		return "", domain.ResidencyCapabilities{}, domain.CapacityBudget{}, 0, err
	}
	nestedMax := 0
	if capabilitiesPresent {
		nestedMax = incoming.Capabilities.MaxAcceleratorsPerWorkload
	}
	if incoming.MaxAcceleratorsPerWorkload < 0 || nestedMax < 0 {
		return "", domain.ResidencyCapabilities{}, domain.CapacityBudget{}, 0, fmt.Errorf("max_accelerators_per_workload may not be negative")
	}
	if incoming.MaxAcceleratorsPerWorkload > 0 && nestedMax > 0 && incoming.MaxAcceleratorsPerWorkload != nestedMax {
		return "", domain.ResidencyCapabilities{}, domain.CapacityBudget{}, 0, fmt.Errorf("max_accelerators_per_workload %d conflicts with nested capability ceiling %d", incoming.MaxAcceleratorsPerWorkload, nestedMax)
	}
	effectiveMax := 0
	if maxPresent {
		effectiveMax = incoming.MaxAcceleratorsPerWorkload
		if effectiveMax == 0 {
			effectiveMax = 1
		}
	}
	if effectiveMax == 0 && nestedMax > 0 {
		effectiveMax = nestedMax
	}
	if effectiveMax == 0 {
		effectiveMax = inheritedMax
	}
	capabilities.MaxAcceleratorsPerWorkload = effectiveMax
	capacity := baseCapacity
	if capacityPresent {
		capacity = mergeNodeCapacityBudget(baseCapacity, incoming.Capacity, incoming)
	}
	if _, err := validateNodeCapabilityEnvelope(version, capabilities, capacity, effectiveMax); err != nil {
		return "", domain.ResidencyCapabilities{}, domain.CapacityBudget{}, 0, err
	}
	return version, capabilities, capacity, effectiveMax, nil
}

// mergeNodeCapacityBudget applies a field-level refresh. Older node agents
// sent only the one capacity fact that changed; replacing the whole nested
// object would erase stored reserves and hard caps and could cause admission
// to overcommit. Explicit JSON zeroes remain updates when presence metadata is
// available, while direct in-process fixtures retain the legacy non-zero
// inference.
func mergeNodeCapacityBudget(base, incoming domain.CapacityBudget, payload wsproto.CapabilitiesPayload) domain.CapacityBudget {
	present := payload.CapacityFieldsPresent
	fieldPresent := func(name string, value int64) bool {
		if present != nil {
			return present[name]
		}
		return value != 0
	}
	if fieldPresent("vram_total_bytes", incoming.VRAMTotalBytes) {
		base.VRAMTotalBytes = incoming.VRAMTotalBytes
	}
	if fieldPresent("vram_reserve_bytes", incoming.VRAMReserveBytes) {
		base.VRAMReserveBytes = incoming.VRAMReserveBytes
	}
	if fieldPresent("vram_hard_cap_bytes", incoming.VRAMHardCapBytes) {
		base.VRAMHardCapBytes = incoming.VRAMHardCapBytes
	}
	if fieldPresent("ram_total_bytes", incoming.RAMTotalBytes) {
		base.RAMTotalBytes = incoming.RAMTotalBytes
	}
	if fieldPresent("ram_reserve_bytes", incoming.RAMReserveBytes) {
		base.RAMReserveBytes = incoming.RAMReserveBytes
	}
	if fieldPresent("ram_hard_cap_bytes", incoming.RAMHardCapBytes) {
		base.RAMHardCapBytes = incoming.RAMHardCapBytes
	}
	if fieldPresent("disk_available_bytes", incoming.DiskAvailableBytes) {
		base.DiskAvailableBytes = incoming.DiskAvailableBytes
	}
	return base
}

func normalizeAdapterCapabilities(advertised wsproto.AdapterAdvertisement) (string, domain.ResidencyCapabilities, int, error) {
	revision, capabilities, maxAccelerators, _, err := normalizeAdapterCapabilitiesWithDefaultsAndIdentity(advertised, domain.ResidencyCapabilities{Version: domain.CapabilityContractVersion})
	return revision, capabilities, maxAccelerators, err
}

func normalizeAdapterCapabilitiesWithDefaults(advertised wsproto.AdapterAdvertisement, defaults domain.ResidencyCapabilities) (string, domain.ResidencyCapabilities, int, error) {
	revision, capabilities, maxAccelerators, _, err := normalizeAdapterCapabilitiesWithDefaultsAndIdentity(advertised, defaults)
	return revision, capabilities, maxAccelerators, err
}

func normalizeAdapterCapabilitiesWithDefaultsAndIdentity(advertised wsproto.AdapterAdvertisement, defaults domain.ResidencyCapabilities) (string, domain.ResidencyCapabilities, int, string, error) {
	return normalizeAdapterCapabilitiesWithSource(advertised, defaults, adapterCapabilitiesDocumentComplete(advertised))
}

func adapterCapabilitiesDocumentComplete(advertised wsproto.AdapterAdvertisement) bool {
	return strings.TrimSpace(advertised.CapabilityRevision) != "" ||
		advertised.Capabilities != (domain.ResidencyCapabilities{}) ||
		(strings.EqualFold(advertised.Adapter, "comfy") && strings.TrimSpace(advertised.Version) != "")
}

func normalizeAdapterCapabilitiesWithSource(advertised wsproto.AdapterAdvertisement, defaults domain.ResidencyCapabilities, targetDocumentComplete bool) (string, domain.ResidencyCapabilities, int, string, error) {
	if err := advertised.Capacity.Validate(); err != nil {
		return "", domain.ResidencyCapabilities{}, 0, "", err
	}
	runtimeIdentity := strings.TrimSpace(advertised.Version)
	legacyRuntimeIdentity := strings.TrimSpace(advertised.CapabilityVersion)
	revision := advertised.CapabilityRevision
	if revision == "" {
		// CapabilityVersion equal to the contract version is a schema marker,
		// not a runtime identity. Other values remain legacy runtime aliases.
		if advertised.CapabilityVersion == domain.CapabilityContractVersion {
			revision = advertised.CapabilityVersion
		} else if advertised.Capabilities.Version != "" {
			revision = advertised.Capabilities.Version
		} else {
			revision = domain.CapabilityContractVersion
		}
	}
	if legacyRuntimeIdentity == domain.CapabilityContractVersion && (advertised.CapabilityRevision == "" || advertised.CapabilityRevision == domain.CapabilityContractVersion) {
		legacyRuntimeIdentity = ""
	}
	if runtimeIdentity != "" && legacyRuntimeIdentity != "" && runtimeIdentity != legacyRuntimeIdentity {
		return "", domain.ResidencyCapabilities{}, 0, "", fmt.Errorf("adapter runtime identity %q conflicts with capability_version %q", runtimeIdentity, legacyRuntimeIdentity)
	}
	if runtimeIdentity == "" {
		runtimeIdentity = legacyRuntimeIdentity
	}
	if err := domain.ValidateCapabilityVersion(revision); err != nil {
		return "", domain.ResidencyCapabilities{}, 0, runtimeIdentity, err
	}
	overlay := advertised.Capabilities
	if overlay.Version != "" && overlay.Version != revision {
		return "", domain.ResidencyCapabilities{}, 0, runtimeIdentity, fmt.Errorf("capabilities version %q does not match capability revision %q", overlay.Version, revision)
	}
	if defaults.Version == "" {
		defaults.Version = revision
	}
	if defaults.Version != revision {
		return "", domain.ResidencyCapabilities{}, 0, runtimeIdentity, fmt.Errorf("default capabilities version %q does not match capability revision %q", defaults.Version, revision)
	}
	// A discovered/runtime advertisement is a complete target document. Its
	// false booleans are authoritative: node-level defaults may fill a legacy
	// envelope with no target identity, but must never turn a verified native
	// ComfyUI false into a reclaim promise (or similarly widen another target
	// capability). Keep non-boolean inherited ceilings intact.
	if targetDocumentComplete {
		defaults.SupportsWarmRAM = false
		defaults.SupportsModelLifecycle = false
		defaults.SupportsAcceleratorReclaim = false
		defaults.SupportsYield = false
		defaults.SupportsSessionCheckpoint = false
		defaults.WarmRAMVerified = false
		defaults.WarmRAMVerification = ""
		defaults.YieldVerified = false
		defaults.YieldProof = ""
		defaults.SessionCheckpointVerified = false
		defaults.SessionCheckpointProof = ""
	}
	if overlay.Version == "" {
		overlay.Version = revision
	}
	aliases := domain.CapabilityAliases{
		SupportsModelLifecycle:     advertised.SupportsModelLifecycle,
		SupportsAcceleratorReclaim: advertised.SupportsAcceleratorReclaim,
		MaxResidentModels:          advertised.MaxResidentModels,
		WarmRAMSupported:           advertised.WarmRAMSupported,
	}
	capabilities, err := domain.MergeResidencyCapabilities(defaults, overlay, aliases)
	if err != nil {
		return "", domain.ResidencyCapabilities{}, 0, runtimeIdentity, err
	}
	nestedMax := overlay.MaxAcceleratorsPerWorkload
	if advertised.MaxAcceleratorsPerWorkload < 0 || nestedMax < 0 {
		return "", domain.ResidencyCapabilities{}, 0, runtimeIdentity, fmt.Errorf("max_accelerators_per_workload may not be negative")
	}
	if advertised.MaxAcceleratorsPerWorkload > 0 && nestedMax > 0 && advertised.MaxAcceleratorsPerWorkload != nestedMax {
		return "", domain.ResidencyCapabilities{}, 0, runtimeIdentity, fmt.Errorf("max_accelerators_per_workload %d conflicts with nested capability ceiling %d", advertised.MaxAcceleratorsPerWorkload, nestedMax)
	}
	maxAccelerators := advertised.MaxAcceleratorsPerWorkload
	if maxAccelerators == 0 {
		maxAccelerators = nestedMax
	}
	if maxAccelerators == 0 {
		maxAccelerators = defaults.MaxAcceleratorsPerWorkload
	}
	if maxAccelerators == 0 {
		maxAccelerators = 1
	}
	if defaults.MaxAcceleratorsPerWorkload > 0 && maxAccelerators > defaults.MaxAcceleratorsPerWorkload {
		return "", domain.ResidencyCapabilities{}, 0, runtimeIdentity, fmt.Errorf("max_accelerators_per_workload %d exceeds inherited ceiling %d", maxAccelerators, defaults.MaxAcceleratorsPerWorkload)
	}
	capabilities.MaxAcceleratorsPerWorkload = maxAccelerators
	capabilities.Version = revision
	if err := capabilities.Validate(); err != nil {
		return "", domain.ResidencyCapabilities{}, 0, runtimeIdentity, err
	}
	if err := advertised.Capacity.Validate(); err != nil {
		return "", domain.ResidencyCapabilities{}, 0, runtimeIdentity, err
	}
	return revision, capabilities, maxAccelerators, runtimeIdentity, nil
}

func validatePlacementCeiling(outer, nested int) (int, error) {
	return domain.NormalizeAcceleratorCeiling(outer, nested)
}

func mergeAdapterDefaults(advertised wsproto.AdapterAdvertisement, version string, capabilities domain.ResidencyCapabilities, capacity domain.CapacityBudget, maxAccelerators int) wsproto.AdapterAdvertisement {
	if advertised.CapabilityRevision == "" && advertised.Capabilities.Version == "" {
		advertised.CapabilityRevision = capabilities.Version
	}
	if advertised.Capabilities.Version == "" {
		advertised.Capabilities.Version = capabilities.Version
	}
	advertised.Capacity = domain.MergeCapacityBudget(capacity, advertised.Capacity)
	if advertised.MaxAcceleratorsPerWorkload == 0 && advertised.Capabilities.MaxAcceleratorsPerWorkload == 0 {
		advertised.MaxAcceleratorsPerWorkload = maxAccelerators
	}
	if advertised.CapabilityRevision == "" {
		advertised.CapabilityRevision = version
	}
	return advertised
}

func runtimeCapacityProfiles(values []wsproto.RuntimeProfileAdvertisement) []workloads.RuntimeCapacityProfile {
	profiles := make([]workloads.RuntimeCapacityProfile, 0, len(values))
	for _, value := range values {
		profiles = append(profiles, workloads.RuntimeCapacityProfile{ID: value.ID, ContextLimit: value.ContextLimit, Slots: value.Slots})
	}
	return profiles
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
	return s.writeCurrentNodeConnection(ctx, conn.nodeID, conn, ack)
}

func (s *Server) registerNode(ctx context.Context, reg wsproto.RegisterPayload) (*domain.Node, error) {
	plan, err := buildRegistrationPlan(reg)
	if err != nil {
		return nil, err
	}
	return s.registerNodeWithPlan(ctx, plan)
}

func (s *Server) registerNodeWithPlan(ctx context.Context, plan *registrationPlan) (*domain.Node, error) {
	reg := plan.reg
	now := time.Now().UTC()
	ready := true // legacy agents omitted readiness; preserve their prior behavior.
	if reg.Ready != nil {
		ready = *reg.Ready
	}
	capabilityVersion := reg.CapabilityVersion
	if capabilityVersion == "" {
		capabilityVersion = domain.CapabilityContractVersion
	}
	capabilities := reg.Capabilities
	if capabilities.Version == "" {
		capabilities.Version = capabilityVersion
	}
	maxAccelerators := plan.maxAccelerators
	previousConnectivity := domain.ConnectivityLost
	n := &domain.Node{
		ID:                         reg.NodeID,
		Name:                       reg.NodeName,
		CapabilityVersion:          capabilityVersion,
		Capabilities:               capabilities,
		Capacity:                   reg.Capacity,
		MaxAcceleratorsPerWorkload: maxAccelerators,
		LocationClass:              domain.LocationClass(reg.LocationClass),
		PriorityTier:               priorityFor(domain.LocationClass(reg.LocationClass)),
		SchedulingState:            domain.SchedulingEnabled,
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
			Ready:         ready,
			LastHeartbeat: now,
			LastSeenAt:    now,
			AgentVersion:  reg.AgentVersion,
		},
	}
	if !ready {
		n.Observed.Lifecycle = domain.LifecycleConnected
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
		return nil, errors.New("node registration persistence failed")
	}
	s.reconcileNodeConnectivityIncident(ctx, stored, previousConnectivity, domain.ConnectivityConnected)
	return stored, nil
}

func priorityFor(lc domain.LocationClass) domain.PriorityTier {
	if lc == domain.LocationRemote {
		return domain.PriorityP0
	}
	return domain.PriorityP1
}

func (s *Server) handleHeartbeat(ctx context.Context, nodeID string, hb wsproto.HeartbeatPayload) error {
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
		} else {
			// A live but blocked node remains observable, never schedulable.
			o.Lifecycle = domain.LifecycleConnected
		}
	})
	if err != nil {
		s.log.Warn("heartbeat for unknown node", "node_id", nodeID, "err", err)
	}
	return err
}

func (s *Server) handleTelemetry(ctx context.Context, nodeID string, tel wsproto.TelemetryPayload) {
	accels := make([]domain.Accelerator, 0, len(tel.Accelerators))
	for _, a := range tel.Accelerators {
		vendor := a.Vendor
		if vendor == "" {
			vendor = "nvidia"
		} // Older node agents omitted vendor.
		accels = append(accels, domain.Accelerator{
			ID:             fmt.Sprintf("%s-gpu%d", nodeID, a.Index),
			NodeID:         nodeID,
			Vendor:         vendor,
			Model:          a.Name,
			MemoryKind:     a.MemoryKind,
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
		s.workloads.ReconcileGPUIdleAfterTelemetry(nodeID)
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

func advertisedModelPools(advertised map[string]wsproto.ModelPool) map[string]workloads.ModelPool {
	if len(advertised) == 0 {
		return nil
	}
	pools := make(map[string]workloads.ModelPool, len(advertised))
	for model, pool := range advertised {
		if pool.PoolTokens > 0 && pool.Slots > 0 && pool.MaxRequestTokens > 0 {
			pools[model] = workloads.ModelPool{PoolTokens: pool.PoolTokens, Slots: pool.Slots, MaxRequestTokens: pool.MaxRequestTokens}
		}
	}
	return pools
}
