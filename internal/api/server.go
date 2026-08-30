package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"vram-governor/internal/artifacts"
	"vram-governor/internal/domain"
	"vram-governor/internal/jobs"
	"vram-governor/internal/store"
	"vram-governor/internal/workloads"
)

// Server wires together the controller's HTTP API, the node<->controller
// websocket endpoint, the node registry (store), and the liveness monitor.
type Server struct {
	cfg   *Config
	log   *slog.Logger
	nodes store.NodeStore
	// Server keeps narrow interface views even though production injects one
	// aggregate PostgreSQL authority.
	engines  store.EngineStore
	profiles store.ProfileStore
	// jobs is the compatibility work-queue engine. Nil leaves those routes 501
	// for embedders that use only unified workloads.
	jobs             *jobs.Manager
	workloads        *workloads.Manager
	workloadStore    store.WorkloadStore
	incidentStore    store.IncidentStore
	artifacts        artifacts.Store
	credentials      []storedCredential
	adminNets        []*net.IPNet
	authSessions     store.BrowserSessionStore
	commandSecret    []byte
	nodeConnMu       sync.RWMutex
	nodeConnections  map[string]*nodeConnection
	telemetryMu      sync.RWMutex
	telemetryHistory map[string][]telemetrySnapshot
	mux              *http.ServeMux
}

// NewServer wires the controller's HTTP+WS surface to a backing store.
// backing must implement store.Store (NodeStore + EngineStore +
// ProfileStore + JobStore) — store.MemoryStore does. jobsMgr may be nil if
// the caller doesn't want the Phase 3 jobs API mounted.
func NewServer(cfg *Config, log *slog.Logger, backing store.Store, jobsMgr *jobs.Manager, dashboardFS http.FileSystem) *Server {
	commandSecret := cfg.Auth.CommandSigningSecret
	if cfg.Auth.CommandSigningSecretEnv != "" {
		commandSecret = os.Getenv(cfg.Auth.CommandSigningSecretEnv)
	}
	s := &Server{cfg: cfg, log: log, nodes: backing, engines: backing, profiles: backing, jobs: jobsMgr, workloadStore: backing, incidentStore: backing, authSessions: backing, commandSecret: []byte(commandSecret), nodeConnections: make(map[string]*nodeConnection), telemetryHistory: make(map[string][]telemetrySnapshot), mux: http.NewServeMux()}
	s.buildCredentials()
	for _, cidr := range cfg.Auth.AdminPrivateCIDRs {
		_, block, err := net.ParseCIDR(cidr)
		if err != nil {
			log.Warn("ignoring invalid admin CIDR", "cidr", cidr)
			continue
		}
		s.adminNets = append(s.adminNets, block)
	}
	s.routes(dashboardFS)
	return s
}

func (s *Server) SetWorkloadManager(manager *workloads.Manager, backing ...store.WorkloadStore) {
	s.workloads = manager
	if manager != nil {
		manager.SetNodeControl(s.executeNodeCommand)
	}
	if len(backing) > 0 && backing[0] != nil {
		s.workloadStore = backing[0]
		if incidents, ok := backing[0].(store.IncidentStore); ok {
			s.incidentStore = incidents
		}
	}
}
func (s *Server) SetArtifactStore(store artifacts.Store) { s.artifacts = store }

func (s *Server) SetAppFS(appFS fs.FS) {
	s.mux.Handle("GET /ui/", http.StripPrefix("/ui/", http.FileServer(http.FS(appFS))))
	s.mux.HandleFunc("GET /studio", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/studio/", http.StatusPermanentRedirect)
	})
	s.mux.HandleFunc("GET /studio/", func(w http.ResponseWriter, r *http.Request) {
		s.serveAppHTML(w, r, appFS, "studio.html", false)
	})
	s.mux.HandleFunc("GET /chat", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/chat/", http.StatusPermanentRedirect)
	})
	s.mux.HandleFunc("GET /chat/", func(w http.ResponseWriter, r *http.Request) {
		s.serveAppHTML(w, r, appFS, "chat.html", false)
	})
	s.mux.HandleFunc("GET /admin", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/admin/", http.StatusPermanentRedirect)
	})
	s.mux.HandleFunc("GET /admin/", func(w http.ResponseWriter, r *http.Request) {
		s.serveAppHTML(w, r, appFS, "admin.html", true)
	})
}

func (s *Server) serveAppHTML(w http.ResponseWriter, r *http.Request, appFS fs.FS, name string, admin bool) {
	if admin {
		if !s.adminRemoteAllowed(r) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "admin_network_denied"})
			return
		}
	}
	data, err := fs.ReadFile(appFS, name)
	if err != nil {
		http.Error(w, "interface unavailable", http.StatusInternalServerError)
		return
	}
	http.ServeContent(w, r, name, time.Time{}, bytes.NewReader(data))
}

func (s *Server) Handler() http.Handler { return s.securityMiddleware(s.mux) }

// RunLivenessMonitor periodically scans the node registry and flips observed
// connectivity between connected/suspect/lost based on time since last
// heartbeat, per architecture.md §34A. It runs until ctx is cancelled.
func (s *Server) RunLivenessMonitor(ctx context.Context) {
	interval := time.Duration(s.cfg.Liveness.HeartbeatIntervalSeconds) * time.Second
	if interval <= 0 {
		interval = 2 * time.Second
	}
	suspectAfter := time.Duration(s.cfg.Liveness.SuspectAfterSeconds) * time.Second
	lostAfter := time.Duration(s.cfg.Liveness.LostAfterSeconds) * time.Second

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.sweepLiveness(ctx, suspectAfter, lostAfter)
			s.reconcileIncidentAnalyses(ctx)
		}
	}
}

func (s *Server) reconcileIncidentAnalyses(ctx context.Context) {
	if s.incidentStore == nil || s.workloads == nil {
		return
	}
	incidents, err := s.incidentStore.ListIncidents(ctx, "")
	if err != nil {
		s.log.Warn("incident analysis reconciliation failed", "error", err)
		return
	}
	for _, incident := range incidents {
		s.syncIncidentAnalysis(ctx, incident)
	}
}

func (s *Server) sweepLiveness(ctx context.Context, suspectAfter, lostAfter time.Duration) {
	nodes, err := s.nodes.ListNodes(ctx)
	if err != nil {
		s.log.Error("liveness sweep: list nodes failed", "err", err)
		return
	}
	now := time.Now().UTC()
	for _, n := range nodes {
		if n.Observed.LastHeartbeat.IsZero() {
			continue
		}
		age := now.Sub(n.Observed.LastHeartbeat)
		var want domain.ConnectivityState
		switch {
		case age >= lostAfter:
			want = domain.ConnectivityLost
		case age >= suspectAfter:
			want = domain.ConnectivitySuspect
		default:
			want = domain.ConnectivityConnected
		}
		if want == n.Observed.Connectivity {
			continue
		}
		id := n.ID
		prev := n.Observed.Connectivity
		err := s.nodes.UpdateObserved(ctx, id, func(o *domain.Observed, _ *[]domain.Accelerator) {
			o.Connectivity = want
			if want == domain.ConnectivityLost {
				o.Ready = false
				o.Lifecycle = domain.LifecycleOffline
			}
		})
		if err != nil {
			s.log.Error("liveness sweep: update failed", "node", id, "err", err)
			continue
		}
		s.log.Info("node connectivity transition", "node", id, "from", prev, "to", want, "heartbeat_age_s", age.Seconds())
		s.reconcileNodeConnectivityIncident(ctx, n, prev, want)
	}
}

func (s *Server) nodeLossMonitoringEnabled() bool {
	return s.cfg.Agents.MonitorNodeLoss == nil || *s.cfg.Agents.MonitorNodeLoss
}

func (s *Server) reconcileNodeConnectivityIncident(ctx context.Context, node *domain.Node, previous, current domain.ConnectivityState) {
	if !s.nodeLossMonitoringEnabled() || s.incidentStore == nil || node == nil {
		return
	}
	evidenceRef := "node:" + node.ID
	incidents, err := s.incidentStore.ListIncidents(ctx, "system")
	if err != nil {
		s.log.Warn("node-loss incident reconciliation failed", "node", node.ID, "error", err)
		return
	}
	var active *domain.Incident
	for _, incident := range incidents {
		if incident.Status == "closed" || incident.Status == "recovered" {
			continue
		}
		for _, evidence := range incident.EvidenceRefs {
			if evidence == evidenceRef {
				active = incident
				break
			}
		}
		if active != nil {
			break
		}
	}
	now := time.Now().UTC()
	if current == domain.ConnectivityLost {
		if active != nil {
			return
		}
		name := node.Name
		if name == "" {
			name = node.ID
		}
		incident := &domain.Incident{ID: "inc-" + randomSecret()[:24], OwnerID: "system", Severity: "S2", Confidence: .99, Summary: "Node lost: " + name, EvidenceRefs: []string{evidenceRef}, Status: "open", CreatedAt: now, UpdatedAt: now}
		if _, err := s.incidentStore.CreateIncident(ctx, incident); err != nil {
			s.log.Warn("node-loss incident creation failed", "node", node.ID, "error", err)
			return
		}
		payload, _ := json.Marshal(map[string]any{"node_id": node.ID, "previous": previous, "current": current})
		_ = s.workloadStore.AppendAuditEvent(ctx, &domain.AuditEvent{ID: "evt-" + randomSecret()[:24], Timestamp: now, OwnerID: "system", Type: "incident.node_lost", Severity: "warn", Payload: payload})
		return
	}
	if current == domain.ConnectivityConnected && active != nil {
		active.Status = "recovered"
		active.UpdatedAt = now
		if _, err := s.incidentStore.UpdateIncident(ctx, active); err != nil {
			s.log.Warn("node-loss incident recovery update failed", "node", node.ID, "error", err)
			return
		}
		payload, _ := json.Marshal(map[string]any{"node_id": node.ID, "previous": previous, "current": current, "incident_id": active.ID})
		_ = s.workloadStore.AppendAuditEvent(ctx, &domain.AuditEvent{ID: "evt-" + randomSecret()[:24], Timestamp: now, OwnerID: "system", Type: "incident.node_recovered", Severity: "info", Payload: payload})
	}
}
