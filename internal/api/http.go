package api

import (
	"encoding/json"
	"net/http"

	"vram-governor/internal/domain"
	"vram-governor/internal/store"
)

func (s *Server) routes(dashboardFS http.FileSystem) {
	s.mux.HandleFunc("GET /nodes", s.handleListNodes)
	s.mux.HandleFunc("GET /nodes/{id}", s.handleGetNode)
	s.mux.HandleFunc("GET /healthz", s.handleHealthz)
	s.mux.HandleFunc("POST /auth/session", s.handleCreateSession)
	s.mux.HandleFunc("DELETE /auth/session", s.handleDeleteSession)
	s.mux.HandleFunc("/ws/node", s.handleNodeWS)

	// Phase 2: runtime + measured-profile surface (architecture.md §33
	// "Runtime" concept list; measurement.md §5 storage). These are
	// node-agent-reported facts, not scheduler actions — no engine
	// start/stop/drain/sleep/wake control endpoints exist yet (later
	// phases wire those through the §34A command channel).
	s.mux.HandleFunc("GET /nodes/{id}/engines", s.handleListEngines)
	s.mux.HandleFunc("POST /nodes/{id}/engines", s.handleReportEngine)
	s.mux.HandleFunc("GET /nodes/{id}/profiles", s.handleListNodeProfiles)
	s.mux.HandleFunc("POST /nodes/{id}/profiles", s.handleReportProfile)
	s.mux.HandleFunc("GET /profiles", s.handleListAllProfiles)

	// Phase 3: work-queue controller API (architecture.md §33 "Jobs").
	s.mux.HandleFunc("POST /jobs", s.handleSubmitJob)
	s.mux.HandleFunc("GET /jobs", s.handleListJobs)
	s.mux.HandleFunc("GET /jobs/{id}", s.handleGetJob)
	s.mux.HandleFunc("POST /jobs/{id}/pause", s.handlePauseJob)
	s.mux.HandleFunc("POST /jobs/{id}/cancel", s.handleCancelJob)

	// Unified workload surface plus OpenAI- and Comfy-compatible gateways.
	s.mux.HandleFunc("POST /api/v1/workloads", s.handleSubmitWorkload)
	s.mux.HandleFunc("POST /api/v1/workloads/preview", s.handlePreviewWorkload)
	s.mux.HandleFunc("GET /api/v1/workloads", s.handleListWorkloads)
	s.mux.HandleFunc("GET /api/v1/workloads/{id}", s.handleGetWorkload)
	s.mux.HandleFunc("POST /api/v1/workloads/{id}/cancel", s.handleCancelWorkload)
	s.mux.HandleFunc("POST /api/v1/workloads/{id}/approve", s.handleApproveWorkload)
	s.mux.HandleFunc("POST /api/v1/workloads/{id}/priority", s.handleReprioritizeWorkload)
	s.mux.HandleFunc("GET /api/v1/workloads/{id}/artifacts", s.handleWorkloadArtifacts)
	s.mux.HandleFunc("GET /api/v1/workloads/{id}/explain", s.handleExplainWorkload)
	s.mux.HandleFunc("GET /api/v1/events", s.handleEvents)
	s.mux.HandleFunc("GET /api/v1/notifications", s.handleNotifications)
	s.mux.HandleFunc("POST /v1/chat/completions", s.handleChatCompletions)
	s.mux.HandleFunc("GET /v1/models", s.handleOpenAIModels)
	s.mux.HandleFunc("POST /prompt", s.handleComfyPrompt)
	s.mux.HandleFunc("GET /history", s.handleComfyHistoryAll)
	s.mux.HandleFunc("GET /history/{id}", s.handleComfyHistory)
	s.mux.HandleFunc("GET /queue", s.handleComfyQueue)
	s.mux.HandleFunc("POST /queue", s.handleComfyQueueMutation)
	s.mux.HandleFunc("GET /ws", s.handleComfyWS)
	s.mux.HandleFunc("POST /upload/image", s.handleUploadImage)
	s.mux.HandleFunc("POST /upload/mask", s.handleUploadImage)
	s.mux.HandleFunc("GET /view", s.handleViewArtifact)
	s.mux.HandleFunc("GET /admin/api/overview", s.handleAdminOverview)
	s.mux.HandleFunc("GET /admin/api/nodes/{id}/telemetry", s.handleAdminNodeTelemetry)
	s.mux.HandleFunc("GET /admin/api/residency", s.handleAdminResidency)
	s.mux.HandleFunc("POST /admin/api/residency/transition", s.handleAdminResidencyTransition)
	s.mux.HandleFunc("GET /admin/api/node-commands", s.handleListNodeCommands)
	s.mux.HandleFunc("POST /admin/api/nodes/{id}/commands", s.handleCreateNodeCommand)
	s.mux.HandleFunc("POST /admin/api/nodes/{id}/scheduling", s.handleAdminNodeScheduling)
	s.mux.HandleFunc("POST /admin/api/nodes/{id}/drain", s.handleAdminNodeDrain)
	s.mux.HandleFunc("GET /admin/api/integrations", s.handleAdminIntegrations)
	s.mux.HandleFunc("PUT /admin/api/targets/{id}/policy", s.handleAdminTargetPolicy)
	s.mux.HandleFunc("POST /admin/api/incidents", s.handleCreateIncident)
	s.mux.HandleFunc("GET /admin/api/incidents", s.handleListIncidents)
	s.mux.HandleFunc("GET /admin/api/incidents/{id}", s.handleGetIncident)
	s.mux.HandleFunc("POST /admin/api/incidents/{id}/proposal", s.handleIncidentProposal)
	s.mux.HandleFunc("POST /admin/api/incidents/{id}/escalate", s.handleIncidentEscalation)
	s.mux.HandleFunc("POST /api/agent/v1/incidents", s.handleCreateIncident)
	s.mux.HandleFunc("GET /api/agent/v1/incidents", s.handleListIncidents)
	s.mux.HandleFunc("GET /api/agent/v1/incidents/{id}", s.handleGetIncident)
	s.mux.HandleFunc("POST /api/agent/v1/incidents/{id}/proposal", s.handleIncidentProposal)
	s.mux.HandleFunc("POST /api/agent/v1/incidents/{id}/escalate", s.handleIncidentEscalation)
	s.mux.HandleFunc("GET /api/agent/v1/events", s.handleAgentEvents)

	if dashboardFS != nil {
		fileServer := http.FileServer(dashboardFS)
		s.mux.Handle("/", fileServer)
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

func (s *Server) handleListNodes(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requirePrincipal(w, r, "nodes:read"); !ok {
		return
	}
	nodes, err := s.nodes.ListNodes(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, nodes)
}

func (s *Server) handleGetNode(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requirePrincipal(w, r, "nodes:read"); !ok {
		return
	}
	id := r.PathValue("id")
	n, err := s.nodes.GetNode(r.Context(), id)
	if err != nil {
		if err == store.ErrNotFound {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "node not found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, n)
}

// handleListEngines returns the managed EngineInstance rows a node agent
// has reported for the given node (architecture.md §33 "GET
// /nodes/{id}/engines").
func (s *Server) handleListEngines(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requirePrincipal(w, r, "runtime:read"); !ok {
		return
	}
	id := r.PathValue("id")
	engines, err := s.engines.ListEnginesForNode(r.Context(), id)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, engines)
}

// handleReportEngine lets a node agent report the state of an
// EngineInstance it launched/observed (on-demand probe path in Phase 2;
// later phases push this over the §34A control channel instead). Auth
// uses the same node-bound credential rule as /ws/node.
func (s *Server) handleReportEngine(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, ok := s.requireNodeReporter(w, r, id); !ok {
		return
	}
	var e domain.EngineInstance
	if err := decodeJSONLimit(r, &e, 1<<20); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad engine payload: " + err.Error()})
		return
	}
	e.NodeID = id
	stored, err := s.engines.UpsertEngine(r.Context(), &e)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, stored)
}

// handleListNodeProfiles returns measured PerformanceProfile rows for one
// node (measurement.md §5).
func (s *Server) handleListNodeProfiles(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requirePrincipal(w, r, "runtime:read"); !ok {
		return
	}
	id := r.PathValue("id")
	profiles, err := s.profiles.ListProfilesForNode(r.Context(), id)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, profiles)
}

// handleReportProfile lets a node agent persist a PerformanceProfile it
// just measured (on-demand probe path in Phase 2).
func (s *Server) handleReportProfile(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, ok := s.requireNodeReporter(w, r, id); !ok {
		return
	}
	var p domain.PerformanceProfile
	if err := decodeJSONLimit(r, &p, 4<<20); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad profile payload: " + err.Error()})
		return
	}
	stored, err := s.profiles.SaveProfile(r.Context(), id, &p)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, stored)
}

// handleListAllProfiles returns every measured profile across all nodes
// (architecture.md §33 "GET /profiles" concept; scheduler feasibility/cost
// stages in later phases read exactly this kind of row).
func (s *Server) handleListAllProfiles(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requirePrincipal(w, r, "runtime:read"); !ok {
		return
	}
	profiles, err := s.profiles.ListAllProfiles(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, profiles)
}
