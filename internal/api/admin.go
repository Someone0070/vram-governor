package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"vram-governor/internal/domain"
	"vram-governor/internal/store"
	"vram-governor/internal/workloads"
)

type integrationStatus struct {
	ID             string          `json:"id"`
	Label          string          `json:"label"`
	Enabled        bool            `json:"enabled"`
	Ready          bool            `json:"ready"`
	Detail         string          `json:"detail"`
	SecretBindings map[string]bool `json:"secret_bindings,omitempty"`
	Allowed        []string        `json:"allowed,omitempty"`
}

type readinessCheck struct {
	ID     string `json:"id"`
	Label  string `json:"label"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

type deploymentReadiness struct {
	Mode            string           `json:"mode"`
	StateBackend    string           `json:"state_backend"`
	ArtifactBackend string           `json:"artifact_backend"`
	ReleaseGate     string           `json:"release_gate"`
	Checks          []readinessCheck `json:"checks"`
}

type telemetrySnapshot struct {
	Timestamp    time.Time              `json:"timestamp"`
	System       domain.SystemTelemetry `json:"system"`
	Accelerators []domain.Accelerator   `json:"accelerators"`
}

func (s *Server) handleAdminNodeTelemetry(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAdmin(w, r); !ok {
		return
	}
	minutes, _ := strconv.Atoi(r.URL.Query().Get("range_minutes"))
	if minutes <= 0 {
		minutes = 5
	}
	if minutes > 24*60 {
		minutes = 24 * 60
	}
	cutoff := time.Now().UTC().Add(-time.Duration(minutes) * time.Minute)
	s.telemetryMu.RLock()
	stored := s.telemetryHistory[r.PathValue("id")]
	rows := make([]telemetrySnapshot, 0, len(stored))
	for _, row := range stored {
		if !row.Timestamp.Before(cutoff) {
			rows = append(rows, row)
		}
	}
	s.telemetryMu.RUnlock()
	if len(rows) > 900 {
		step := (len(rows) + 899) / 900
		downsampled := make([]telemetrySnapshot, 0, 901)
		for index := 0; index < len(rows); index += step {
			downsampled = append(downsampled, rows[index])
		}
		if downsampled[len(downsampled)-1].Timestamp != rows[len(rows)-1].Timestamp {
			downsampled = append(downsampled, rows[len(rows)-1])
		}
		rows = downsampled
	}
	writeJSON(w, http.StatusOK, map[string]any{"node_id": r.PathValue("id"), "range_minutes": minutes, "samples": jsonSlice(rows)})
}

// readiness is the console's health summary: live facts about this
// deployment (nodes, GPUs, routes, storage, recent job outcomes). Optional
// features that are not configured are "off", not "missing", so the overall
// state only degrades for something that is actually broken.
func (s *Server) readiness(nodes []*domain.Node, targets []workloads.Target, rows []*domain.Workload) deploymentReadiness {
	mode := "development"
	if s.cfg.Production {
		mode = "production"
	}
	var problems []string
	check := func(id, label, status, detail string) readinessCheck {
		if status == "missing" || status == "partial" {
			problems = append(problems, label)
		}
		return readinessCheck{ID: id, Label: label, Status: status, Detail: detail}
	}
	var checks []readinessCheck

	stateBackend := "memory (restart-ephemeral)"
	if s.cfg.DatabaseURL != "" {
		stateBackend = "postgresql"
		checks = append(checks, check("durable_state", "Controller state", "ready", "PostgreSQL"))
	} else {
		checks = append(checks, check("durable_state", "Controller state", "partial", "in memory: queues and history are lost on restart"))
	}

	connected, gpus := 0, []string{}
	var offline []string
	for _, node := range nodes {
		if node.Observed.Connectivity == domain.ConnectivityConnected {
			connected++
			for _, gpu := range node.Accelerators {
				gpus = append(gpus, gpu.Model)
			}
		} else {
			offline = append(offline, firstNonEmptyString(node.Name, node.ID))
		}
	}
	nodeStatus, nodeDetail := "ready", fmt.Sprintf("%d of %d connected", connected, len(nodes))
	if len(offline) > 0 {
		nodeStatus = "partial"
		if connected == 0 {
			nodeStatus = "missing"
		}
		nodeDetail += "; offline: " + strings.Join(offline, ", ")
	}
	checks = append(checks, check("nodes", "Nodes", nodeStatus, nodeDetail))
	if len(gpus) > 0 {
		checks = append(checks, check("gpus", "GPUs", "ready", strings.Join(gpus, ", ")))
	} else {
		checks = append(checks, check("gpus", "GPUs", "missing", "no connected node reports a GPU"))
	}

	llmRoutes, comfyRoutes, cloudReady := 0, 0, 0
	models, loaded := map[string]bool{}, []string{}
	for _, target := range targets {
		if !target.Enabled || target.Quarantined {
			continue
		}
		switch strings.ToLower(target.Adapter) {
		case "llamacpp", "llama":
			llmRoutes++
			for _, model := range target.Models {
				models[model] = true
			}
			loaded = append(loaded, target.ResidentModels...)
		case "comfy":
			comfyRoutes++
		case "openrouter":
			if target.Endpoint != "" && target.Authorization != "" {
				cloudReady++
			}
		}
	}
	if llmRoutes > 0 {
		detail := fmt.Sprintf("%d routes, %d models", llmRoutes, len(models))
		if len(loaded) > 0 {
			detail += "; loaded: " + strings.Join(loaded, ", ")
		} else {
			detail += "; none loaded (first request loads on demand)"
		}
		checks = append(checks, check("llm", "LLM routes", "ready", detail))
	} else {
		checks = append(checks, check("llm", "LLM routes", "missing", "no enabled local LLM route"))
	}
	if comfyRoutes > 0 {
		checks = append(checks, check("comfy", "ComfyUI", "ready", fmt.Sprintf("%d routes (image, video, audio workflows)", comfyRoutes)))
	} else {
		checks = append(checks, check("comfy", "ComfyUI", "off", "no ComfyUI route configured"))
	}
	artifacts := s.cfg.Workloads.ArtifactStore.Type
	if artifacts == "" {
		artifacts = "filesystem"
	}
	checks = append(checks, check("artifacts", "Output storage", "ready", artifacts))

	since := time.Now().Add(-24 * time.Hour)
	succeeded, failed := 0, 0
	for _, row := range rows {
		if row == nil || row.FinishedAt == nil || row.FinishedAt.Before(since) {
			continue
		}
		switch row.Status {
		case domain.WorkloadSucceeded:
			succeeded++
		case domain.WorkloadFailed:
			failed++
		}
	}
	jobStatus := "ready"
	if failed > 0 && failed*5 > succeeded+failed {
		jobStatus = "partial"
	}
	checks = append(checks, check("jobs", "Jobs (24 h)", jobStatus, fmt.Sprintf("%d succeeded, %d failed", succeeded, failed)))
	if cloudReady > 0 {
		checks = append(checks, check("cloud", "Cloud fallback", "ready", fmt.Sprintf("%d OpenRouter route(s)", cloudReady)))
	} else {
		checks = append(checks, check("cloud", "Cloud fallback", "off", "local only (no OpenRouter key configured)"))
	}
	if s.nodeLossMonitoringEnabled() {
		checks = append(checks, check("monitoring", "Node-loss monitoring", "ready", "opens an incident when a node drops, closes it on reconnect"))
	}

	overall := "healthy"
	if len(problems) > 0 {
		overall = "degraded: " + strings.Join(problems, ", ")
	}
	return deploymentReadiness{Mode: mode, StateBackend: stateBackend, ArtifactBackend: artifacts, ReleaseGate: overall, Checks: checks}
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func ternaryStatus(ok bool) string {
	if ok {
		return "ready"
	}
	return "missing"
}

func countDetail(count int, singular, plural, zero string) string {
	if count == 0 {
		return zero
	}
	if count == 1 {
		return "1 " + singular
	}
	return fmt.Sprintf("%d %s", count, plural)
}

func (s *Server) requireAdmin(w http.ResponseWriter, r *http.Request) (Principal, bool) {
	p, ok := s.requirePrincipal(w, r, "admin")
	if !ok {
		return Principal{}, false
	}
	if !s.adminRemoteAllowed(r) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "admin_network_denied"})
		return Principal{}, false
	}
	return p, true
}

func (s *Server) handleAdminNodeScheduling(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	if r.Header.Get("Idempotency-Key") == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Idempotency-Key is required"})
		return
	}
	var body struct {
		State domain.SchedulingState `json:"state"`
	}
	if err := decodeJSONLimit(r, &body, 16<<10); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	switch body.State {
	case domain.SchedulingEnabled, domain.SchedulingDraining, domain.SchedulingDisabled:
	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "state must be enabled, draining, or disabled"})
		return
	}
	nodeID := r.PathValue("id")
	err := s.nodes.UpdateDesired(r.Context(), nodeID, func(desired *domain.Desired, scheduling *domain.SchedulingState) {
		*scheduling = body.State
		desired.SchedulingEnabled = body.State == domain.SchedulingEnabled
	})
	if errors.Is(err, store.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "node not found"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	node, err := s.nodes.GetNode(r.Context(), nodeID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	payload, _ := json.Marshal(map[string]any{"node_id": nodeID, "scheduling_state": body.State, "idempotency_key": r.Header.Get("Idempotency-Key")})
	_ = s.workloadStore.AppendAuditEvent(r.Context(), &domain.AuditEvent{ID: "evt-" + randomSecret()[:24], Timestamp: time.Now().UTC(), ActorID: principal.ID, Type: "node.scheduling.changed", Severity: "info", Payload: payload})
	writeJSON(w, http.StatusOK, node)
}

func (s *Server) handleAdminNodeDrain(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Idempotency-Key is required"})
		return
	}
	result, err := s.workloads.DrainNode(r.Context(), r.PathValue("id"), principal.ID, idempotencyKey)
	if errors.Is(err, store.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "node not found"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]any{"error": err.Error(), "result": result})
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleAdminOverview(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	nodes, _ := s.nodes.ListNodes(r.Context())
	workloads, _ := s.workloads.List(r.Context())
	events, _ := s.workloadStore.ListAuditEvents(r.Context(), "", 50)
	residencies, _ := s.workloads.ListResidencies(r.Context())
	transitions, _ := s.workloads.ListResidencyTransitions(r.Context(), 50)
	notifications, _ := s.workloads.ListNotifications(r.Context(), "", 50)
	budgets, _ := s.workloadStore.ListBudgetReservations(r.Context(), "")
	learning, _ := s.workloadStore.ListSchedulerLearningSamples(r.Context(), "", 100)
	profiles, _ := s.workloadStore.ListInterferenceProfiles(r.Context())
	transitionPlans, _ := s.workloadStore.ListTransitionPlans(r.Context(), "", 100)
	incidents, _ := s.incidentStore.ListIncidents(r.Context(), "")
	performanceProfiles, _ := s.profiles.ListAllProfiles(r.Context())
	nodeCommands, _ := s.workloadStore.ListNodeCommands(r.Context(), "", 100)
	targets := s.workloads.Targets()
	readiness := s.readiness(nodes, targets, workloads)
	// The console polls this every two seconds: send what it shows, not the
	// full history (452 jobs with base64 payloads and 11.6k recovered
	// node-loss incidents made it 15 MB).
	workloads = overviewWorkloads(workloads, overviewRecentWorkloads)
	incidentCounts := map[string]int{"total": len(incidents)}
	incidents = overviewIncidents(incidents, overviewRecentIncidents)
	for index, incident := range incidents {
		if incident.Status != "closed" && incident.Status != "recovered" {
			incidentCounts["unresolved"]++
		}
		incidents[index] = s.syncIncidentAnalysis(r.Context(), incident)
	}
	residencies = servedResidencies(residencies, targets)
	nodes = jsonSlice(nodes)
	workloads = jsonSlice(workloads)
	events = jsonSlice(events)
	residencies = jsonSlice(residencies)
	transitions = jsonSlice(transitions)
	notifications = jsonSlice(notifications)
	budgets = jsonSlice(budgets)
	learning = jsonSlice(learning)
	profiles = jsonSlice(profiles)
	transitionPlans = jsonSlice(transitionPlans)
	incidents = jsonSlice(incidents)
	performanceProfiles = jsonSlice(performanceProfiles)
	nodeCommands = jsonSlice(nodeCommands)
	writeJSON(w, http.StatusOK, map[string]any{"principal": p.ID, "readiness": readiness, "nodes": nodes, "targets": targets, "workloads": workloads, "events": events, "model_residencies": residencies, "residency_transitions": transitions, "notifications": notifications, "budget_reservations": budgets, "scheduler_learning_samples": learning, "interference_profiles": profiles, "performance_profiles": performanceProfiles, "transition_plans": transitionPlans, "node_commands": nodeCommands, "incidents": incidents, "incident_counts": incidentCounts})
}

const (
	overviewRecentWorkloads = 150
	overviewRecentIncidents = 25
)

// overviewWorkloads keeps every unfinished workload plus the most recent
// finished ones, without request payloads, plan material or outputs (the
// console shows none of them; GET /api/v1/workloads/{id} has the full row).
func overviewWorkloads(rows []*domain.Workload, recent int) []*domain.Workload {
	sorted := append([]*domain.Workload(nil), rows...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].CreatedAt.After(sorted[j].CreatedAt) })
	out := make([]*domain.Workload, 0, recent)
	finished := 0
	for _, row := range sorted {
		if row == nil {
			continue
		}
		switch row.Status {
		case domain.WorkloadSucceeded, domain.WorkloadFailed, domain.WorkloadCancelled, domain.WorkloadRejected:
			if finished >= recent {
				continue
			}
			finished++
		}
		summary := *row
		summary.Request.Payload = nil
		summary.Request.TransformationParameters = nil
		summary.InlineOutput = nil
		if row.Plan != nil {
			plan := *row.Plan
			plan.Material = nil
			summary.Plan = &plan
		}
		if row.Execution != nil {
			execution := *row.Execution
			execution.Opaque = nil
			summary.Execution = &execution
		}
		out = append(out, &summary)
	}
	return out
}

// overviewIncidents keeps unresolved incidents plus the most recent others.
func overviewIncidents(rows []*domain.Incident, recent int) []*domain.Incident {
	sorted := append([]*domain.Incident(nil), rows...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].UpdatedAt.After(sorted[j].UpdatedAt) })
	out := make([]*domain.Incident, 0, recent)
	resolved := 0
	for _, row := range sorted {
		if row == nil {
			continue
		}
		if row.Status == "closed" || row.Status == "recovered" {
			if resolved >= recent {
				continue
			}
			resolved++
		}
		out = append(out, row)
	}
	return out
}

// servedResidencies drops residency rows for models no route serves any
// more (models removed from a node keep their old rows in the store).
func servedResidencies(rows []*domain.ModelResidency, targets []workloads.Target) []*domain.ModelResidency {
	served := make(map[string]bool)
	for _, target := range targets {
		for _, model := range target.Models {
			served[target.ID+"\x00"+model] = true
		}
	}
	out := make([]*domain.ModelResidency, 0, len(rows))
	for _, row := range rows {
		if row != nil && served[row.TargetID+"\x00"+row.Model] {
			out = append(out, row)
		}
	}
	return out
}

func (s *Server) handleAdminIntegrations(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAdmin(w, r); !ok {
		return
	}
	artifact := s.cfg.Workloads.ArtifactStore
	artifactReady := artifact.Type == "filesystem" || (artifact.Endpoint != "" && artifact.Bucket != "" && os.Getenv(artifact.AccessKeyEnv) != "" && os.Getenv(artifact.SecretKeyEnv) != "")
	notificationSecretReady := s.cfg.Notifications.SigningSecret != "" || (s.cfg.Notifications.SigningSecretEnv != "" && os.Getenv(s.cfg.Notifications.SigningSecretEnv) != "")
	cloudTargets := 0
	cloudReady := 0
	for _, configured := range s.cfg.Workloads.Targets {
		if !configured.Cloud {
			continue
		}
		cloudTargets++
		if configured.Endpoint != "" && ((configured.AuthorizationEnv != "" && os.Getenv(configured.AuthorizationEnv) != "") || configured.Authorization != "") {
			cloudReady++
		}
	}
	statuses := []integrationStatus{
		{ID: "state", Label: "PostgreSQL authority", Enabled: s.cfg.DatabaseURL != "", Ready: s.cfg.DatabaseURL != "", Detail: map[bool]string{true: "Durable controller state is active", false: "Using restart-ephemeral in-memory state"}[s.cfg.DatabaseURL != ""]},
		{ID: "artifacts", Label: "Artifact storage", Enabled: true, Ready: artifactReady, Detail: fmt.Sprintf("%s backend%s", artifact.Type, map[bool]string{true: " is initialized", false: " is missing required bindings"}[artifactReady]), SecretBindings: map[string]bool{"access_key": artifact.AccessKeyEnv != "" && os.Getenv(artifact.AccessKeyEnv) != "", "secret_key": artifact.SecretKeyEnv != "" && os.Getenv(artifact.SecretKeyEnv) != ""}},
		{ID: "openrouter", Label: "OpenRouter fallback", Enabled: cloudTargets > 0, Ready: cloudTargets > 0 && cloudReady == cloudTargets, Detail: fmt.Sprintf("%d of %d cloud routes have endpoint and authorization bindings", cloudReady, cloudTargets), Allowed: append([]string(nil), s.cfg.Agents.AllowedCloudModels...)},
		{ID: "webhooks", Label: "Signed webhook outbox", Enabled: s.cfg.Notifications.Enabled, Ready: s.cfg.Notifications.Enabled && notificationSecretReady && len(s.cfg.Notifications.AllowedHosts) > 0, Detail: fmt.Sprintf("%d allowlisted destinations; at most %d attempts per delivery", len(s.cfg.Notifications.AllowedHosts), s.cfg.Notifications.MaxAttempts), SecretBindings: map[string]bool{"signing_secret": notificationSecretReady}, Allowed: append([]string(nil), s.cfg.Notifications.AllowedHosts...)},
		{ID: "system_agent", Label: "System-agent escalation", Enabled: true, Ready: len(s.cfg.Agents.LocalVerifierModels) > 0, Detail: fmt.Sprintf("%d local verifiers; %d allowed cloud models; paid emergency %t", len(s.cfg.Agents.LocalVerifierModels), len(s.cfg.Agents.AllowedCloudModels), s.cfg.Agents.PaidEmergencyFallback), Allowed: append([]string(nil), s.cfg.Agents.AllowedCloudProviders...)},
	}
	writeJSON(w, http.StatusOK, map[string]any{"integrations": statuses, "residency": map[string]any{"enabled": s.cfg.Workloads.Residency.Enabled == nil || *s.cfg.Workloads.Residency.Enabled, "idle_unload_seconds": s.cfg.Workloads.Residency.IdleUnloadSeconds, "min_residency_seconds": s.cfg.Workloads.Residency.MinResidencySeconds, "quiet_hours_start": s.cfg.Workloads.Residency.QuietHoursStart, "quiet_hours_end": s.cfg.Workloads.Residency.QuietHoursEnd}, "restart_required_fields": []string{"target endpoints", "credentials", "database URL", "artifact backend", "provider allowlists", "webhook allowlists"}})
}

func (s *Server) handleAdminTargetPolicy(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	if r.Header.Get("Idempotency-Key") == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Idempotency-Key is required"})
		return
	}
	var policy domain.TargetPolicyOverride
	if err := decodeJSONLimit(r, &policy, 64<<10); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	policy.TargetID = r.PathValue("id")
	policy.UpdatedAt = time.Now().UTC()
	policy.UpdatedBy = p.ID
	var previous *workloads.Target
	for _, target := range s.workloads.Targets() {
		if target.ID == policy.TargetID {
			copy := target
			previous = &copy
			break
		}
	}
	updated, err := s.workloads.UpdateTargetPolicy(policy)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	stored, err := s.workloadStore.UpsertTargetPolicyOverride(r.Context(), &policy)
	if err != nil {
		if previous != nil {
			_, _ = s.workloads.UpdateTargetPolicy(domain.TargetPolicyOverride{TargetID: previous.ID, Enabled: previous.Enabled, Quarantined: previous.Quarantined, SharingEnabled: previous.SharingEnabled, GuardedExploration: previous.GuardedExploration, VRAMReserveMB: previous.VRAMReserveMB, MaxSlowdown: previous.MaxSlowdown})
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "policy persistence failed: " + err.Error()})
		return
	}
	payload, _ := json.Marshal(stored)
	_ = s.workloadStore.AppendAuditEvent(r.Context(), &domain.AuditEvent{ID: "evt-" + randomSecret()[:24], Timestamp: policy.UpdatedAt, ActorID: p.ID, Type: "target.policy.changed", Severity: "info", Payload: payload})
	writeJSON(w, http.StatusOK, map[string]any{"policy": stored, "target": updated})
}

func jsonSlice[T any](values []T) []T {
	if values == nil {
		return []T{}
	}
	return values
}

func (s *Server) handleAdminResidency(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAdmin(w, r); !ok {
		return
	}
	residencies, err := s.workloads.ListResidencies(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	transitions, err := s.workloads.ListResidencyTransitions(r.Context(), 100)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"residencies": residencies, "transitions": transitions})
}

func (s *Server) handleAdminResidencyTransition(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	var body struct {
		TargetID    string                     `json:"target_id"`
		Model       string                     `json:"model"`
		DesiredTier domain.ResidencyTier       `json:"desired_tier"`
		Policy      domain.ResidencyPolicyMode `json:"policy,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON: " + err.Error()})
		return
	}
	idempotencyKey := r.Header.Get("Idempotency-Key")
	if body.TargetID == "" || body.Model == "" || body.DesiredTier == "" || idempotencyKey == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "target_id, model, desired_tier, and Idempotency-Key are required"})
		return
	}
	residency, transitions, err := s.workloads.ConfigureResidency(r.Context(), body.TargetID, body.Model, body.DesiredTier, body.Policy, p.ID, idempotencyKey)
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]any{"error": err.Error(), "residency": residency, "transitions": transitions})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"residency": residency, "transitions": transitions})
}
