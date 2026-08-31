package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
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

// readiness reports observable deployment facts, not roadmap claims. It is
// intentionally conservative: configuration and simulator tests do not count
// as a live integration.
func (s *Server) readiness(nodes []*domain.Node, targets []workloads.Target, profiles []*domain.InterferenceProfile, samples []*domain.SchedulerLearningSample) deploymentReadiness {
	mode := "development"
	if s.cfg.Production {
		mode = "production"
	}
	stateBackend := "memory (restart-ephemeral)"
	persistenceStatus := "missing"
	persistenceDetail := "database_url is empty; queues, leases, prompt mappings, approvals, incidents, and notifications are lost on controller restart"
	if s.cfg.DatabaseURL != "" {
		stateBackend = "postgresql"
		persistenceStatus = "ready"
		persistenceDetail = "controller opened PostgreSQL successfully at startup"
	}

	connected := 0
	for _, node := range nodes {
		if node.Observed.Connectivity == domain.ConnectivityConnected {
			connected++
		}
	}
	llmTargets, comfyTargets, cloudTargets, unverifiedCapacity, sharingTargets := 0, 0, 0, 0, 0
	for _, target := range targets {
		if !target.Enabled {
			continue
		}
		switch strings.ToLower(target.Adapter) {
		case "llamacpp", "llama":
			llmTargets++
			if !target.CapacityVerified {
				unverifiedCapacity++
			}
		case "comfy":
			comfyTargets++
		case "openrouter":
			cloudTargets++
		}
		if target.SharingEnabled {
			sharingTargets++
		}
	}
	trustedProfiles := 0
	for _, profile := range profiles {
		if profile.Confidence >= .5 {
			trustedProfiles++
		}
	}
	guardedSharingSuccesses, guardedSharingRollbacks := 0, 0
	for _, sample := range samples {
		var predicted struct {
			GuardedExploration bool `json:"guarded_exploration"`
		}
		var observed struct {
			VRAMMB int64 `json:"vram_mb"`
		}
		if json.Unmarshal(sample.Predicted, &predicted) != nil || !predicted.GuardedExploration || json.Unmarshal(sample.Observed, &observed) != nil || observed.VRAMMB <= 0 {
			continue
		}
		if sample.Outcome == "succeeded" {
			guardedSharingSuccesses++
		} else {
			guardedSharingRollbacks++
		}
	}

	checks := []readinessCheck{
		{ID: "durable_state", Label: "Durable controller state", Status: persistenceStatus, Detail: persistenceDetail},
		{ID: "node_telemetry", Label: "Live accelerator telemetry", Status: ternaryStatus(connected > 0), Detail: countDetail(connected, "connected node", "connected nodes", "no connected node agent")},
		{ID: "local_llm", Label: "Local LLM route", Status: ternaryStatus(llmTargets > 0), Detail: countDetail(llmTargets, "enabled local LLM target", "enabled local LLM targets", "no enabled local LLM target")},
		{ID: "comfy", Label: "External ComfyUI route", Status: ternaryStatus(comfyTargets > 0), Detail: countDetail(comfyTargets, "enabled discovered/configured Comfy target", "enabled discovered/configured Comfy targets", "no enabled Comfy target; the dual-workload release gate is not met")},
		{ID: "capacity", Label: "Runtime-verified context and slots", Status: "ready", Detail: "all enabled local LLM targets report verified capacity"},
		{ID: "artifacts", Label: "Production object storage", Status: "partial", Detail: "filesystem artifact storage is active; suitable for development, not the production S3 durability boundary"},
		{ID: "cloud", Label: "OpenRouter fallback", Status: ternaryStatus(cloudTargets > 0), Detail: countDetail(cloudTargets, "enabled cloud target (live provider behavior is not asserted here)", "enabled cloud targets (live provider behavior is not asserted here)", "no enabled OpenRouter target")},
		{ID: "checkpoint", Label: "Runtime checkpoint / resume", Status: "missing", Detail: "the HTTP adapters currently return unsupported for yield, checkpoint, and resume"},
		{ID: "coscheduling", Label: "Measured adaptive co-scheduling", Status: "missing", Detail: "no sharing target with a trusted real-run interference profile"},
		{ID: "system_agent", Label: "Autonomous system-agent monitoring", Status: "partial", Detail: "a built-in node-loss observer opens and verifies recovery incidents; model-based evidence analysis and broader monitors are not running"},
	}
	if unverifiedCapacity > 0 {
		checks[4].Status = "partial"
		checks[4].Detail = fmt.Sprintf("%d enabled local LLM target(s) use configured/fallback rather than runtime-verified capacity", unverifiedCapacity)
	}
	if s.cfg.Workloads.ArtifactStore.Type == "s3" {
		checks[5].Status = "ready"
		checks[5].Detail = "S3-compatible artifact storage opened successfully at startup"
	}
	if guardedSharingSuccesses > 0 {
		checks[8].Status = "ready"
		checks[8].Detail = fmt.Sprintf("%d measured guarded co-scheduling success(es), %d rollback sample(s), and %d trusted profile(s) are persisted", guardedSharingSuccesses, guardedSharingRollbacks, trustedProfiles)
	} else if sharingTargets > 0 && trustedProfiles > 0 {
		checks[8].Status = "partial"
		checks[8].Detail = fmt.Sprintf("%d sharing target(s) and %d trusted profile(s) are configured; no guarded physical co-scheduling success is recorded", sharingTargets, trustedProfiles)
	}
	releaseGate := "not ready"
	if persistenceStatus == "ready" && connected > 0 && llmTargets > 0 && comfyTargets > 0 && unverifiedCapacity == 0 {
		releaseGate = "integration-ready; live acceptance still required"
	}
	return deploymentReadiness{Mode: mode, StateBackend: stateBackend, ArtifactBackend: s.cfg.Workloads.ArtifactStore.Type, ReleaseGate: releaseGate, Checks: checks}
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
	for index, incident := range incidents {
		incidents[index] = s.syncIncidentAnalysis(r.Context(), incident)
	}
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
	targets := s.workloads.Targets()
	writeJSON(w, http.StatusOK, map[string]any{"principal": p.ID, "readiness": s.readiness(nodes, targets, profiles, learning), "nodes": nodes, "targets": targets, "workloads": workloads, "events": events, "model_residencies": residencies, "residency_transitions": transitions, "notifications": notifications, "budget_reservations": budgets, "scheduler_learning_samples": learning, "interference_profiles": profiles, "performance_profiles": performanceProfiles, "transition_plans": transitionPlans, "node_commands": nodeCommands, "incidents": incidents})
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
