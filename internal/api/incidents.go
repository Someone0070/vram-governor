package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"vram-governor/internal/domain"
	"vram-governor/internal/store"
)

func severityRank(value string) int {
	switch value {
	case "S0":
		return 0
	case "S1":
		return 1
	case "S2":
		return 2
	case "S3":
		return 3
	case "S4":
		return 4
	default:
		return -1
	}
}

func clampSeverity(requested, ceiling string) string {
	if severityRank(requested) < 0 {
		requested = "S0"
	}
	if severityRank(ceiling) < 0 {
		ceiling = "S0"
	}
	if severityRank(requested) > severityRank(ceiling) {
		return ceiling
	}
	return requested
}

func (s *Server) handleCreateIncident(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requirePrincipal(w, r, "incidents:create")
	if !ok {
		return
	}
	var body struct {
		Severity     string   `json:"severity"`
		Confidence   float64  `json:"confidence"`
		Summary      string   `json:"summary"`
		EvidenceRefs []string `json:"evidence_refs"`
	}
	if err := decodeJSONLimit(r, &body, 1<<20); err != nil || body.Summary == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "summary is required"})
		return
	}
	if body.Confidence < 0 {
		body.Confidence = 0
	}
	if body.Confidence > 1 {
		body.Confidence = 1
	}
	now := time.Now().UTC()
	incident := &domain.Incident{ID: "inc-" + randomSecret()[:24], OwnerID: p.OwnerID, Severity: clampSeverity(body.Severity, p.MaxIncidentSeverity), Confidence: body.Confidence, Summary: body.Summary, EvidenceRefs: body.EvidenceRefs, Status: "open", CreatedAt: now, UpdatedAt: now}
	created, err := s.incidentStore.CreateIncident(r.Context(), incident)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	payload, _ := json.Marshal(map[string]string{"severity": created.Severity})
	_ = s.workloadStore.AppendAuditEvent(r.Context(), &domain.AuditEvent{ID: "evt-" + randomSecret()[:24], Timestamp: now, ActorID: p.ID, OwnerID: p.OwnerID, Type: "incident.created", Severity: "warn", Payload: payload})
	writeJSON(w, http.StatusCreated, created)
}

func (s *Server) handleListIncidents(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requirePrincipal(w, r, "incidents:read")
	if !ok {
		return
	}
	owner := p.OwnerID
	if hasScope(p, "admin") {
		owner = ""
	}
	rows, err := s.incidentStore.ListIncidents(r.Context(), owner)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	for index, incident := range rows {
		rows[index] = s.syncIncidentAnalysis(r.Context(), incident)
	}
	writeJSON(w, http.StatusOK, rows)
}

func (s *Server) getOwnedIncident(w http.ResponseWriter, r *http.Request, p Principal) (*domain.Incident, bool) {
	incident, err := s.incidentStore.GetIncident(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) || (err == nil && !hasScope(p, "admin") && incident.OwnerID != p.OwnerID) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "incident not found"})
		return nil, false
	}
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return nil, false
	}
	return incident, true
}

func (s *Server) handleGetIncident(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requirePrincipal(w, r, "incidents:read")
	if !ok {
		return
	}
	if incident, found := s.getOwnedIncident(w, r, p); found {
		writeJSON(w, http.StatusOK, s.syncIncidentAnalysis(r.Context(), incident))
	}
}

func (s *Server) syncIncidentAnalysis(ctx context.Context, incident *domain.Incident) *domain.Incident {
	if incident == nil || incident.AnalysisWorkloadID == "" || s.workloads == nil {
		return incident
	}
	analysis, err := s.workloads.Get(ctx, incident.AnalysisWorkloadID)
	if err != nil {
		return incident
	}
	changed := false
	if analysis.Plan != nil {
		provider := analysis.Plan.Provider
		if provider == "" {
			provider = analysis.Plan.Adapter
		}
		if provider != "" && incident.ActualProvider != provider {
			incident.ActualProvider = provider
			changed = true
		}
		if analysis.Plan.Model != "" && incident.ActualModel != analysis.Plan.Model {
			incident.ActualModel = analysis.Plan.Model
			changed = true
		}
	}
	previousStatus := incident.Status
	if incident.Status == "analyzing" {
		switch analysis.Status {
		case domain.WorkloadSucceeded:
			incident.Status = "verified"
		case domain.WorkloadFailed, domain.WorkloadRejected, domain.WorkloadCancelled:
			incident.Status = "analysis_failed"
		}
		changed = changed || incident.Status != previousStatus
	}
	if !changed {
		return incident
	}
	incident.UpdatedAt = time.Now().UTC()
	updated, err := s.incidentStore.UpdateIncident(ctx, incident)
	if err != nil {
		return incident
	}
	if previousStatus != updated.Status {
		payload, _ := json.Marshal(map[string]any{"analysis_workload_id": updated.AnalysisWorkloadID, "status": updated.Status, "provider": updated.ActualProvider, "model": updated.ActualModel})
		_ = s.workloadStore.AppendAuditEvent(ctx, &domain.AuditEvent{ID: "evt-" + randomSecret()[:24], Timestamp: updated.UpdatedAt, OwnerID: updated.OwnerID, WorkloadID: updated.AnalysisWorkloadID, Type: "incident.analysis." + updated.Status, Severity: "info", Payload: payload})
	}
	return updated
}

func (s *Server) handleIncidentProposal(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requirePrincipal(w, r, "incidents:propose")
	if !ok {
		return
	}
	incident, found := s.getOwnedIncident(w, r, p)
	if !found {
		return
	}
	proposal, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil || !json.Valid(proposal) {
		writeJSON(w, 400, map[string]string{"error": "valid proposal JSON is required"})
		return
	}
	incident.Proposal = proposal
	incident.Status = "proposed"
	incident.UpdatedAt = time.Now().UTC()
	updated, err := s.incidentStore.UpdateIncident(r.Context(), incident)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, updated)
}

func stringAllowed(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted || value == "*" {
			return true
		}
	}
	return false
}

func (s *Server) handleIncidentEscalation(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requirePrincipal(w, r, "incidents:escalate")
	if !ok {
		return
	}
	incident, found := s.getOwnedIncident(w, r, p)
	if !found {
		return
	}
	var body struct {
		Adapter                string `json:"adapter"`
		Provider               string `json:"provider"`
		Model                  string `json:"model"`
		RequestedModelTier     string `json:"requested_model_tier"`
		EvidenceClassification string `json:"evidence_classification"`
		EvidenceSanitized      bool   `json:"evidence_sanitized"`
		SanitizedSummary       string `json:"sanitized_summary"`
		ZDR                    bool   `json:"zdr"`
		PaidEmergency          bool   `json:"paid_emergency"`
	}
	if err := decodeJSONLimit(r, &body, 1<<20); err != nil || body.Adapter == "" || body.Model == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "adapter and model are required"})
		return
	}
	if !allowsAdapter(p, body.Adapter) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "adapter is outside principal authority"})
		return
	}
	cloud := body.Adapter == "openrouter" || (body.Provider != "" && !strings.EqualFold(body.Provider, "local"))
	egress := domain.EgressLocalOnly
	prompt := incident.Summary
	if cloud {
		if p.EgressPolicy == "" || p.EgressPolicy == string(domain.EgressLocalOnly) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "principal egress policy is local-only"})
			return
		}
		if !body.EvidenceSanitized || body.SanitizedSummary == "" || (body.EvidenceClassification != "public" && body.EvidenceClassification != "internal_sanitized") {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "cloud escalation requires classified, sanitized evidence and a sanitized summary"})
			return
		}
		if !stringAllowed(s.cfg.Agents.AllowedCloudProviders, body.Provider) || !stringAllowed(s.cfg.Agents.AllowedCloudModels, body.Model) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "cloud provider or model is not allowlisted"})
			return
		}
		if stringAllowed(s.cfg.Agents.QuarantinedModels, body.Model) {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "cloud model is quarantined pending evaluation"})
			return
		}
		if body.PaidEmergency && !s.cfg.Agents.PaidEmergencyFallback {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "paid emergency fallback is disabled"})
			return
		}
		// ZDR is recorded as provider policy metadata; redaction remains
		// mandatory and independent.
		_ = body.ZDR
		egress = domain.EgressSanitized
		prompt = body.SanitizedSummary
	} else if len(s.cfg.Agents.LocalVerifierModels) > 0 && !stringAllowed(s.cfg.Agents.LocalVerifierModels, body.Model) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "local verifier model is not allowlisted"})
		return
	}
	payload, _ := json.Marshal(map[string]any{"model": body.Model, "messages": []map[string]string{{"role": "system", "content": "Analyze the incident and return evidence-backed findings only."}, {"role": "user", "content": prompt}}})
	priority := 40
	if p.MaxPriority > 0 && priority > p.MaxPriority {
		priority = p.MaxPriority
	}
	analysis, _, err := s.workloads.Submit(r.Context(), domain.WorkloadRequest{OwnerID: p.OwnerID, PrincipalID: p.ID, Plane: domain.PlaneAgent, Adapter: body.Adapter, WorkloadType: "incident_verification", Payload: payload, ItemID: incident.ID, OperationVersion: "analysis-v1", IdempotencyKey: incident.ID + ":" + body.Provider + ":" + body.Model, QoS: domain.QoSInteractive, Priority: priority, QueuePolicy: domain.QueueWait, Disruption: domain.DisruptionLocked, Egress: egress, Recoverable: true, ConcurrencyLimit: p.ConcurrencyLimit, BudgetLimitCents: p.BudgetCents})
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
		return
	}
	incident.RequestedModelTier = body.RequestedModelTier
	incident.EvidenceClassification = body.EvidenceClassification
	incident.EvidenceSanitized = body.EvidenceSanitized
	incident.Egress = egress
	incident.AnalysisWorkloadID = analysis.Request.ID
	incident.ActualProvider = body.Provider
	if incident.ActualProvider == "" {
		incident.ActualProvider = "local"
	}
	incident.ActualModel = body.Model
	incident.Status = "analyzing"
	incident.UpdatedAt = time.Now().UTC()
	updated, err := s.incidentStore.UpdateIncident(r.Context(), incident)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	payloadAudit, _ := json.Marshal(map[string]any{"analysis_workload_id": analysis.Request.ID, "provider": incident.ActualProvider, "model": incident.ActualModel, "egress": egress, "zdr": body.ZDR})
	_ = s.workloadStore.AppendAuditEvent(r.Context(), &domain.AuditEvent{ID: "evt-" + randomSecret()[:24], Timestamp: incident.UpdatedAt, ActorID: p.ID, OwnerID: p.OwnerID, WorkloadID: analysis.Request.ID, Type: "incident.escalated", Severity: "warn", Payload: payloadAudit})
	writeJSON(w, http.StatusAccepted, updated)
}

func (s *Server) handleAgentEvents(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requirePrincipal(w, r, "agent:events")
	if !ok {
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeJSON(w, 500, map[string]string{"error": "streaming unsupported"})
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	events, unsubscribe := s.workloads.Subscribe()
	defer unsubscribe()
	for {
		select {
		case <-r.Context().Done():
			return
		case event := <-events:
			if !hasScope(p, "admin") && event.OwnerID != p.OwnerID {
				continue
			}
			encoded, _ := json.Marshal(event)
			_, _ = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event.Type, encoded)
			flusher.Flush()
		}
	}
}
