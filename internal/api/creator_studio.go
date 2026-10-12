package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"vram-governor/internal/domain"
	"vram-governor/internal/store"
	"vram-governor/internal/workflowtpl"
	"vram-governor/internal/workloads"
)

func decodeStrictCreator(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	return decoder.Decode(target)
}

type creatorStudioRequest struct {
	WorkloadID         string                         `json:"workload_id"`
	IdempotencyKey     string                         `json:"idempotency_key"`
	Operation          string                         `json:"operation"`
	QualityClass       string                         `json:"quality_class"`
	Requirements       domain.CapabilityRequirements  `json:"requirements"`
	ProfilePreferences domain.ProfilePreferences      `json:"profile_preferences"`
	Inputs             json.RawMessage                `json:"inputs"`
	Payload            json.RawMessage                `json:"payload"`
	AffinityKey        string                         `json:"affinity_key"`
	SessionID          string                         `json:"session_id"`
	BatchID            string                         `json:"batch_id"`
	Priority           string                         `json:"priority"`
	LatencyClass       string                         `json:"latency_class"`
	Parallelism        domain.ParallelismPolicy       `json:"parallelism"`
	Ordered            bool                           `json:"ordered"`
	Dependencies       []string                       `json:"dependencies"`
	ContinuationRef    string                         `json:"continuation_ref"`
	CompatibilityToken string                         `json:"compatibility_token"`
	Deadline           *time.Time                     `json:"deadline"`
	Bounds             domain.WorkloadBounds          `json:"bounds"`
	QueuePolicy        domain.QueuePolicy             `json:"queue_policy"`
	Disruption         domain.DisruptionPolicy        `json:"disruption"`
	Egress             domain.EgressPolicy            `json:"egress"`
	Notifications      domain.NotificationPreferences `json:"notifications"`
	ArtifactRefs       []string                       `json:"artifact_refs"`
	// Workflow names a parameterized template (GET /api/v1/workflows); the
	// controller compiles Params into the graph payload.
	Workflow string         `json:"workflow"`
	Params   map[string]any `json:"params"`
}

type creatorBatchRequest struct {
	BatchID        string                 `json:"batch_id"`
	AffinityKey    string                 `json:"affinity_key"`
	Ordered        bool                   `json:"ordered"`
	Parallelizable bool                   `json:"parallelizable"`
	Items          []creatorStudioRequest `json:"items"`
}

type creatorBatchRejection struct {
	Index      int            `json:"index"`
	WorkloadID string         `json:"workload_id,omitempty"`
	Status     string         `json:"status"`
	Reason     string         `json:"reason"`
	Missing    []string       `json:"missing,omitempty"`
	Details    map[string]any `json:"details,omitempty"`
}

type creatorArtifactOutput struct {
	ArtifactRef   string                        `json:"artifact_ref"`
	MediaType     string                        `json:"media_type,omitempty"`
	Producer      *domain.ArtifactProducer      `json:"producer,omitempty"`
	Compatibility *domain.ArtifactCompatibility `json:"compatibility,omitempty"`
}

type creatorProfileIdentity struct {
	ProfileID                string `json:"profile_id"`
	Version                  string `json:"version"`
	Digest                   string `json:"digest"`
	CapabilityRevision       string `json:"capability_revision"`
	CapabilityDefinitionHash string `json:"capability_definition_hash"`
}

type creatorWorkloadResponse struct {
	WorkloadID          string                  `json:"workload_id"`
	Status              string                  `json:"status"`
	Operation           string                  `json:"operation"`
	BatchID             string                  `json:"batch_id,omitempty"`
	AffinityKey         string                  `json:"affinity_key,omitempty"`
	Profile             *creatorProfileIdentity `json:"profile,omitempty"`
	Reason              string                  `json:"reason,omitempty"`
	Missing             []string                `json:"missing,omitempty"`
	Progress            float64                 `json:"progress,omitempty"`
	ProgressStage       string                  `json:"progress_stage,omitempty"`
	ProgressCurrent     int                     `json:"progress_current,omitempty"`
	ProgressTotal       int                     `json:"progress_total,omitempty"`
	Outputs             []creatorArtifactOutput `json:"outputs,omitempty"`
	ContinuationRef     string                  `json:"continuation_ref,omitempty"`
	InfrastructureError string                  `json:"infrastructure_error,omitempty"`
	// Workflow echoes the template and the effective params (defaults and
	// the chosen seed filled in) so a result can be reproduced exactly.
	Workflow *creatorWorkflowEcho `json:"workflow,omitempty"`
	// Machine-readable admission detail for queued/blocked rows. Reason stays
	// the Creator Studio enum; these mirror the scheduler decision.
	BlockerCode       domain.AdmissionBlocker `json:"blocker_code,omitempty"`
	EstimatedStart    *time.Time              `json:"estimated_start,omitempty"`
	RetryAfterSeconds int                     `json:"retry_after_seconds,omitempty"`
	Alternatives      []string                `json:"alternatives,omitempty"`
}

type creatorWorkflowEcho struct {
	Ref    string         `json:"ref"`
	Params map[string]any `json:"params"`
}

type creatorBlockedResponse struct {
	Status                      string         `json:"status"`
	Reason                      string         `json:"reason"`
	Missing                     []string       `json:"missing"`
	AcceptableProfilesAvailable []string       `json:"acceptable_profiles_available"`
	Details                     map[string]any `json:"details,omitempty"`
}

func creatorPriority(class, latency string) (domain.QoSClass, int, error) {
	baseQoS := domain.QoSNormal
	if latency == "interactive" {
		baseQoS = domain.QoSInteractive
	} else if latency == "background" {
		baseQoS = domain.QoSBackground
	}
	switch class {
	case "", "production":
		return baseQoS, 50, nil
	case "interactive_user":
		return domain.QoSInteractive, 90, nil
	case "review_blocking":
		return domain.QoSInteractive, 75, nil
	case "autonomous_content":
		return baseQoS, 20, nil
	case "background_calibration":
		return domain.QoSBackground, 5, nil
	case "maintenance":
		return domain.QoSBackground, 0, nil
	default:
		return "", 0, fmt.Errorf("unsupported priority %q", class)
	}
}

func stripArtifactScheme(ref string) string {
	return strings.TrimPrefix(strings.TrimSpace(ref), "artifact://")
}

func creatorPayload(body creatorStudioRequest) (json.RawMessage, []string, error) {
	payload := body.Payload
	if len(payload) == 0 {
		payload = body.Inputs
	}
	if len(payload) == 0 {
		payload = json.RawMessage(`{}`)
	}
	if !json.Valid(payload) {
		return nil, nil, fmt.Errorf("payload or inputs must contain valid JSON")
	}
	if body.ContinuationRef != "" {
		var object map[string]any
		if err := json.Unmarshal(payload, &object); err != nil || object == nil {
			return nil, nil, fmt.Errorf("continuation_ref requires an object payload")
		}
		if _, supplied := object["continuation_ref"]; !supplied {
			object["continuation_ref"] = body.ContinuationRef
		}
		payload, _ = json.Marshal(object)
	}
	if body.CompatibilityToken != "" {
		var object map[string]any
		if err := json.Unmarshal(payload, &object); err != nil || object == nil {
			return nil, nil, fmt.Errorf("compatibility_token requires an object payload")
		}
		if _, supplied := object["compatibility_token"]; !supplied {
			object["compatibility_token"] = body.CompatibilityToken
		}
		payload, _ = json.Marshal(object)
	}
	refs := append([]string(nil), body.ArtifactRefs...)
	var inputs struct {
		ArtifactRefs []string `json:"artifact_refs"`
	}
	_ = json.Unmarshal(body.Inputs, &inputs)
	refs = append(refs, inputs.ArtifactRefs...)
	for index := range refs {
		refs[index] = stripArtifactScheme(refs[index])
		if refs[index] == "" {
			return nil, nil, fmt.Errorf("artifact references may not be empty")
		}
	}
	return payload, refs, nil
}

func profileRequiresCompatibility(profile domain.RuntimeProfile, operation string) bool {
	return containsText(profile.CompatibilityOperations, operation)
}

func (s *Server) compatibleCreatorProfiles(r *http.Request, principal Principal, profiles []domain.RuntimeProfile, operation string, refs []string, token string) ([]domain.RuntimeProfile, *creatorBlockedResponse, error) {
	if len(refs) == 0 {
		compatible := make([]domain.RuntimeProfile, 0, len(profiles))
		for _, profile := range profiles {
			if !profileRequiresCompatibility(profile, operation) && token == "" {
				compatible = append(compatible, profile)
			}
		}
		if len(compatible) > 0 {
			return compatible, nil, nil
		}
		return nil, &creatorBlockedResponse{Status: "blocked", Reason: "SOURCE_ARTIFACT_INCOMPATIBLE", Missing: []string{"source artifact and compatibility token"}, AcceptableProfilesAvailable: []string{}, Details: map[string]any{"operation": operation}}, nil
	}
	if s.artifacts == nil {
		return nil, nil, fmt.Errorf("artifact store is unavailable")
	}
	resolved := make([]*domain.Artifact, 0, len(refs))
	for _, ref := range refs {
		artifact, reader, err := s.artifacts.Open(r.Context(), ref)
		if reader != nil {
			reader.Close()
		}
		if err != nil || (!hasScope(principal, "admin") && artifact.OwnerID != principal.OwnerID) {
			return nil, nil, fmt.Errorf("artifact %q is unavailable", ref)
		}
		resolved = append(resolved, artifact)
	}
	compatible := make([]domain.RuntimeProfile, 0, len(profiles))
	for _, profile := range profiles {
		valid := true
		for _, artifact := range resolved {
			if !workloads.MediaTypeMatches(profile.AcceptedArtifactTypes, artifact.MediaType) {
				valid = false
				break
			}
		}
		if valid && (profileRequiresCompatibility(profile, operation) || token != "") {
			valid = false
			for _, artifact := range resolved {
				compatibility := artifact.Compatibility
				if compatibility == nil || artifact.Producer == nil || compatibility.SourceArtifactID != artifact.ID || compatibility.ProducerImplementation != profile.Ref() || compatibility.CapabilityRevision != profile.CapabilityRevision || compatibility.CapabilityDefinitionHash != profile.CapabilityDefinitionHash || artifact.Producer.ProfileID != profile.ProfileID || artifact.Producer.ProfileVersion != profile.Version || artifact.Producer.ProfileDigest != profile.Digest || artifact.Producer.CapabilityRevision != profile.CapabilityRevision || artifact.Producer.CapabilityDefinitionHash != profile.CapabilityDefinitionHash {
					continue
				}
				if expected := compatibility.Tokens[operation]; expected != "" && expected == token {
					valid = true
					break
				}
			}
		}
		if valid {
			compatible = append(compatible, profile)
		}
	}
	if len(compatible) == 0 {
		publicRefs := make([]string, 0, len(refs))
		for _, ref := range refs {
			publicRefs = append(publicRefs, "artifact://"+ref)
		}
		return nil, &creatorBlockedResponse{Status: "blocked", Reason: "SOURCE_ARTIFACT_INCOMPATIBLE", Missing: []string{"compatible source artifact"}, AcceptableProfilesAvailable: []string{}, Details: map[string]any{"operation": operation, "artifact_refs": publicRefs}}, nil
	}
	return compatible, nil, nil
}

func canonicalProfileGroups(preferences domain.ProfilePreferences, resolved []domain.RuntimeProfile) domain.ProfilePreferences {
	matchGroup := func(selectors []string) []string {
		var result []string
		seen := map[string]struct{}{}
		for _, selector := range selectors {
			for _, profile := range resolved {
				ref := profile.Ref()
				if selector != profile.ProfileID && selector != ref {
					continue
				}
				if _, found := seen[ref]; !found {
					seen[ref] = struct{}{}
					result = append(result, ref)
				}
			}
		}
		return result
	}
	canonical := domain.ProfilePreferences{FallbackPolicy: preferences.FallbackPolicy}
	canonical.Preferred = matchGroup(preferences.Preferred)
	canonical.Acceptable = matchGroup(preferences.Acceptable)
	if len(preferences.Preferred) == 0 && len(preferences.Acceptable) == 0 {
		for _, profile := range resolved {
			canonical.Preferred = append(canonical.Preferred, profile.Ref())
		}
		canonical.FallbackPolicy = "preferred_only"
	}
	if canonical.FallbackPolicy == "" {
		canonical.FallbackPolicy = "explicit"
	}
	return canonical
}

// compileCreatorWorkflow turns workflow+params into the graph payload a
// hand-written request would carry. The template supplies the operation and
// profile; explicit values must agree with it.
func (s *Server) compileCreatorWorkflow(body *creatorStudioRequest) error {
	if len(body.Payload) > 0 || len(body.Inputs) > 0 {
		return fmt.Errorf("a workflow request takes params, not payload or inputs")
	}
	var registry *workflowtpl.Registry
	if s.cfg != nil {
		registry = s.cfg.WorkflowTemplates
	}
	template, err := registry.Get(body.Workflow)
	if err != nil {
		return err
	}
	if body.Operation == "" {
		body.Operation = template.Operation
	} else if body.Operation != template.Operation {
		return fmt.Errorf("workflow %s runs operation %s, not %s", template.Ref(), template.Operation, body.Operation)
	}
	prefs := body.ProfilePreferences
	if len(prefs.Preferred) == 0 && len(prefs.Acceptable) == 0 {
		body.ProfilePreferences = domain.ProfilePreferences{Preferred: []string{template.Profile}, FallbackPolicy: "explicit"}
	} else if !slices.Contains(prefs.Preferred, template.Profile) && !slices.Contains(prefs.Acceptable, template.Profile) {
		return fmt.Errorf("workflow %s runs under profile %s, which profile_preferences exclude", template.Ref(), template.Profile)
	}
	compiled, err := template.Compile(body.Params)
	if err != nil {
		return err
	}
	payload, err := json.Marshal(map[string]any{
		"managed_chunks": []any{map[string]any{"id": body.WorkloadID, "prompt": compiled.Graph}},
		"workflow":       creatorWorkflowEcho{Ref: template.Ref(), Params: compiled.Params},
	})
	if err != nil {
		return err
	}
	body.Payload = payload
	for _, ref := range compiled.ArtifactRefs {
		if !slices.Contains(body.ArtifactRefs, ref) {
			body.ArtifactRefs = append(body.ArtifactRefs, ref)
		}
	}
	return nil
}

func (s *Server) buildCreatorWorkload(r *http.Request, principal Principal, body creatorStudioRequest) (domain.WorkloadRequest, *creatorBlockedResponse, error) {
	if body.WorkloadID == "" && body.IdempotencyKey == "" {
		return domain.WorkloadRequest{}, nil, fmt.Errorf("workload_id or idempotency_key is required")
	}
	if body.WorkloadID == "" {
		body.WorkloadID = "wl-" + randomSecret()[:24]
	}
	if body.IdempotencyKey == "" {
		body.IdempotencyKey = "creator-studio:" + body.WorkloadID
	}
	if body.Workflow != "" {
		if err := s.compileCreatorWorkflow(&body); err != nil {
			return domain.WorkloadRequest{}, nil, err
		}
	} else if body.Params != nil {
		return domain.WorkloadRequest{}, nil, fmt.Errorf("params require a workflow")
	}
	if body.Operation == "" {
		return domain.WorkloadRequest{}, nil, fmt.Errorf("operation is required")
	}
	if body.QualityClass == "" {
		body.QualityClass = "final"
	}
	if body.LatencyClass == "" {
		body.LatencyClass = "batch"
	}
	if body.ProfilePreferences.FallbackPolicy == "" {
		body.ProfilePreferences.FallbackPolicy = "explicit"
	}
	if body.Deadline != nil && !body.Deadline.After(time.Now()) {
		return domain.WorkloadRequest{}, &creatorBlockedResponse{Status: "blocked", Reason: "DEADLINE_EXPIRED", Missing: []string{}, AcceptableProfilesAvailable: []string{}}, nil
	}
	if body.CompatibilityToken != "" && body.ContinuationRef != "" && body.CompatibilityToken != body.ContinuationRef {
		return domain.WorkloadRequest{}, nil, fmt.Errorf("compatibility_token and continuation_ref must match when both are supplied")
	}
	qos, priority, err := creatorPriority(body.Priority, body.LatencyClass)
	if err != nil {
		return domain.WorkloadRequest{}, nil, err
	}
	resolution, err := s.workloads.ResolveCreatorProfiles(r.Context(), body.Operation, body.QualityClass, body.Requirements, body.ProfilePreferences)
	if err != nil {
		return domain.WorkloadRequest{}, nil, err
	}
	if resolution.Reason != "" {
		return domain.WorkloadRequest{}, &creatorBlockedResponse{Status: "blocked", Reason: resolution.Reason, Missing: resolution.Missing, AcceptableProfilesAvailable: []string{}}, nil
	}
	payload, refs, err := creatorPayload(body)
	if err != nil {
		return domain.WorkloadRequest{}, nil, err
	}
	token := body.CompatibilityToken
	if token == "" {
		token = body.ContinuationRef
	}
	compatible, incompatible, err := s.compatibleCreatorProfiles(r, principal, resolution.Profiles, body.Operation, refs, token)
	if err != nil {
		return domain.WorkloadRequest{}, nil, err
	}
	if incompatible != nil {
		return domain.WorkloadRequest{}, incompatible, nil
	}
	resolution.Profiles = compatible
	request := domain.WorkloadRequest{
		ID: body.WorkloadID, Plane: domain.PlaneCreatorStudio, Adapter: resolution.Adapter,
		WorkloadType: body.Operation, Operation: body.Operation, QualityClass: body.QualityClass,
		CapabilityRequirements: body.Requirements, ProfilePreferences: canonicalProfileGroups(body.ProfilePreferences, resolution.Profiles),
		Payload: payload, ArtifactRefs: refs, ItemID: body.WorkloadID, OperationVersion: "creator-v3r4",
		IdempotencyKey: body.IdempotencyKey, QoS: qos, Priority: priority, PriorityClass: body.Priority,
		Deadline: body.Deadline, QueuePolicy: body.QueuePolicy, Notifications: body.Notifications,
		Disruption: body.Disruption, Egress: body.Egress, Bounds: body.Bounds,
		SessionID: body.SessionID, BatchID: body.BatchID, AffinityKey: body.AffinityKey,
		Ordered: body.Ordered, Parallelism: body.Parallelism, Dependencies: append([]string(nil), body.Dependencies...),
		LatencyClass: body.LatencyClass, ContinuationRef: body.ContinuationRef, CompatibilityToken: token, Recoverable: true,
	}
	if request.QueuePolicy == "" {
		request.QueuePolicy = domain.QueueWait
	}
	if request.Disruption == "" {
		request.Disruption = domain.DisruptionLocked
	}
	return request, nil, nil
}

func (s *Server) creatorResponse(ctx *http.Request, row *domain.Workload) creatorWorkloadResponse {
	response := creatorWorkloadResponse{WorkloadID: row.Request.ID, Operation: row.Request.Operation, BatchID: row.Request.BatchID, AffinityKey: row.Request.AffinityKey, Progress: row.Progress, ProgressStage: row.ProgressStage, ProgressCurrent: row.ProgressCurrent, ProgressTotal: row.ProgressTotal}
	var compiled struct {
		Workflow *creatorWorkflowEcho `json:"workflow"`
	}
	if json.Unmarshal(row.Request.Payload, &compiled) == nil && compiled.Workflow != nil && compiled.Workflow.Ref != "" {
		response.Workflow = compiled.Workflow
	}
	switch row.Status {
	case domain.WorkloadQueued:
		response.Status = "queued"
	case domain.WorkloadWaiting:
		response.Status = "queued"
		response.Reason = s.creatorBlockingReason(ctx, row)
		if strings.HasPrefix(row.Decision.Blocker, "DEPENDENCY_") {
			response.Status, response.Reason = "blocked", row.Decision.Blocker
		}
		if response.Reason == "CAPACITY_UNAVAILABLE" || response.Reason == "NO_FEASIBLE_ROUTE" {
			response.Status = "blocked"
		}
	case domain.WorkloadPendingApproval:
		response.Status, response.Reason = "blocked", "APPROVAL_REQUIRED"
	case domain.WorkloadRunning:
		if row.Execution == nil {
			response.Status = "preparing"
		} else {
			response.Status = "running"
		}
	case domain.WorkloadSucceeded:
		response.Status = "completed"
	case domain.WorkloadCancelled:
		response.Status = "cancelled"
	case domain.WorkloadRejected:
		response.Status, response.Reason = "blocked", s.creatorBlockingReason(ctx, row)
	case domain.WorkloadFailed:
		response.Status, response.InfrastructureError = "failed", row.Error
	default:
		response.Status = "queued"
	}
	if (row.Status == domain.WorkloadWaiting || row.Status == domain.WorkloadRejected) && !row.Decision.Admitted {
		response.BlockerCode = row.Decision.BlockerCode
		if response.BlockerCode == "" && row.Decision.Blocker != "" {
			response.BlockerCode = workloads.ClassifyBlocker(row.Decision.Blocker)
		}
		response.Alternatives = row.Decision.Alternatives
		// Only real estimates are published: ETA is set by the scheduler when the
		// start time is history-backed (or a known min_residency expiry).
		if row.Decision.ETA != nil {
			eta := *row.Decision.ETA
			response.EstimatedStart = &eta
		}
		if row.Decision.RetryAfter != nil {
			if seconds := int(time.Until(*row.Decision.RetryAfter).Seconds()); seconds > 0 {
				response.RetryAfterSeconds = seconds
			} else {
				response.RetryAfterSeconds = 1
			}
		}
	}
	if row.Plan != nil && row.Plan.ProfileID != "" {
		response.Profile = &creatorProfileIdentity{ProfileID: row.Plan.ProfileID, Version: row.Plan.ProfileVersion, Digest: row.Plan.ProfileDigest, CapabilityRevision: row.Plan.CapabilityRevision, CapabilityDefinitionHash: row.Plan.CapabilityDefinitionHash}
	}
	for _, ref := range row.OutputRefs {
		output := creatorArtifactOutput{ArtifactRef: "artifact://" + ref}
		if s.artifacts != nil {
			artifact, reader, err := s.artifacts.Open(ctx.Context(), ref)
			if reader != nil {
				reader.Close()
			}
			if err == nil && artifact.OwnerID == row.Request.OwnerID {
				output.MediaType, output.Producer, output.Compatibility = artifact.MediaType, artifact.Producer, artifact.Compatibility
			}
		}
		response.Outputs = append(response.Outputs, output)
	}
	if len(row.InlineOutput) > 0 {
		var output struct {
			ContinuationRef string `json:"continuation_ref"`
		}
		_ = json.Unmarshal(row.InlineOutput, &output)
		response.ContinuationRef = output.ContinuationRef
	}
	return response
}

func (s *Server) creatorBlockingReason(r *http.Request, row *domain.Workload) string {
	blocker := strings.ToLower(row.Decision.Blocker)
	if strings.Contains(blocker, "deadline") {
		return "DEADLINE_EXPIRED"
	}
	if strings.Contains(blocker, "approval") {
		return "APPROVAL_REQUIRED"
	}
	if strings.HasPrefix(row.Decision.Blocker, "DEPENDENCY_") {
		return row.Decision.Blocker
	}
	capabilities, err := s.workloads.Capabilities(r.Context())
	if err != nil {
		return "NO_FEASIBLE_ROUTE"
	}
	allowed := append(append([]string(nil), row.Request.ProfilePreferences.Preferred...), row.Request.ProfilePreferences.Acceptable...)
	available, busy, defined := false, false, false
	for _, profile := range capabilities {
		if !containsText(allowed, profile.Ref()) {
			continue
		}
		defined = true
		switch profile.Status {
		case workloads.ProfileAvailable:
			available = true
		case workloads.ProfileTemporarilyBusy:
			busy = true
		}
	}
	if !defined {
		return "CAPABILITY_UNAVAILABLE"
	}
	if busy && !available {
		return "TEMPORARILY_BUSY"
	}
	if !available && !busy {
		return "CAPACITY_UNAVAILABLE"
	}
	return "NO_FEASIBLE_ROUTE"
}

func containsText(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func (s *Server) handleCreatorCapabilities(w http.ResponseWriter, r *http.Request) {
	if s.workloadsUnavailable(w) {
		return
	}
	if _, ok := s.requirePrincipal(w, r, "workloads:read"); !ok {
		return
	}
	profiles, err := s.workloads.Capabilities(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	workflows := []workflowSummary{}
	for _, t := range s.workflowRegistry().All() {
		workflows = append(workflows, summarizeWorkflow(t))
	}
	writeJSON(w, http.StatusOK, map[string]any{"profiles": profiles, "workflows": workflows})
}

type workflowSummary struct {
	Ref            string              `json:"ref"`
	ID             string              `json:"id"`
	Version        int                 `json:"version"`
	Title          string              `json:"title"`
	Description    string              `json:"description,omitempty"`
	Operation      string              `json:"operation"`
	Profile        string              `json:"profile"`
	Outputs        []string            `json:"outputs,omitempty"`
	TypicalSeconds int                 `json:"typical_seconds,omitempty"`
	Params         []workflowParamInfo `json:"params"`
}

// workflowParamInfo is the public view of a parameter: node bindings are
// controller-private.
type workflowParamInfo struct {
	Name        string   `json:"name"`
	Type        string   `json:"type"`
	Description string   `json:"description,omitempty"`
	Required    bool     `json:"required,omitempty"`
	Default     any      `json:"default,omitempty"`
	Min         *float64 `json:"min,omitempty"`
	Max         *float64 `json:"max,omitempty"`
	MultipleOf  int64    `json:"multiple_of,omitempty"`
	MaxLength   int      `json:"max_length,omitempty"`
	Values      []string `json:"values,omitempty"`
}

func summarizeWorkflow(t *workflowtpl.Template) workflowSummary {
	out := workflowSummary{Ref: t.Ref(), ID: t.ID, Version: t.Version, Title: t.Title, Description: t.Description, Operation: t.Operation, Profile: t.Profile, Outputs: t.Outputs, TypicalSeconds: t.TypicalSeconds, Params: []workflowParamInfo{}}
	for _, p := range t.Params {
		out.Params = append(out.Params, workflowParamInfo{Name: p.Name, Type: p.Type, Description: p.Description, Required: p.Required, Default: p.Default, Min: p.Min, Max: p.Max, MultipleOf: p.MultipleOf, MaxLength: p.MaxLength, Values: p.Values})
	}
	return out
}

func (s *Server) workflowRegistry() *workflowtpl.Registry {
	if s.cfg == nil {
		return nil
	}
	return s.cfg.WorkflowTemplates
}

func (s *Server) handleListWorkflows(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requirePrincipal(w, r, "workloads:read"); !ok {
		return
	}
	list := []workflowSummary{}
	for _, t := range s.workflowRegistry().All() {
		list = append(list, summarizeWorkflow(t))
	}
	writeJSON(w, http.StatusOK, map[string]any{"workflows": list})
}

func (s *Server) handleGetWorkflow(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requirePrincipal(w, r, "workloads:read"); !ok {
		return
	}
	t, err := s.workflowRegistry().Get(r.PathValue("ref"))
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, summarizeWorkflow(t))
}

func (s *Server) handleCreatorBatch(w http.ResponseWriter, r *http.Request) {
	if s.workloadsUnavailable(w) {
		return
	}
	principal, ok := s.requirePrincipal(w, r, "workloads:submit")
	if !ok {
		return
	}
	var batch creatorBatchRequest
	if err := decodeJSONLimit(r, &batch, 32<<20); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if batch.BatchID == "" || len(batch.Items) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "batch_id and at least one item are required"})
		return
	}
	accepted := make([]creatorWorkloadResponse, 0, len(batch.Items))
	rejected := make([]creatorBatchRejection, 0)
	previous := ""
	orderedBlocked := false
	for index, item := range batch.Items {
		item.BatchID, item.Ordered = batch.BatchID, batch.Ordered
		item.Parallelism.Parallelizable = batch.Parallelizable
		if item.AffinityKey == "" {
			item.AffinityKey = batch.AffinityKey
		}
		if item.WorkloadID == "" {
			item.WorkloadID = fmt.Sprintf("%s-%04d", batch.BatchID, index+1)
		}
		if item.IdempotencyKey == "" {
			item.IdempotencyKey = fmt.Sprintf("creator-batch:%s:%s", batch.BatchID, item.WorkloadID)
		}
		if batch.Ordered && orderedBlocked {
			rejected = append(rejected, creatorBatchRejection{Index: index, WorkloadID: item.WorkloadID, Status: "blocked", Reason: "DEPENDENCY_UNAVAILABLE", Details: map[string]any{"dependency": previous}})
			continue
		}
		if batch.Ordered && previous != "" {
			item.Dependencies = append(item.Dependencies, previous)
		}
		request, blocked, err := s.buildCreatorWorkload(r, principal, item)
		if err != nil {
			rejected = append(rejected, creatorBatchRejection{Index: index, WorkloadID: item.WorkloadID, Status: "blocked", Reason: "INVALID_REQUEST", Details: map[string]any{"message": err.Error()}})
			orderedBlocked = batch.Ordered
			previous = item.WorkloadID
			continue
		}
		if blocked != nil {
			rejected = append(rejected, creatorBatchRejection{Index: index, WorkloadID: item.WorkloadID, Status: "blocked", Reason: blocked.Reason, Missing: blocked.Missing, Details: blocked.Details})
			orderedBlocked = batch.Ordered
			previous = item.WorkloadID
			continue
		}
		if err := s.prepareRequest(r, principal, &request); err != nil {
			rejected = append(rejected, creatorBatchRejection{Index: index, WorkloadID: item.WorkloadID, Status: "blocked", Reason: "POLICY_DENIED", Details: map[string]any{"message": err.Error()}})
			orderedBlocked = batch.Ordered
			previous = item.WorkloadID
			continue
		}
		row, _, err := s.workloads.Submit(r.Context(), request)
		if err != nil {
			rejected = append(rejected, creatorBatchRejection{Index: index, WorkloadID: item.WorkloadID, Status: "blocked", Reason: "SUBMISSION_REJECTED", Details: map[string]any{"message": err.Error()}})
			orderedBlocked = batch.Ordered
			previous = item.WorkloadID
			continue
		}
		accepted = append(accepted, s.creatorResponse(r, row))
		previous = request.ID
	}
	status := http.StatusCreated
	if len(rejected) > 0 && len(accepted) > 0 {
		status = http.StatusMultiStatus
	} else if len(accepted) == 0 {
		status = http.StatusUnprocessableEntity
	}
	writeJSON(w, status, map[string]any{"batch_id": batch.BatchID, "partial_acceptance": len(rejected) > 0, "items": accepted, "accepted": accepted, "rejected": rejected})
}

func (s *Server) handleCreatorBatchStatus(w http.ResponseWriter, r *http.Request) {
	if s.workloadsUnavailable(w) {
		return
	}
	principal, ok := s.requirePrincipal(w, r, "workloads:read")
	if !ok {
		return
	}
	rows, err := s.workloads.List(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	items := make([]creatorWorkloadResponse, 0)
	completed, failed := 0, 0
	for _, row := range rows {
		if row.Request.Plane != domain.PlaneCreatorStudio || row.Request.BatchID != r.PathValue("batch_id") || (!hasScope(principal, "admin") && row.Request.OwnerID != principal.OwnerID) {
			continue
		}
		item := s.creatorResponse(r, row)
		items = append(items, item)
		if item.Status == "completed" || item.Status == "cancelled" {
			completed++
		}
		if item.Status == "failed" {
			failed++
		}
	}
	if len(items) == 0 {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "batch not found"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"batch_id": r.PathValue("batch_id"), "items_total": len(items), "items_complete": completed, "items_failed": failed, "progress": float64(completed+failed) / float64(len(items)), "items": items})
}

func (s *Server) creatorStore() (store.CreatorStudioStore, bool) {
	creatorStore, ok := s.workloadStore.(store.CreatorStudioStore)
	return creatorStore, ok
}

func validateWorkingSetRefs(workingSet *domain.WorkingSet) error {
	for _, refs := range [][]string{workingSet.DesiredProfiles, workingSet.LikelyNextProfiles, workingSet.UnlikelyProfiles} {
		for _, ref := range refs {
			if !strings.Contains(ref, "@") {
				return fmt.Errorf("working-set profile %q must include immutable @version", ref)
			}
		}
	}
	return nil
}

func (s *Server) handleUpsertWorkingSet(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requirePrincipal(w, r, "workloads:submit")
	if !ok {
		return
	}
	creatorStore, ok := s.creatorStore()
	if !ok {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "working-set store unavailable"})
		return
	}
	var workingSet domain.WorkingSet
	if err := decodeJSONLimit(r, &workingSet, 1<<20); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if pathSession := r.PathValue("session_id"); pathSession != "" {
		workingSet.SessionID = pathSession
	}
	if pathPhase := r.PathValue("phase_id"); pathPhase != "" {
		workingSet.PhaseID = pathPhase
	}
	if workingSet.SessionID == "" || workingSet.PhaseID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "session_id and phase_id are required"})
		return
	}
	if err := validateWorkingSetRefs(&workingSet); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	now := time.Now().UTC()
	workingSet.OwnerID, workingSet.UpdatedAt, workingSet.ReleasedAt = principal.OwnerID, now, nil
	if workingSet.CreatedAt.IsZero() {
		workingSet.CreatedAt = now
	}
	stored, err := creatorStore.UpsertWorkingSet(r.Context(), &workingSet)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, stored)
}

func (s *Server) handleListWorkingSets(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requirePrincipal(w, r, "workloads:read")
	if !ok {
		return
	}
	creatorStore, ok := s.creatorStore()
	if !ok {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "working-set store unavailable"})
		return
	}
	sets, err := creatorStore.ListWorkingSets(r.Context(), principal.OwnerID, r.PathValue("session_id"), r.URL.Query().Get("include_released") == "true")
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"working_sets": sets})
}

func (s *Server) handleReleaseWorkingSet(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requirePrincipal(w, r, "workloads:submit")
	if !ok {
		return
	}
	creatorStore, ok := s.creatorStore()
	if !ok {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "working-set store unavailable"})
		return
	}
	sessionID := r.PathValue("session_id")
	if sessionID == "" {
		sessionID = r.URL.Query().Get("session_id")
	}
	phaseID := r.PathValue("phase_id")
	if sessionID == "" || phaseID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "session_id and phase_id are required"})
		return
	}
	released, err := creatorStore.ReleaseWorkingSet(r.Context(), principal.OwnerID, sessionID, phaseID, time.Now().UTC())
	if errors.Is(err, store.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "working set not found"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, released)
}
