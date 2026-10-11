package workloads

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"vram-governor/internal/domain"
	"vram-governor/internal/store"
)

const (
	ProfileAvailable       = "available"
	ProfileTemporarilyBusy = "temporarily_busy"
	ProfileOffline         = "offline"
	ProfileUnavailable     = "unavailable"
)

type CreatorProfileResolution struct {
	Profiles []domain.RuntimeProfile
	Adapter  string
	Reason   string
	Missing  []string
}

func profileKey(profile domain.RuntimeProfile) string {
	return profile.ProfileID + "@" + profile.Version
}

func canonicalStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, found := seen[value]; found {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func inferModality(operations []string) domain.ImplementationModality {
	if len(operations) == 0 {
		return domain.ModalityOther
	}
	prefix := strings.SplitN(strings.ToLower(operations[0]), ".", 2)[0]
	switch prefix {
	case "llm":
		return domain.ModalityLLM
	case "image", "qa":
		return domain.ModalityImage
	case "video":
		return domain.ModalityVideo
	case "audio":
		return domain.ModalityAudio
	case "training":
		return domain.ModalityTraining
	case "spatial":
		return domain.ModalitySpatial
	default:
		return domain.ModalityOther
	}
}

func defaultSchemas(adapter string) (domain.JSONSchema, domain.JSONSchema, []string, []string) {
	switch strings.ToLower(adapter) {
	case "llamacpp", "openrouter":
		return domain.JSONSchema{"type": "object", "required": []any{"messages"}, "properties": map[string]any{"model": map[string]any{"type": "string"}, "messages": map[string]any{"type": "array"}}}, domain.JSONSchema{"type": "object", "required": []any{"choices"}, "properties": map[string]any{"choices": map[string]any{"type": "array"}, "usage": map[string]any{"type": "object"}}}, []string{"application/json", "text/plain"}, []string{"application/vnd.creator-studio.agent-result+json"}
	case "mock":
		return domain.JSONSchema{"type": "object"}, domain.JSONSchema{"type": "object"}, []string{"*/*"}, []string{"application/json"}
	default:
		return nil, nil, nil, nil
	}
}

func adapterOperationRunnable(adapter, operation string) bool {
	switch strings.ToLower(adapter) {
	case "llamacpp", "openrouter":
		return operation == "llm.inference"
	case "comfy":
		return strings.HasPrefix(operation, "image.") || strings.HasPrefix(operation, "video.") || strings.HasPrefix(operation, "audio.") || operation == "qa.vision"
	case "mock":
		return operation != ""
	default:
		return false
	}
}

func validModality(modality domain.ImplementationModality) bool {
	switch modality {
	case domain.ModalityLLM, domain.ModalityImage, domain.ModalityVideo, domain.ModalityAudio, domain.ModalityTraining, domain.ModalitySpatial, domain.ModalityOther:
		return true
	default:
		return false
	}
}

func schemaObject(schema domain.JSONSchema) bool {
	return len(schema) > 0 && schema["type"] != nil
}

func normalizedProfile(target Target, profile domain.RuntimeProfile) domain.RuntimeProfile {
	profile.Adapter = target.Adapter
	profile.Operations = canonicalStrings(profile.Operations)
	profile.Features = canonicalStrings(profile.Features)
	profile.AcceptedArtifactTypes = canonicalStrings(profile.AcceptedArtifactTypes)
	profile.ProducedArtifactTypes = canonicalStrings(profile.ProducedArtifactTypes)
	profile.CompatibilityOperations = canonicalStrings(profile.CompatibilityOperations)
	profile.CalibrationStatus = ""
	if profile.CapabilityRevision == "" {
		profile.CapabilityRevision = "1"
	}
	if profile.Modality == "" {
		profile.Modality = inferModality(profile.Operations)
	}
	if target.Cloud {
		profile.ExecutionLocality = domain.ExecutionLocalityHosted
	} else {
		profile.ExecutionLocality = domain.ExecutionLocalityLBManaged
	}
	defaultInput, defaultOutput, defaultAccepted, defaultProduced := defaultSchemas(target.Adapter)
	if strings.EqualFold(target.Adapter, "mock") && profile.Modality == domain.ModalityLLM {
		defaultInput, defaultOutput, defaultAccepted, defaultProduced = defaultSchemas("llamacpp")
	}
	if len(profile.InputSchema) == 0 {
		profile.InputSchema = defaultInput
	}
	if len(profile.OutputSchema) == 0 {
		profile.OutputSchema = defaultOutput
	}
	if len(profile.AcceptedArtifactTypes) == 0 {
		profile.AcceptedArtifactTypes = defaultAccepted
	}
	if len(profile.ProducedArtifactTypes) == 0 {
		profile.ProducedArtifactTypes = defaultProduced
	}
	material, _ := json.Marshal(struct {
		ProfileID, Version, Adapter, Model, Workflow, CapabilityVersion, ModelFingerprint string
		CapabilityRevision, Modality, Locality                                            string
		Operations, Features, Accepted, Produced, Compatibility                           []string
		InputSchema, OutputSchema                                                         domain.JSONSchema
	}{profile.ProfileID, profile.Version, profile.Adapter, profile.Model, profile.Workflow, target.CapabilityVersion, target.ModelFingerprint, profile.CapabilityRevision, string(profile.Modality), string(profile.ExecutionLocality), profile.Operations, profile.Features, profile.AcceptedArtifactTypes, profile.ProducedArtifactTypes, profile.CompatibilityOperations, profile.InputSchema, profile.OutputSchema})
	digest := sha256.Sum256(material)
	computed := hex.EncodeToString(digest[:])
	if profile.Digest == "" {
		profile.Digest = computed
	}
	definitionMaterial, _ := json.Marshal(struct {
		ProfileID, Version, Digest, CapabilityRevision, Modality, Locality string
		Operations, Features, Accepted, Produced, Compatibility            []string
		InputSchema, OutputSchema                                          domain.JSONSchema
	}{profile.ProfileID, profile.Version, profile.Digest, profile.CapabilityRevision, string(profile.Modality), string(profile.ExecutionLocality), profile.Operations, profile.Features, profile.AcceptedArtifactTypes, profile.ProducedArtifactTypes, profile.CompatibilityOperations, profile.InputSchema, profile.OutputSchema})
	definitionDigest := sha256.Sum256(definitionMaterial)
	profile.CapabilityDefinitionHash = hex.EncodeToString(definitionDigest[:])
	if profile.CreatedAt.IsZero() {
		profile.CreatedAt = time.Now().UTC()
	}
	return profile
}

func (m *Manager) registerTargetProfiles(target Target, adapterRegistered bool) []domain.RuntimeProfile {
	creatorStore, ok := m.store.(store.CreatorStudioStore)
	if !ok {
		return nil
	}
	profiles := target.Profiles
	accepted := make([]domain.RuntimeProfile, 0, len(profiles))
	for _, profile := range profiles {
		if profile.ProfileID == "" || profile.Version == "" || len(profile.Operations) == 0 {
			m.log.Warn("ignoring invalid logical runtime profile", "target", target.ID, "profile_id", profile.ProfileID)
			continue
		}
		profile = normalizedProfile(target, profile)
		if !adapterRegistered {
			m.log.Warn("ignoring execution implementation with unregistered adapter", "target", target.ID, "adapter", target.Adapter, "profile_id", profile.ProfileID)
			continue
		}
		valid := schemaObject(profile.InputSchema) && schemaObject(profile.OutputSchema) && validModality(profile.Modality)
		for _, operation := range profile.Operations {
			valid = valid && adapterOperationRunnable(target.Adapter, operation)
		}
		for _, operation := range profile.CompatibilityOperations {
			valid = valid && containsString(profile.Operations, operation)
		}
		if strings.EqualFold(target.Adapter, "comfy") && (profile.Workflow == "" || len(profile.AcceptedArtifactTypes) == 0 || len(profile.ProducedArtifactTypes) == 0) {
			valid = false
		}
		if !valid {
			m.log.Warn("ignoring execution implementation without a validated callable contract", "target", target.ID, "profile_id", profile.ProfileID)
			continue
		}
		stored, _, err := creatorStore.UpsertRuntimeProfile(context.Background(), &profile)
		if err != nil {
			m.log.Error("rejecting mutable runtime profile identity", "target", target.ID, "profile", profileKey(profile), "error", err)
			continue
		}
		accepted = append(accepted, *stored)
	}
	return accepted
}

func (m *Manager) profileOperational(ctx context.Context, target Target) bool {
	if !target.Enabled || target.Quarantined {
		return false
	}
	if target.Cloud || target.AcceleratorID == "" || m.nodes == nil {
		return true
	}
	return m.targetNodeAvailable(ctx, target)
}

func (m *Manager) Capabilities(ctx context.Context) ([]domain.RuntimeProfile, error) {
	creatorStore, ok := m.store.(store.CreatorStudioStore)
	if !ok {
		return nil, fmt.Errorf("logical capability store is unavailable")
	}
	stored, err := creatorStore.ListRuntimeProfiles(ctx)
	if err != nil {
		return nil, err
	}
	targets := m.Targets()
	result := make([]domain.RuntimeProfile, 0, len(stored))
	for _, persisted := range stored {
		profile := *persisted
		profile.Status = ProfileUnavailable
		registered := false
		for _, target := range targets {
			if !targetHasProfile(target, profile.ProfileID, profile.Version) {
				continue
			}
			registered = true
			if !m.profileOperational(ctx, target) {
				if profile.Status == ProfileUnavailable {
					profile.Status = ProfileOffline
				}
				continue
			}
			if m.availableSlots(target) > 0 {
				profile.Status = ProfileAvailable
				break
			}
			profile.Status = ProfileTemporarilyBusy
		}
		if !registered {
			continue
		}
		profile.Availability = &domain.RuntimeAvailability{Status: profile.Status, ObservedAt: time.Now().UTC()}
		profile.Adapter, profile.Model = "", ""
		profile.Operations = append([]string(nil), profile.Operations...)
		profile.Features = append([]string(nil), profile.Features...)
		profile.AcceptedArtifactTypes = append([]string(nil), profile.AcceptedArtifactTypes...)
		profile.ProducedArtifactTypes = append([]string(nil), profile.ProducedArtifactTypes...)
		profile.CompatibilityOperations = append([]string(nil), profile.CompatibilityOperations...)
		result = append(result, profile)
	}
	return result, nil
}

func (m *Manager) registeredCreatorProfiles() []*domain.RuntimeProfile {
	m.mu.RLock()
	defer m.mu.RUnlock()
	seen := make(map[string]struct{})
	profiles := make([]*domain.RuntimeProfile, 0)
	for _, target := range m.targets {
		for index := range target.Profiles {
			profile := target.Profiles[index]
			key := profileKey(profile)
			if _, found := seen[key]; found {
				continue
			}
			seen[key] = struct{}{}
			copy := profile
			profiles = append(profiles, &copy)
		}
	}
	sort.Slice(profiles, func(i, j int) bool { return profileKey(*profiles[i]) < profileKey(*profiles[j]) })
	return profiles
}

func targetHasProfile(target Target, profileID, version string) bool {
	for _, profile := range target.Profiles {
		if profile.ProfileID == profileID && profile.Version == version {
			return true
		}
	}
	return false
}

func supportsAll(profile domain.RuntimeProfile, operation string, features []string) bool {
	if operation == "" || !containsString(profile.Operations, operation) {
		return false
	}
	for _, feature := range features {
		if !containsString(profile.Features, feature) {
			return false
		}
	}
	return true
}

func resolveSelector(profiles []*domain.RuntimeProfile, selector string) ([]*domain.RuntimeProfile, string) {
	selector = strings.TrimSpace(selector)
	if selector == "" {
		return nil, ""
	}
	if strings.Contains(selector, "@") {
		for _, profile := range profiles {
			if profileKey(*profile) == selector {
				return []*domain.RuntimeProfile{profile}, ""
			}
		}
		return nil, "required profile unavailable"
	}
	var matches []*domain.RuntimeProfile
	for _, profile := range profiles {
		if profile.ProfileID == selector {
			matches = append(matches, profile)
		}
	}
	if len(matches) > 1 {
		return nil, "profile version required"
	}
	if len(matches) == 0 {
		return nil, "required profile unavailable"
	}
	return matches, ""
}

func (m *Manager) ResolveCreatorProfiles(ctx context.Context, operation, quality string, requirements domain.CapabilityRequirements, preferences domain.ProfilePreferences) (CreatorProfileResolution, error) {
	if _, ok := m.store.(store.CreatorStudioStore); !ok {
		return CreatorProfileResolution{}, fmt.Errorf("logical capability store is unavailable")
	}
	profiles := m.registeredCreatorProfiles()
	features := canonicalStrings(requirements.Features)
	fallback := preferences.FallbackPolicy
	if fallback == "" {
		if quality == "final" {
			fallback = "equivalent_or_better_only"
		} else {
			fallback = "explicit"
		}
	}
	if fallback != "preferred_only" && fallback != "explicit" && fallback != "equivalent_or_better_only" {
		return CreatorProfileResolution{}, fmt.Errorf("unsupported fallback_policy %q", fallback)
	}
	selectors := append([]string(nil), preferences.Preferred...)
	if fallback != "preferred_only" {
		selectors = append(selectors, preferences.Acceptable...)
	}
	if quality == "final" && len(selectors) == 0 {
		return CreatorProfileResolution{Reason: "PROFILE_REQUIRED", Missing: []string{"calibrated final profile"}}, nil
	}
	selected := make([]domain.RuntimeProfile, 0)
	seen := make(map[string]struct{})
	if len(selectors) == 0 {
		for _, profile := range profiles {
			if supportsAll(*profile, operation, features) {
				selected = append(selected, *profile)
			}
		}
	} else {
		for _, selector := range selectors {
			matches, reason := resolveSelector(profiles, selector)
			if reason == "profile version required" {
				return CreatorProfileResolution{Reason: "PROFILE_VERSION_REQUIRED", Missing: []string{selector + "@version"}}, nil
			}
			if reason != "" {
				continue
			}
			for _, profile := range matches {
				if !supportsAll(*profile, operation, features) {
					continue
				}
				if _, exists := seen[profileKey(*profile)]; exists {
					continue
				}
				seen[profileKey(*profile)] = struct{}{}
				selected = append(selected, *profile)
			}
		}
	}
	if len(selected) == 0 {
		missing := append([]string(nil), features...)
		if len(missing) == 0 {
			missing = []string{operation}
		}
		return CreatorProfileResolution{Reason: "CAPABILITY_UNAVAILABLE", Missing: missing}, nil
	}
	adapter := selected[0].Adapter
	for _, profile := range selected[1:] {
		if profile.Adapter != adapter {
			return CreatorProfileResolution{Reason: "PROFILE_SET_INCOMPATIBLE", Missing: []string{"compatible profile execution protocol"}}, nil
		}
	}
	return CreatorProfileResolution{Profiles: selected, Adapter: adapter}, nil
}

func creatorProfileForTarget(target Target, request domain.WorkloadRequest) (domain.RuntimeProfile, int, bool) {
	allowed := append([]string(nil), request.ProfilePreferences.Preferred...)
	allowed = append(allowed, request.ProfilePreferences.Acceptable...)
	if request.ProfilePreferences.FallbackPolicy == "preferred_only" {
		allowed = append([]string(nil), request.ProfilePreferences.Preferred...)
	}
	for rank, selector := range allowed {
		for _, profile := range target.Profiles {
			if selector == profileKey(profile) && supportsAll(profile, request.Operation, request.CapabilityRequirements.Features) {
				return profile, rank, true
			}
		}
	}
	return domain.RuntimeProfile{}, 0, false
}

func (m *Manager) dependencyBlocker(ctx context.Context, workload *domain.Workload) (string, bool) {
	for _, dependencyID := range workload.Request.Dependencies {
		dependency, err := m.store.GetWorkload(ctx, dependencyID)
		if err != nil || dependency.Request.OwnerID != workload.Request.OwnerID {
			return "DEPENDENCY_UNAVAILABLE", true
		}
		switch dependency.Status {
		case domain.WorkloadSucceeded:
			continue
		case domain.WorkloadFailed, domain.WorkloadCancelled, domain.WorkloadRejected:
			return "DEPENDENCY_FAILED", true
		default:
			return "DEPENDENCY_PENDING", false
		}
	}
	return "", false
}

func (m *Manager) creatorHintAdjustment(ctx context.Context, workload *domain.Workload, target Target) float64 {
	if workload.Request.Plane != domain.PlaneCreatorStudio {
		return 0
	}
	adjustment := 0.0
	if workload.Request.AffinityKey != "" {
		if rows, err := m.store.ListWorkloads(ctx); err == nil {
			for _, row := range rows {
				if row.Request.OwnerID == workload.Request.OwnerID && row.Request.AffinityKey == workload.Request.AffinityKey && row.Plan != nil && row.Plan.TargetID == target.ID && row.Status == domain.WorkloadSucceeded {
					adjustment -= 12
					break
				}
			}
		}
	}
	creatorStore, ok := m.store.(store.CreatorStudioStore)
	if !ok || workload.Request.SessionID == "" {
		return adjustment
	}
	sets, err := creatorStore.ListWorkingSets(ctx, workload.Request.OwnerID, workload.Request.SessionID, false)
	if err != nil {
		return adjustment
	}
	for _, workingSet := range sets {
		for _, profile := range target.Profiles {
			ref := profileKey(profile)
			if containsString(workingSet.DesiredProfiles, ref) {
				adjustment -= 8
			}
			if containsString(workingSet.LikelyNextProfiles, ref) {
				adjustment -= 3
			}
			if containsString(workingSet.UnlikelyProfiles, ref) {
				adjustment += 6
			}
		}
	}
	return adjustment
}
