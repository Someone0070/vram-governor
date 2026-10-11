package workloads

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"vram-governor/internal/artifacts"
	"vram-governor/internal/domain"
)

const creatorAgentResultMediaType = "application/vnd.creator-studio.agent-result+json"

func opaqueCompatibilityToken() (string, error) {
	buffer := make([]byte, 32)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return "compat-v1-" + base64.RawURLEncoding.EncodeToString(buffer), nil
}

func profileForPlan(target Target, plan *domain.ExecutionPlan) (domain.RuntimeProfile, bool) {
	if plan == nil || plan.ProfileID == "" {
		return domain.RuntimeProfile{}, false
	}
	for _, profile := range target.Profiles {
		if profile.ProfileID == plan.ProfileID && profile.Version == plan.ProfileVersion && profile.Digest == plan.ProfileDigest {
			return profile, true
		}
	}
	return domain.RuntimeProfile{}, false
}

func artifactPutOptions(req domain.WorkloadRequest, plan *domain.ExecutionPlan, profile domain.RuntimeProfile, name, mediaType string) (artifacts.PutOptions, error) {
	producer := &domain.ArtifactProducer{ProfileID: plan.ProfileID, ProfileVersion: plan.ProfileVersion, ProfileDigest: plan.ProfileDigest, CapabilityRevision: plan.CapabilityRevision, CapabilityDefinitionHash: plan.CapabilityDefinitionHash, Operation: req.Operation}
	compatibility := &domain.ArtifactCompatibility{ProducerImplementation: profile.Ref(), CapabilityRevision: profile.CapabilityRevision, CapabilityDefinitionHash: profile.CapabilityDefinitionHash, Tokens: make(map[string]string)}
	for _, operation := range profile.CompatibilityOperations {
		token, err := opaqueCompatibilityToken()
		if err != nil {
			return artifacts.PutOptions{}, err
		}
		compatibility.Tokens[operation] = token
	}
	if len(compatibility.Tokens) == 0 {
		compatibility = nil
	}
	return artifacts.PutOptions{OwnerID: req.OwnerID, WorkloadID: req.ID, Name: name, MediaType: mediaType, Producer: producer, Compatibility: compatibility}, nil
}

func creatorInlineMediaType(operation string, output json.RawMessage) (string, string) {
	if operation == "llm.inference" {
		return "result.json", creatorAgentResultMediaType
	}
	if json.Valid(output) {
		return "result.json", "application/json"
	}
	return "result.txt", "text/plain; charset=utf-8"
}

// materializeCreatorOutputs turns every small adapter result into an immutable
// Artifact before the logical workload is committed as completed. Media output
// refs already produced by an adapter are retained alongside the result
// manifest; physical attempts and provider endpoints remain private.
func (m *Manager) materializeCreatorOutputs(ctx context.Context, workload *domain.Workload, target Target, output json.RawMessage, refs []string) (json.RawMessage, []string, error) {
	if workload == nil || workload.Request.Plane != domain.PlaneCreatorStudio {
		return output, refs, nil
	}
	m.mu.RLock()
	artifactStore := m.artifacts
	m.mu.RUnlock()
	if artifactStore == nil {
		return nil, nil, fmt.Errorf("Creator Studio output artifact store is unavailable")
	}
	profile, ok := profileForPlan(target, workload.Plan)
	if !ok {
		if workload.Plan == nil || workload.Plan.ProfileID == "" || workload.Plan.ProfileVersion == "" || workload.Plan.ProfileDigest == "" {
			return nil, nil, fmt.Errorf("selected execution implementation is unavailable for output provenance")
		}
		revision := workload.Plan.CapabilityRevision
		if revision == "" {
			revision = "legacy"
		}
		produced := []string{"*/*"}
		if workload.Request.Operation == "llm.inference" {
			produced = []string{creatorAgentResultMediaType}
		}
		profile = domain.RuntimeProfile{ProfileID: workload.Plan.ProfileID, Version: workload.Plan.ProfileVersion, Digest: workload.Plan.ProfileDigest, CapabilityRevision: revision, CapabilityDefinitionHash: workload.Plan.CapabilityDefinitionHash, ExecutionLocality: workload.Plan.ExecutionLocality, Modality: inferModality([]string{workload.Request.Operation}), Operations: []string{workload.Request.Operation}, ProducedArtifactTypes: produced}
	}
	if workload.Plan.CapabilityRevision == "" {
		workload.Plan.CapabilityRevision = profile.CapabilityRevision
		workload.Plan.CapabilityDefinitionHash = profile.CapabilityDefinitionHash
		workload.Plan.ExecutionLocality = profile.ExecutionLocality
	}
	trimmed := bytes.TrimSpace(output)
	if len(trimmed) > 0 && string(trimmed) != "null" {
		name, mediaType := creatorInlineMediaType(workload.Request.Operation, output)
		if !MediaTypeMatches(profile.ProducedArtifactTypes, mediaType) {
			if len(refs) == 0 {
				return nil, nil, fmt.Errorf("output media type %q is not declared by %s", mediaType, profile.Ref())
			}
		} else {
			options, err := artifactPutOptions(workload.Request, workload.Plan, profile, name, mediaType)
			if err != nil {
				return nil, nil, err
			}
			artifact, err := artifactStore.PutWithMetadata(ctx, options, bytes.NewReader(output))
			if err != nil {
				return nil, nil, err
			}
			found := false
			for _, existing := range refs {
				found = found || existing == artifact.ID
			}
			if !found {
				refs = append(refs, artifact.ID)
			}
		}
	}
	for _, ref := range refs {
		artifact, reader, err := artifactStore.Open(ctx, ref)
		if reader != nil {
			reader.Close()
		}
		if err != nil || artifact.OwnerID != workload.Request.OwnerID || artifact.WorkloadID != workload.Request.ID || artifact.Producer == nil || artifact.Producer.ProfileID != profile.ProfileID || artifact.Producer.ProfileVersion != profile.Version || artifact.Producer.ProfileDigest != profile.Digest || artifact.Producer.CapabilityRevision != profile.CapabilityRevision || artifact.Producer.CapabilityDefinitionHash != profile.CapabilityDefinitionHash || artifact.Producer.Operation != workload.Request.Operation || !MediaTypeMatches(profile.ProducedArtifactTypes, artifact.MediaType) {
			return nil, nil, fmt.Errorf("output artifact %q lacks matching immutable producer provenance", ref)
		}
	}
	return output, refs, nil
}

func MediaTypeMatches(patterns []string, mediaType string) bool {
	mediaType = strings.ToLower(strings.TrimSpace(strings.SplitN(mediaType, ";", 2)[0]))
	if len(patterns) == 0 {
		return true
	}
	for _, pattern := range patterns {
		pattern = strings.ToLower(strings.TrimSpace(pattern))
		if pattern == "*/*" || pattern == mediaType || (strings.HasSuffix(pattern, "/*") && strings.HasPrefix(mediaType, strings.TrimSuffix(pattern, "*"))) {
			return true
		}
	}
	return false
}
