package workloads

import (
	"context"
	"testing"
	"time"

	"vram-governor/internal/domain"
	"vram-governor/internal/store"
)

func TestRuntimeProfileRegistrationRequiresCallableWorkflowContract(t *testing.T) {
	manager := NewManager(quietLogger(), store.NewMemoryStore(), time.Second)
	manager.RegisterAdapter(NewHTTPAdapter("comfy", "comfy", nil))
	manager.RegisterTarget(Target{ID: "catalog-only", Adapter: "comfy", Models: []string{"vae.safetensors", "text_encoder.safetensors"}, Enabled: true})
	manager.RegisterTarget(Target{ID: "configured-but-not-workflow", Adapter: "comfy", Enabled: true, Profiles: []domain.RuntimeProfile{{ProfileID: "bad", Version: "1", Operations: []string{"image.generate"}, InputSchema: domain.JSONSchema{"type": "object"}, OutputSchema: domain.JSONSchema{"type": "object"}, AcceptedArtifactTypes: []string{"image/*"}, ProducedArtifactTypes: []string{"image/png"}}}})
	profiles, err := manager.Capabilities(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(profiles) != 0 {
		t.Fatalf("component or non-workflow profiles were advertised: %+v", profiles)
	}
	manager.RegisterTarget(Target{ID: "runnable-workflow", Adapter: "comfy", Enabled: true, Profiles: []domain.RuntimeProfile{{ProfileID: "image_workflow", Version: "2", Workflow: "workflow://image/main/2", Operations: []string{"image.generate", "image.edit"}, Features: []string{"multi_reference"}, InputSchema: domain.JSONSchema{"type": "object", "required": []any{"prompt"}}, OutputSchema: domain.JSONSchema{"type": "object", "required": []any{"outputs"}}, AcceptedArtifactTypes: []string{"image/*", "application/json"}, ProducedArtifactTypes: []string{"image/png"}}}})
	profiles, err = manager.Capabilities(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(profiles) != 1 || profiles[0].ProfileID != "image_workflow" || profiles[0].CapabilityDefinitionHash == "" || profiles[0].CapabilityRevision == "" || profiles[0].ExecutionLocality != domain.ExecutionLocalityLBManaged {
		t.Fatalf("runnable workflow definition missing: %+v", profiles)
	}
}
