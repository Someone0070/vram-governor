package store

import (
	"context"
	"encoding/json"
	"testing"

	"vram-governor/internal/domain"
)

func TestMemoryRuntimeProfileUpsertAcceptsEquivalentYAMLAndJSONSchemas(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	yamlProfile := runtimeProfileWithSchema(runtimeProfileYAMLSchema())
	jsonProfile := runtimeProfileWithSchema(runtimeProfileJSONRoundTrip(t, yamlProfile.InputSchema))
	jsonProfile.OutputSchema = runtimeProfileJSONRoundTrip(t, yamlProfile.OutputSchema)

	if _, created, err := store.UpsertRuntimeProfile(ctx, yamlProfile); err != nil || !created {
		t.Fatalf("initial YAML profile upsert: created=%v err=%v", created, err)
	}
	stored, created, err := store.UpsertRuntimeProfile(ctx, jsonProfile)
	if err != nil || created {
		t.Fatalf("equivalent JSON profile must be an idempotent upsert: created=%v err=%v", created, err)
	}
	if stored.ProfileID != yamlProfile.ProfileID || stored.Version != yamlProfile.Version {
		t.Fatalf("unexpected stored profile: %+v", stored)
	}
}

func TestMemoryRuntimeProfileUpsertRejectsActualSchemaChange(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	profile := runtimeProfileWithSchema(runtimeProfileYAMLSchema())
	if _, created, err := store.UpsertRuntimeProfile(ctx, profile); err != nil || !created {
		t.Fatalf("initial profile upsert: created=%v err=%v", created, err)
	}
	changed := runtimeProfileWithSchema(domain.JSONSchema{
		"type": "object",
		"properties": domain.JSONSchema{
			"messages": domain.JSONSchema{
				"type":     "array",
				"minItems": 2,
			},
		},
	})
	if _, _, err := store.UpsertRuntimeProfile(ctx, changed); err == nil {
		t.Fatal("materially changed immutable schema was accepted")
	}
}

func runtimeProfileWithSchema(input domain.JSONSchema) *domain.RuntimeProfile {
	return &domain.RuntimeProfile{
		ProfileID:                "llm-profile",
		Version:                  "1",
		Digest:                   "sha256:profile",
		CapabilityRevision:       "1",
		CapabilityDefinitionHash: "sha256:capability",
		Adapter:                  "llamacpp",
		Model:                    "logical-model",
		Modality:                 domain.ModalityLLM,
		ExecutionLocality:        domain.ExecutionLocalityLBManaged,
		Operations:               []string{"llm.inference"},
		InputSchema:              input,
		OutputSchema:             domain.JSONSchema{"type": "object"},
		ProducedArtifactTypes:    []string{"application/json"},
	}
}

func runtimeProfileYAMLSchema() domain.JSONSchema {
	return domain.JSONSchema{
		"type": "object",
		"properties": domain.JSONSchema{
			"messages": domain.JSONSchema{
				"type":     "array",
				"minItems": 1,
			},
		},
	}
}

func runtimeProfileJSONRoundTrip(t *testing.T, schema domain.JSONSchema) domain.JSONSchema {
	t.Helper()
	raw, err := json.Marshal(schema)
	if err != nil {
		t.Fatalf("marshal schema: %v", err)
	}
	var decoded domain.JSONSchema
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal schema: %v", err)
	}
	return decoded
}
