package wsproto

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"vram-governor/internal/domain"
	checkpointRuntime "vram-governor/internal/runtime"
)

func TestCheckpointProofV2WireSchemaAndMalformedMutants(t *testing.T) {
	proof := checkpointRuntime.CheckpointCapabilityProof{
		ProofVersion: checkpointRuntime.CheckpointCapabilityProofVersion, ModelAlias: "wire-model-alias", LocalCheckpointBinding: "sha256:" + strings.Repeat("a", 64),
		Verified: true, SlotAssignment: true, SafeBoundaryPause: true, SnapshotSave: true,
		BackendStopConfirmed: true, SnapshotRestore: true, KVReused: true,
		ProvenAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Hour), NodeID: "node", TargetID: "node-runtime",
		ModelFingerprint: "catalog-fingerprint", RuntimeIdentity: "runtime", ProfileFingerprint: "profile",
		ContextLimit: 4096, SlotID: 0, Generation: 1, OldFence: 1, NewFence: 2,
		SavedTokens: 2, ReusedTokens: 1, EvidenceID: "evidence", Signature: "fixture-signature", Digest: "sha256:fixture-digest",
		SnapshotDigest: "sha256:snapshot", SnapshotBytes: 8, AcceleratorID: "node-gpu0",
		Nonce: "00000000000000000001-e00000000000000000001-0123456789abcdef0123456789abcdef",
	}
	proofJSON, err := json.Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	valid := `{"id":"runtime","checkpoint_proof":` + string(proofJSON) + `}`
	var ad AdapterAdvertisement
	if err := json.Unmarshal([]byte(valid), &ad); err != nil || !ad.CheckpointProof.ComponentsComplete() {
		t.Fatalf("exact valid v2 proof was rejected: err=%v proof=%+v", err, ad.CheckpointProof)
	}

	// Pre-v2 encoders emitted the all-zero proof struct instead of omitting it.
	// Keep that no-claim form interoperable, while never accepting a legacy
	// positive claim as checkpoint capability.
	legacyZero := `{"id":"runtime","checkpoint_proof":{"verified":false,"probe_only":false,"slot_assignment":false,"safe_boundary_pause":false,"snapshot_save":false,"backend_stop_confirmed":false,"snapshot_restore":false,"kv_reused":false,"proven_at":"0001-01-01T00:00:00Z","node_id":"","target_id":"","model_fingerprint":"","runtime_identity":"","profile_fingerprint":"","context_limit":0,"slot_id":0,"generation":0,"old_fence":0,"new_fence":0,"saved_tokens":0,"reused_tokens":0,"evidence_id":"","signature":"","digest":"","snapshot_digest":"","snapshot_bytes":0,"accelerator_id":"","expires_at":"0001-01-01T00:00:00Z","nonce":""}}`
	var legacyAdvertisement AdapterAdvertisement
	if err := json.Unmarshal([]byte(legacyZero), &legacyAdvertisement); err != nil || legacyAdvertisement.CheckpointProof.ComponentsComplete() {
		t.Fatalf("real pre-v2 omitempty zero proof (without reason) should remain a no-capability advertisement: err=%v proof=%+v", err, legacyAdvertisement.CheckpointProof)
	}
	legacyZeroWithReason := strings.Replace(legacyZero, `"node_id"`, `"reason":"","node_id"`, 1)
	if err := json.Unmarshal([]byte(legacyZeroWithReason), &legacyAdvertisement); err != nil || legacyAdvertisement.CheckpointProof.ComponentsComplete() {
		t.Fatalf("optional empty legacy reason should remain a no-capability advertisement: err=%v proof=%+v", err, legacyAdvertisement.CheckpointProof)
	}
	legacyClaim := strings.Replace(legacyZero, `"verified":false`, `"verified":true`, 1)
	if err := json.Unmarshal([]byte(legacyClaim), &legacyAdvertisement); err == nil {
		t.Fatalf("legacy positive proof claim was accepted as capability: %+v", legacyAdvertisement.CheckpointProof)
	}
	legacyReason := strings.Replace(legacyZero, `"node_id"`, `"reason":"not-zero","node_id"`, 1)
	if err := json.Unmarshal([]byte(legacyReason), &legacyAdvertisement); err == nil {
		t.Fatalf("legacy zero proof accepted a nonzero optional reason: %+v", legacyAdvertisement.CheckpointProof)
	}

	mutants := map[string]string{
		"duplicate":       strings.Replace(valid, `"verified":true`, `"verified":true,"verified":true`, 1),
		"alternate case":  strings.Replace(valid, `"model_alias"`, `"Model_alias"`, 1),
		"unknown":         strings.Replace(valid, `"model_alias":"wire-model-alias"`, `"model_alias":"wire-model-alias","unknown":true`, 1),
		"missing":         strings.Replace(valid, `"proof_version":"`+checkpointRuntime.CheckpointCapabilityProofVersion+`",`, "", 1),
		"null":            strings.Replace(valid, `"model_alias":"wire-model-alias"`, `"model_alias":null`, 1),
		"malformed type":  strings.Replace(valid, `"slot_id":0`, `"slot_id":"0"`, 1),
		"malformed epoch": strings.Replace(valid, `"nonce":"00000000000000000001-e00000000000000000001-0123456789abcdef0123456789abcdef"`, `"nonce":"legacy-nonce"`, 1),
		"trailing value":  valid + ` {}`,
	}
	for name, mutant := range mutants {
		t.Run(name, func(t *testing.T) {
			var decoded AdapterAdvertisement
			if err := json.Unmarshal([]byte(mutant), &decoded); err == nil {
				t.Fatalf("malformed proof mutant was accepted: %s", mutant)
			}
		})
	}
}

func TestResidencyCommandSchemaMatrix(t *testing.T) {
	actions := []struct {
		name string
		tier string
	}{
		{"load_model", "hot_vram"}, {"unload_model", "cold_disk"},
		{"warm_model", "warm_ram"}, {"offload_model", "warm_ram"},
		{"demote_model", "warm_ram"}, {"protect_warm_model", "warm_ram"},
		{"cleanup_warm_model", "cold_disk"}, {"reverify_warm_model", "warm_ram"},
	}
	base := func(tier string) map[string]any {
		args := CanonicalResidencyCommandArgs("node-runtime", "model", "node-runtime|llamacpp||runtime-v1|fingerprint", "runtime-v1", domain.CapabilityContractVersion, tier, 7)
		return args
	}
	for _, action := range actions {
		t.Run(action.name, func(t *testing.T) {
			valid := base(action.tier)
			if action.name == "protect_warm_model" {
				valid["active_references"] = int64(2)
				valid["protected"] = true
			}
			if err := ValidateResidencyCommandArgs(action.name, valid); err != nil {
				t.Fatalf("valid envelope rejected: %v", err)
			}
			missingModel := base(action.tier)
			delete(missingModel, "model")
			if err := ValidateResidencyCommandArgs(action.name, missingModel); err == nil || !strings.Contains(err.Error(), "model") {
				t.Fatalf("missing model was accepted: %v", err)
			}
			wrongFence := base(action.tier)
			wrongFence["fencing_token"] = "7"
			if err := ValidateResidencyCommandArgs(action.name, wrongFence); err == nil {
				t.Fatal("string fencing token was accepted")
			}
			if action.name == "protect_warm_model" {
				missingProtection := base(action.tier)
				if err := ValidateResidencyCommandArgs(action.name, missingProtection); err == nil || !strings.Contains(err.Error(), "active_references") {
					t.Fatalf("protect envelope without protection fields was accepted: %v", err)
				}
			} else {
				forbidden := base(action.tier)
				forbidden["unexpected"] = true
				if err := ValidateResidencyCommandArgs(action.name, forbidden); err == nil || !strings.Contains(err.Error(), "not allowed") {
					t.Fatalf("unknown field was accepted: %v", err)
				}
			}
		})
	}
	// Exhaustive boundary matrix: every required field is tested for absence,
	// every typed field for a wrong JSON type, and every action gets a field
	// from another action's schema as a forbidden control.
	commonRequired := []string{"target_kind", "target_id", "model", "runtime_identity", "capability_version", "capability_revision", "expected_tier", "fencing_token"}
	for _, action := range actions {
		t.Run(action.name+"-exhaustive", func(t *testing.T) {
			valid := base(action.tier)
			if action.name == "protect_warm_model" {
				valid["active_references"], valid["protected"] = int64(2), true
			}
			required := append([]string(nil), commonRequired...)
			if action.name == "protect_warm_model" {
				required = append(required, "active_references", "protected")
			}
			if action.name == "query_model_state" {
				required = append(required, "expected_fence", "observed_after_fence", "original_command_id", "original_idempotency_key")
				valid["expected_fence"], valid["observed_after_fence"] = int64(7), int64(7)
				valid["original_command_id"], valid["original_idempotency_key"] = "original", "original-key"
			}
			for _, key := range required {
				missing := cloneArgs(valid)
				delete(missing, key)
				if err := ValidateResidencyCommandArgs(action.name, missing); err == nil {
					t.Fatalf("missing required field %q was accepted", key)
				}
			}
			wrongTypes := map[string]any{"target_kind": true, "target_id": true, "model": true, "runtime_identity": true, "capability_version": true, "capability_revision": true, "expected_tier": true, "fencing_token": "7"}
			if action.name == "protect_warm_model" {
				wrongTypes["active_references"], wrongTypes["protected"] = "2", "true"
			}
			if action.name == "query_model_state" {
				wrongTypes["expected_fence"], wrongTypes["observed_after_fence"] = "7", "7"
				wrongTypes["original_command_id"], wrongTypes["original_idempotency_key"] = true, true
			}
			for key, value := range wrongTypes {
				wrong := cloneArgs(valid)
				wrong[key] = value
				if err := ValidateResidencyCommandArgs(action.name, wrong); err == nil {
					t.Fatalf("wrong type for %q was accepted", key)
				}
			}
			if action.name == "warm_model" || action.name == "offload_model" || action.name == "demote_model" {
				for _, key := range []string{"model_path", "path", "active_references", "protected"} {
					wrong := cloneArgs(valid)
					wrong[key] = any("wrong-type")
					if key == "model_path" || key == "path" {
						wrong[key] = int64(7)
					}
					if err := ValidateResidencyCommandArgs(action.name, wrong); err == nil {
						t.Fatalf("wrong type for optional %q was accepted", key)
					}
				}
			}
			forbidden := cloneArgs(valid)
			forbiddenKey := "expected_fence"
			if action.name == "protect_warm_model" {
				forbiddenKey = "path"
			} else if action.name == "query_model_state" {
				forbiddenKey = "protected"
			}
			forbidden[forbiddenKey] = true
			if action.name != "query_model_state" && action.name != "protect_warm_model" {
				delete(forbidden, "expected_fence")
				forbidden["original_command_id"] = "not-allowed"
			}
			if err := ValidateResidencyCommandArgs(action.name, forbidden); err == nil {
				t.Fatalf("forbidden field %q was accepted", forbiddenKey)
			}
		})
	}
}

func TestOwnedStopWireSchemaAndOriginalEnvelope(t *testing.T) {
	stopArgs := map[string]any{
		"operation_id": "op-1", "step_id": "victim_stop", "target_kind": "llamacpp", "target_id": "node-a-server",
		"accelerator_id": "GPU-01234567-89ab-cdef-0123-456789abcdef", "workload_id": "workload-a", "workload_revision": int64(3),
		"model": "catalog/model-a", "model_alias": "fixed-alias", "local_checkpoint_binding": strings.Repeat("a", 64),
		"snapshot_name": "snapshot-1.kv", "snapshot_digest": strings.Repeat("b", 64), "recovery_epoch": "epoch-1", "fencing_token": int64(7),
	}
	command := CommandPayload{ID: "command-1", IdempotencyKey: "idem-1", NodeID: "node-a", Command: "llm_displacement_stop", Args: stopArgs, IssuedAt: time.Now().UTC().Add(-time.Minute), ExpiresAt: time.Now().UTC().Add(time.Minute)}
	secret := []byte("fixture-command-secret-at-least-16")
	var err error
	command.Signature, err = SignCommand(command, secret)
	if err != nil || !VerifyCommand(command, secret) || ValidateOwnedStopCommandArgs(command.Command, command.Args) != nil {
		t.Fatalf("valid signed stop rejected: err=%v", err)
	}
	wire, err := CanonicalCommandEnvelope(command)
	if err != nil {
		t.Fatal(err)
	}
	var decoded CommandPayload
	if err := json.Unmarshal(wire, &decoded); err != nil || !VerifyCommand(decoded, secret) {
		t.Fatalf("original canonical stop envelope did not survive round trip: %v", err)
	}
	material, err := CommandSigningMaterialForOwnedStop(decoded)
	if err != nil || len(material) == 0 {
		t.Fatalf("signed material was unavailable: %v", err)
	}
	for name, mutate := range map[string]func(map[string]any){
		"noncanonical_target":      func(a map[string]any) { a["target_id"] = "alias" },
		"unknown_admin_argument":   func(a map[string]any) { a["force_kill"] = true },
		"wrong_step":               func(a map[string]any) { a["step_id"] = "reload" },
		"nonpositive_fence":        func(a map[string]any) { a["fencing_token"] = int64(0) },
		"uppercase_binding_digest": func(a map[string]any) { a["local_checkpoint_binding"] = strings.Repeat("A", 64) },
		"unsafe_snapshot":          func(a map[string]any) { a["snapshot_name"] = "../snapshot.kv" },
	} {
		t.Run(name, func(t *testing.T) {
			args := make(map[string]any, len(stopArgs))
			for key, value := range stopArgs {
				args[key] = value
			}
			mutate(args)
			if err := ValidateOwnedStopCommandArgs("llm_displacement_stop", args); err == nil {
				t.Fatal("malformed owned-stop wire was accepted")
			}
		})
	}
	queryArgs := make(map[string]any, len(stopArgs)+5)
	for key, value := range stopArgs {
		queryArgs[key] = value
	}
	queryArgs["original_command_id"] = command.ID
	queryArgs["original_idempotency_key"] = command.IdempotencyKey
	queryArgs["original_envelope_sha256"] = sha256HexForTest(wire)
	queryArgs["expected_fence"] = int64(7)
	queryArgs["observed_after_fence"] = int64(7)
	if err := ValidateOwnedStopCommandArgs("llm_displacement_stop_query", queryArgs); err != nil {
		t.Fatalf("exact linked read-only query was rejected: %v", err)
	}
	queryArgs["observed_after_fence"] = int64(8)
	if err := ValidateOwnedStopCommandArgs("llm_displacement_stop_query", queryArgs); err == nil {
		t.Fatal("query with changed observed accelerator fence was accepted")
	}
}

func TestPlanRelaunchWireIsCatalogTypedAndRejectsGenericAuthority(t *testing.T) {
	base := map[string]any{
		"operation_id": "op-18", "target_kind": "llamacpp", "target_id": "node-a-server",
		"accelerator_id": "node-a-gpu0", "workload_id": "workload-a", "workload_revision": int64(4),
		"recovery_epoch": "epoch-18", "fencing_token": int64(18), "catalog_id": "victim-v1",
		"prior_command_id": "victim-stop", "prior_idempotency_key": "victim-stop-key", "prior_receipt_sha256": strings.Repeat("a", 64),
	}
	urgent := cloneArgs(base)
	urgent["catalog_id"] = "urgent-v1"
	urgent["linked_catalog_id"] = "victim-v1"
	if err := ValidatePlanRelaunchCommandArgs("llm_displacement_plan_urgent_load", urgent); err != nil {
		t.Fatalf("catalog-bound urgent load rejected: %v", err)
	}
	victim := cloneArgs(base)
	if err := ValidatePlanRelaunchCommandArgs("llm_displacement_plan_victim_reload", victim); err != nil {
		t.Fatalf("catalog-bound victim reload rejected: %v", err)
	}
	query := cloneArgs(victim)
	query["query_step"] = "victim_reload"
	query["original_command_id"] = "victim-reload"
	query["original_idempotency_key"] = "victim-reload-key"
	query["original_envelope_sha256"] = strings.Repeat("b", 64)
	query["expected_fence"] = int64(18)
	query["observed_after_fence"] = int64(18)
	if err := ValidatePlanRelaunchCommandArgs("llm_displacement_plan_query", query); err != nil {
		t.Fatalf("exact linked plan query rejected: %v", err)
	}
	mutants := []struct {
		command string
		mutate  func(map[string]any)
	}{
		{"llm_displacement_plan_urgent_load", func(a map[string]any) { delete(a, "linked_catalog_id") }},
		{"llm_displacement_plan_urgent_load", func(a map[string]any) { a["catalog_id"] = a["linked_catalog_id"] }},
		{"llm_displacement_plan_victim_reload", func(a map[string]any) { a["plan_path"] = "/tmp/attacker.json" }},
		{"llm_displacement_plan_victim_reload", func(a map[string]any) { a["argv"] = []string{"/bin/sh"} }},
		{"llm_displacement_plan_victim_reload", func(a map[string]any) { a["unit"] = "attacker.service" }},
		{"llm_displacement_plan_victim_reload", func(a map[string]any) { a["pid"] = int64(1) }},
		{"llm_displacement_plan_victim_reload", func(a map[string]any) { a["prior_receipt_sha256"] = strings.Repeat("A", 64) }},
		{"llm_displacement_plan_query", func(a map[string]any) { a["observed_after_fence"] = int64(19) }},
		{"llm_displacement_plan_query", func(a map[string]any) { a["original_envelope_sha256"] = "bad" }},
		{"llm_displacement_plan_query", func(a map[string]any) { a["linked_catalog_id"] = "unrelated-v1" }},
		{"llm_displacement_plan_query", func(a map[string]any) { a["original_command_id"] = a["prior_command_id"] }},
	}
	for i, mutant := range mutants {
		args := cloneArgs(victim)
		command := mutant.command
		if command == "llm_displacement_plan_query" {
			args = cloneArgs(query)
		}
		mutant.mutate(args)
		if err := ValidatePlanRelaunchCommandArgs(command, args); err == nil {
			t.Fatalf("plan relaunch mutation %d was accepted", i)
		}
	}
	urgentQuery := cloneArgs(query)
	urgentQuery["query_step"] = "urgent_load"
	urgentQuery["catalog_id"] = "urgent-v1"
	urgentQuery["linked_catalog_id"] = "victim-v1"
	if err := ValidatePlanRelaunchCommandArgs("llm_displacement_plan_query", urgentQuery); err != nil {
		t.Fatalf("exact urgent-load query rejected: %v", err)
	}
}

func sha256HexForTest(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func cloneArgs(input map[string]any) map[string]any {
	output := make(map[string]any, len(input))
	for key, value := range input {
		output[key] = value
	}
	return output
}

func TestParseLlamaModelsPlainRouterAndMixed(t *testing.T) {
	plain := []byte(`{"object":"list","data":[{"id":"/models/qwen.gguf","object":"model"}]}`)
	records, isPlain, err := ParseLlamaModels(plain)
	if err != nil || !isPlain || len(records) != 1 || records[0].State != RouterModelLoaded {
		t.Fatalf("plain llama-server not parsed as one loaded model: %+v plain=%v err=%v", records, isPlain, err)
	}
	router := []byte(`{"data":[{"id":"a","status":{"value":"loaded","args":["-c","4096"]}},{"id":"b","status":"unloaded"}]}`)
	records, isPlain, err = ParseLlamaModels(router)
	if err != nil || isPlain || len(records) != 2 || records[0].State != RouterModelLoaded || records[1].State != RouterModelUnloaded {
		t.Fatalf("router object/string status not parsed: %+v plain=%v err=%v", records, isPlain, err)
	}
	mixed := []byte(`{"data":[{"id":"a","status":"loaded"},{"id":"b"}]}`)
	if _, _, err := ParseLlamaModels(mixed); err == nil {
		t.Fatal("mixed router/plain response was accepted")
	}
	if _, err := ParseRouterModels(plain); err == nil {
		t.Fatal("strict router parser accepted entries without status")
	}
}

// Model pools travel in the strictly validated adapter advertisement: a
// known shape is accepted, unknown or null pool fields are not.
func TestAdapterAdvertisementAcceptsOnlyCanonicalModelPools(t *testing.T) {
	valid := `{"id":"a","adapter":"llamacpp","endpoint":"http://x","models":["m"],"model_pools":{"m":{"pool_tokens":40000,"slots":4,"max_request_tokens":32768}}}`
	if err := validateAdapterAdvertisementJSON([]byte(valid)); err != nil {
		t.Fatalf("valid pools refused: %v", err)
	}
	for _, bad := range []string{
		`{"id":"a","adapter":"llamacpp","endpoint":"http://x","model_pools":{"m":{"pool_tokens":1,"slots":1,"max_request_tokens":1,"extra":1}}}`,
		`{"id":"a","adapter":"llamacpp","endpoint":"http://x","model_pools":{"m":{"pool_tokens":null,"slots":1,"max_request_tokens":1}}}`,
		`{"id":"a","adapter":"llamacpp","endpoint":"http://x","model_pools":[1]}`,
	} {
		if err := validateAdapterAdvertisementJSON([]byte(bad)); err == nil {
			t.Fatalf("accepted %s", bad)
		}
	}
}
