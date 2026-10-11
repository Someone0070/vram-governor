package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"vram-governor/internal/domain"
	checkpointRuntime "vram-governor/internal/runtime"
	"vram-governor/internal/wsproto"
)

func TestSampleControllerConfigParsesResidencyPolicy(t *testing.T) {
	config, err := LoadConfig("../../configs/controller.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if config.Workloads.Residency.Enabled == nil || !*config.Workloads.Residency.Enabled {
		t.Fatal("sample config should enable residency reconciliation")
	}
	if config.Workloads.Residency.IdleUnloadSeconds != 900 || config.Workloads.Residency.MinResidencySeconds != 300 {
		t.Fatalf("unexpected residency defaults: %+v", config.Workloads.Residency)
	}
	if config.Workloads.DefaultMaxAcceleratorsPerModel != 1 {
		t.Fatalf("sample config must default each model to one accelerator, got %d", config.Workloads.DefaultMaxAcceleratorsPerModel)
	}
}

func signedAPIProof(secret, nonce string, generation, fence uint64) checkpointRuntime.CheckpointCapabilityProof {
	parts := strings.Split(nonce, "-")
	epoch := uint64(1)
	if len(parts) > 1 && len(parts[1]) > 1 && parts[1][0] == 'e' {
		if parsed, err := strconv.ParseUint(parts[1][1:], 10, 64); err == nil && parsed > 0 {
			epoch = parsed
		}
	}
	stamp := time.Now().UTC()
	if len(parts) > 0 && len(parts[0]) == 20 {
		if parsed, err := strconv.ParseInt(parts[0], 10, 64); err == nil {
			stamp = time.Unix(0, parsed).UTC()
		}
	}
	sum := sha256.Sum256([]byte(nonce))
	nonce = fmt.Sprintf("%020d-e%020d-%x", stamp.UnixNano(), epoch, sum[:16])
	proof := checkpointRuntime.CheckpointCapabilityProof{
		ProofVersion: checkpointRuntime.CheckpointCapabilityProofVersion, ModelAlias: "local-model-alias", LocalCheckpointBinding: "sha256:" + strings.Repeat("a", 64),
		Verified: true, SlotAssignment: true, SafeBoundaryPause: true,
		SnapshotSave: true, BackendStopConfirmed: true, SnapshotRestore: true,
		KVReused: true, ProvenAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Hour),
		NodeID: "node", TargetID: "node-runtime", ModelFingerprint: "model",
		RuntimeIdentity: "runtime", ProfileFingerprint: "profile", ContextLimit: 4096,
		SlotID: 0, Generation: generation, OldFence: fence - 1, NewFence: fence,
		SavedTokens: 4, ReusedTokens: 2, EvidenceID: "evidence-" + nonce,
		SnapshotDigest: "sha256:snapshot", SnapshotBytes: 128, AcceleratorID: "node-gpu0", Nonce: nonce,
	}
	proof.Digest = checkpointRuntime.CheckpointProofDigest(proof)
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(proof.Digest))
	proof.Signature = hex.EncodeToString(mac.Sum(nil))
	return proof
}

func checkpointAPIAdvertisement(proof checkpointRuntime.CheckpointCapabilityProof) wsproto.AdapterAdvertisement {
	return wsproto.AdapterAdvertisement{
		ID: "runtime", Adapter: "llamacpp", Endpoint: "http://node.invalid", AcceleratorIndex: 0,
		Models: []string{proof.ModelAlias}, ResidentModels: []string{proof.ModelAlias},
		Version: "runtime", ModelFingerprint: "model", ActiveRuntimeProfile: "profile", ContextLimit: 4096,
		CapabilityGeneration: proof.Generation, CheckpointProof: proof,
	}
}

func TestCheckpointProofAdmissionRequiresV2DigestAndDurableEpoch(t *testing.T) {
	secret := strings.Repeat("v", 32)
	server := newCheckpointProofTestServer(&Config{}, secret, filepath.Join(t.TempDir(), "proof-journal.json"))
	proof := signedAPIProof(secret, "00000000000000000001-e00000000000000000001-first", 3, 8)
	t.Run("positive_v2_control", func(t *testing.T) {
		if err := server.validateCheckpointAdvertisementProofSession("node", checkpointAPIAdvertisement(proof), false, ""); err != nil {
			t.Fatalf("positive signed v2 control was rejected: %v", err)
		}
	})
	for _, tc := range []struct {
		name   string
		mutate func(*checkpointRuntime.CheckpointCapabilityProof, *wsproto.AdapterAdvertisement)
	}{
		{name: "unknown_model_alias", mutate: func(_ *checkpointRuntime.CheckpointCapabilityProof, ad *wsproto.AdapterAdvertisement) {
			ad.Models, ad.ResidentModels = []string{"different-alias"}, []string{"different-alias"}
		}},
		{name: "nonresident_model_alias", mutate: func(proof *checkpointRuntime.CheckpointCapabilityProof, ad *wsproto.AdapterAdvertisement) {
			ad.ResidentModels = []string{"different-alias"}
			_ = proof
		}},
		{name: "ambiguous_resident_alias", mutate: func(proof *checkpointRuntime.CheckpointCapabilityProof, ad *wsproto.AdapterAdvertisement) {
			ad.ResidentModels = []string{proof.ModelAlias, proof.ModelAlias}
		}},
		{name: "legacy_proof", mutate: func(proof *checkpointRuntime.CheckpointCapabilityProof, _ *wsproto.AdapterAdvertisement) {
			proof.ProofVersion, proof.ModelAlias, proof.LocalCheckpointBinding = "", "", ""
			proof.Nonce = "legacy-nonce"
			proof.Digest = checkpointRuntime.CheckpointProofDigest(*proof)
			mac := hmac.New(sha256.New, []byte(secret))
			_, _ = mac.Write([]byte(proof.Digest))
			proof.Signature = hex.EncodeToString(mac.Sum(nil))
		}},
		{name: "missing_durable_epoch", mutate: func(proof *checkpointRuntime.CheckpointCapabilityProof, _ *wsproto.AdapterAdvertisement) {
			proof.Nonce = "legacy-nonce"
			proof.Digest = checkpointRuntime.CheckpointProofDigest(*proof)
			mac := hmac.New(sha256.New, []byte(secret))
			_, _ = mac.Write([]byte(proof.Digest))
			proof.Signature = hex.EncodeToString(mac.Sum(nil))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			candidate := signedAPIProof(secret, "00000000000000000001-e00000000000000000001-mutant", 3, 8)
			ad := checkpointAPIAdvertisement(candidate)
			tc.mutate(&candidate, &ad)
			ad.CheckpointProof = candidate
			freshServer := newCheckpointProofTestServer(&Config{}, secret, filepath.Join(t.TempDir(), "proof-journal.json"))
			if err := freshServer.validateCheckpointAdvertisementProofSession("node", ad, false, ""); err == nil {
				t.Fatalf("invalid proof mutant was accepted: %+v", candidate)
			}
		})
	}
	t.Run("positive_durable_epoch_control", func(t *testing.T) {
		if err := server.validateCheckpointAdvertisementProofSession("node", checkpointAPIAdvertisement(proof), true, "node:1"); err != nil {
			t.Fatalf("positive durable proof control was rejected: %v", err)
		}
	})
	t.Run("durable_epoch_replay", func(t *testing.T) {
		replay := signedAPIProof(secret, "00000000000000000002-e00000000000000000001-second", 3, 8)
		if err := server.validateCheckpointAdvertisementProofSession("node", checkpointAPIAdvertisement(replay), true, "node:2"); err == nil || !strings.Contains(err.Error(), "issuance") {
			t.Fatalf("replayed durable epoch was accepted: %v", err)
		}
	})
}

func newCheckpointProofTestServer(cfg *Config, secret, journalPath string) *Server {
	return &Server{
		cfg: cfg, commandSecret: []byte(secret),
		checkpointProofNonces: make(map[string]string), checkpointProofIssuedAt: make(map[string]time.Time),
		checkpointProofSessions: make(map[string]string), checkpointProofHighWater: make(map[string]uint64),
		checkpointProofFences: make(map[string]uint64), checkpointProofGenerations: make(map[string]uint64),
		checkpointProofNoncePath: journalPath,
	}
}

func TestCheckpointProofHighWaterSurvivesControllerRestartAndSessionRefresh(t *testing.T) {
	secret := strings.Repeat("p", 32)
	root := t.TempDir()
	cfg := &Config{}
	cfg.Workloads.Checkpoint.ProofJournalRetentionSeconds = 48 * 60 * 60
	journalPath := filepath.Join(root, "proof-journal.json")
	server := newCheckpointProofTestServer(cfg, secret, journalPath)
	proof := signedAPIProof(secret, fmt.Sprintf("%020d-e%020d-first", time.Now().UnixNano(), 1), 3, 8)
	advertisement := checkpointAPIAdvertisement(proof)
	if err := server.validateCheckpointAdvertisementProofSession("node", advertisement, true, "node:1"); err != nil {
		t.Fatal(err)
	}
	if err := server.validateCheckpointAdvertisementProofSession("node", advertisement, true, "node:1"); err != nil {
		t.Fatalf("same-session refresh was not idempotent: %v", err)
	}

	restarted := newCheckpointProofTestServer(cfg, secret, journalPath)
	if err := restarted.loadCheckpointProofNonces(); err != nil {
		t.Fatal(err)
	}
	if err := restarted.validateCheckpointAdvertisementProofSession("node", advertisement, true, "node:2"); err == nil {
		t.Fatal("controller restart accepted replayed issuance")
	}
	rollbackClock := signedAPIProof(secret, fmt.Sprintf("%020d-e%020d-clock-rollback", time.Now().Add(-time.Hour).UnixNano(), 2), 3, 8)
	if err := restarted.validateCheckpointAdvertisementProofSession("node", checkpointAPIAdvertisement(rollbackClock), true, "node:2"); err != nil {
		t.Fatalf("durable epoch should survive a wall-clock rollback: %v", err)
	}
	oldGeneration := signedAPIProof(secret, fmt.Sprintf("%020d-e%020d-old-generation", time.Now().UnixNano(), 3), 2, 9)
	if err := restarted.validateCheckpointAdvertisementProofSession("node", checkpointAPIAdvertisement(oldGeneration), true, "node:3"); err == nil {
		t.Fatal("generation rollback crossed proof admission")
	}
}

func TestCheckpointProofJournalRejectsLastComponentSymlink(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "proof-journal-real.json")
	link := filepath.Join(root, "proof-journal-link.json")
	if err := os.WriteFile(target, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	server := newCheckpointProofTestServer(&Config{}, strings.Repeat("p", 32), link)
	if err := server.loadCheckpointProofNonces(); err == nil {
		t.Fatal("checkpoint proof journal symlink was accepted")
	}
}

func TestCheckpointProofJournalV2ParserRejectsCorruptionAndDowngrade(t *testing.T) {
	secret := strings.Repeat("p", 32)
	cfg := &Config{}
	issued := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	valid := checkpointProofJournal{
		Version:     "llm-checkpoint-proof-journal-v2",
		Nonces:      map[string]string{"node-runtime|nonce": "digest"},
		IssuedAt:    map[string]time.Time{"node-runtime|nonce": issued},
		HighWater:   map[string]uint64{"node|node-runtime": 4},
		Fences:      map[string]uint64{"node|node-runtime": 8},
		Generations: map[string]uint64{"node|node-runtime": 3},
	}
	validBody, err := json.Marshal(valid)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		body string
		ok   bool
	}{
		{name: "malformed", body: "{", ok: false},
		{name: "unknown version", body: `{"version":"llm-checkpoint-proof-journal-v3","nonces":{},"issued_at":{},"high_water":{},"fences":{},"generations":{}}`, ok: false},
		{name: "partial v2", body: `{"version":"llm-checkpoint-proof-journal-v2","nonces":{}}`, ok: false},
		{name: "nil map", body: `{"version":"llm-checkpoint-proof-journal-v2","nonces":{},"issued_at":{},"high_water":null,"fences":{},"generations":{}}`, ok: false},
		{name: "inconsistent maps", body: `{"version":"llm-checkpoint-proof-journal-v2","nonces":{"node-runtime|nonce":"digest"},"issued_at":{"node-runtime|nonce":"2026-01-02T03:04:05Z"},"high_water":{"node|node-runtime":4},"fences":{"node|node-runtime":8},"generations":{}}`, ok: false},
		{name: "orphan fence", body: `{"version":"llm-checkpoint-proof-journal-v2","nonces":{},"issued_at":{},"high_water":{},"fences":{"node|runtime":8},"generations":{"node|runtime":3}}`, ok: false},
		{name: "orphan generation", body: `{"version":"llm-checkpoint-proof-journal-v2","nonces":{},"issued_at":{},"high_water":{},"fences":{"node|runtime":8},"generations":{"other|runtime":3}}`, ok: false},
		{name: "duplicate top-level key", body: `{"version":"llm-checkpoint-proof-journal-v2","version":"llm-checkpoint-proof-journal-v2","nonces":{},"issued_at":{},"high_water":{},"fences":{},"generations":{}}`, ok: false},
		{name: "duplicate nested key", body: `{"version":"llm-checkpoint-proof-journal-v2","nonces":{"node|nonce":"digest","node|nonce":"other"},"issued_at":{},"high_water":{},"fences":{},"generations":{}}`, ok: false},
		{name: "legacy ambiguity", body: `{"nonces":"digest"}`, ok: false},
		{name: "valid v2", body: string(validBody), ok: true},
		{name: "valid explicit legacy", body: `{"node-runtime|legacy":"digest"}`, ok: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := newCheckpointProofTestServer(cfg, secret, "")
			err := server.loadCheckpointProofNonceBody([]byte(test.body))
			if test.ok && err != nil {
				t.Fatalf("valid journal rejected: %v", err)
			}
			if !test.ok && err == nil {
				t.Fatal("corrupt journal was accepted")
			}
		})
	}

	server := newCheckpointProofTestServer(cfg, secret, "")
	if err := server.loadCheckpointProofNonceBody(validBody); err != nil {
		t.Fatal(err)
	}
	if err := server.loadCheckpointProofNonceBody([]byte(`{"version":"llm-checkpoint-proof-journal-v2","nonces":{"node-runtime|nonce":"digest"},"issued_at":{"node-runtime|nonce":"2026-01-02T03:04:05Z"},"high_water":{"node|node-runtime":3},"fences":{"node|node-runtime":7},"generations":{"node|node-runtime":2}}`)); err == nil {
		t.Fatal("journal high-water downgrade was accepted")
	}
	if err := server.loadCheckpointProofNonceBody([]byte(`{"node-runtime|legacy":"digest"}`)); err == nil {
		t.Fatal("legacy journal was allowed to discard resident high-water state")
	}
}

func TestModelCapacityPolicyIsConfigurableAndValidated(t *testing.T) {
	valid := `auth:
  credentials: []
workloads:
  default_max_accelerators_per_model: 2
  model_capacity_policies:
    - model: large-model
      max_accelerators: 1
`
	config, err := LoadConfig(writeConfig(t, valid))
	if err != nil {
		t.Fatal(err)
	}
	if config.Workloads.DefaultMaxAcceleratorsPerModel != 2 || len(config.Workloads.ModelCapacityPolicies) != 1 || config.Workloads.ModelCapacityPolicies[0].MaxAccelerators != 1 {
		t.Fatalf("model capacity policy was not decoded: %+v", config.Workloads)
	}
	duplicate := strings.Replace(valid, "      max_accelerators: 1\n", "      max_accelerators: 1\n    - model: large-model\n      max_accelerators: 2\n", 1)
	if _, err := LoadConfig(writeConfig(t, duplicate)); err == nil || !strings.Contains(err.Error(), "duplicate model capacity policy") {
		t.Fatalf("duplicate model policy was accepted: %v", err)
	}
}

func TestControllerConfigParsesStructuredCreatorSchemas(t *testing.T) {
	body := `auth:
  credentials: []
workloads:
  targets:
    - id: comfy-workflow
      adapter: comfy
      profiles:
        - profile_id: image-main
          version: "1"
          workflow: workflow://image/main/1
          modality: IMAGE
          operations: [image.generate]
          input_schema:
            type: object
            required: [prompt]
          output_schema:
            type: object
            required: [outputs]
          accepted_artifact_types: [image/*]
          produced_artifact_types: [image/png]
`
	config, err := LoadConfig(writeConfig(t, body))
	if err != nil {
		t.Fatal(err)
	}
	profile := config.Workloads.Targets[0].Profiles[0]
	if len(profile.InputSchema) == 0 || len(profile.OutputSchema) == 0 || profile.Workflow == "" {
		t.Fatalf("structured execution contract was not decoded: %+v", profile)
	}
}

func TestDevelopmentTLSRequiresCertificateAndKeyTogether(t *testing.T) {
	valid := `listen_addr: ":8443"
tls_cert_file: "controller.crt"
tls_key_file: "controller.key"
auth:
  credentials: []
workloads:
  artifact_store:
    type: "filesystem"
`
	if _, err := LoadConfig(writeConfig(t, valid)); err != nil {
		t.Fatalf("development TLS configuration was rejected: %v", err)
	}

	missingKey := strings.Replace(valid, "tls_key_file: \"controller.key\"\n", "", 1)
	if _, err := LoadConfig(writeConfig(t, missingKey)); err == nil || !strings.Contains(err.Error(), "configured together") {
		t.Fatalf("unpaired development TLS certificate was accepted: %v", err)
	}
}

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "controller.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func productionConfig(adminCIDR string) string {
	return `production: true
listen_addr: ":8443"
tls_cert_file: "controller.crt"
tls_key_file: "controller.key"
database_url: "postgres://controller@example/controller"
auth:
  command_signing_secret_env: "TEST_NODE_COMMAND_SECRET"
  admin_private_cidrs: ["` + adminCIDR + `"]
  credentials:
    - id: "operator"
      token_sha256: "` + strings.Repeat("ab", 32) + `"
      plane: "admin"
      owner_id: "ops"
      scopes: ["*"]
      adapters: ["*"]
      max_priority: 100
      egress_policy: "cloud_allowed"
workloads:
  artifact_store:
    type: "s3"
    endpoint: "https://objects.example.test"
    bucket: "vram"
    access_key_env: "TEST_S3_ACCESS"
    secret_key_env: "TEST_S3_SECRET"
`
}

func TestProductionConfigRequiresPrivateAdminNetworkAndCommandSecret(t *testing.T) {
	t.Setenv("TEST_NODE_COMMAND_SECRET", strings.Repeat("s", 32))
	if _, err := LoadConfig(writeConfig(t, productionConfig("10.10.0.0/16"))); err != nil {
		t.Fatalf("valid production security configuration rejected: %v", err)
	}
	if _, err := LoadConfig(writeConfig(t, productionConfig("0.0.0.0/0"))); err == nil || !strings.Contains(err.Error(), "private or loopback") {
		t.Fatalf("public admin network was not rejected: %v", err)
	}
	t.Setenv("TEST_NODE_COMMAND_SECRET", "short")
	if _, err := LoadConfig(writeConfig(t, productionConfig("10.10.0.0/16"))); err == nil || !strings.Contains(err.Error(), "at least 32 bytes") {
		t.Fatalf("weak production command secret was not rejected: %v", err)
	}
}

func TestProductionConfigRejectsDevelopmentBypass(t *testing.T) {
	t.Setenv("TEST_NODE_COMMAND_SECRET", strings.Repeat("s", 32))
	body := strings.Replace(productionConfig("10.10.0.0/16"), "auth:\n", "auth:\n  development_bypass: true\n", 1)
	if _, err := LoadConfig(writeConfig(t, body)); err == nil || !strings.Contains(err.Error(), "development_bypass") {
		t.Fatalf("production development bypass was not rejected: %v", err)
	}
}

func TestProductionConfigAllowsExplicitPasswordlessAdminLAN(t *testing.T) {
	t.Setenv("TEST_NODE_COMMAND_SECRET", strings.Repeat("s", 32))
	body := strings.Replace(productionConfig("10.10.0.0/16"), "auth:\n", "auth:\n  passwordless_admin_lan: true\n", 1)
	config, err := LoadConfig(writeConfig(t, body))
	if err != nil || !config.Auth.PasswordlessAdminLAN {
		t.Fatalf("explicit LAN-only passwordless admin config rejected: %v", err)
	}
}

func TestCredentialValidationRejectsInvalidPlaneAndDigest(t *testing.T) {
	body := `auth:
  credentials:
    - id: "bad"
      token_sha256: "not-a-digest"
      plane: "side-door"
      owner_id: "owner"
`
	if _, err := LoadConfig(writeConfig(t, body)); err == nil {
		t.Fatal("invalid credential plane and digest were accepted")
	}
}

func TestRuntimeProtocolValidation(t *testing.T) {
	valid := `auth:
  credentials: []
workloads:
  targets:
    - id: managed-video
      adapter: comfy
      runtime_protocol: managed_comfy_v1
      endpoint: http://renderer.invalid:8190
`
	config, err := LoadConfig(writeConfig(t, valid))
	if err != nil || config.Workloads.Targets[0].RuntimeProtocol != "managed_comfy_v1" {
		t.Fatalf("managed protocol was not decoded: %+v err=%v", config, err)
	}
	wrongAdapter := strings.Replace(valid, "adapter: comfy", "adapter: llamacpp", 1)
	if _, err := LoadConfig(writeConfig(t, wrongAdapter)); err == nil || !strings.Contains(err.Error(), "requires adapter comfy") {
		t.Fatalf("managed protocol on another adapter was accepted: %v", err)
	}
	unknown := strings.Replace(valid, "managed_comfy_v1", "future_protocol", 1)
	if _, err := LoadConfig(writeConfig(t, unknown)); err == nil || !strings.Contains(err.Error(), "invalid runtime_protocol") {
		t.Fatalf("unknown runtime protocol was accepted: %v", err)
	}
}

func TestResidencyContractValidatesByteBudgetsAndKeepsCheckpointSeparate(t *testing.T) {
	valid := `auth:
  credentials: []
workloads:
  capability_version: fleet-residency.v1
  max_accelerators_per_workload: 1
  capacity:
    vram_total_bytes: 100000
    vram_reserve_bytes: 1000
    ram_total_bytes: 1000000
    ram_reserve_bytes: 10000
  capabilities:
    supports_warm_ram: true
    warm_ram_verified: false
    supports_session_checkpoint: false
    session_checkpoint_verified: false
`
	cfg, err := LoadConfig(writeConfig(t, valid))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Workloads.MaxAcceleratorsPerWorkload != 1 || cfg.Workloads.Capabilities.WarmRAMVerified || cfg.Workloads.Capabilities.SessionCheckpointVerified {
		t.Fatalf("unexpected residency contract: %+v", cfg.Workloads)
	}
	bad := strings.Replace(valid, "vram_reserve_bytes: 1000", "vram_reserve_bytes: 100001", 1)
	if _, err := LoadConfig(writeConfig(t, bad)); err == nil || !strings.Contains(err.Error(), "vram_reserve_bytes") {
		t.Fatalf("unsafe byte budget was accepted: %v", err)
	}
	unknown := strings.Replace(valid, "fleet-residency.v1", "gpu-3080-special", 1)
	if _, err := LoadConfig(writeConfig(t, unknown)); err == nil || !strings.Contains(err.Error(), "unsupported capability contract version") {
		t.Fatalf("unknown capability version was accepted: %v", err)
	}
}

func TestPlacementCeilingDefaultsIndependentlyOfLegacyModelPolicy(t *testing.T) {
	body := `auth:
  credentials: []
workloads:
  default_max_accelerators_per_model: 3
`
	cfg, err := LoadConfig(writeConfig(t, body))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Workloads.DefaultMaxAcceleratorsPerModel != 3 || cfg.Workloads.MaxAcceleratorsPerWorkload != 1 {
		t.Fatalf("legacy model policy changed placement ceiling: default=%d ceiling=%d", cfg.Workloads.DefaultMaxAcceleratorsPerModel, cfg.Workloads.MaxAcceleratorsPerWorkload)
	}
}

func TestNestedPlacementCeilingNormalizesOmittedOuterValue(t *testing.T) {
	body := `auth:
  credentials: []
workloads:
  capabilities:
    max_accelerators_per_workload: 2
`
	cfg, err := LoadConfig(writeConfig(t, body))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Workloads.MaxAcceleratorsPerWorkload != 2 || cfg.Workloads.Capabilities.MaxAcceleratorsPerWorkload != 2 {
		t.Fatalf("nested placement ceiling was not normalized: %+v", cfg.Workloads)
	}
}

func TestOperatorConfigCannotMintVerifiedResidencyProof(t *testing.T) {
	body := `auth:
  credentials: []
workloads:
  capabilities:
    supports_warm_ram: true
    warm_ram_verified: true
    warm_ram_verification: mincore
`
	if _, err := LoadConfig(writeConfig(t, body)); err == nil || !strings.Contains(err.Error(), "authoritative runtime proof") {
		t.Fatalf("operator proof claim was accepted: %v", err)
	}
}

func TestTargetCapabilityOverrideGetsContractRevisionDuringLoad(t *testing.T) {
	body := `auth:
  credentials: []
workloads:
  capacity:
    vram_total_bytes: 1000
    vram_reserve_bytes: 100
    vram_hard_cap_bytes: 900
  targets:
    - id: node-llm
      adapter: llamacpp
      endpoint: http://node.invalid
      capabilities:
        supports_warm_ram: true
        supports_model_lifecycle: true
        supports_accelerator_reclaim: true
        max_resident_models: 3
      capacity:
        vram_total_bytes: 2000
`
	cfg, err := LoadConfig(writeConfig(t, body))
	if err != nil {
		t.Fatal(err)
	}
	target := cfg.Workloads.Targets[0]
	if target.CapabilityVersion != "" || target.Capabilities.Version != domain.CapabilityContractVersion || target.CapabilityRevision != domain.CapabilityContractVersion || !target.SupportsModelLifecycle || !target.SupportsAcceleratorReclaim || target.MaxResidentModels != 3 || !target.WarmRAMSupported {
		t.Fatalf("target capability override was not normalized: %+v", target)
	}
	if target.Capacity.VRAMTotalBytes != 2000 || target.Capacity.VRAMReserveBytes != 100 || target.Capacity.VRAMHardCapBytes != 900 {
		t.Fatalf("partial target capacity discarded global protections: %+v", target.Capacity)
	}
}

func TestTargetCannotRaiseInheritedAcceleratorCeiling(t *testing.T) {
	body := `auth:
  credentials: []
workloads:
  max_accelerators_per_workload: 1
  targets:
    - id: too-wide
      adapter: llamacpp
      endpoint: http://node.invalid
      max_accelerators_per_workload: 2
`
	if _, err := LoadConfig(writeConfig(t, body)); err == nil || !strings.Contains(err.Error(), "exceeds inherited ceiling") {
		t.Fatalf("target raised the inherited accelerator ceiling: %v", err)
	}
}

func TestTargetCapacityOverrideRejectsNegativeRawBudget(t *testing.T) {
	body := `auth:
  credentials: []
workloads:
  capacity:
    vram_total_bytes: 1000
  targets:
    - id: invalid-capacity
      adapter: llamacpp
      endpoint: http://node.invalid
      capacity:
        vram_reserve_bytes: -1
`
	if _, err := LoadConfig(writeConfig(t, body)); err == nil || !strings.Contains(err.Error(), "capacity override") {
		t.Fatalf("negative target capacity override was accepted: %v", err)
	}
}

func TestTargetCapacityOverrideCannotRaiseInheritedHardCaps(t *testing.T) {
	body := `auth:
  credentials: []
workloads:
  capacity:
    vram_total_bytes: 2000
    vram_hard_cap_bytes: 1000
    ram_total_bytes: 4000
    ram_hard_cap_bytes: 3000
  targets:
    - id: too-much-vram
      adapter: llamacpp
      endpoint: http://node.invalid
      capacity:
        vram_hard_cap_bytes: 1001
    - id: too-much-ram
      adapter: llamacpp
      endpoint: http://node.invalid
      capacity:
        ram_hard_cap_bytes: 3001
`
	if _, err := LoadConfig(writeConfig(t, body)); err == nil || !strings.Contains(err.Error(), "exceeds inherited ceiling") {
		t.Fatalf("target raised an inherited hard cap: %v", err)
	}
}

func TestResidencyEvidenceRejectsDanglingProofs(t *testing.T) {
	for name, capabilities := range map[string]domain.ResidencyCapabilities{
		"warm":       {Version: domain.CapabilityContractVersion, SupportsWarmRAM: true, WarmRAMVerification: "mincore"},
		"checkpoint": {Version: domain.CapabilityContractVersion, SupportsSessionCheckpoint: true, SessionCheckpointProof: "runtime"},
		"yield":      {Version: domain.CapabilityContractVersion, YieldProof: "runtime"},
	} {
		if err := capabilities.Validate(); err == nil {
			t.Fatalf("dangling %s proof was accepted", name)
		}
	}
}

func TestOperatorConfigCannotAssertCheckpointCapability(t *testing.T) {
	body := `auth:
  credentials: []
workloads:
  capabilities:
    supports_session_checkpoint: true
`
	if _, err := LoadConfig(writeConfig(t, body)); err == nil || !strings.Contains(err.Error(), "authoritative runtime proof") {
		t.Fatalf("static checkpoint capability was accepted: %v", err)
	}
}

func TestStaticTargetCannotMintCapacityEvidence(t *testing.T) {
	body := `auth:
  credentials: []
workloads:
  targets:
    - id: node-llm
      adapter: llamacpp
      endpoint: http://node.invalid
      capacity_verified: true
`
	if _, err := LoadConfig(writeConfig(t, body)); err == nil || !strings.Contains(err.Error(), "capacity_verified is runtime-only") {
		t.Fatalf("static capacity evidence was accepted: %v", err)
	}
}

func TestTargetCapabilityAliasesMergeAfterGlobalFallback(t *testing.T) {
	body := `auth:
  credentials: []
workloads:
  capabilities:
    supports_model_lifecycle: true
    max_resident_models: 4
    supports_warm_ram: true
  targets:
    - id: inherited
      adapter: llamacpp
      endpoint: http://node.invalid
      warm_ram_supported: true
      capabilities:
        supports_accelerator_reclaim: true
        max_resident_models: 4
    - id: empty
      adapter: llamacpp
      endpoint: http://node.invalid
`
	cfg, err := LoadConfig(writeConfig(t, body))
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range cfg.Workloads.Targets {
		if !target.Capabilities.SupportsModelLifecycle || !target.SupportsModelLifecycle || !target.Capabilities.SupportsWarmRAM || !target.WarmRAMSupported || target.MaxResidentModels != 4 || target.Capabilities.MaxResidentModels != 4 {
			t.Fatalf("target aliases did not preserve inherited truths: %+v", target)
		}
	}
}

func TestTargetCapabilityAliasConflictFailsClosed(t *testing.T) {
	body := `auth:
  credentials: []
workloads:
  capabilities:
    max_resident_models: 4
  targets:
    - id: conflicting
      adapter: llamacpp
      endpoint: http://node.invalid
      max_resident_models: 3
`
	if _, err := LoadConfig(writeConfig(t, body)); err == nil || !strings.Contains(err.Error(), "max_resident_models values conflict") {
		t.Fatalf("conflicting inherited and legacy max resident models were accepted: %v", err)
	}
}

func TestOperatorConfigCannotAssertYieldCapability(t *testing.T) {
	body := `auth:
  credentials: []
workloads:
  capabilities:
    supports_yield: true
`
	if _, err := LoadConfig(writeConfig(t, body)); err == nil || !strings.Contains(err.Error(), "authoritative runtime proof") {
		t.Fatalf("static yield capability was accepted: %v", err)
	}
}
