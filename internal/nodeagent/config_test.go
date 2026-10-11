package nodeagent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"vram-governor/internal/domain"
	"vram-governor/internal/wsproto"
)

func writeAgentConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "node-agent.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestNodeConfigRequiresCredentialsAndSafeWSSSecrets(t *testing.T) {
	if _, err := LoadConfig(writeAgentConfig(t, "controller_url: ws://127.0.0.1/ws/node\nnode_id: node-a\n")); err == nil || !strings.Contains(err.Error(), "token") {
		t.Fatalf("credential-free node config was accepted: %v", err)
	}
	t.Setenv("TEST_NODE_TOKEN", "node-token")
	t.Setenv("TEST_NODE_COMMAND", strings.Repeat("s", 32))
	config, err := LoadConfig(writeAgentConfig(t, `controller_url: wss://controller.example/ws/node
token_env: TEST_NODE_TOKEN
node_id: node-a
command_signing_secret_env: TEST_NODE_COMMAND
`))
	if err != nil || config.Token != "node-token" || len(config.CommandSigningSecret) != 32 {
		t.Fatalf("valid wss node config rejected: %+v err=%v", config, err)
	}
	if _, err := LoadConfig(writeAgentConfig(t, `controller_url: wss://controller.example/ws/node
token: literal
node_id: node-a
command_signing_secret_env: TEST_NODE_COMMAND
`)); err == nil || !strings.Contains(err.Error(), "token_env") {
		t.Fatalf("literal production node token was accepted: %v", err)
	}
}

func TestNodeConfigRejectsReconnectStormSettings(t *testing.T) {
	_, err := LoadConfig(writeAgentConfig(t, `controller_url: ws://127.0.0.1/ws/node
token: dev
node_id: node-a
reconnect_min_seconds: 10
reconnect_max_seconds: 2
`))
	if err == nil || !strings.Contains(err.Error(), "reconnect_max_seconds") {
		t.Fatalf("unsafe reconnect range accepted: %v", err)
	}
}

func TestNodeConfigRecoveryGenerationRequiresBoundedEpoch(t *testing.T) {
	base := `controller_url: ws://127.0.0.1/ws/node
token: dev
node_id: node-a
`
	if _, err := LoadConfig(writeAgentConfig(t, base+"command_recovery_epoch: epoch-only\n")); err == nil || !strings.Contains(err.Error(), "generation") {
		t.Fatal("epoch without generation was accepted")
	}
	if _, err := LoadConfig(writeAgentConfig(t, base+"command_recovery_generation: 4\n")); err == nil || !strings.Contains(err.Error(), "epoch") {
		t.Fatal("generation without epoch was accepted")
	}
	cfg, err := LoadConfig(writeAgentConfig(t, base+"command_recovery_generation: 4\ncommand_recovery_epoch: epoch-four\n"))
	if err != nil || cfg.CommandRecoveryGeneration != 4 || cfg.CommandRecoveryEpoch != "epoch-four" {
		t.Fatalf("valid startup recovery configuration was rejected: cfg=%+v err=%v", cfg, err)
	}
}

func TestRuntimeProfileConfigRejectsExecutableInputAndDuplicateIDs(t *testing.T) {
	base := `controller_url: ws://127.0.0.1/ws/node
token: dev
node_id: node-a
llamacpp:
  servers:
    - id: local
      endpoint: http://127.0.0.1:11434
      runtime_profiles:
        - id: short
          context_limit: 8192
          slots: 4
          switch_command: [COMMAND]
`
	for _, command := range []string{`"systemctl restart anything"`, `""`} {
		_, err := LoadConfig(writeAgentConfig(t, strings.Replace(base, "COMMAND", command, 1)))
		if err == nil || !strings.Contains(err.Error(), "absolute fixed switch_command") {
			t.Fatalf("unsafe switch command %s accepted: %v", command, err)
		}
	}
	duplicate := strings.Replace(base, "COMMAND", `"/usr/local/libexec/vram-governor/switch-runtime-profile", "local", "short"`, 1) + `        - id: short
          context_limit: 32768
          slots: 1
          switch_command: ["/usr/local/libexec/vram-governor/switch-runtime-profile", "local", "long"]
`
	if _, err := LoadConfig(writeAgentConfig(t, duplicate)); err == nil || !strings.Contains(err.Error(), "duplicate runtime profile") {
		t.Fatalf("duplicate runtime profile accepted: %v", err)
	}
}

func TestNodeConfigDefaultsVersionAndSingleAcceleratorCeiling(t *testing.T) {
	cfg, err := LoadConfig(writeAgentConfig(t, `controller_url: ws://127.0.0.1/ws/node
token: dev
node_id: node-a
capacity:
  vram_total_bytes: 1000
  vram_reserve_bytes: 100
`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.CapabilityVersion == "" || cfg.Capabilities.Version == "" {
		t.Fatalf("capability version was not defaulted: %+v", cfg)
	}
	if cfg.MaxAcceleratorsPerWorkload != 1 || cfg.Capacity.VRAMHardCapBytes != 1000 {
		t.Fatalf("unexpected safe defaults: ceiling=%d budget=%+v", cfg.MaxAcceleratorsPerWorkload, cfg.Capacity)
	}
}

func TestNodeConfigRejectsUnsafeByteBudgetsAndCapabilityProofs(t *testing.T) {
	unsafeBudget := `controller_url: ws://127.0.0.1/ws/node
token: dev
node_id: node-a
capacity:
  vram_total_bytes: 100
  vram_reserve_bytes: 101
`
	if _, err := LoadConfig(writeAgentConfig(t, unsafeBudget)); err == nil {
		t.Fatal("reserve larger than total was accepted")
	}
	unsafeProof := `controller_url: ws://127.0.0.1/ws/node
token: dev
node_id: node-a
capabilities:
  supports_warm_ram: true
  warm_ram_verified: true
  warm_ram_verification: guessed
`
	if _, err := LoadConfig(writeAgentConfig(t, unsafeProof)); err == nil {
		t.Fatal("unverified warm-RAM oracle was accepted")
	}
	unsafeYield := `controller_url: ws://127.0.0.1/ws/node
token: dev
node_id: node-a
capabilities:
  supports_yield: true
`
	if _, err := LoadConfig(writeAgentConfig(t, unsafeYield)); err == nil || !strings.Contains(err.Error(), "authoritative runtime proof") {
		t.Fatalf("static yield capability was accepted: %v", err)
	}
	unsafeCheckpoint := `controller_url: ws://127.0.0.1/ws/node
token: dev
node_id: node-a
capabilities:
  supports_session_checkpoint: true
`
	if _, err := LoadConfig(writeAgentConfig(t, unsafeCheckpoint)); err == nil || !strings.Contains(err.Error(), "authoritative runtime proof") {
		t.Fatalf("static checkpoint capability was accepted: %v", err)
	}
}

func TestNodeConfigNormalizesNestedPlacementCeiling(t *testing.T) {
	cfg, err := LoadConfig(writeAgentConfig(t, `controller_url: ws://127.0.0.1/ws/node
token: dev
node_id: node-a
capabilities:
  max_accelerators_per_workload: 2
`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MaxAcceleratorsPerWorkload != 2 || cfg.Capabilities.MaxAcceleratorsPerWorkload != 2 {
		t.Fatalf("nested placement ceiling was not normalized: %+v", cfg)
	}
}

func TestNodeRegistrationAndRefreshCarryCapabilityEnvelope(t *testing.T) {
	cfg, err := LoadConfig(writeAgentConfig(t, `controller_url: ws://127.0.0.1/ws/node
token: dev
node_id: node-a
capabilities:
  supports_warm_ram: true
capacity:
  vram_total_bytes: 1000
  vram_reserve_bytes: 100
`))
	if err != nil {
		t.Fatal(err)
	}
	// Runtime discovery, not operator YAML, supplies authoritative proof.
	cfg.Capabilities.WarmRAMVerified = true
	cfg.Capabilities.WarmRAMVerification = "mincore"
	register := registerPayloadForConfig(cfg)
	refresh := capabilitiesPayloadForConfig(cfg, []wsproto.AdapterAdvertisement{{ID: "llm", Adapter: "llamacpp", Endpoint: "http://node.invalid"}})
	if register.CapabilityVersion != domain.CapabilityContractVersion || refresh.CapabilityVersion != register.CapabilityVersion || !register.Capabilities.WarmRAMVerified || refresh.Capacity.VRAMReserveBytes != 100 {
		t.Fatalf("registration/refresh dropped capability envelope: register=%+v refresh=%+v", register, refresh)
	}
}

func TestWarmRAMConfigRequiresExplicitValidatedPolicy(t *testing.T) {
	root := t.TempDir()
	base := WarmRAMConfig{Enabled: true, ModelRoots: []string{filepath.Join(root, "models")}, RAMTotalBytes: 16 << 30, RAMReserveBytes: 1 << 30, RAMHardCapBytes: 8 << 30, MaxWarmBytes: 4 << 30, MemlockLimitBytes: 4 << 30, CgroupLimitBytes: 8 << 30, PressureRefusalPercent: 80, MemInfoPath: filepath.Join(root, "meminfo"), PressurePath: filepath.Join(root, "pressure"), CgroupCurrentPath: filepath.Join(root, "current"), CgroupMaxPath: filepath.Join(root, "max"), CgroupEventsPath: filepath.Join(root, "events"), OOMEventsPath: filepath.Join(root, "oom")}
	if err := base.Validate(); err != nil {
		t.Fatalf("valid warm policy rejected: %v", err)
	}
	for name, mutate := range map[string]func(*WarmRAMConfig){
		"missing roots":  func(c *WarmRAMConfig) { c.ModelRoots = nil },
		"unsafe root":    func(c *WarmRAMConfig) { c.ModelRoots = []string{"relative/models"} },
		"missing source": func(c *WarmRAMConfig) { c.PressurePath = "" },
		"unsafe budget":  func(c *WarmRAMConfig) { c.RAMReserveBytes = c.RAMHardCapBytes + 1 },
	} {
		candidate := base
		mutate(&candidate)
		if err := candidate.Validate(); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	if err := (WarmRAMConfig{ModelRoots: []string{filepath.Join(root, "models")}}).Validate(); err == nil {
		t.Fatal("disabled policy silently accepted model roots")
	}
}

func TestNodeConfigValidatesExplicitModelPathMappings(t *testing.T) {
	root := t.TempDir()
	models := filepath.Join(root, "models")
	base := `controller_url: ws://127.0.0.1/ws/node
token: dev
node_id: node-a
warm_ram:
  enabled: true
  model_roots: [MODEL_ROOT]
  ram_hard_cap_bytes: 1000
  ram_reserve_bytes: 100
  max_warm_bytes: 500
  memlock_limit_bytes: 1000
  cgroup_limit_bytes: 1000
  pressure_refusal_percent: 80
  meminfo_path: CONTROL_ROOT/meminfo
  pressure_path: CONTROL_ROOT/pressure
  cgroup_current_path: CONTROL_ROOT/current
  cgroup_max_path: CONTROL_ROOT/max
  cgroup_events_path: CONTROL_ROOT/events
  oom_events_path: CONTROL_ROOT/events
llamacpp:
  servers:
    - id: local
      endpoint: http://127.0.0.1:11434
      model_paths:
        model: MODEL_PATH
      model_fingerprints:
        model: 0000000000000000000000000000000000000000000000000000000000000000
      runtime_fingerprints:
        model: 1111111111111111111111111111111111111111111111111111111111111111
`
	valid := strings.NewReplacer("MODEL_ROOT", models, "MODEL_PATH", filepath.Join(models, "model.gguf"), "CONTROL_ROOT", filepath.ToSlash(root)).Replace(base)
	if _, err := LoadConfig(writeAgentConfig(t, valid)); err != nil {
		t.Fatalf("valid model mapping rejected: %v", err)
	}
	for name, replacement := range map[string]string{
		"missing mapping": "      model_paths: {}\n",
		"relative path":   "        model: relative/model.gguf\n",
		"outside root":    "        model: " + filepath.Join(root, "outside.gguf") + "\n",
	} {
		candidate := base
		switch name {
		case "missing mapping":
			candidate = strings.Replace(candidate, "      model_paths:\n        model: MODEL_PATH\n", replacement, 1)
		case "relative path":
			candidate = strings.Replace(candidate, "        model: MODEL_PATH", replacement[:len(replacement)-1], 1)
		case "outside root":
			candidate = strings.Replace(candidate, "        model: MODEL_PATH", replacement[:len(replacement)-1], 1)
		}
		candidate = strings.NewReplacer("MODEL_ROOT", models, "MODEL_PATH", filepath.Join(models, "model.gguf"), "CONTROL_ROOT", filepath.ToSlash(root)).Replace(candidate)
		if _, err := LoadConfig(writeAgentConfig(t, candidate)); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}
