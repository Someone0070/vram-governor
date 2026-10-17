package nodeagent

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
	"vram-governor/internal/domain"
)

// Config is the node agent's configuration file shape (configs/node-agent.yaml).
type Config struct {
	ControllerURL    string `yaml:"controller_url"`     // ws:// or wss:// URL of /ws/node
	ControllerCAFile string `yaml:"controller_ca_file"` // Optional private CA for a self-signed controller.
	Token            string `yaml:"token"`
	TokenEnv         string `yaml:"token_env"`
	NodeID           string `yaml:"node_id"`
	NodeName         string `yaml:"node_name"`
	LogLevel         string `yaml:"log_level"`

	// LocationClass / PowerControlMode are capability flags (§45 #33/#34),
	// not a hard local/remote architectural split.
	LocationClass    string `yaml:"location_class"`     // local | remote
	PowerControlMode string `yaml:"power_control_mode"` // auto|manual|off|dont_touch|external

	HeartbeatIntervalSeconds   int                          `yaml:"heartbeat_interval_seconds"`
	CapabilityRefreshSeconds   int                          `yaml:"capability_refresh_seconds"`
	ReconnectMinSeconds        int                          `yaml:"reconnect_min_seconds"`
	ReconnectMaxSeconds        int                          `yaml:"reconnect_max_seconds"`
	AgentVersion               string                       `yaml:"-"`
	CapabilityVersion          string                       `yaml:"capability_version"`
	Capabilities               domain.ResidencyCapabilities `yaml:"capabilities"`
	Capacity                   domain.CapacityBudget        `yaml:"capacity"`
	MaxAcceleratorsPerWorkload int                          `yaml:"max_accelerators_per_workload"`
	CommandSigningSecret       string                       `yaml:"command_signing_secret"`
	CommandSigningSecretEnv    string                       `yaml:"command_signing_secret_env"`
	// CommandRecoveryEpoch is an administrator/controller supplied epoch.  It
	// is intentionally separate from command fences so a recovery can never
	// be authorized by a stale command stream.
	CommandRecoveryEpoch      string           `yaml:"command_recovery_epoch"`
	CommandRecoveryGeneration uint64           `yaml:"command_recovery_generation"`
	CommandStatePath          string           `yaml:"command_state_path"`
	WarmRAM                   WarmRAMConfig    `yaml:"warm_ram"`
	Checkpoint                CheckpointConfig `yaml:"checkpoint"`
	GPUPerformance            struct {
		Accelerators []GPUPerformanceConfig `yaml:"accelerators"`
	} `yaml:"gpu_performance"`

	// Phase 2: runtime-driver + probe settings (measurement.md §4 "probing
	// is a node-agent responsibility"). Optional — only needed when running
	// with -probe.
	LlamaServerPath     string `yaml:"llama_server_path"`
	GPUIndex            int    `yaml:"gpu_index"`
	ProbeWorkDir        string `yaml:"probe_work_dir"`
	ServingProfilesFile string `yaml:"serving_profiles_file"`
	LlamaCPP            struct {
		Servers []LlamaCPPServerConfig `yaml:"servers"`
	} `yaml:"llamacpp"`

	ComfyUI struct {
		Endpoint         string `yaml:"endpoint"`
		PublicEndpoint   string `yaml:"public_endpoint"`
		AcceleratorIndex int    `yaml:"accelerator_index"`
	} `yaml:"comfyui"`
}

type CheckpointConfig struct {
	Enabled bool `yaml:"enabled"`
	// ProofExerciseEnabled is an explicit one-shot gate. Checkpointing stays
	// fail-closed unless an operator authorizes the live, disruptive exercise.
	ProofExerciseEnabled   bool   `yaml:"proof_exercise_enabled"`
	Root                   string `yaml:"root"`
	MaxBytes               int64  `yaml:"max_bytes"`
	MaxFiles               int    `yaml:"max_files"`
	PerOwnerMaxBytes       int64  `yaml:"per_owner_max_bytes"`
	PerOwnerMaxFiles       int    `yaml:"per_owner_max_files"`
	MaxMetadataBytes       int64  `yaml:"max_metadata_bytes"`
	MaxOutputBytes         int64  `yaml:"max_output_bytes"`
	ExpirySeconds          int    `yaml:"expiry_seconds"`
	CleanupIntervalSeconds int    `yaml:"cleanup_interval_seconds"`
	ProofPath              string `yaml:"proof_path"`
	// IssuanceStatePath is a separate private node-local sidecar containing
	// proof issuance high-water. It survives agent restarts and is never sent
	// over the websocket. Empty derives from ProofPath for compatibility.
	IssuanceStatePath string `yaml:"issuance_state_path"`
}

func (c CheckpointConfig) Validate() error {
	if !c.Enabled {
		return nil
	}
	if c.Root == "" || !filepath.IsAbs(c.Root) || filepath.Clean(c.Root) != c.Root || strings.ContainsAny(c.Root, "\r\n\x00") {
		return fmt.Errorf("checkpoint root must be a clean absolute path")
	}
	if c.MaxBytes <= 0 || c.MaxFiles <= 0 || c.PerOwnerMaxBytes <= 0 || c.PerOwnerMaxFiles <= 0 || c.PerOwnerMaxBytes > c.MaxBytes || c.PerOwnerMaxFiles > c.MaxFiles {
		return fmt.Errorf("checkpoint quotas are invalid")
	}
	if c.MaxMetadataBytes <= 0 || c.MaxOutputBytes <= 0 || c.ExpirySeconds <= 0 || c.CleanupIntervalSeconds <= 0 {
		return fmt.Errorf("checkpoint bounds and cleanup intervals are required")
	}
	if c.ProofPath == "" || !filepath.IsAbs(c.ProofPath) || filepath.Clean(c.ProofPath) != c.ProofPath {
		return fmt.Errorf("checkpoint proof_path must be a clean absolute path")
	}
	if c.IssuanceStatePath != "" && (!filepath.IsAbs(c.IssuanceStatePath) || filepath.Clean(c.IssuanceStatePath) != c.IssuanceStatePath || strings.ContainsAny(c.IssuanceStatePath, "\r\n\x00")) {
		return fmt.Errorf("checkpoint issuance_state_path must be a clean absolute path")
	}
	return nil
}

// WarmRAMConfig is explicit because warm residency is a safety-sensitive
// promise. An omitted block disables warm offload; no probe/work directory is
// treated as an implicit model allowlist.
type WarmRAMConfig struct {
	Enabled                bool     `yaml:"enabled"`
	ModelRoots             []string `yaml:"model_roots"`
	RAMTotalBytes          int64    `yaml:"ram_total_bytes"`
	RAMReserveBytes        int64    `yaml:"ram_reserve_bytes"`
	RAMHardCapBytes        int64    `yaml:"ram_hard_cap_bytes"`
	MaxWarmBytes           int64    `yaml:"max_warm_bytes"`
	MemlockLimitBytes      int64    `yaml:"memlock_limit_bytes"`
	CgroupLimitBytes       int64    `yaml:"cgroup_limit_bytes"`
	UnifiedMemory          bool     `yaml:"unified_memory"`
	UnifiedMemoryBytes     int64    `yaml:"unified_memory_bytes"`
	PressureRefusalPercent float64  `yaml:"pressure_refusal_percent"`
	MemInfoPath            string   `yaml:"meminfo_path"`
	PressurePath           string   `yaml:"pressure_path"`
	CgroupCurrentPath      string   `yaml:"cgroup_current_path"`
	CgroupMaxPath          string   `yaml:"cgroup_max_path"`
	CgroupEventsPath       string   `yaml:"cgroup_events_path"`
	OOMEventsPath          string   `yaml:"oom_events_path"`
}

func (c WarmRAMConfig) Validate() error {
	if !c.Enabled {
		if len(c.ModelRoots) > 0 {
			return fmt.Errorf("warm_ram model_roots require enabled: true")
		}
		return nil
	}
	if len(c.ModelRoots) == 0 {
		return fmt.Errorf("warm_ram model_roots are required")
	}
	for _, root := range c.ModelRoots {
		if root == "" || !filepath.IsAbs(root) || filepath.Clean(root) != root || strings.ContainsAny(root, "\r\n\x00") {
			return fmt.Errorf("warm_ram model roots must be clean absolute paths")
		}
	}
	if c.RAMHardCapBytes <= 0 || c.RAMReserveBytes < 0 || c.RAMReserveBytes > c.RAMHardCapBytes {
		return fmt.Errorf("warm_ram RAM hard cap/reserve are invalid")
	}
	if c.RAMTotalBytes > 0 && c.RAMHardCapBytes > c.RAMTotalBytes {
		return fmt.Errorf("warm_ram RAM hard cap exceeds total")
	}
	if c.MaxWarmBytes <= 0 || c.MemlockLimitBytes <= 0 || c.CgroupLimitBytes <= 0 {
		return fmt.Errorf("warm_ram max_warm, memlock, and cgroup limits are required")
	}
	if c.UnifiedMemory && c.UnifiedMemoryBytes <= 0 {
		return fmt.Errorf("warm_ram unified-memory accounting requires a positive limit")
	}
	if c.UnifiedMemoryBytes < 0 || (c.UnifiedMemory && c.UnifiedMemoryBytes > c.RAMHardCapBytes-c.RAMReserveBytes) {
		return fmt.Errorf("warm_ram unified-memory accounting is invalid")
	}
	if c.PressureRefusalPercent <= 0 || c.PressureRefusalPercent > 100 {
		return fmt.Errorf("warm_ram pressure_refusal_percent must be between 0 and 100")
	}
	for name, value := range map[string]string{"meminfo_path": c.MemInfoPath, "pressure_path": c.PressurePath, "cgroup_current_path": c.CgroupCurrentPath, "cgroup_max_path": c.CgroupMaxPath, "cgroup_events_path": c.CgroupEventsPath, "oom_events_path": c.OOMEventsPath} {
		if value == "" || !filepath.IsAbs(value) || strings.ContainsAny(value, "\r\n\x00") {
			return fmt.Errorf("warm_ram %s must be an absolute path", name)
		}
	}
	return nil
}

// LlamaCPPServerConfig describes an already-running llama-server. Runtime
// discovery verifies model, context, and parallel slot capacity; the explicit
// values are conservative fallbacks for older or locked-down servers.
type LlamaCPPServerConfig struct {
	ID                  string                 `yaml:"id"`
	Endpoint            string                 `yaml:"endpoint"`
	PublicEndpoint      string                 `yaml:"public_endpoint"`
	AcceleratorIndex    int                    `yaml:"accelerator_index"`
	ContextLimit        int                    `yaml:"context_limit"`
	Slots               int                    `yaml:"slots"`
	RuntimeArgs         []string               `yaml:"runtime_args"`
	ModelPaths          map[string]string      `yaml:"model_paths"`
	ModelFingerprints   map[string]string      `yaml:"model_fingerprints"`
	RuntimeFingerprints map[string]string      `yaml:"runtime_fingerprints"`
	RouterManaged       bool                   `yaml:"router_managed"`
	MaxResidentModels   int                    `yaml:"max_resident_models"`
	RuntimeProfiles     []RuntimeProfileConfig `yaml:"runtime_profiles"`
	// ModelPoolsFile is the JSON map {model: {pool_tokens, slots,
	// max_request_tokens}} written by vram-llama-placement; read on every
	// discovery and advertised so the controller admits by context tokens.
	ModelPoolsFile string `yaml:"model_pools_file"`
}

// RuntimeProfileConfig binds a public capacity mode to one fixed local
// command. Controller input selects only ID; it can never provide executable
// text or arguments.
type RuntimeProfileConfig struct {
	ID            string   `yaml:"id"`
	ContextLimit  int      `yaml:"context_limit"`
	Slots         int      `yaml:"slots"`
	SwitchCommand []string `yaml:"switch_command"`
}

// GPUPerformanceConfig binds an accelerator to fixed operator-approved
// commands. The controller may select only idle or active; it cannot supply
// executable text, clocks, power limits, or a different GPU index.
type GPUPerformanceConfig struct {
	Index         int      `yaml:"index"`
	IdleCommand   []string `yaml:"idle_command"`
	ActiveCommand []string `yaml:"active_command"`
}

const AgentVersion = "1.2.3"

func LoadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	var c Config
	if err := yaml.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	if c.ControllerURL == "" {
		return nil, fmt.Errorf("controller_url is required")
	}
	controllerURL, err := url.Parse(c.ControllerURL)
	if err != nil || (controllerURL.Scheme != "ws" && controllerURL.Scheme != "wss") || controllerURL.Host == "" {
		return nil, fmt.Errorf("controller_url must be an absolute ws:// or wss:// URL")
	}
	if c.TokenEnv != "" {
		c.Token = os.Getenv(c.TokenEnv)
	}
	if c.Token == "" {
		return nil, fmt.Errorf("node credential token is required")
	}
	if c.NodeID == "" {
		return nil, fmt.Errorf("node_id is required")
	}
	// Server IDs and their advertised node-prefixed aliases share one
	// namespace.  Reject collisions before any target can be canonicalized
	// into an ambiguous fence/state key.
	seenServerIDs := make(map[string]struct{}, len(c.LlamaCPP.Servers))
	seenTargetAliases := make(map[string]string, len(c.LlamaCPP.Servers)*2)
	for _, server := range c.LlamaCPP.Servers {
		if server.ID == "" {
			return nil, fmt.Errorf("llamacpp server id is required")
		}
		if _, exists := seenServerIDs[server.ID]; exists {
			return nil, fmt.Errorf("duplicate llamacpp server id %q", server.ID)
		}
		seenServerIDs[server.ID] = struct{}{}
		canonical := c.NodeID + "-" + server.ID
		if previous, exists := seenTargetAliases[server.ID]; exists {
			return nil, fmt.Errorf("llamacpp server id %q collides with target alias of %s", server.ID, previous)
		}
		if previous, exists := seenTargetAliases[canonical]; exists {
			return nil, fmt.Errorf("llamacpp target alias %q collides with %s", canonical, previous)
		}
		seenTargetAliases[server.ID] = server.ID
		seenTargetAliases[canonical] = server.ID
	}
	if c.NodeName == "" {
		c.NodeName = c.NodeID
	}
	if c.CapabilityVersion == "" {
		c.CapabilityVersion = domain.CapabilityContractVersion
	}
	if err := domain.ValidateCapabilityVersion(c.CapabilityVersion); err != nil {
		return nil, err
	}
	if c.Capabilities.Version == "" {
		c.Capabilities.Version = c.CapabilityVersion
	}
	if err := domain.ValidateOperatorCapabilities(c.Capabilities); err != nil {
		return nil, fmt.Errorf("capabilities: %w", err)
	}
	if err := c.Capabilities.Validate(); err != nil {
		return nil, fmt.Errorf("capabilities: %w", err)
	}
	if c.Capacity.VRAMHardCapBytes == 0 && c.Capacity.VRAMTotalBytes > 0 {
		c.Capacity.VRAMHardCapBytes = c.Capacity.VRAMTotalBytes
	}
	if c.Capacity.RAMHardCapBytes == 0 && c.Capacity.RAMTotalBytes > 0 {
		c.Capacity.RAMHardCapBytes = c.Capacity.RAMTotalBytes
	}
	if err := c.Capacity.Validate(); err != nil {
		return nil, fmt.Errorf("capacity: %w", err)
	}
	if err := c.WarmRAM.Validate(); err != nil {
		return nil, fmt.Errorf("warm_ram: %w", err)
	}
	if err := c.Checkpoint.Validate(); err != nil {
		return nil, fmt.Errorf("checkpoint: %w", err)
	}
	normalizedMax, err := domain.NormalizeAcceleratorCeiling(c.MaxAcceleratorsPerWorkload, c.Capabilities.MaxAcceleratorsPerWorkload)
	if err != nil {
		return nil, err
	}
	c.MaxAcceleratorsPerWorkload = normalizedMax
	c.Capabilities.MaxAcceleratorsPerWorkload = normalizedMax
	if c.LogLevel == "" {
		c.LogLevel = "info"
	}
	if c.LocationClass == "" {
		c.LocationClass = "local"
	}
	if c.PowerControlMode == "" {
		c.PowerControlMode = "manual"
	}
	if c.HeartbeatIntervalSeconds == 0 {
		c.HeartbeatIntervalSeconds = 2
	}
	if c.CapabilityRefreshSeconds == 0 {
		c.CapabilityRefreshSeconds = 30
	}
	if c.ReconnectMinSeconds == 0 {
		c.ReconnectMinSeconds = 1
	}
	if c.ReconnectMaxSeconds == 0 {
		c.ReconnectMaxSeconds = 15
	}
	if c.LlamaServerPath == "" {
		c.LlamaServerPath = os.ExpandEnv("$HOME/llama.cpp/build/bin/llama-server")
	}
	if c.ProbeWorkDir == "" {
		c.ProbeWorkDir = "/tmp/vram-governor-probe"
	}
	if c.ServingProfilesFile == "" {
		c.ServingProfilesFile = "configs/serving-profiles.yaml"
	}
	if c.CommandSigningSecretEnv != "" {
		c.CommandSigningSecret = os.Getenv(c.CommandSigningSecretEnv)
	}
	if c.Checkpoint.Enabled && c.Checkpoint.IssuanceStatePath == "" && c.Checkpoint.ProofPath != "" {
		c.Checkpoint.IssuanceStatePath = checkpointProofIssuancePath(c.Checkpoint.ProofPath)
	}
	if c.HeartbeatIntervalSeconds <= 0 || c.CapabilityRefreshSeconds <= 0 || c.ReconnectMinSeconds <= 0 || c.ReconnectMaxSeconds < c.ReconnectMinSeconds {
		return nil, fmt.Errorf("heartbeat/capability intervals must be positive and reconnect_max_seconds must be at least reconnect_min_seconds")
	}
	if c.LocationClass != "local" && c.LocationClass != "remote" {
		return nil, fmt.Errorf("location_class must be local or remote")
	}
	switch c.PowerControlMode {
	case "auto", "manual", "off", "dont_touch", "external":
	default:
		return nil, fmt.Errorf("invalid power_control_mode %q", c.PowerControlMode)
	}
	if strings.EqualFold(controllerURL.Scheme, "wss") {
		if c.TokenEnv == "" {
			return nil, fmt.Errorf("wss controller connections require token_env instead of a literal token")
		}
		if c.CommandSigningSecretEnv == "" || len(c.CommandSigningSecret) < 32 {
			return nil, fmt.Errorf("wss controller connections require a command signing secret of at least 32 bytes via command_signing_secret_env")
		}
	}
	if c.CommandStatePath == "" {
		c.CommandStatePath = "data/node-command-state.json"
	}
	if c.CommandRecoveryGeneration == 0 && strings.TrimSpace(c.CommandRecoveryEpoch) != "" {
		return nil, fmt.Errorf("command_recovery_epoch requires a positive command_recovery_generation")
	}
	if c.CommandRecoveryGeneration > 0 {
		if strings.TrimSpace(c.CommandRecoveryEpoch) == "" || len(c.CommandRecoveryEpoch) > 256 || strings.ContainsAny(c.CommandRecoveryEpoch, "\r\n\x00") {
			return nil, fmt.Errorf("command recovery generation requires a bounded non-empty epoch")
		}
	}
	for _, server := range c.LlamaCPP.Servers {
		if c.WarmRAM.Enabled && len(server.ModelPaths) == 0 {
			return nil, fmt.Errorf("llamacpp server %q requires explicit model_paths when warm_ram is enabled", server.ID)
		}
		seenModelPaths := make(map[string]string, len(server.ModelPaths))
		for model, modelPath := range server.ModelPaths {
			if model == "" || modelPath == "" || !filepath.IsAbs(modelPath) || filepath.Clean(modelPath) != modelPath || strings.ContainsAny(modelPath, "\r\n\x00") {
				return nil, fmt.Errorf("llamacpp model_paths must contain clean absolute paths")
			}
			if c.WarmRAM.Enabled {
				if previous, exists := seenModelPaths[modelPath]; exists && previous != model {
					return nil, fmt.Errorf("llamacpp model_paths bind multiple models to one file: %s and %s", previous, model)
				}
				seenModelPaths[modelPath] = model
				fingerprint := server.ModelFingerprints[model]
				decoded, decodeErr := hex.DecodeString(fingerprint)
				if len(decoded) != sha256.Size || decodeErr != nil {
					return nil, fmt.Errorf("llamacpp model_fingerprints for %s must be a SHA-256 digest", model)
				}
				runtimeFingerprint, runtimeDecodeErr := hex.DecodeString(server.RuntimeFingerprints[model])
				if len(runtimeFingerprint) != sha256.Size || runtimeDecodeErr != nil {
					return nil, fmt.Errorf("llamacpp runtime_fingerprints for %s must be a SHA-256 digest", model)
				}
				allowed := false
				for _, root := range c.WarmRAM.ModelRoots {
					if rel, e := filepath.Rel(root, modelPath); e == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel) {
						allowed = true
						break
					}
				}
				if !allowed {
					return nil, fmt.Errorf("llamacpp model path for %s is outside warm_ram model_roots", model)
				}
			}
		}
		if c.WarmRAM.Enabled {
			for model := range server.ModelFingerprints {
				if _, ok := server.ModelPaths[model]; !ok {
					return nil, fmt.Errorf("llamacpp model_fingerprints contains an unmapped model %s", model)
				}
			}
			for model := range server.RuntimeFingerprints {
				if _, ok := server.ModelPaths[model]; !ok {
					return nil, fmt.Errorf("llamacpp runtime_fingerprints contains an unmapped model %s", model)
				}
			}
		}
	}
	seenAccelerators := map[int]struct{}{}
	for _, profile := range c.GPUPerformance.Accelerators {
		if profile.Index < 0 {
			return nil, fmt.Errorf("gpu_performance accelerator index must be nonnegative")
		}
		if _, exists := seenAccelerators[profile.Index]; exists {
			return nil, fmt.Errorf("duplicate gpu_performance accelerator index %d", profile.Index)
		}
		seenAccelerators[profile.Index] = struct{}{}
		for _, command := range [][]string{profile.IdleCommand, profile.ActiveCommand} {
			if len(command) == 0 || !strings.HasPrefix(command[0], "/") {
				return nil, fmt.Errorf("gpu_performance accelerator %d requires absolute fixed idle and active commands", profile.Index)
			}
			for _, argument := range command {
				if argument == "" || strings.ContainsAny(argument, "\r\n\x00") {
					return nil, fmt.Errorf("gpu_performance accelerator %d has an invalid command argument", profile.Index)
				}
			}
		}
	}
	for _, server := range c.LlamaCPP.Servers {
		seenProfiles := make(map[string]struct{}, len(server.RuntimeProfiles))
		for _, profile := range server.RuntimeProfiles {
			if profile.ID == "" || profile.ContextLimit <= 0 || profile.Slots <= 0 {
				return nil, fmt.Errorf("llamacpp server %q runtime profiles require id, positive context_limit, and positive slots", server.ID)
			}
			if _, exists := seenProfiles[profile.ID]; exists {
				return nil, fmt.Errorf("llamacpp server %q has duplicate runtime profile %q", server.ID, profile.ID)
			}
			seenProfiles[profile.ID] = struct{}{}
			if len(profile.SwitchCommand) == 0 || !strings.HasPrefix(profile.SwitchCommand[0], "/") {
				return nil, fmt.Errorf("llamacpp server %q runtime profile %q requires an absolute fixed switch_command", server.ID, profile.ID)
			}
			for _, argument := range profile.SwitchCommand {
				if argument == "" || strings.ContainsAny(argument, "\r\n\x00") {
					return nil, fmt.Errorf("llamacpp server %q runtime profile %q has an invalid switch_command argument", server.ID, profile.ID)
				}
			}
		}
	}
	c.AgentVersion = AgentVersion
	return &c, nil
}
