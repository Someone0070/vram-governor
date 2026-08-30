package nodeagent

import (
	"fmt"
	"net/url"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config is the node agent's configuration file shape (configs/node-agent.yaml).
type Config struct {
	ControllerURL string `yaml:"controller_url"` // ws:// or wss:// URL of /ws/node
	Token         string `yaml:"token"`
	TokenEnv      string `yaml:"token_env"`
	NodeID        string `yaml:"node_id"`
	NodeName      string `yaml:"node_name"`
	LogLevel      string `yaml:"log_level"`

	// LocationClass / PowerControlMode are capability flags (§45 #33/#34),
	// not a hard local/remote architectural split.
	LocationClass    string `yaml:"location_class"`     // local | remote
	PowerControlMode string `yaml:"power_control_mode"` // auto|manual|off|dont_touch|external

	HeartbeatIntervalSeconds int    `yaml:"heartbeat_interval_seconds"`
	CapabilityRefreshSeconds int    `yaml:"capability_refresh_seconds"`
	ReconnectMinSeconds      int    `yaml:"reconnect_min_seconds"`
	ReconnectMaxSeconds      int    `yaml:"reconnect_max_seconds"`
	AgentVersion             string `yaml:"-"`
	CommandSigningSecret     string `yaml:"command_signing_secret"`
	CommandSigningSecretEnv  string `yaml:"command_signing_secret_env"`
	CommandStatePath         string `yaml:"command_state_path"`

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

// LlamaCPPServerConfig describes an already-running llama-server. Runtime
// discovery verifies model, context, and parallel slot capacity; the explicit
// values are conservative fallbacks for older or locked-down servers.
type LlamaCPPServerConfig struct {
	ID                string   `yaml:"id"`
	Endpoint          string   `yaml:"endpoint"`
	PublicEndpoint    string   `yaml:"public_endpoint"`
	AcceleratorIndex  int      `yaml:"accelerator_index"`
	ContextLimit      int      `yaml:"context_limit"`
	Slots             int      `yaml:"slots"`
	RuntimeArgs       []string `yaml:"runtime_args"`
	RouterManaged     bool     `yaml:"router_managed"`
	MaxResidentModels int      `yaml:"max_resident_models"`
}

const AgentVersion = "1.1.0"

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
	if c.NodeName == "" {
		c.NodeName = c.NodeID
	}
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
	c.AgentVersion = AgentVersion
	return &c, nil
}
