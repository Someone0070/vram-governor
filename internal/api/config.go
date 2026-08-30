package api

import (
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the controller's configuration file shape (configs/controller.yaml).
type Config struct {
	ListenAddr  string `yaml:"listen_addr"`
	LogLevel    string `yaml:"log_level"`
	DatabaseURL string `yaml:"database_url"`
	Production  bool   `yaml:"production"`
	TLSCertFile string `yaml:"tls_cert_file"`
	TLSKeyFile  string `yaml:"tls_key_file"`

	// Auth defines scoped identities for every security plane. SharedToken is
	// retained only for development compatibility and is forbidden in production.
	Auth struct {
		SharedToken             string             `yaml:"shared_token"`
		DevelopmentBypass       bool               `yaml:"development_bypass"`
		Credentials             []CredentialConfig `yaml:"credentials"`
		AdminPrivateCIDRs       []string           `yaml:"admin_private_cidrs"`
		CommandSigningSecret    string             `yaml:"command_signing_secret"`
		CommandSigningSecretEnv string             `yaml:"command_signing_secret_env"`
	} `yaml:"auth"`

	Workloads struct {
		LeaseTTLSeconds int                    `yaml:"lease_ttl_seconds"`
		ArtifactRoot    string                 `yaml:"artifact_root"`
		ArtifactStore   ArtifactStoreConfig    `yaml:"artifact_store"`
		Residency       ResidencyConfig        `yaml:"residency"`
		Targets         []WorkloadTargetConfig `yaml:"targets"`
	} `yaml:"workloads"`

	Notifications NotificationConfig `yaml:"notifications"`
	Agents        AgentConfig        `yaml:"agents"`

	// Liveness tuning per §34A (heartbeat ~2s, SUSPECT ~3 missed, LOST ~15s).
	Liveness struct {
		HeartbeatIntervalSeconds int `yaml:"heartbeat_interval_seconds"`
		SuspectAfterSeconds      int `yaml:"suspect_after_seconds"`
		LostAfterSeconds         int `yaml:"lost_after_seconds"`
	} `yaml:"liveness"`

	// Jobs tunes the Phase 3 work-queue engine (internal/jobs.Manager).
	Jobs struct {
		LeaseTTLSeconds      int `yaml:"lease_ttl_seconds"`
		ReaperIntervalMillis int `yaml:"reaper_interval_millis"`
		DefaultMaxAttempts   int `yaml:"default_max_attempts"`
	} `yaml:"jobs"`
}

func LoadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	var c Config
	if err := yaml.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	if c.ListenAddr == "" {
		c.ListenAddr = ":8080"
	}
	if c.LogLevel == "" {
		c.LogLevel = "info"
	}
	if c.Liveness.HeartbeatIntervalSeconds == 0 {
		c.Liveness.HeartbeatIntervalSeconds = 2
	}
	if c.Liveness.SuspectAfterSeconds == 0 {
		c.Liveness.SuspectAfterSeconds = 6
	}
	if c.Liveness.LostAfterSeconds == 0 {
		c.Liveness.LostAfterSeconds = 15
	}
	if c.Jobs.LeaseTTLSeconds == 0 {
		c.Jobs.LeaseTTLSeconds = 10
	}
	if c.Jobs.ReaperIntervalMillis == 0 {
		c.Jobs.ReaperIntervalMillis = 500
	}
	if c.Jobs.DefaultMaxAttempts == 0 {
		c.Jobs.DefaultMaxAttempts = 8
	}
	if c.Workloads.LeaseTTLSeconds == 0 {
		c.Workloads.LeaseTTLSeconds = 30
	}
	if c.Workloads.ArtifactRoot == "" {
		c.Workloads.ArtifactRoot = "data/artifacts"
	}
	if c.Workloads.ArtifactStore.Type == "" {
		c.Workloads.ArtifactStore.Type = "filesystem"
	}
	if c.Workloads.ArtifactStore.Type != "filesystem" && c.Workloads.ArtifactStore.Type != "s3" {
		return nil, fmt.Errorf("artifact_store.type must be filesystem or s3")
	}
	if c.Workloads.ArtifactStore.Type == "s3" {
		if c.Workloads.ArtifactStore.Endpoint == "" || c.Workloads.ArtifactStore.Bucket == "" || c.Workloads.ArtifactStore.AccessKeyEnv == "" || c.Workloads.ArtifactStore.SecretKeyEnv == "" {
			return nil, fmt.Errorf("S3 artifact storage requires endpoint, bucket, access_key_env, and secret_key_env")
		}
		if c.Production && !strings.HasPrefix(strings.ToLower(c.Workloads.ArtifactStore.Endpoint), "https://") {
			return nil, fmt.Errorf("production S3 artifact endpoint must use HTTPS")
		}
	}
	if c.Workloads.Residency.ReconcileSeconds == 0 {
		c.Workloads.Residency.ReconcileSeconds = 10
	}
	if c.Workloads.Residency.IdleUnloadSeconds == 0 {
		c.Workloads.Residency.IdleUnloadSeconds = 900
	}
	if c.Workloads.Residency.MinResidencySeconds == 0 {
		c.Workloads.Residency.MinResidencySeconds = 300
	}
	if c.Workloads.Residency.TransitionTimeoutSeconds == 0 {
		c.Workloads.Residency.TransitionTimeoutSeconds = 120
	}
	if c.Workloads.Residency.ReconcileSeconds < 0 || c.Workloads.Residency.IdleUnloadSeconds < 0 || c.Workloads.Residency.MinResidencySeconds < 0 || c.Workloads.Residency.TransitionTimeoutSeconds < 0 {
		return nil, fmt.Errorf("workload residency durations may not be negative")
	}
	quietStart := c.Workloads.Residency.QuietHoursStart
	quietEnd := c.Workloads.Residency.QuietHoursEnd
	if (quietStart == "") != (quietEnd == "") {
		return nil, fmt.Errorf("quiet_hours_start and quiet_hours_end must both be set or both be empty")
	}
	if quietStart != "" {
		if _, err := time.Parse("15:04", quietStart); err != nil {
			return nil, fmt.Errorf("invalid quiet_hours_start: %w", err)
		}
		if _, err := time.Parse("15:04", quietEnd); err != nil {
			return nil, fmt.Errorf("invalid quiet_hours_end: %w", err)
		}
	}
	for _, target := range c.Workloads.Targets {
		switch target.ResidencyPolicy {
		case "", "auto", "pinned", "manual", "off":
		default:
			return nil, fmt.Errorf("target %q has invalid residency_policy %q", target.ID, target.ResidencyPolicy)
		}
		if target.IdleUnloadSeconds < 0 || target.MinResidencySeconds < 0 {
			return nil, fmt.Errorf("target %q residency durations may not be negative", target.ID)
		}
		if target.InputCentsPerMTok < 0 || target.OutputCentsPerMTok < 0 {
			return nil, fmt.Errorf("target %q cloud pricing may not be negative", target.ID)
		}
		if target.StandaloneVRAMMB < 0 || target.AcceleratorVRAMMB < 0 || target.VRAMReserveMB < 0 {
			return nil, fmt.Errorf("target %q VRAM envelopes may not be negative", target.ID)
		}
		if target.PredictedSlowdown < 0 || target.MaxSlowdown < 0 {
			return nil, fmt.Errorf("target %q slowdown factors may not be negative", target.ID)
		}
		if target.SharingEnabled && target.AcceleratorVRAMMB == 0 {
			return nil, fmt.Errorf("target %q sharing requires accelerator_vram_mb; standalone_vram_mb may be learned from exclusive runs", target.ID)
		}
	}
	for _, credential := range c.Auth.Credentials {
		if credential.ConcurrencyLimit < 0 || credential.BudgetCents < 0 || credential.PreemptionBudget < 0 {
			return nil, fmt.Errorf("credential %q concurrency, budget, and preemption limits may not be negative", credential.ID)
		}
		if credential.MaxPriority < 0 || credential.MaxPriority > 100 {
			return nil, fmt.Errorf("credential %q max_priority must be between 0 and 100", credential.ID)
		}
		if credential.ID == "" || credential.OwnerID == "" {
			return nil, fmt.Errorf("credential id and owner_id are required")
		}
		switch credential.Plane {
		case "admin", "node", "agent", "ui", "api", "mcp", "workflow":
		default:
			return nil, fmt.Errorf("credential %q has invalid plane %q", credential.ID, credential.Plane)
		}
		switch credential.EgressPolicy {
		case "", "local_only", "sanitized_cloud", "cloud_allowed":
		default:
			return nil, fmt.Errorf("credential %q has invalid egress_policy %q", credential.ID, credential.EgressPolicy)
		}
		if credential.MaxIncidentSeverity != "" && severityRank(credential.MaxIncidentSeverity) < 0 {
			return nil, fmt.Errorf("credential %q has invalid max_incident_severity %q", credential.ID, credential.MaxIncidentSeverity)
		}
		if credential.TokenSHA256 != "" {
			digest, err := hex.DecodeString(credential.TokenSHA256)
			if err != nil || len(digest) != 32 {
				return nil, fmt.Errorf("credential %q token_sha256 must be a 64-character SHA-256 hex digest", credential.ID)
			}
		}
	}
	for _, raw := range c.Auth.AdminPrivateCIDRs {
		if !isPrivateAdminCIDR(raw) {
			return nil, fmt.Errorf("admin_private_cidrs entry %q must be a private or loopback CIDR", raw)
		}
	}
	if c.Notifications.MaxAttempts == 0 {
		c.Notifications.MaxAttempts = 8
	}
	if c.Notifications.BaseRetrySeconds == 0 {
		c.Notifications.BaseRetrySeconds = 1
	}
	if c.Notifications.RequestTimeoutSeconds == 0 {
		c.Notifications.RequestTimeoutSeconds = 10
	}
	if c.Notifications.DispatchIntervalSeconds == 0 {
		c.Notifications.DispatchIntervalSeconds = 1
	}
	if c.Notifications.MaxAttempts < 0 || c.Notifications.BaseRetrySeconds < 0 || c.Notifications.RequestTimeoutSeconds < 0 || c.Notifications.DispatchIntervalSeconds < 0 {
		return nil, fmt.Errorf("notification retry settings may not be negative")
	}
	if c.Production {
		if c.Auth.DevelopmentBypass {
			return nil, fmt.Errorf("production mode forbids auth.development_bypass")
		}
		if c.TLSCertFile == "" || c.TLSKeyFile == "" {
			return nil, fmt.Errorf("production mode requires tls_cert_file and tls_key_file")
		}
		if c.Auth.SharedToken != "" {
			return nil, fmt.Errorf("production mode forbids auth.shared_token; use scoped token_sha256 credentials")
		}
		if c.Auth.CommandSigningSecret != "" {
			return nil, fmt.Errorf("production mode forbids literal auth.command_signing_secret; use command_signing_secret_env")
		}
		if c.DatabaseURL == "" {
			return nil, fmt.Errorf("production mode requires database_url")
		}
		if len(c.Auth.Credentials) == 0 {
			return nil, fmt.Errorf("production mode requires at least one scoped credential")
		}
		if len(c.Auth.AdminPrivateCIDRs) == 0 {
			return nil, fmt.Errorf("production mode requires admin_private_cidrs")
		}
		if c.Auth.CommandSigningSecretEnv == "" {
			return nil, fmt.Errorf("production mode requires command_signing_secret_env")
		}
		if len(os.Getenv(c.Auth.CommandSigningSecretEnv)) < 32 {
			return nil, fmt.Errorf("production node command signing secret must contain at least 32 bytes")
		}
		if c.Workloads.ArtifactStore.Type != "s3" {
			return nil, fmt.Errorf("production mode requires S3-compatible artifact storage")
		}
		for _, credential := range c.Auth.Credentials {
			if credential.Token != "" || credential.TokenSHA256 == "" {
				return nil, fmt.Errorf("production credential %q must use token_sha256 and may not contain token", credential.ID)
			}
		}
		for _, target := range c.Workloads.Targets {
			if target.Authorization != "" {
				return nil, fmt.Errorf("production target %q must use authorization_env instead of a literal authorization value", target.ID)
			}
		}
		if c.Notifications.SigningSecret != "" {
			return nil, fmt.Errorf("production mode forbids literal notifications.signing_secret; use signing_secret_env")
		}
		if c.Notifications.Enabled && c.Notifications.SigningSecretEnv == "" {
			return nil, fmt.Errorf("production notifications require signing_secret_env")
		}
	}
	return &c, nil
}

func isPrivateAdminCIDR(raw string) bool {
	_, candidate, err := net.ParseCIDR(strings.TrimSpace(raw))
	if err != nil {
		return false
	}
	private := []string{"127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "::1/128", "fc00::/7", "fe80::/10"}
	candidatePrefix, candidateBits := candidate.Mask.Size()
	for _, rawAllowed := range private {
		_, allowed, _ := net.ParseCIDR(rawAllowed)
		allowedPrefix, allowedBits := allowed.Mask.Size()
		if candidateBits == allowedBits && candidatePrefix >= allowedPrefix && allowed.Contains(candidate.IP) {
			return true
		}
	}
	return false
}

type ArtifactStoreConfig struct {
	Type            string `yaml:"type"`
	Endpoint        string `yaml:"endpoint"`
	Bucket          string `yaml:"bucket"`
	Region          string `yaml:"region"`
	Prefix          string `yaml:"prefix"`
	AccessKeyEnv    string `yaml:"access_key_env"`
	SecretKeyEnv    string `yaml:"secret_key_env"`
	SessionTokenEnv string `yaml:"session_token_env"`
}

type NotificationConfig struct {
	Enabled                 bool     `yaml:"enabled"`
	SigningSecret           string   `yaml:"signing_secret"`
	SigningSecretEnv        string   `yaml:"signing_secret_env"`
	AllowedHosts            []string `yaml:"allowed_hosts"`
	AllowedPrivateCIDRs     []string `yaml:"allowed_private_cidrs"`
	AllowHTTP               bool     `yaml:"allow_http"`
	MaxAttempts             int      `yaml:"max_attempts"`
	BaseRetrySeconds        int      `yaml:"base_retry_seconds"`
	RequestTimeoutSeconds   int      `yaml:"request_timeout_seconds"`
	DispatchIntervalSeconds int      `yaml:"dispatch_interval_seconds"`
}

type AgentConfig struct {
	AllowedCloudProviders []string `yaml:"allowed_cloud_providers"`
	AllowedCloudModels    []string `yaml:"allowed_cloud_models"`
	QuarantinedModels     []string `yaml:"quarantined_models"`
	LocalVerifierModels   []string `yaml:"local_verifier_models"`
	PaidEmergencyFallback bool     `yaml:"paid_emergency_fallback"`
	MonitorNodeLoss       *bool    `yaml:"monitor_node_loss"`
}

type ResidencyConfig struct {
	Enabled                  *bool  `yaml:"enabled"`
	ReconcileSeconds         int    `yaml:"reconcile_seconds"`
	IdleUnloadSeconds        int    `yaml:"idle_unload_seconds"`
	MinResidencySeconds      int    `yaml:"min_residency_seconds"`
	TransitionTimeoutSeconds int    `yaml:"transition_timeout_seconds"`
	QuietHoursStart          string `yaml:"quiet_hours_start"`
	QuietHoursEnd            string `yaml:"quiet_hours_end"`
}

type CredentialConfig struct {
	ID                  string   `yaml:"id"`
	Token               string   `yaml:"token"`
	TokenSHA256         string   `yaml:"token_sha256"`
	Plane               string   `yaml:"plane"`
	OwnerID             string   `yaml:"owner_id"`
	Scopes              []string `yaml:"scopes"`
	Adapters            []string `yaml:"adapters"`
	NodeID              string   `yaml:"node_id"`
	MaxPriority         int      `yaml:"max_priority"`
	MaxIncidentSeverity string   `yaml:"max_incident_severity"`
	EgressPolicy        string   `yaml:"egress_policy"`
	ConcurrencyLimit    int      `yaml:"concurrency_limit"`
	BudgetCents         int64    `yaml:"budget_cents"`
	PreemptionBudget    int      `yaml:"preemption_budget"`
}

type WorkloadTargetConfig struct {
	ID                         string   `yaml:"id"`
	Adapter                    string   `yaml:"adapter"`
	Endpoint                   string   `yaml:"endpoint"`
	AcceleratorID              string   `yaml:"accelerator_id"`
	Models                     []string `yaml:"models"`
	ResidentModels             []string `yaml:"resident_models"`
	CustomNodes                []string `yaml:"custom_nodes"`
	ContextLimit               int      `yaml:"context_limit"`
	Slots                      int      `yaml:"slots"`
	CapabilityVersion          string   `yaml:"capability_version"`
	ModelFingerprint           string   `yaml:"model_fingerprint"`
	CapacitySource             string   `yaml:"capacity_source"`
	CapacityVerified           bool     `yaml:"capacity_verified"`
	SupportsModelLifecycle     bool     `yaml:"supports_model_lifecycle"`
	SupportsAcceleratorReclaim bool     `yaml:"supports_accelerator_reclaim"`
	MaxResidentModels          int      `yaml:"max_resident_models"`
	WarmRAMSupported           bool     `yaml:"warm_ram_supported"`
	ResidencyPolicy            string   `yaml:"residency_policy"`
	IdleUnloadSeconds          int      `yaml:"idle_unload_seconds"`
	MinResidencySeconds        int      `yaml:"min_residency_seconds"`
	Cloud                      bool     `yaml:"cloud"`
	Enabled                    *bool    `yaml:"enabled"`
	Authorization              string   `yaml:"authorization"`
	AuthorizationEnv           string   `yaml:"authorization_env"`
	InputCentsPerMTok          int64    `yaml:"input_cents_per_million_tokens"`
	OutputCentsPerMTok         int64    `yaml:"output_cents_per_million_tokens"`
	WorkloadClass              string   `yaml:"workload_class"`
	StandaloneVRAMMB           int64    `yaml:"standalone_vram_mb"`
	AcceleratorVRAMMB          int64    `yaml:"accelerator_vram_mb"`
	VRAMReserveMB              int64    `yaml:"vram_reserve_mb"`
	SharingEnabled             bool     `yaml:"sharing_enabled"`
	GuardedExploration         bool     `yaml:"guarded_exploration"`
	PredictedSlowdown          float64  `yaml:"predicted_slowdown"`
	MaxSlowdown                float64  `yaml:"max_slowdown"`
	SafetyCritical             bool     `yaml:"safety_critical"`
	Provider                   string   `yaml:"provider"`
	Quarantined                bool     `yaml:"quarantined"`
}
