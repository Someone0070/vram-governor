package api

import (
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"vram-governor/internal/domain"
	"vram-governor/internal/workflowtpl"
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
		SharedToken       string `yaml:"shared_token"`
		DevelopmentBypass bool   `yaml:"development_bypass"`
		// PasswordlessAdminLAN temporarily permits blank-token admin browser
		// sessions from admin_private_cidrs. API and node bearer tokens remain required.
		PasswordlessAdminLAN    bool               `yaml:"passwordless_admin_lan"`
		Credentials             []CredentialConfig `yaml:"credentials"`
		AdminPrivateCIDRs       []string           `yaml:"admin_private_cidrs"`
		CommandSigningSecret    string             `yaml:"command_signing_secret"`
		CommandSigningSecretEnv string             `yaml:"command_signing_secret_env"`
	} `yaml:"auth"`

	Workloads struct {
		LeaseTTLSeconds                int                          `yaml:"lease_ttl_seconds"`
		DefaultMaxAcceleratorsPerModel int                          `yaml:"default_max_accelerators_per_model"`
		MaxAcceleratorsPerWorkload     int                          `yaml:"max_accelerators_per_workload"`
		CapabilityVersion              string                       `yaml:"capability_version"`
		Capabilities                   domain.ResidencyCapabilities `yaml:"capabilities"`
		Capacity                       domain.CapacityBudget        `yaml:"capacity"`
		ModelCapacityPolicies          []ModelCapacityPolicyConfig  `yaml:"model_capacity_policies"`
		ArtifactRoot                   string                       `yaml:"artifact_root"`
		ArtifactStore                  ArtifactStoreConfig          `yaml:"artifact_store"`
		Checkpoint                     CheckpointConfig             `yaml:"checkpoint"`
		Residency                      ResidencyConfig              `yaml:"residency"`
		Targets                        []WorkloadTargetConfig       `yaml:"targets"`
		// WorkflowTemplatesDir holds parameterized Comfy workflow templates
		// (internal/workflowtpl). Each must name a configured profile.
		WorkflowTemplatesDir string `yaml:"workflow_templates_dir"`
		// GPUIdleLingerSeconds delays parking a released GPU so queued and
		// back-to-back jobs keep active clocks. Unset means 5; 0 parks at once.
		GPUIdleLingerSeconds *int `yaml:"gpu_idle_linger_seconds"`
		// ResultExport copies final media outputs (not intermediates) to a
		// plain directory such as a NAS share, with a JSON sidecar each.
		ResultExport struct {
			Dir        string   `yaml:"dir"`
			MediaTypes []string `yaml:"media_types"`
		} `yaml:"result_export"`
		// OpenAI queueing fallbacks below body, X-VRAM-* headers and the
		// credential. fail_fast stays the default so existing clients keep
		// their immediate 429/503 behaviour.
		OpenAIDefaultQueuePolicy    string `yaml:"openai_default_queue_policy"`
		OpenAIDefaultMaxWaitSeconds int    `yaml:"openai_default_max_wait_seconds"`
	} `yaml:"workloads"`
	SmartPlugs []SmartPlugConfig `yaml:"smart_plugs"`

	// WorkflowTemplates is loaded from Workloads.WorkflowTemplatesDir.
	WorkflowTemplates *workflowtpl.Registry `yaml:"-"`

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

// CheckpointConfig controls the controller-side durable KV bundle store. It
// is deliberately disabled unless an operator supplies every bound; a probe
// or a default path must never create a resumability promise.
type CheckpointConfig struct {
	Enabled                      bool   `yaml:"enabled"`
	Root                         string `yaml:"root"`
	MaxBytes                     int64  `yaml:"max_bytes"`
	MaxFiles                     int    `yaml:"max_files"`
	PerOwnerMaxBytes             int64  `yaml:"per_owner_max_bytes"`
	PerOwnerMaxFiles             int    `yaml:"per_owner_max_files"`
	MaxMetadataBytes             int64  `yaml:"max_metadata_bytes"`
	MaxOutputBytes               int64  `yaml:"max_output_bytes"`
	ExpirySeconds                int    `yaml:"expiry_seconds"`
	LockStaleSeconds             int    `yaml:"lock_stale_seconds"`
	ProofJournalRetentionSeconds int    `yaml:"proof_journal_retention_seconds"`
}

func (c CheckpointConfig) Validate() error {
	if !c.Enabled {
		return nil
	}
	if c.Root == "" || !filepath.IsAbs(c.Root) || filepath.Clean(c.Root) != c.Root || strings.ContainsAny(c.Root, "\r\n\x00") {
		return fmt.Errorf("checkpoint root must be canonical absolute path")
	}
	if c.MaxBytes <= 0 || c.MaxFiles <= 0 || c.PerOwnerMaxBytes <= 0 || c.PerOwnerMaxFiles <= 0 || c.PerOwnerMaxBytes > c.MaxBytes || c.PerOwnerMaxFiles > c.MaxFiles {
		return fmt.Errorf("checkpoint quotas are invalid")
	}
	if c.MaxMetadataBytes <= 0 || c.MaxOutputBytes <= 0 || c.ExpirySeconds <= 0 || c.LockStaleSeconds <= 0 || c.ProofJournalRetentionSeconds < 0 {
		return fmt.Errorf("checkpoint bounds and lock expiry are required")
	}
	return nil
}

// validateOpenAIQueueDefaults normalizes workloads.openai_default_* and
// rejects values the request path would otherwise silently reinterpret.
func (c *Config) validateOpenAIQueueDefaults() error {
	policy := strings.TrimSpace(c.Workloads.OpenAIDefaultQueuePolicy)
	switch policy {
	case "":
		policy = string(domain.QueueFailFast)
	case string(domain.QueueFailFast), string(domain.QueueWait):
	default:
		return fmt.Errorf("workloads.openai_default_queue_policy must be fail_fast or wait")
	}
	c.Workloads.OpenAIDefaultQueuePolicy = policy
	if c.Workloads.OpenAIDefaultMaxWaitSeconds == 0 {
		c.Workloads.OpenAIDefaultMaxWaitSeconds = 120
	}
	if c.Workloads.OpenAIDefaultMaxWaitSeconds < 1 || c.Workloads.OpenAIDefaultMaxWaitSeconds > 900 {
		return fmt.Errorf("workloads.openai_default_max_wait_seconds must be between 1 and 900")
	}
	return nil
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
	if c.Workloads.DefaultMaxAcceleratorsPerModel == 0 {
		c.Workloads.DefaultMaxAcceleratorsPerModel = 1
	}
	if c.Workloads.DefaultMaxAcceleratorsPerModel < 1 {
		return nil, fmt.Errorf("default_max_accelerators_per_model must be at least 1")
	}
	// This is the fleet-wide placement ceiling. Keep it independent from
	// the legacy per-model policy, which may be explicitly raised later.
	normalizedMax, err := domain.NormalizeAcceleratorCeiling(c.Workloads.MaxAcceleratorsPerWorkload, c.Workloads.Capabilities.MaxAcceleratorsPerWorkload)
	if err != nil {
		return nil, err
	}
	c.Workloads.MaxAcceleratorsPerWorkload = normalizedMax
	c.Workloads.Capabilities.MaxAcceleratorsPerWorkload = normalizedMax
	if c.Workloads.CapabilityVersion == "" {
		c.Workloads.CapabilityVersion = domain.CapabilityContractVersion
	}
	if err := domain.ValidateCapabilityVersion(c.Workloads.CapabilityVersion); err != nil {
		return nil, err
	}
	if c.Workloads.Capabilities.Version == "" {
		c.Workloads.Capabilities.Version = c.Workloads.CapabilityVersion
	}
	if err := domain.ValidateOperatorCapabilities(c.Workloads.Capabilities); err != nil {
		return nil, fmt.Errorf("workloads.capabilities: %w", err)
	}
	if err := c.Workloads.Capabilities.Validate(); err != nil {
		return nil, fmt.Errorf("workloads.capabilities: %w", err)
	}
	if c.Workloads.Capacity.VRAMHardCapBytes == 0 && c.Workloads.Capacity.VRAMTotalBytes > 0 {
		c.Workloads.Capacity.VRAMHardCapBytes = c.Workloads.Capacity.VRAMTotalBytes
	}
	if c.Workloads.Capacity.RAMHardCapBytes == 0 && c.Workloads.Capacity.RAMTotalBytes > 0 {
		c.Workloads.Capacity.RAMHardCapBytes = c.Workloads.Capacity.RAMTotalBytes
	}
	if c.Workloads.Checkpoint.ProofJournalRetentionSeconds == 0 {
		c.Workloads.Checkpoint.ProofJournalRetentionSeconds = 48 * 60 * 60
	}
	if err := c.Workloads.Capacity.Validate(); err != nil {
		return nil, fmt.Errorf("workloads.capacity: %w", err)
	}
	if err := c.validateOpenAIQueueDefaults(); err != nil {
		return nil, err
	}
	if err := c.Workloads.Checkpoint.Validate(); err != nil {
		return nil, fmt.Errorf("workloads.checkpoint: %w", err)
	}
	seenPlugNodes := map[string]bool{}
	seenPlugHosts := map[string]bool{}
	for _, plug := range c.SmartPlugs {
		parsed, err := url.Parse(plug.URL)
		if plug.NodeID == "" || err != nil || parsed.Scheme != "http" || parsed.Host == "" || parsed.Path != "" || parsed.RawQuery != "" || parsed.User != nil || parsed.Fragment != "" {
			return nil, fmt.Errorf("smart_plugs require node_id and a bare http URL")
		}
		ip := net.ParseIP(parsed.Hostname())
		if ip == nil || !ip.IsPrivate() || ip.To4() == nil {
			return nil, fmt.Errorf("smart plug %q must use a private IPv4 address", plug.NodeID)
		}
		if seenPlugNodes[plug.NodeID] || seenPlugHosts[parsed.Host] {
			return nil, fmt.Errorf("smart plug node IDs and addresses must be unique")
		}
		seenPlugNodes[plug.NodeID], seenPlugHosts[parsed.Host] = true, true
	}
	seenModelPolicies := make(map[string]struct{}, len(c.Workloads.ModelCapacityPolicies))
	for _, policy := range c.Workloads.ModelCapacityPolicies {
		if policy.Model == "" || policy.MaxAccelerators < 1 {
			return nil, fmt.Errorf("model capacity policies require model and max_accelerators of at least 1")
		}
		if _, exists := seenModelPolicies[policy.Model]; exists {
			return nil, fmt.Errorf("duplicate model capacity policy for %q", policy.Model)
		}
		seenModelPolicies[policy.Model] = struct{}{}
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
	for targetIndex := range c.Workloads.Targets {
		target := &c.Workloads.Targets[targetIndex]
		aliases := domain.CapabilityAliases{
			SupportsModelLifecycle:     target.SupportsModelLifecycle,
			SupportsAcceleratorReclaim: target.SupportsAcceleratorReclaim,
			MaxResidentModels:          target.MaxResidentModels,
			WarmRAMSupported:           target.WarmRAMSupported,
		}
		capabilitiesSpecified := target.Capabilities != (domain.ResidencyCapabilities{}) || target.CapabilityRevision != "" || aliases != (domain.CapabilityAliases{})
		targetRevision := target.CapabilityRevision
		if targetRevision == "" {
			targetRevision = target.Capabilities.Version
		}
		if targetRevision == "" {
			targetRevision = c.Workloads.CapabilityVersion
		}
		if err := domain.ValidateCapabilityVersion(targetRevision); err != nil {
			return nil, fmt.Errorf("target %q: %w", target.ID, err)
		}
		overlay := target.Capabilities
		if overlay.Version == "" {
			overlay.Version = targetRevision
		}
		if capabilitiesSpecified {
			if err := domain.ValidateOperatorCapabilities(overlay); err != nil {
				return nil, fmt.Errorf("target %q capabilities: %w", target.ID, err)
			}
		}
		capabilities, err := domain.MergeResidencyCapabilities(c.Workloads.Capabilities, overlay, aliases)
		if err != nil {
			return nil, fmt.Errorf("target %q capabilities: %w", target.ID, err)
		}
		capabilities.Version = targetRevision
		target.Capabilities = capabilities
		target.CapabilityRevision = targetRevision
		if target.CapacityVerified {
			return nil, fmt.Errorf("target %q capacity_verified is runtime-only and may not be set in static configuration", target.ID)
		}
		if err := domain.ValidateCapacityOverride(c.Workloads.Capacity, target.Capacity); err != nil {
			return nil, fmt.Errorf("target %q capacity override: %w", target.ID, err)
		}
		target.Capacity = domain.MergeCapacityBudget(c.Workloads.Capacity, target.Capacity)
		if err := target.Capabilities.Validate(); err != nil {
			return nil, fmt.Errorf("target %q capabilities: %w", target.ID, err)
		}
		if err := target.Capacity.Validate(); err != nil {
			return nil, fmt.Errorf("target %q capacity: %w", target.ID, err)
		}
		nestedMaxOverride := overlay.MaxAcceleratorsPerWorkload
		if target.MaxAcceleratorsPerWorkload < 0 || nestedMaxOverride < 0 {
			return nil, fmt.Errorf("target %q max_accelerators_per_workload may not be negative", target.ID)
		}
		if target.MaxAcceleratorsPerWorkload > 0 && nestedMaxOverride > 0 && target.MaxAcceleratorsPerWorkload != nestedMaxOverride {
			return nil, fmt.Errorf("target %q max_accelerators_per_workload conflicts with nested capability ceiling", target.ID)
		}
		effectiveMax := target.MaxAcceleratorsPerWorkload
		if effectiveMax == 0 {
			effectiveMax = nestedMaxOverride
		}
		if effectiveMax == 0 {
			effectiveMax = c.Workloads.MaxAcceleratorsPerWorkload
		}
		if effectiveMax > c.Workloads.MaxAcceleratorsPerWorkload {
			return nil, fmt.Errorf("target %q max_accelerators_per_workload %d exceeds inherited ceiling %d", target.ID, effectiveMax, c.Workloads.MaxAcceleratorsPerWorkload)
		}
		target.MaxAcceleratorsPerWorkload = effectiveMax
		target.Capabilities.MaxAcceleratorsPerWorkload = effectiveMax
		target.SupportsModelLifecycle = target.Capabilities.SupportsModelLifecycle
		target.SupportsAcceleratorReclaim = target.Capabilities.SupportsAcceleratorReclaim
		target.MaxResidentModels = target.Capabilities.MaxResidentModels
		target.WarmRAMSupported = target.Capabilities.SupportsWarmRAM
		switch target.RuntimeProtocol {
		case "", "native", "managed_comfy_v1":
		default:
			return nil, fmt.Errorf("target %q has invalid runtime_protocol %q", target.ID, target.RuntimeProtocol)
		}
		if target.RuntimeProtocol == "managed_comfy_v1" && target.Adapter != "comfy" {
			return nil, fmt.Errorf("target %q runtime_protocol managed_comfy_v1 requires adapter comfy", target.ID)
		}
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
		for _, profile := range target.Profiles {
			if profile.ProfileID == "" || profile.Version == "" || len(profile.Operations) == 0 {
				return nil, fmt.Errorf("target %q Creator Studio profiles require profile_id, version, and operations", target.ID)
			}
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
		case "admin", "node", "enrollment", "agent", "ui", "api", "mcp", "workflow":
		default:
			return nil, fmt.Errorf("credential %q has invalid plane %q", credential.ID, credential.Plane)
		}
		if credential.Plane == "enrollment" && (credential.NodeID != "" || len(credential.Scopes) != 1 || credential.Scopes[0] != "node:enroll") {
			return nil, fmt.Errorf("credential %q enrollment plane must have only node:enroll scope and no node_id", credential.ID)
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
	if (c.TLSCertFile == "") != (c.TLSKeyFile == "") {
		return nil, fmt.Errorf("tls_cert_file and tls_key_file must be configured together")
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
	if c.Workloads.WorkflowTemplatesDir != "" {
		registry, err := workflowtpl.LoadDir(c.Workloads.WorkflowTemplatesDir)
		if err != nil {
			return nil, fmt.Errorf("workflow templates: %w", err)
		}
		if err := validateWorkflowTemplates(registry, c.Workloads.Targets); err != nil {
			return nil, err
		}
		c.WorkflowTemplates = registry
	}
	return &c, nil
}

// validateWorkflowTemplates requires every template to run under a configured
// profile that offers its operation, so a typo fails -check-config instead of
// every request.
func validateWorkflowTemplates(registry *workflowtpl.Registry, targets []WorkloadTargetConfig) error {
	profiles := map[string]domain.RuntimeProfile{}
	for _, target := range targets {
		for _, profile := range target.Profiles {
			profiles[profile.Ref()] = profile
		}
	}
	for _, template := range registry.All() {
		profile, ok := profiles[template.Profile]
		if !ok {
			return fmt.Errorf("workflow %s names unknown profile %s", template.Ref(), template.Profile)
		}
		if !slices.Contains(profile.Operations, template.Operation) {
			return fmt.Errorf("workflow %s operation %s is not offered by profile %s", template.Ref(), template.Operation, template.Profile)
		}
	}
	return nil
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

type ModelCapacityPolicyConfig struct {
	Model           string `yaml:"model"`
	MaxAccelerators int    `yaml:"max_accelerators"`
}

type SmartPlugConfig struct {
	NodeID         string `yaml:"node_id"`
	URL            string `yaml:"url"`
	ControlEnabled bool   `yaml:"control_enabled"`
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
	// Defaults applied to OpenAI-compatible requests from this credential, so
	// an application's API key alone can carry its priority class.
	DefaultPriority     int    `yaml:"default_priority"`
	DefaultQueuePolicy  string `yaml:"default_queue_policy"`
	MaxQueueWaitSeconds int    `yaml:"max_queue_wait_seconds"`
}

type WorkloadTargetConfig struct {
	ID                         string                       `yaml:"id"`
	Adapter                    string                       `yaml:"adapter"`
	Endpoint                   string                       `yaml:"endpoint"`
	RuntimeProtocol            string                       `yaml:"runtime_protocol"`
	AcceleratorID              string                       `yaml:"accelerator_id"`
	Models                     []string                     `yaml:"models"`
	Profiles                   []domain.RuntimeProfile      `yaml:"profiles"`
	ResidentModels             []string                     `yaml:"resident_models"`
	CustomNodes                []string                     `yaml:"custom_nodes"`
	ContextLimit               int                          `yaml:"context_limit"`
	Slots                      int                          `yaml:"slots"`
	CapabilityVersion          string                       `yaml:"capability_version"`
	CapabilityRevision         string                       `yaml:"capability_revision"`
	Capabilities               domain.ResidencyCapabilities `yaml:"capabilities"`
	Capacity                   domain.CapacityBudget        `yaml:"capacity"`
	MaxAcceleratorsPerWorkload int                          `yaml:"max_accelerators_per_workload"`
	ModelFingerprint           string                       `yaml:"model_fingerprint"`
	CapacitySource             string                       `yaml:"capacity_source"`
	CapacityVerified           bool                         `yaml:"capacity_verified"`
	SupportsModelLifecycle     bool                         `yaml:"supports_model_lifecycle"`
	SupportsAcceleratorReclaim bool                         `yaml:"supports_accelerator_reclaim"`
	MaxResidentModels          int                          `yaml:"max_resident_models"`
	WarmRAMSupported           bool                         `yaml:"warm_ram_supported"`
	ResidencyPolicy            string                       `yaml:"residency_policy"`
	IdleUnloadSeconds          int                          `yaml:"idle_unload_seconds"`
	MinResidencySeconds        int                          `yaml:"min_residency_seconds"`
	Cloud                      bool                         `yaml:"cloud"`
	Enabled                    *bool                        `yaml:"enabled"`
	Authorization              string                       `yaml:"authorization"`
	AuthorizationEnv           string                       `yaml:"authorization_env"`
	InputCentsPerMTok          int64                        `yaml:"input_cents_per_million_tokens"`
	OutputCentsPerMTok         int64                        `yaml:"output_cents_per_million_tokens"`
	WorkloadClass              string                       `yaml:"workload_class"`
	StandaloneVRAMMB           int64                        `yaml:"standalone_vram_mb"`
	AcceleratorVRAMMB          int64                        `yaml:"accelerator_vram_mb"`
	VRAMReserveMB              int64                        `yaml:"vram_reserve_mb"`
	SharingEnabled             bool                         `yaml:"sharing_enabled"`
	GuardedExploration         bool                         `yaml:"guarded_exploration"`
	PredictedSlowdown          float64                      `yaml:"predicted_slowdown"`
	MaxSlowdown                float64                      `yaml:"max_slowdown"`
	SafetyCritical             bool                         `yaml:"safety_critical"`
	Provider                   string                       `yaml:"provider"`
	Quarantined                bool                         `yaml:"quarantined"`
}
