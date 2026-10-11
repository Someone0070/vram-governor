package domain

import "time"

type JSONSchema map[string]any

type ExecutionLocality string

const (
	ExecutionLocalityLBManaged ExecutionLocality = "LB_MANAGED"
	ExecutionLocalityHosted    ExecutionLocality = "HOSTED"
)

type ImplementationModality string

const (
	ModalityLLM      ImplementationModality = "LLM"
	ModalityImage    ImplementationModality = "IMAGE"
	ModalityVideo    ImplementationModality = "VIDEO"
	ModalityAudio    ImplementationModality = "AUDIO"
	ModalityTraining ImplementationModality = "TRAINING"
	ModalitySpatial  ImplementationModality = "SPATIAL"
	ModalityOther    ImplementationModality = "OTHER"
)

// RuntimeAvailability is ephemeral operational state. It is deliberately not
// included in Digest or CapabilityDefinitionHash.
type RuntimeAvailability struct {
	Status     string    `json:"status"`
	ObservedAt time.Time `json:"observed_at"`
}

// RuntimeProfile is the immutable, hardware-neutral execution identity exposed
// to Creator Studio. Adapter and Model are controller-private binding data and
// are never serialized on the public capabilities plane.
type RuntimeProfile struct {
	ProfileID                string                 `json:"profile_id" yaml:"profile_id"`
	Version                  string                 `json:"version" yaml:"version"`
	Digest                   string                 `json:"digest" yaml:"digest"`
	CapabilityRevision       string                 `json:"capability_revision" yaml:"capability_revision"`
	CapabilityDefinitionHash string                 `json:"capability_definition_hash" yaml:"capability_definition_hash"`
	Modality                 ImplementationModality `json:"modality" yaml:"modality"`
	ExecutionLocality        ExecutionLocality      `json:"execution_locality" yaml:"execution_locality"`
	Operations               []string               `json:"operations" yaml:"operations"`
	Features                 []string               `json:"features,omitempty" yaml:"features"`
	InputSchema              JSONSchema             `json:"input_schema,omitempty" yaml:"input_schema"`
	OutputSchema             JSONSchema             `json:"output_schema,omitempty" yaml:"output_schema"`
	AcceptedArtifactTypes    []string               `json:"accepted_artifact_types,omitempty" yaml:"accepted_artifact_types"`
	ProducedArtifactTypes    []string               `json:"produced_artifact_types,omitempty" yaml:"produced_artifact_types"`
	CompatibilityOperations  []string               `json:"compatibility_operations,omitempty" yaml:"compatibility_operations"`
	Availability             *RuntimeAvailability   `json:"availability,omitempty" yaml:"-"`
	// Status is retained as a convenience/backward-compatibility mirror of
	// Availability.Status. It is ephemeral and never part of immutable identity.
	Status string `json:"status,omitempty" yaml:"-"`
	// CalibrationStatus is retained only so old configuration can be decoded.
	// It is never serialized or used for selection; creative calibration belongs
	// to Creator Studio's Production Profile.
	CalibrationStatus string    `json:"-" yaml:"calibration_status"`
	Adapter           string    `json:"-" yaml:"adapter"`
	Model             string    `json:"-" yaml:"model"`
	Workflow          string    `json:"-" yaml:"workflow"`
	CreatedAt         time.Time `json:"created_at,omitempty" yaml:"created_at,omitempty"`
}

type CapabilityRequirements struct {
	Features []string `json:"features,omitempty"`
}

type ProfilePreferences struct {
	Preferred      []string `json:"preferred,omitempty"`
	Acceptable     []string `json:"acceptable,omitempty"`
	FallbackPolicy string   `json:"fallback_policy,omitempty"`
}

type ParallelismPolicy struct {
	Parallelizable bool `json:"parallelizable"`
}

// WorkingSet is a durable demand forecast. It contains no placement or memory
// commands: the scheduler may use it as a scoring hint or ignore it.
type WorkingSet struct {
	OwnerID            string     `json:"owner_id"`
	SessionID          string     `json:"session_id"`
	PhaseID            string     `json:"phase_id"`
	PhaseType          string     `json:"phase_type,omitempty"`
	AffinityKey        string     `json:"affinity_key,omitempty"`
	DesiredProfiles    []string   `json:"desired_profiles,omitempty"`
	LikelyNextProfiles []string   `json:"likely_next_profiles,omitempty"`
	UnlikelyProfiles   []string   `json:"unlikely_profiles,omitempty"`
	CreatedAt          time.Time  `json:"created_at"`
	UpdatedAt          time.Time  `json:"updated_at"`
	ReleasedAt         *time.Time `json:"released_at,omitempty"`
}

func (p RuntimeProfile) Ref() string { return p.ProfileID + "@" + p.Version }
