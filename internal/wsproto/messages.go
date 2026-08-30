// Package wsproto defines the small JSON message envelope multiplexed over
// the single outbound node<->controller control channel (architecture.md
// §34A). Bulk data never travels this channel — only registration,
// heartbeat/telemetry, events, acks, and (later) commands.
package wsproto

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"
)

// MsgType discriminates the envelope payload.
type MsgType string

const (
	// Node -> Controller
	MsgRegister     MsgType = "register"
	MsgHeartbeat    MsgType = "heartbeat"
	MsgTelemetry    MsgType = "telemetry"
	MsgCapabilities MsgType = "capabilities"
	MsgEvent        MsgType = "event"

	// Controller -> Node
	MsgAck           MsgType = "ack"
	MsgCommand       MsgType = "command"
	MsgCommandResult MsgType = "command_result"
)

// Envelope is the outer frame for every message on the control channel.
type Envelope struct {
	Type MsgType   `json:"type"`
	Time time.Time `json:"time"`
	// Payload is one of the Register/Heartbeat/Telemetry/Event/Ack/Command
	// structs below, encoded as raw JSON. Callers decode based on Type.
	Payload json.RawMessage `json:"payload,omitempty"`
}

// RegisterPayload is sent once, immediately after the node dials in and
// authenticates. It carries the static facts about the node.
type RegisterPayload struct {
	NodeID           string                 `json:"node_id"`
	NodeName         string                 `json:"node_name"`
	LocationClass    string                 `json:"location_class"`     // domain.LocationClass
	PowerControlMode string                 `json:"power_control_mode"` // domain.PowerControlMode
	AgentVersion     string                 `json:"agent_version"`
	Adapters         []AdapterAdvertisement `json:"adapters,omitempty"`
}

// AdapterAdvertisement reports existing runtime capabilities. No protocol
// command permits installing arbitrary ComfyUI custom nodes.
type AdapterAdvertisement struct {
	ID                         string   `json:"id"`
	Adapter                    string   `json:"adapter"`
	Endpoint                   string   `json:"endpoint"`
	AcceleratorIndex           int      `json:"accelerator_index"`
	Models                     []string `json:"models,omitempty"`
	ResidentModels             []string `json:"resident_models,omitempty"`
	CustomNodes                []string `json:"custom_nodes,omitempty"`
	Version                    string   `json:"version,omitempty"`
	ModelFingerprint           string   `json:"model_fingerprint,omitempty"`
	ContextLimit               int      `json:"context_limit,omitempty"`
	Slots                      int      `json:"slots,omitempty"`
	CapacitySource             string   `json:"capacity_source,omitempty"`
	CapabilitiesVerified       bool     `json:"capabilities_verified,omitempty"`
	RuntimeArgs                []string `json:"runtime_args,omitempty"`
	SupportsModelLifecycle     bool     `json:"supports_model_lifecycle,omitempty"`
	SupportsAcceleratorReclaim bool     `json:"supports_accelerator_reclaim,omitempty"`
	MaxResidentModels          int      `json:"max_resident_models,omitempty"`
	WarmRAMSupported           bool     `json:"warm_ram_supported,omitempty"`
	QueueRunning               int      `json:"queue_running,omitempty"`
	QueuePending               int      `json:"queue_pending,omitempty"`
}

// AcceleratorTelemetry mirrors the live fields of domain.Accelerator that
// the node agent can measure via nvidia-smi every heartbeat cycle.
type AcceleratorTelemetry struct {
	Index            int     `json:"index"`
	Name             string  `json:"name"`
	VRAMTotalMB      int64   `json:"vram_total_mb"`
	VRAMUsedMB       int64   `json:"vram_used_mb"`
	VRAMFreeMB       int64   `json:"vram_free_mb"`
	UtilizationPct   float64 `json:"utilization_pct"`
	TemperatureC     float64 `json:"temperature_c"`
	Driver           string  `json:"driver,omitempty"`
	PowerDrawW       float64 `json:"power_draw_w,omitempty"`
	PowerLimitW      float64 `json:"power_limit_w,omitempty"`
	FanSpeedPct      float64 `json:"fan_speed_pct,omitempty"`
	GraphicsClockMHz float64 `json:"graphics_clock_mhz,omitempty"`
	MemoryClockMHz   float64 `json:"memory_clock_mhz,omitempty"`
	PCIeGeneration   int     `json:"pcie_generation,omitempty"`
	PCIeWidth        int     `json:"pcie_width,omitempty"`
	PerformanceState string  `json:"performance_state,omitempty"`
}

// HeartbeatPayload is sent ~every 2s (§34A). It is intentionally tiny;
// richer telemetry rides in TelemetryPayload on the same cadence in Phase 1
// (they could be decoupled later).
type HeartbeatPayload struct {
	NodeID string `json:"node_id"`
	Ready  bool   `json:"ready"`
}

// TelemetryPayload carries GPU telemetry gathered from nvidia-smi.
type TelemetryPayload struct {
	NodeID       string                 `json:"node_id"`
	Accelerators []AcceleratorTelemetry `json:"accelerators"`
	System       SystemTelemetry        `json:"system"`
	AgentLogs    []LogEntry             `json:"agent_logs,omitempty"`
}

type SystemTelemetry struct {
	Hostname          string    `json:"hostname,omitempty"`
	OS                string    `json:"os,omitempty"`
	Kernel            string    `json:"kernel,omitempty"`
	Architecture      string    `json:"architecture,omitempty"`
	CPUModel          string    `json:"cpu_model,omitempty"`
	CPULogical        int       `json:"cpu_logical,omitempty"`
	CPUUtilizationPct float64   `json:"cpu_utilization_pct,omitempty"`
	Load1             float64   `json:"load_1,omitempty"`
	Load5             float64   `json:"load_5,omitempty"`
	Load15            float64   `json:"load_15,omitempty"`
	RAMTotalMB        int64     `json:"ram_total_mb,omitempty"`
	RAMUsedMB         int64     `json:"ram_used_mb,omitempty"`
	RAMAvailableMB    int64     `json:"ram_available_mb,omitempty"`
	SwapTotalMB       int64     `json:"swap_total_mb,omitempty"`
	SwapUsedMB        int64     `json:"swap_used_mb,omitempty"`
	RootDiskTotalMB   int64     `json:"root_disk_total_mb,omitempty"`
	RootDiskUsedMB    int64     `json:"root_disk_used_mb,omitempty"`
	RootDiskFreeMB    int64     `json:"root_disk_free_mb,omitempty"`
	NetworkAddresses  []string  `json:"network_addresses,omitempty"`
	NetworkRXBPS      float64   `json:"network_rx_bytes_per_second"`
	NetworkTXBPS      float64   `json:"network_tx_bytes_per_second"`
	UptimeSeconds     float64   `json:"uptime_seconds,omitempty"`
	SampledAt         time.Time `json:"sampled_at"`
}

type LogEntry struct {
	Timestamp  time.Time      `json:"timestamp"`
	Level      string         `json:"level"`
	Message    string         `json:"message"`
	Attributes map[string]any `json:"attributes,omitempty"`
}

// CapabilitiesPayload refreshes runtime-derived adapter facts without
// reconnecting the node control channel.
type CapabilitiesPayload struct {
	NodeID   string                 `json:"node_id"`
	Adapters []AdapterAdvertisement `json:"adapters"`
}

// EventPayload is a free-form lifecycle event (architecture.md §28). Phase 1
// does not generate any of these yet; the type exists so the wire format is
// stable when it does.
type EventPayload struct {
	NodeID   string         `json:"node_id"`
	Type     string         `json:"type"`
	Severity string         `json:"severity"`
	Payload  map[string]any `json:"payload,omitempty"`
}

// AckPayload is the controller's reply to register/heartbeat/telemetry.
type AckPayload struct {
	OK      bool   `json:"ok"`
	Message string `json:"message,omitempty"`
	// ServerTime lets the node agent sanity-check clock skew.
	ServerTime time.Time `json:"server_time"`
}

// CommandPayload is a signed, idempotent controller-to-node command. The node
// agent rejects unknown commands and verifies node binding and expiry.
type CommandPayload struct {
	ID             string         `json:"id"`
	IdempotencyKey string         `json:"idempotency_key"`
	NodeID         string         `json:"node_id"`
	Command        string         `json:"command"`
	Args           map[string]any `json:"args,omitempty"`
	IssuedAt       time.Time      `json:"issued_at"`
	ExpiresAt      time.Time      `json:"expires_at"`
	Signature      string         `json:"signature"`
}

type CommandResultPayload struct {
	ID          string         `json:"id"`
	NodeID      string         `json:"node_id"`
	OK          bool           `json:"ok"`
	Result      map[string]any `json:"result,omitempty"`
	Error       string         `json:"error,omitempty"`
	CompletedAt time.Time      `json:"completed_at"`
}

func SignCommand(command CommandPayload, secret []byte) (string, error) {
	material, err := commandSigningMaterial(command)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(material)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil)), nil
}

func VerifyCommand(command CommandPayload, secret []byte) bool {
	expected, err := SignCommand(command, secret)
	return err == nil && hmac.Equal([]byte(expected), []byte(command.Signature))
}

func commandSigningMaterial(command CommandPayload) ([]byte, error) {
	return json.Marshal(struct {
		ID             string         `json:"id"`
		IdempotencyKey string         `json:"idempotency_key"`
		NodeID         string         `json:"node_id"`
		Command        string         `json:"command"`
		Args           map[string]any `json:"args,omitempty"`
		IssuedAt       time.Time      `json:"issued_at"`
		ExpiresAt      time.Time      `json:"expires_at"`
	}{command.ID, command.IdempotencyKey, command.NodeID, command.Command, command.Args, command.IssuedAt, command.ExpiresAt})
}
