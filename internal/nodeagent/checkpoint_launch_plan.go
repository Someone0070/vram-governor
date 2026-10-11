package nodeagent

// This file defines a local, typed input for a future fixed launcher. Parsing
// this value grants no execution authority and does not establish custody.
import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"
)

const checkpointLaunchPlanVersion = "checkpoint-launch-plan-v1"
const checkpointLaunchPlanVersion2 = "checkpoint-launch-plan-v2"
const checkpointLaunchPlanMaxBytes = 64 << 10

var checkpointLaunchAliasRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
var checkpointLaunchSHA256RE = regexp.MustCompile(`^[a-fA-F0-9]{64}$`)

// CheckpointLaunchPlan is the complete v1 JSON schema. total_context_tokens is
// the server-wide context budget passed to llama-server -c; it is not a
// per-request limit and does not promise dynamic resizing. Paths are canonical
// absolute local paths. Model and executable hashes are approvals for later
// custody verification, not hashes computed by this bounded parser.
type CheckpointLaunchPlan struct {
	Version            string                          `json:"version"`
	Alias              string                          `json:"alias"`
	Model              CheckpointLaunchModel           `json:"model"`
	Executable         CheckpointLaunchExecutable      `json:"executable"`
	Endpoint           CheckpointLaunchEndpoint        `json:"endpoint"`
	TotalContextTokens int64                           `json:"total_context_tokens"`
	ParallelSlots      int64                           `json:"parallel_slots"`
	SnapshotRoot       string                          `json:"snapshot_root"`
	Custody            CheckpointLaunchCustodyQuotas   `json:"custody"`
	Placement          *CheckpointLaunchPlacement      `json:"placement,omitempty"`
	RuntimeOptions     *CheckpointLaunchRuntimeOptions `json:"runtime_options,omitempty"`
}

// CheckpointLaunchRuntimeOptions is the one reviewed v2 startup tuple. It is
// configuration only: it does not prove initialized KV geometry, descriptor
// validity, checkpoint capability, or same-worker context switching.
type CheckpointLaunchRuntimeOptions struct {
	KVUnified            bool   `json:"kv_unified"`
	FlashAttention       string `json:"flash_attention"`
	CheckpointDescriptor bool   `json:"checkpoint_descriptor"`
}

// CheckpointLaunchPlacement pins one backend runtime device to a stable
// physical identity. full_gpu means all layers the pinned llama.cpp build
// reports as offloadable were assigned to that GPU. The runtime deliberately
// keeps the input layer on CPU, so this does not mean every model weight or
// tensor is in VRAM. partial_cpu is represented but not executable until
// actual partial placement can be measured honestly.
type CheckpointLaunchPlacement struct {
	Backend            string `json:"backend"`
	IdentityKind       string `json:"identity_kind"`
	PhysicalIdentity   string `json:"physical_identity"`
	RuntimeDeviceToken string `json:"runtime_device_token"`
	RuntimeVersion     string `json:"runtime_version"`
	MaxAccelerators    int    `json:"max_accelerators"`
	OffloadPolicy      string `json:"offload_policy"`
	MinGPUBytes        int64  `json:"min_gpu_bytes"`
	MaxHostRSSBytes    int64  `json:"max_host_rss_bytes"`
}

type CheckpointLaunchModel struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}
type CheckpointLaunchExecutable struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}
type CheckpointLaunchEndpoint struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}
type CheckpointLaunchCustodyQuotas struct {
	Root             string `json:"root"`
	MaxArtifactBytes int64  `json:"max_artifact_bytes"`
	MaxStagingBytes  int64  `json:"max_staging_bytes"`
	ReserveBytes     int64  `json:"reserve_bytes"`
}

// pinnedCheckpointLaunchPlan retains an immutable parsed plan and the exact
// local plan-file descriptor used to read it. Platform files provide open and
// recheck so unsupported systems fail closed.
type PinnedCheckpointLaunchPlan struct {
	mu            sync.Mutex
	plan          CheckpointLaunchPlan
	args          []string
	path          string
	file          *os.File
	device, inode uint64
	expectedUID   uint32
	size          int64
	contentSHA256 [32]byte
	parents       []checkpointLaunchParent
	closed        bool
}

type checkpointLaunchParent struct {
	path          string
	device, inode uint64
	uid           uint32
	mode          uint32
}

// ParseCheckpointLaunchPlan strictly parses and validates a bounded JSON plan.
// It performs local path availability checks but does not hash large artifacts.
func ParseCheckpointLaunchPlan(raw []byte) (CheckpointLaunchPlan, error) {
	var p CheckpointLaunchPlan
	if len(raw) == 0 || len(raw) > checkpointLaunchPlanMaxBytes {
		return p, errors.New("launch plan size is outside 1..65536 bytes")
	}
	if !utf8.Valid(raw) {
		return p, errors.New("launch plan is not valid UTF-8")
	}
	if err := rejectDuplicateJSONKeys(raw); err != nil {
		return p, err
	}
	if err := rejectNoncanonicalLaunchPlanKeys(raw); err != nil {
		return p, err
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&p); err != nil {
		return CheckpointLaunchPlan{}, fmt.Errorf("decode launch plan: %w", err)
	}
	var trailing any
	if err := d.Decode(&trailing); err != io.EOF {
		if err == nil {
			return CheckpointLaunchPlan{}, errors.New("launch plan has a trailing JSON value")
		}
		return CheckpointLaunchPlan{}, fmt.Errorf("launch plan trailing data: %w", err)
	}
	if err := validateCheckpointLaunchPlan(p); err != nil {
		return CheckpointLaunchPlan{}, err
	}
	return p, nil
}

// encoding/json intentionally matches struct fields case-insensitively. A
// security plan uses one canonical spelling per field, so inspect every
// object before decoding and reject aliases such as "Alias" for "alias".
func rejectNoncanonicalLaunchPlanKeys(raw []byte) error {
	var header struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(raw, &header); err != nil {
		return fmt.Errorf("read launch plan version: %w", err)
	}
	rootFields := map[string]struct{}{"version": {}, "alias": {}, "model": {}, "executable": {}, "endpoint": {}, "total_context_tokens": {}, "parallel_slots": {}, "snapshot_root": {}, "custody": {}}
	if header.Version == checkpointLaunchPlanVersion2 {
		rootFields["placement"] = struct{}{}
		rootFields["runtime_options"] = struct{}{}
	}
	allowed := map[string]map[string]struct{}{
		"$":            rootFields,
		"$.model":      {"path": {}, "sha256": {}, "bytes": {}},
		"$.executable": {"path": {}, "sha256": {}},
		"$.endpoint":   {"host": {}, "port": {}},
		"$.custody":    {"root": {}, "max_artifact_bytes": {}, "max_staging_bytes": {}, "reserve_bytes": {}},
	}
	if header.Version == checkpointLaunchPlanVersion2 {
		allowed["$.placement"] = map[string]struct{}{"backend": {}, "identity_kind": {}, "physical_identity": {}, "runtime_device_token": {}, "runtime_version": {}, "max_accelerators": {}, "offload_policy": {}, "min_gpu_bytes": {}, "max_host_rss_bytes": {}}
		allowed["$.runtime_options"] = map[string]struct{}{"kv_unified": {}, "flash_attention": {}, "checkpoint_descriptor": {}}
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	var walk func(string) error
	walk = func(objectPath string) error {
		t, err := d.Token()
		if err != nil {
			return err
		}
		delim, ok := t.(json.Delim)
		if !ok {
			if t == nil {
				return fmt.Errorf("null JSON field at %s", objectPath)
			}
			return nil
		}
		switch delim {
		case '{':
			fields, knownObject := allowed[objectPath]
			if !knownObject {
				return fmt.Errorf("unexpected nested JSON object at %s", objectPath)
			}
			seen := make(map[string]struct{}, len(fields))
			for d.More() {
				keyToken, e := d.Token()
				if e != nil {
					return e
				}
				key, ok := keyToken.(string)
				if !ok {
					return errors.New("JSON object key is not a string")
				}
				if _, ok := fields[key]; !ok {
					return fmt.Errorf("unknown or noncanonical JSON key %q at %s", key, objectPath)
				}
				seen[key] = struct{}{}
				child := objectPath + "." + key
				if e = walk(child); e != nil {
					return e
				}
			}
			end, e := d.Token()
			if e != nil || end != json.Delim('}') {
				return errors.New("malformed JSON object")
			}
			for field := range fields {
				_, present := seen[field]
				if objectPath == "$" && header.Version == checkpointLaunchPlanVersion2 && (field == "placement" || field == "runtime_options") && !present {
					if field == "runtime_options" {
						continue
					}
					return errors.New("missing required JSON key \"placement\" at $")
				}
				if !present {
					return fmt.Errorf("missing required JSON key %q at %s", field, objectPath)
				}
			}
		case '[':
			for d.More() {
				if err := walk(objectPath + "[]"); err != nil {
					return err
				}
			}
			end, e := d.Token()
			if e != nil || end != json.Delim(']') {
				return errors.New("malformed JSON array")
			}
		default:
			return errors.New("unexpected JSON delimiter")
		}
		return nil
	}
	if err := walk("$"); err != nil {
		return fmt.Errorf("strict JSON key spelling: %w", err)
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("strict JSON key spelling has trailing data")
	}
	return nil
}

func rejectDuplicateJSONKeys(raw []byte) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var walk func() error
	walk = func() error {
		t, err := d.Token()
		if err != nil {
			return err
		}
		delim, ok := t.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]struct{}{}
			for d.More() {
				keyToken, e := d.Token()
				if e != nil {
					return e
				}
				key, ok := keyToken.(string)
				if !ok {
					return errors.New("JSON object key is not a string")
				}
				if _, exists := seen[key]; exists {
					return fmt.Errorf("duplicate JSON key %q", key)
				}
				seen[key] = struct{}{}
				if e = walk(); e != nil {
					return e
				}
			}
			end, e := d.Token()
			if e != nil || end != json.Delim('}') {
				return errors.New("malformed JSON object")
			}
		case '[':
			for d.More() {
				if err := walk(); err != nil {
					return err
				}
			}
			end, e := d.Token()
			if e != nil || end != json.Delim(']') {
				return errors.New("malformed JSON array")
			}
		default:
			return errors.New("unexpected JSON delimiter")
		}
		return nil
	}
	if err := walk(); err != nil {
		return fmt.Errorf("strict JSON: %w", err)
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("strict JSON has trailing data")
	}
	return nil
}

func validateCheckpointLaunchPlan(p CheckpointLaunchPlan) error {
	if p.Version != checkpointLaunchPlanVersion && p.Version != checkpointLaunchPlanVersion2 {
		return errors.New("unsupported launch plan version")
	}
	if !checkpointLaunchAliasRE.MatchString(p.Alias) {
		return errors.New("alias is invalid")
	}
	if p.Model.Bytes <= 0 || p.Model.Bytes > custodyMaxArtifactBytes || !checkpointLaunchSHA256RE.MatchString(p.Model.SHA256) {
		return errors.New("model size or SHA-256 is invalid")
	}
	if !checkpointLaunchSHA256RE.MatchString(p.Executable.SHA256) {
		return errors.New("executable SHA-256 is invalid")
	}
	if p.TotalContextTokens < 256 || p.TotalContextTokens > 1048576 || p.ParallelSlots < 1 || p.ParallelSlots > 128 || p.TotalContextTokens < p.ParallelSlots*256 {
		return errors.New("context and parallel slot limits are inconsistent")
	}
	addr := net.ParseIP(p.Endpoint.Host)
	if addr == nil || !addr.IsLoopback() || p.Endpoint.Port < 1 || p.Endpoint.Port > 65535 {
		return errors.New("endpoint must be a literal loopback address and valid port")
	}
	if err := validateCanonicalLaunchFile(p.Model.Path, false); err != nil {
		return fmt.Errorf("model path: %w", err)
	}
	if err := validateCanonicalLaunchFile(p.Executable.Path, true); err != nil {
		return fmt.Errorf("executable path: %w", err)
	}
	for name, path := range map[string]string{"snapshot root": p.SnapshotRoot, "custody root": p.Custody.Root} {
		if err := validateCanonicalLaunchDirectory(path); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	if p.Custody.MaxArtifactBytes <= 0 || p.Custody.MaxArtifactBytes > custodyMaxArtifactBytes || p.Custody.MaxArtifactBytes < p.Model.Bytes || p.Custody.MaxStagingBytes <= 0 || p.Custody.MaxStagingBytes > custodyMaxStagingBytes || p.Custody.ReserveBytes < 0 || p.Custody.ReserveBytes > custodyMaxReserveBytes || p.Custody.ReserveBytes > p.Custody.MaxStagingBytes || p.Custody.MaxStagingBytes-p.Custody.ReserveBytes < p.Model.Bytes {
		return errors.New("custody quotas are invalid or inconsistent")
	}
	if p.Version == checkpointLaunchPlanVersion2 {
		if p.Placement == nil {
			return errors.New("v2 placement object is required")
		}
		if err := validateCheckpointLaunchPlacement(*p.Placement); err != nil {
			return err
		}
	} else if p.Placement != nil {
		return errors.New("legacy v1 launch plan cannot contain managed placement")
	}
	if err := validateCheckpointLaunchRuntimeOptions(p.Version, p.RuntimeOptions); err != nil {
		return err
	}
	return nil
}

func validateCheckpointLaunchRuntimeOptions(version string, options *CheckpointLaunchRuntimeOptions) error {
	if options == nil {
		return nil
	}
	if version != checkpointLaunchPlanVersion2 {
		return errors.New("legacy v1 launch plan cannot contain runtime options")
	}
	if !options.KVUnified || options.FlashAttention != "off" || !options.CheckpointDescriptor {
		return errors.New("runtime options do not match the one supported startup tuple")
	}
	return nil
}

func validateCheckpointLaunchPlacement(p CheckpointLaunchPlacement) error {
	if p.Backend != "cuda" || p.MaxAccelerators != 1 {
		return errors.New("placement backend is unsupported or accelerator ceiling is not exactly one")
	}
	if p.IdentityKind != "uuid" && p.IdentityKind != "pci_bus_id" {
		return errors.New("placement physical identity kind is unsupported")
	}
	if p.IdentityKind == "uuid" && !checkpointGPUUUIDRE.MatchString(p.PhysicalIdentity) {
		return errors.New("placement GPU UUID is malformed")
	}
	if p.IdentityKind == "pci_bus_id" && !checkpointPCIBusIDRE.MatchString(p.PhysicalIdentity) {
		return errors.New("placement PCI identity is malformed")
	}
	if p.RuntimeDeviceToken != "CUDA0" {
		return errors.New("placement runtime token is unsupported")
	}
	if p.RuntimeVersion == "" || len(p.RuntimeVersion) > 128 || strings.ContainsAny(p.RuntimeVersion, "\x00\r\n") || !strings.Contains(p.RuntimeVersion, "commit 62acc89") {
		return errors.New("placement runtime version pin is invalid")
	}
	if p.OffloadPolicy != "full_gpu" && p.OffloadPolicy != "partial_cpu" {
		return errors.New("placement offload policy is invalid")
	}
	if p.MinGPUBytes <= 0 || p.MinGPUBytes > 1<<60 || p.MaxHostRSSBytes <= 0 || p.MaxHostRSSBytes > 1<<60 {
		return errors.New("placement footprint bounds are invalid")
	}
	return nil
}

func validateCanonicalLaunchFile(path string, executable bool) error {
	if err := validateCanonicalPathSyntax(path); err != nil {
		return err
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return err
	}
	if resolved != path {
		return errors.New("path is not canonical or contains a symlink")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("path must name a regular file")
	}
	if executable && info.Mode().Perm()&0111 == 0 {
		return errors.New("executable has no execute bit")
	}
	return nil
}
func validateCanonicalLaunchDirectory(path string) error {
	if err := validateCanonicalPathSyntax(path); err != nil {
		return err
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return err
	}
	if resolved != path {
		return errors.New("directory is not canonical or contains a symlink")
	}
	i, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !i.IsDir() || i.Mode()&os.ModeSymlink != 0 {
		return errors.New("path must name an existing real directory")
	}
	return nil
}
func validateCanonicalPathSyntax(path string) error {
	if path == "" || len(path) > 4096 || !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.IndexFunc(path, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
		return errors.New("path is empty, noncanonical, oversized, or contains control characters")
	}
	for _, part := range strings.Split(filepath.ToSlash(path), "/") {
		if part == ".." || part == "." {
			return errors.New("path traversal or dot component is forbidden")
		}
	}
	return nil
}

func fixedCheckpointLaunchArguments(p CheckpointLaunchPlan) []string {
	host := net.ParseIP(p.Endpoint.Host).String()
	return []string{"-m", "{CHECKPOINT_MODEL}", "--alias", p.Alias, "--host", host, "--port", strconv.Itoa(p.Endpoint.Port), "--no-webui", "-c", strconv.FormatInt(p.TotalContextTokens, 10), "--parallel", strconv.FormatInt(p.ParallelSlots, 10), "--slot-save-path", p.SnapshotRoot}
}

func fixedCheckpointPlacementArguments(p CheckpointLaunchPlan) ([]string, error) {
	if err := validateCheckpointLaunchRuntimeOptions(p.Version, p.RuntimeOptions); err != nil {
		return nil, err
	}
	if p.Version != checkpointLaunchPlanVersion2 {
		return nil, errors.New("legacy v1 plan cannot authorize managed placement")
	}
	if p.Placement == nil {
		return nil, errors.New("v2 placement object is required")
	}
	if err := validateCheckpointLaunchPlacement(*p.Placement); err != nil {
		return nil, err
	}
	if p.Placement.OffloadPolicy != "full_gpu" {
		return nil, errors.New("planned partial CPU offload is unsupported by the pinned runtime evidence")
	}
	args := fixedCheckpointLaunchArguments(p)
	args = append(args, "--device", p.Placement.RuntimeDeviceToken, "--split-mode", "none", "--main-gpu", "0", "--n-gpu-layers", "all")
	if p.RuntimeOptions != nil {
		args = append(args, "--kv-unified", "--flash-attn", "off")
	}
	return args, nil
}

// OpenCheckpointLaunchPlan opens and pins a root-owned, locally trusted Linux
// plan file. The JSON plan is policy input only; it never starts a process.
func OpenCheckpointLaunchPlan(ctx context.Context, canonicalPlanPath string) (*PinnedCheckpointLaunchPlan, error) {
	return openCheckpointLaunchPlan(ctx, canonicalPlanPath, 0)
}

// Spec returns an independent value copy; its fields contain no mutable maps.
func (p *PinnedCheckpointLaunchPlan) Spec() CheckpointLaunchPlan {
	if p == nil {
		return CheckpointLaunchPlan{}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	spec := p.plan
	if p.plan.Placement != nil {
		placement := *p.plan.Placement
		spec.Placement = &placement
	}
	if p.plan.RuntimeOptions != nil {
		options := *p.plan.RuntimeOptions
		spec.RuntimeOptions = &options
	}
	return spec
}

// Arguments returns a defensive copy of the fixed llama-server argument vector.
func (p *PinnedCheckpointLaunchPlan) Arguments() []string {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.args...)
}

// Close releases the original descriptor and is safe to call repeatedly.
func (p *PinnedCheckpointLaunchPlan) Close() error {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil
	}
	p.closed = true
	if p.file == nil {
		return nil
	}
	err := p.file.Close()
	p.file = nil
	return err
}
