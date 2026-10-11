package nodeagent

// This file contains the policy/state machine for warm model bytes.  The
// operating-system proof is deliberately isolated in warmram_linux.go and
// warmram_other.go: a page-cache hit is never treated as a warm residency
// claim.

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	ErrWarmRAMUnsupported = errors.New("verified warm RAM is unsupported on this operating system")
	ErrWarmRAMPressure    = errors.New("warm RAM refused while memory pressure is unsafe")
)

const warmMaxInt64 = int64(^uint64(0) >> 1)

func warmAdd(a, b int64) (int64, bool) {
	if a < 0 || b < 0 || a > warmMaxInt64-b {
		return 0, false
	}
	return a + b, true
}

// The parsers below intentionally have no operating-system dependencies. The
// Linux adapter only supplies bytes from authoritative files; deterministic
// tests therefore exercise the same validation rules on every platform.
func parseNonnegativeDecimal(value string) (int64, error) {
	n, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
	if err != nil || n < 0 {
		return 0, errors.New("invalid nonnegative accounting value")
	}
	return n, nil
}

func parseMemInfoBytes(data []byte) (int64, int64, error) {
	values := make(map[string]int64, 2)
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 0 {
			continue
		}
		key := strings.TrimSuffix(fields[0], ":")
		if key != "MemTotal" && key != "MemAvailable" {
			continue
		}
		if len(fields) != 3 || fields[2] != "kB" {
			return 0, 0, errors.New("required meminfo field has invalid units")
		}
		n, err := parseNonnegativeDecimal(fields[1])
		if err != nil || n > warmMaxInt64/1024 {
			return 0, 0, errors.New("required meminfo field is malformed")
		}
		if _, exists := values[key]; exists {
			return 0, 0, errors.New("required meminfo field is duplicated")
		}
		values[key] = n * 1024
	}
	if err := scanner.Err(); err != nil {
		return 0, 0, err
	}
	total, totalOK := values["MemTotal"]
	available, availableOK := values["MemAvailable"]
	if !totalOK || !availableOK || total <= 0 || available < 0 || available > total {
		return 0, 0, errors.New("required meminfo fields are invalid")
	}
	return total, available, nil
}

func parsePSIBytes(data []byte) (float64, error) {
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != "some" {
			continue
		}
		seen := map[string]bool{}
		var avg10 float64
		for _, field := range fields[1:] {
			name, valueText, found := strings.Cut(field, "=")
			if !found || (name != "avg10" && name != "avg60" && name != "avg300" && name != "total") || seen[name] {
				return 0, errors.New("memory pressure fields are malformed")
			}
			seen[name] = true
			if name == "total" {
				if _, err := parseNonnegativeDecimal(valueText); err != nil {
					return 0, errors.New("memory pressure total is malformed")
				}
				continue
			}
			value, err := strconv.ParseFloat(valueText, 64)
			if err != nil || math.IsNaN(value) || math.IsInf(value, 0) || value < 0 || value > 100 {
				return 0, errors.New("memory pressure is not finite")
			}
			if name == "avg10" {
				avg10 = value
			}
		}
		if !seen["avg10"] || !seen["avg60"] || !seen["avg300"] || !seen["total"] {
			return 0, errors.New("memory pressure fields are incomplete")
		}
		return avg10, nil
	}
	return 0, errors.New("memory pressure average unavailable")
}

func parseOOMBytes(data []byte) (int64, error) {
	var total int64
	recognized := false
	seen := map[string]bool{}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		// The source is an exact-key counter file.  A malformed recognized
		// line must poison the whole read; silently ignoring it beside a
		// valid counter would turn partial accounting into an admission.
		if fields[0] != "oom" && fields[0] != "oom_kill" && fields[0] != "oom_group_kill" {
			if strings.HasPrefix(fields[0], "oom") {
				return 0, errors.New("malformed OOM event counter")
			}
			continue
		}
		if len(fields) != 2 {
			return 0, errors.New("malformed OOM event counter")
		}
		recognized = true
		if seen[fields[0]] {
			return 0, errors.New("duplicate OOM event counter")
		}
		seen[fields[0]] = true
		n, err := parseNonnegativeDecimal(fields[1])
		if err != nil || total > warmMaxInt64-n {
			return 0, errors.New("invalid OOM event counter")
		}
		total += n
	}
	if !recognized {
		return 0, errors.New("OOM event counter unavailable")
	}
	return total, nil
}

func parseVmLckBytes(data []byte) (int64, error) {
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != "VmLck:" {
			continue
		}
		if len(fields) != 3 || fields[2] != "kB" {
			return 0, errors.New("VmLck has invalid units")
		}
		n, err := parseNonnegativeDecimal(fields[1])
		if err != nil || n > warmMaxInt64/1024 {
			return 0, errors.New("VmLck is malformed")
		}
		return n * 1024, nil
	}
	return 0, errors.New("VmLck unavailable")
}

// WarmRAMPolicy is intentionally byte based. Zero limits are unknown, and
// unknown safety limits fail closed rather than silently becoming unlimited.
type WarmRAMPolicy struct {
	AllowedRoots                                    []string
	RAMTotalBytes, RAMReserveBytes, RAMHardCapBytes int64
	MemlockLimitBytes, CgroupLimitBytes             int64
	MaxWarmBytes                                    int64
	UnifiedMemory                                   bool
	UnifiedMemoryBytes                              int64
	PressureRefusalPercent                          float64
	OOMEvents                                       func() (int64, error)
	OOMEventsBaseline                               int64
	MemInfoPath, PressurePath, CgroupCurrentPath    string
	CgroupMaxPath                                   string
	CgroupEventsPath, OOMEventsPath                 string
	CurrentRAMBytes                                 func() (int64, error)
	AvailableRAMBytes                               func() (int64, error)
	CurrentCgroupBytes                              func() (int64, error)
	CurrentMemlockBytes                             func() (int64, error)
	PressurePercent                                 func() (float64, error)
	OpenIdentity                                    func(string, []string) (warmFileIdentity, error)
	PinFile                                         func(string, []string, warmFileIdentity) (warmRAMPin, warmFileIdentity, error)
	Oracle                                          func() string
	Snapshot                                        func() (int64, int64, int64, int64, float64, error)
	MemlockLimit                                    func() (int64, error)
}

type WarmRAMRequest struct {
	TargetID            string
	Model               string
	Path                string
	ExpectedFingerprint string
	RuntimeFingerprint  string
	RuntimeEndpoint     string
	RuntimeVersion      string
	RuntimeProfile      string
	ReleaseVRAM         func(context.Context) error
	ConfirmReleased     func(context.Context) (bool, error)
	RestoreVRAM         func(context.Context) error
	// MarkSideEffect is invoked immediately before an existing pin is
	// invalidated or a retained pin is closed.  The command processor uses it
	// to keep the signed intent durable across uncertain local cleanup.
	MarkSideEffect   func()
	ActiveReferences int
	Protected        bool
}

type WarmRAMResult struct {
	Model, CanonicalPath              string
	FileFingerprint                   string
	Bytes, ResidentBytes, LockedBytes int64
	VRAMReleased, Verified            bool
	Oracle                            string
}

type WarmRAMEntry struct {
	WarmRAMResult
	lastUsed           time.Time
	pin                warmRAMPin
	activeReferences   int
	protected          bool
	identity           warmFileIdentity
	key                string
	runtimeFingerprint string
	runtimeEndpoint    string
	runtimeVersion     string
	runtimeProfile     string
}

type WarmRAMManifest struct {
	TargetID              string `json:"target_id,omitempty"`
	Model                 string `json:"model,omitempty"`
	CanonicalPath         string `json:"canonical_path,omitempty"`
	FileFingerprint       string `json:"file_fingerprint,omitempty"`
	RuntimeFingerprint    string `json:"runtime_fingerprint,omitempty"`
	RuntimeEndpoint       string `json:"runtime_endpoint,omitempty"`
	RuntimeVersion        string `json:"runtime_version,omitempty"`
	RuntimeProfile        string `json:"runtime_profile,omitempty"`
	RuntimeProfilePresent bool   `json:"runtime_profile_present"`
	Dev                   uint64 `json:"dev,omitempty"`
	Ino                   uint64 `json:"ino,omitempty"`
	Size                  int64  `json:"size,omitempty"`
	Mtime                 int64  `json:"mtime,omitempty"`
	ActiveReferences      int    `json:"active_references,omitempty"`
	Protected             bool   `json:"protected,omitempty"`
	Verified              bool   `json:"verified,omitempty"`
	VRAMReleased          bool   `json:"vram_released,omitempty"`
	// MetadataOnly is a durable restart placeholder. It carries a previously
	// verified claim without pretending that a process restart preserved the
	// live mapping/lock; reconciliation must re-discover and re-pin it.
	MetadataOnly bool      `json:"metadata_only,omitempty"`
	LastUsed     time.Time `json:"last_used"`
}

type WarmRAMManager struct {
	mu       sync.Mutex
	policy   WarmRAMPolicy
	entries  map[string]*WarmRAMEntry
	reserved int64
	inflight map[string]bool
}

func NewWarmRAMManager(policy WarmRAMPolicy) *WarmRAMManager {
	return &WarmRAMManager{policy: policy, entries: make(map[string]*WarmRAMEntry), inflight: make(map[string]bool)}
}

func warmEntryKey(targetID, model string) string { return targetID + "\x00" + model }

func (m *WarmRAMManager) Supported() bool {
	backend := warmRAMOSSupported() || (m.policy.OpenIdentity != nil && m.policy.PinFile != nil)
	return backend && len(m.policy.AllowedRoots) > 0 && m.policy.RAMHardCapBytes > 0 && m.policy.RAMReserveBytes >= 0
}

func (m *WarmRAMManager) OffloadModel(ctx context.Context, request WarmRAMRequest) (WarmRAMResult, error) {
	if !warmRAMOSSupported() && (m.policy.OpenIdentity == nil || m.policy.PinFile == nil) {
		return WarmRAMResult{}, errors.New("unsupported backend")
	}
	if len(m.policy.AllowedRoots) == 0 || m.policy.RAMHardCapBytes <= 0 || m.policy.RAMReserveBytes < 0 {
		return WarmRAMResult{}, errors.New("unsupported policy")
	}
	if strings.TrimSpace(request.Model) == "" {
		return WarmRAMResult{}, errors.New("model is required")
	}
	if request.ReleaseVRAM == nil || request.ConfirmReleased == nil {
		return WarmRAMResult{}, errors.New("warm offload requires release and VRAM confirmation")
	}
	canonical, err := canonicalWarmModelPath(request.Path, m.policy.AllowedRoots)
	if err != nil {
		return WarmRAMResult{}, err
	}

	m.mu.Lock()
	key := warmEntryKey(request.TargetID, request.Model)
	if old := m.entries[key]; old != nil {
		m.revalidateEntryLocked(old)
		if !old.Verified || !old.VRAMReleased {
			m.mu.Unlock()
			return WarmRAMResult{}, errors.New("warm model requires cleanup or reverification")
		}
		if old.CanonicalPath != canonical {
			m.mu.Unlock()
			return WarmRAMResult{}, errors.New("model identity is already warm at a different canonical path")
		}
		old.activeReferences = request.ActiveReferences
		old.protected = request.Protected
		old.lastUsed = time.Now().UTC()
		// A verified pin is not proof that the runtime is still unloaded: the
		// model may have been manually reloaded since the prior command. Keep
		// the mapping as a retry handle, invalidate its proof, and require this
		// call to unload and re-confirm VRAM before restoring Verified=true.
		if request.MarkSideEffect != nil {
			request.MarkSideEffect()
		}
		old.Verified = false
		old.VRAMReleased = false
		m.mu.Unlock()
		if err := request.ReleaseVRAM(ctx); err != nil {
			if request.MarkSideEffect != nil {
				request.MarkSideEffect()
			}
			if request.RestoreVRAM != nil {
				_ = request.RestoreVRAM(context.Background())
			}
			return WarmRAMResult{}, errors.New("warm transition state is uncertain; accelerator release failed")
		}
		released, err := request.ConfirmReleased(ctx)
		if err != nil || !released {
			if request.MarkSideEffect != nil {
				request.MarkSideEffect()
			}
			if request.RestoreVRAM != nil {
				_ = request.RestoreVRAM(context.Background())
			}
			return WarmRAMResult{}, errors.New("released VRAM state is uncertain; confirmation failed")
		}
		m.mu.Lock()
		if current := m.entries[key]; current == old {
			old.Verified = true
			old.VRAMReleased = true
			old.runtimeFingerprint = request.RuntimeFingerprint
			old.runtimeEndpoint = request.RuntimeEndpoint
			old.runtimeVersion = request.RuntimeVersion
			old.runtimeProfile = request.RuntimeProfile
			result := old.WarmRAMResult
			m.mu.Unlock()
			return result, nil
		}
		m.mu.Unlock()
		return WarmRAMResult{}, errors.New("warm model entry changed during revalidation")
	}
	if m.inflight[key] {
		m.mu.Unlock()
		return WarmRAMResult{}, errors.New("model warm transition is already in progress")
	}
	m.inflight[key] = true
	m.mu.Unlock()
	defer func() { m.mu.Lock(); delete(m.inflight, key); m.mu.Unlock() }()

	identityFn := m.policy.OpenIdentity
	if identityFn == nil {
		identityFn = warmSecureFileIdentity
	}
	identity, err := identityFn(canonical, m.policy.AllowedRoots)
	if err != nil {
		return WarmRAMResult{}, errors.New("warm model identity could not be authorized")
	}
	if (identity.Hash != "" && request.ExpectedFingerprint == "") || (request.ExpectedFingerprint != "" && !strings.EqualFold(identity.Hash, request.ExpectedFingerprint)) {
		return WarmRAMResult{}, errors.New("warm model fingerprint could not be verified")
	}
	releaseReservation, err := m.reserve(identity.Size, request.MarkSideEffect)
	if err != nil {
		return WarmRAMResult{}, err
	}
	defer releaseReservation()
	pinFn := m.policy.PinFile
	if pinFn == nil {
		pinFn = pinWarmModelFileExpected
	}
	pin, openedIdentity, err := pinFn(canonical, m.policy.AllowedRoots, identity)
	if err != nil {
		return WarmRAMResult{}, errors.New("warm model residency could not be established")
	}
	identity = openedIdentity
	if recheckedIdentity, err := identityFn(canonical, m.policy.AllowedRoots); err != nil || recheckedIdentity != identity {
		if request.MarkSideEffect != nil {
			request.MarkSideEffect()
		}
		closeErr := pin.Close()
		if closeErr != nil {
			m.retainUnverified(request.TargetID, request.Model, canonical, identity.Hash, identity.Size, pin)
			return WarmRAMResult{}, errors.New("model identity changed during warm transition; cleanup required")
		}
		return WarmRAMResult{}, errors.New("model identity changed during warm transition")
	}
	if rechecked, recheckErr := canonicalWarmModelPath(canonical, m.policy.AllowedRoots); recheckErr != nil || rechecked != canonical {
		if request.MarkSideEffect != nil {
			request.MarkSideEffect()
		}
		closeErr := pin.Close()
		if closeErr != nil {
			m.retainUnverified(request.TargetID, request.Model, canonical, identity.Hash, identity.Size, pin)
			return WarmRAMResult{}, errors.New("model path changed during warm transition; cleanup required")
		}
		return WarmRAMResult{}, errors.New("model path changed during warm transition")
	}
	bytes := identity.Size
	// The map is pinned before runtime release, so every failure can restore
	// the prior hot state without leaving a false warm record behind.
	if err := request.ReleaseVRAM(ctx); err != nil {
		if request.MarkSideEffect != nil {
			request.MarkSideEffect()
		}
		closeErr := pin.Close()
		if closeErr != nil {
			m.retainUnverified(request.TargetID, request.Model, canonical, identity.Hash, bytes, pin)
		}
		if request.RestoreVRAM != nil {
			restoreCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			restoreErr := request.RestoreVRAM(restoreCtx)
			cancel()
			if restoreErr != nil || closeErr != nil {
				return WarmRAMResult{}, errors.New("warm transition state is uncertain; release rollback failed")
			}
		}
		if closeErr != nil {
			return WarmRAMResult{}, errors.New("warm transition state is uncertain; cleanup failed")
		}
		return WarmRAMResult{}, errors.New("warm transition state is uncertain; accelerator release failed")
	}
	released, err := request.ConfirmReleased(ctx)
	if err != nil || !released {
		if request.MarkSideEffect != nil {
			request.MarkSideEffect()
		}
		closeErr := pin.Close()
		if closeErr != nil {
			m.retainUnverified(request.TargetID, request.Model, canonical, identity.Hash, bytes, pin)
		}
		if request.RestoreVRAM != nil {
			restoreCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			restoreErr := request.RestoreVRAM(restoreCtx)
			cancel()
			if restoreErr != nil && closeErr == nil {
				closeErr = restoreErr
			}
		}
		if err != nil {
			if closeErr != nil {
				return WarmRAMResult{}, errors.New("released VRAM state is uncertain; confirmation cleanup failed")
			}
			return WarmRAMResult{}, errors.New("released VRAM state is uncertain; confirmation failed")
		}
		if closeErr != nil {
			return WarmRAMResult{}, errors.New("warm transition state is uncertain; cleanup failed")
		}
		return WarmRAMResult{}, errors.New("released VRAM state is uncertain; runtime did not confirm")
	}

	oracle := warmRAMOracle()
	if m.policy.Oracle != nil {
		oracle = m.policy.Oracle()
	}
	result := WarmRAMResult{Model: request.Model, CanonicalPath: canonical, FileFingerprint: identity.Hash, Bytes: bytes,
		ResidentBytes: pin.ResidentBytes(), LockedBytes: pin.LockedBytes(), VRAMReleased: true,
		Verified: pin.ResidentBytes() >= bytes && pin.LockedBytes() >= bytes, Oracle: oracle}
	if err := validateWarmRAMResult(result); err != nil {
		if request.MarkSideEffect != nil {
			request.MarkSideEffect()
		}
		closeErr := pin.Close()
		if closeErr != nil {
			m.retainUnverified(request.TargetID, request.Model, canonical, identity.Hash, bytes, pin)
		}
		if request.RestoreVRAM != nil {
			restoreCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			restoreErr := request.RestoreVRAM(restoreCtx)
			cancel()
			if restoreErr != nil && closeErr == nil {
				closeErr = restoreErr
			}
		}
		if closeErr != nil {
			return WarmRAMResult{}, errors.New("warm transition state is uncertain; rollback failed")
		}
		return WarmRAMResult{}, err
	}
	m.mu.Lock()
	m.entries[key] = &WarmRAMEntry{WarmRAMResult: result, lastUsed: time.Now().UTC(), pin: pin, activeReferences: request.ActiveReferences, protected: request.Protected, identity: identity, key: key, runtimeFingerprint: request.RuntimeFingerprint, runtimeEndpoint: request.RuntimeEndpoint, runtimeVersion: request.RuntimeVersion, runtimeProfile: request.RuntimeProfile}
	m.mu.Unlock()
	return result, nil
}

func (m *WarmRAMManager) retainUnverified(targetID, model, canonical, fingerprint string, bytes int64, pin warmRAMPin) {
	identity := warmFileIdentity{Size: bytes, Hash: fingerprint}
	m.retainUnverifiedState(targetID, model, canonical, identity, pin, 0, false, "", "", "", "")
}

func (m *WarmRAMManager) retainUnverifiedState(targetID, model, canonical string, identity warmFileIdentity, pin warmRAMPin, activeReferences int, protected bool, runtimeFingerprint, runtimeEndpoint, runtimeVersion, runtimeProfile string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := warmEntryKey(targetID, model)
	resident, locked := int64(0), int64(0)
	if pin != nil {
		resident, locked = pin.ResidentBytes(), pin.LockedBytes()
	}
	m.entries[key] = &WarmRAMEntry{WarmRAMResult: WarmRAMResult{
		Model: model, CanonicalPath: canonical, FileFingerprint: identity.Hash, Bytes: identity.Size,
		ResidentBytes: resident, LockedBytes: locked,
		Oracle: warmRAMOracle(), Verified: false, VRAMReleased: false,
	}, lastUsed: time.Now().UTC(), pin: pin, activeReferences: activeReferences, protected: protected,
		identity: identity, key: key, runtimeFingerprint: runtimeFingerprint, runtimeEndpoint: runtimeEndpoint,
		runtimeVersion: runtimeVersion, runtimeProfile: runtimeProfile}
}

func validateWarmRAMResult(result WarmRAMResult) error {
	if !result.Verified || result.Bytes <= 0 || result.ResidentBytes < result.Bytes || result.LockedBytes < result.Bytes {
		return errors.New("warm model bytes were not independently verified")
	}
	if result.Oracle != "mincore+mlock" {
		return errors.New("warm model bytes lack a resident-and-locked OS oracle")
	}
	if !result.VRAMReleased {
		return errors.New("warm model bytes lack released VRAM confirmation")
	}
	return nil
}

func (m *WarmRAMManager) ReleaseModel(model string) error {
	return m.ReleaseModelFor("", model)
}

func (m *WarmRAMManager) ReleaseModelFor(targetID, model string) error {
	m.mu.Lock()
	entry := m.entries[warmEntryKey(targetID, model)]
	if entry == nil {
		m.mu.Unlock()
		return nil
	}
	if entry.pin == nil {
		delete(m.entries, warmEntryKey(targetID, model))
		m.mu.Unlock()
		return nil
	}
	if err := entry.pin.Close(); err != nil {
		entry.Verified = false
		entry.VRAMReleased = false
		m.mu.Unlock()
		return errors.New("warm residency cleanup failed; reconciliation required")
	}
	delete(m.entries, warmEntryKey(targetID, model))
	m.mu.Unlock()
	return nil
}

func (m *WarmRAMManager) Snapshot() []WarmRAMResult {
	m.mu.Lock()
	defer m.mu.Unlock()
	rows := make([]WarmRAMResult, 0, len(m.entries))
	for _, entry := range m.entries {
		m.revalidateEntryLocked(entry)
		rows = append(rows, entry.WarmRAMResult)
	}
	return rows
}

func (m *WarmRAMManager) ManifestSnapshot() []WarmRAMManifest {
	m.mu.Lock()
	defer m.mu.Unlock()
	manifests := make([]WarmRAMManifest, 0, len(m.entries))
	for _, entry := range m.entries {
		m.revalidateEntryLocked(entry)
		targetID := ""
		if separator := strings.IndexByte(entry.key, 0); separator >= 0 {
			targetID = entry.key[:separator]
		}
		manifests = append(manifests, WarmRAMManifest{
			TargetID: targetID, Model: entry.Model, CanonicalPath: entry.CanonicalPath,
			FileFingerprint: entry.FileFingerprint, RuntimeFingerprint: entry.runtimeFingerprint, RuntimeEndpoint: entry.runtimeEndpoint,
			RuntimeVersion: entry.runtimeVersion, RuntimeProfile: entry.runtimeProfile, RuntimeProfilePresent: true, Dev: entry.identity.Dev, Ino: entry.identity.Ino,
			Size: entry.identity.Size, Mtime: entry.identity.Mtime, ActiveReferences: entry.activeReferences, Protected: entry.protected,
			Verified: entry.Verified, VRAMReleased: entry.VRAMReleased, LastUsed: entry.lastUsed,
			MetadataOnly: entry.pin == nil && entry.Verified && !entry.VRAMReleased,
		})
	}
	return manifests
}

func (m *WarmRAMManager) SetRuntimeManifest(targetID, model, fingerprint, endpoint, version, profile string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	entry := m.entries[warmEntryKey(targetID, model)]
	if entry == nil || !entry.Verified || !entry.VRAMReleased {
		return errors.New("warm model is not verified")
	}
	entry.runtimeFingerprint, entry.runtimeEndpoint, entry.runtimeVersion, entry.runtimeProfile = fingerprint, endpoint, version, profile
	return nil
}

func (m *WarmRAMManager) ValidateManifestIdentity(manifest WarmRAMManifest) error {
	canonical, err := canonicalWarmModelPath(manifest.CanonicalPath, m.policy.AllowedRoots)
	if err != nil || canonical != manifest.CanonicalPath {
		return errors.New("warm manifest path is not canonical")
	}
	identityFn := m.policy.OpenIdentity
	if identityFn == nil {
		identityFn = warmSecureFileIdentity
	}
	identity, err := identityFn(canonical, m.policy.AllowedRoots)
	if err != nil || identity.Hash != manifest.FileFingerprint || identity.Dev != manifest.Dev || identity.Ino != manifest.Ino || identity.Size != manifest.Size || identity.Mtime != manifest.Mtime {
		return errors.New("warm manifest file identity changed")
	}
	return nil
}

func (m *WarmRAMManager) RestoreManifests(manifests []WarmRAMManifest) {
	seen := make(map[string]struct{}, len(manifests))
	for _, manifest := range manifests {
		if manifest.TargetID == "" || manifest.Model == "" || manifest.CanonicalPath == "" || manifest.FileFingerprint == "" {
			continue
		}
		key := warmEntryKey(manifest.TargetID, manifest.Model)
		if _, duplicate := seen[key]; duplicate {
			// Ambiguous durable state is rejected rather than allowing the last
			// manifest to overwrite a different identity.
			continue
		}
		seen[key] = struct{}{}
		if manifest.ActiveReferences < 0 {
			continue
		}
		now := time.Now().UTC()
		if manifest.LastUsed.IsZero() || manifest.LastUsed.After(now.Add(5*time.Minute)) || manifest.LastUsed.Before(time.Unix(0, 0).UTC()) {
			continue
		}
		if manifest.Verified && manifest.VRAMReleased && (manifest.RuntimeFingerprint == "" || manifest.RuntimeEndpoint == "" || manifest.RuntimeVersion == "" || !manifest.RuntimeProfilePresent) {
			continue
		}
		identity := warmFileIdentity{Dev: manifest.Dev, Ino: manifest.Ino, Size: manifest.Size, Mtime: manifest.Mtime, Hash: manifest.FileFingerprint}
		// A failed/uncertain cleanup manifest is deliberately restored as an
		// unverified retry handle, never repinned from disk.
		if !manifest.Verified || (!manifest.VRAMReleased && !manifest.MetadataOnly) {
			m.retainUnverifiedState(manifest.TargetID, manifest.Model, manifest.CanonicalPath, identity, nil, manifest.ActiveReferences, manifest.Protected, manifest.RuntimeFingerprint, manifest.RuntimeEndpoint, manifest.RuntimeVersion, manifest.RuntimeProfile)
			continue
		}
		// Completed manifests are metadata-only until runtime discovery proves
		// the exact model is unloaded. ReconcileWarmManifests performs the
		// full admission and pin operation after that proof.
		result := WarmRAMResult{Model: manifest.Model, CanonicalPath: manifest.CanonicalPath, FileFingerprint: identity.Hash, Bytes: identity.Size, Verified: true, VRAMReleased: false, Oracle: "unverified-restart"}
		m.mu.Lock()
		m.entries[key] = &WarmRAMEntry{WarmRAMResult: result, lastUsed: manifest.LastUsed, pin: nil, activeReferences: manifest.ActiveReferences, protected: manifest.Protected, identity: identity, key: key, runtimeFingerprint: manifest.RuntimeFingerprint, runtimeEndpoint: manifest.RuntimeEndpoint, runtimeVersion: manifest.RuntimeVersion, runtimeProfile: manifest.RuntimeProfile}
		m.mu.Unlock()
	}
}

func (m *WarmRAMManager) UpdateProtection(model string, activeReferences int, protected bool) (WarmRAMResult, error) {
	return m.UpdateProtectionFor("", model, activeReferences, protected)
}

func (m *WarmRAMManager) UpdateProtectionFor(targetID, model string, activeReferences int, protected bool, markSideEffect ...func()) (WarmRAMResult, error) {
	if activeReferences < 0 {
		return WarmRAMResult{}, errors.New("active references must be nonnegative")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	entry := m.entries[warmEntryKey(targetID, model)]
	if entry == nil {
		return WarmRAMResult{}, errors.New("warm model is not present")
	}
	if len(markSideEffect) > 0 && markSideEffect[0] != nil {
		markSideEffect[0]()
	}
	m.revalidateEntryLocked(entry)
	if !entry.Verified || !entry.VRAMReleased {
		return WarmRAMResult{}, errors.New("warm model requires cleanup or reverification")
	}
	entry.activeReferences = activeReferences
	entry.protected = protected
	entry.lastUsed = time.Now().UTC()
	return entry.WarmRAMResult, nil
}

func (m *WarmRAMManager) IsVerified(model string) bool {
	return m.IsVerifiedFor("", model)
}

func (m *WarmRAMManager) IsVerifiedFor(targetID, model string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	entry := m.entries[warmEntryKey(targetID, model)]
	return entry != nil && m.revalidateEntryLocked(entry) && entry.Verified && entry.VRAMReleased
}

func (m *WarmRAMManager) HasEntryFor(targetID, model string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.entries[warmEntryKey(targetID, model)]
	return ok
}

// HasUnverifiedEntries reports retained cleanup handles, including entries
// belonging to an LRU victim rather than the model currently being admitted.
func (m *WarmRAMManager) HasUnverifiedEntries() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, entry := range m.entries {
		if entry != nil && (!entry.Verified || !entry.VRAMReleased) {
			return true
		}
	}
	return false
}

// ReverifyModel reconstructs a live resident-and-locked pin for an existing
// entry. It performs no runtime mutation; the caller must separately confirm
// that the runtime is in the warm/offloaded state.
func (m *WarmRAMManager) ReverifyModel(targetID, model, path, expectedHash string, authoritativeVRAMReleased ...bool) (WarmRAMResult, error) {
	return m.reverifyModel(targetID, model, path, expectedHash, false, nil, authoritativeVRAMReleased...)
}

func (m *WarmRAMManager) ReverifyModelWithCallback(targetID, model, path, expectedHash string, markSideEffect func(), authoritativeVRAMReleased ...bool) (WarmRAMResult, error) {
	return m.reverifyModel(targetID, model, path, expectedHash, false, markSideEffect, authoritativeVRAMReleased...)
}

// ReverifyModelPreserveLastUsed is used only while reconciling a persisted
// manifest. Re-establishing the pin must not make a cold entry look newly
// used to the LRU policy.
func (m *WarmRAMManager) ReverifyModelPreserveLastUsed(targetID, model, path, expectedHash string, authoritativeVRAMReleased ...bool) (WarmRAMResult, error) {
	return m.reverifyModel(targetID, model, path, expectedHash, true, nil, authoritativeVRAMReleased...)
}

func (m *WarmRAMManager) ReverifyModelPreserveLastUsedWithCallback(targetID, model, path, expectedHash string, markSideEffect func(), authoritativeVRAMReleased ...bool) (WarmRAMResult, error) {
	return m.reverifyModel(targetID, model, path, expectedHash, true, markSideEffect, authoritativeVRAMReleased...)
}

func (m *WarmRAMManager) reverifyModel(targetID, model, path, expectedHash string, preserveLastUsed bool, markSideEffect func(), authoritativeVRAMReleased ...bool) (WarmRAMResult, error) {
	if len(authoritativeVRAMReleased) != 1 || !authoritativeVRAMReleased[0] {
		return WarmRAMResult{}, errors.New("reverification requires authoritative released VRAM confirmation")
	}
	canonical, err := canonicalWarmModelPath(path, m.policy.AllowedRoots)
	if err != nil {
		return WarmRAMResult{}, errors.New("warm model identity could not be authorized")
	}
	key := warmEntryKey(targetID, model)
	m.mu.Lock()
	if m.inflight[key] {
		m.mu.Unlock()
		return WarmRAMResult{}, errors.New("model warm transition is already in progress")
	}
	m.inflight[key] = true
	entry := m.entries[key]
	var prior WarmRAMEntry
	if entry != nil {
		prior = *entry
		if markSideEffect != nil {
			markSideEffect()
		}
		entry.Verified = false
		entry.VRAMReleased = false
	}
	m.mu.Unlock()
	defer func() { m.mu.Lock(); delete(m.inflight, key); m.mu.Unlock() }()
	retainFailure := func(identity warmFileIdentity, pin warmRAMPin) {
		if entry == nil && pin == nil {
			return
		}
		activeReferences, protected := 0, false
		runtimeFingerprint, runtimeEndpoint, runtimeVersion, runtimeProfile := "", "", "", ""
		if entry != nil {
			activeReferences, protected = prior.activeReferences, prior.protected
			runtimeFingerprint, runtimeEndpoint, runtimeVersion, runtimeProfile = prior.runtimeFingerprint, prior.runtimeEndpoint, prior.runtimeVersion, prior.runtimeProfile
		}
		m.retainUnverifiedState(targetID, model, canonical, identity, pin, activeReferences, protected, runtimeFingerprint, runtimeEndpoint, runtimeVersion, runtimeProfile)
	}
	if entry != nil && entry.pin != nil {
		if markSideEffect != nil {
			markSideEffect()
		}
		if err := entry.pin.Close(); err != nil {
			retainFailure(prior.identity, entry.pin)
			return WarmRAMResult{}, errors.New("warm residency cleanup failed; reconciliation required")
		}
	}
	m.mu.Lock()
	delete(m.entries, key)
	m.mu.Unlock()
	identityFn := m.policy.OpenIdentity
	if identityFn == nil {
		identityFn = warmSecureFileIdentity
	}
	identity, err := identityFn(canonical, m.policy.AllowedRoots)
	if err != nil || (expectedHash != "" && !strings.EqualFold(identity.Hash, expectedHash)) {
		retainFailure(prior.identity, nil)
		return WarmRAMResult{}, errors.New("warm model fingerprint could not be verified")
	}
	release, err := m.reserve(identity.Size, markSideEffect)
	if err != nil {
		retainFailure(identity, nil)
		return WarmRAMResult{}, err
	}
	defer release()
	pinFn := m.policy.PinFile
	if pinFn == nil {
		pinFn = pinWarmModelFileExpected
	}
	pin, opened, err := pinFn(canonical, m.policy.AllowedRoots, identity)
	if err != nil || opened != identity {
		if pin != nil {
			if markSideEffect != nil {
				markSideEffect()
			}
			if closeErr := pin.Close(); closeErr != nil {
				retainFailure(identity, pin)
				return WarmRAMResult{}, errors.New("warm model residency cleanup failed; reconciliation required")
			}
		}
		retainFailure(identity, nil)
		return WarmRAMResult{}, errors.New("warm model residency could not be re-established")
	}
	if rechecked, recheckErr := identityFn(canonical, m.policy.AllowedRoots); recheckErr != nil || rechecked != identity {
		if markSideEffect != nil {
			markSideEffect()
		}
		if closeErr := pin.Close(); closeErr != nil {
			retainFailure(identity, pin)
			return WarmRAMResult{}, errors.New("model identity changed during reverification; cleanup required")
		}
		retainFailure(identity, nil)
		return WarmRAMResult{}, errors.New("model identity changed during reverification")
	}
	oracle := warmRAMOracle()
	if m.policy.Oracle != nil {
		oracle = m.policy.Oracle()
	}
	result := WarmRAMResult{Model: model, CanonicalPath: canonical, FileFingerprint: identity.Hash, Bytes: identity.Size,
		ResidentBytes: pin.ResidentBytes(), LockedBytes: pin.LockedBytes(), VRAMReleased: true, Verified: true, Oracle: oracle}
	if err := validateWarmRAMResult(result); err != nil {
		if markSideEffect != nil {
			markSideEffect()
		}
		if closeErr := pin.Close(); closeErr != nil {
			retainFailure(identity, pin)
		} else {
			retainFailure(identity, nil)
		}
		return WarmRAMResult{}, err
	}
	m.mu.Lock()
	lastUsed := time.Now().UTC()
	if preserveLastUsed && entry != nil && !prior.lastUsed.IsZero() {
		lastUsed = prior.lastUsed
	}
	m.entries[key] = &WarmRAMEntry{WarmRAMResult: result, lastUsed: lastUsed, pin: pin, identity: identity, key: key,
		activeReferences: prior.activeReferences, protected: prior.protected, runtimeFingerprint: prior.runtimeFingerprint,
		runtimeEndpoint: prior.runtimeEndpoint, runtimeVersion: prior.runtimeVersion, runtimeProfile: prior.runtimeProfile}
	m.mu.Unlock()
	return result, nil
}

func (m *WarmRAMManager) revalidateEntryLocked(entry *WarmRAMEntry) bool {
	if entry == nil || !entry.Verified || !entry.VRAMReleased || entry.CanonicalPath == "" {
		return false
	}
	identityFn := m.policy.OpenIdentity
	if identityFn == nil {
		identityFn = warmSecureFileIdentity
	}
	identity, err := identityFn(entry.CanonicalPath, m.policy.AllowedRoots)
	if err != nil || identity != entry.identity {
		entry.Verified = false
		entry.VRAMReleased = false
		return false
	}
	return true
}

func (m *WarmRAMManager) admit(bytes int64) error {
	release, err := m.reserve(bytes, nil)
	if err != nil {
		return err
	}
	release()
	return nil
}

func (m *WarmRAMManager) reserve(bytes int64, markSideEffect func()) (func(), error) {
	if bytes <= 0 {
		return nil, errors.New("model file is empty")
	}
	if m.policy.RAMHardCapBytes <= 0 || m.policy.RAMReserveBytes < 0 {
		return nil, errors.New("RAM hard cap and reserve are required")
	}
	if m.policy.RAMHardCapBytes < m.policy.RAMReserveBytes {
		return nil, errors.New("RAM hard cap is below reserve")
	}
	if m.policy.UnifiedMemory && m.policy.UnifiedMemoryBytes <= 0 {
		return nil, errors.New("unified-memory accounting is unavailable")
	}
	m.mu.Lock()
	var current int64
	for _, e := range m.entries {
		if e.pin == nil {
			continue
		}
		var ok bool
		current, ok = warmAdd(current, e.Bytes)
		if !ok {
			m.mu.Unlock()
			return nil, errors.New("warm RAM accounting overflow")
		}
	}
	committedBefore, ok := warmAdd(current, m.reserved)
	if !ok {
		m.mu.Unlock()
		return nil, errors.New("warm RAM accounting overflow")
	}
	requested, ok := warmAdd(committedBefore, bytes)
	if !ok {
		m.mu.Unlock()
		return nil, errors.New("warm RAM accounting overflow")
	}
	if m.policy.MaxWarmBytes > 0 && requested > m.policy.MaxWarmBytes {
		if err := m.evictLRULocked(bytes, markSideEffect); err != nil {
			m.mu.Unlock()
			return nil, err
		}
		current = 0
		for _, e := range m.entries {
			if e.pin == nil {
				continue
			}
			current, ok = warmAdd(current, e.Bytes)
			if !ok {
				m.mu.Unlock()
				return nil, errors.New("warm RAM accounting overflow")
			}
		}
		committedBefore, ok = warmAdd(current, m.reserved)
		if !ok {
			m.mu.Unlock()
			return nil, errors.New("warm RAM accounting overflow")
		}
		requested, ok = warmAdd(committedBefore, bytes)
		if !ok || requested > m.policy.MaxWarmBytes {
			m.mu.Unlock()
			return nil, fmt.Errorf("warm RAM LRU budget exceeded: need %d bytes", bytes)
		}
	}
	newReserved, ok := warmAdd(m.reserved, bytes)
	if !ok {
		m.mu.Unlock()
		return nil, errors.New("warm RAM accounting overflow")
	}
	m.reserved = newReserved
	committed := committedBefore
	// OS counters already include committed warm mappings. Only concurrent
	// reservations (including this request) are added to those counters.
	osAdditional := m.reserved
	m.mu.Unlock()
	release := func() {
		m.mu.Lock()
		if m.reserved >= bytes {
			m.reserved -= bytes
		} else {
			m.reserved = 0
		}
		m.mu.Unlock()
	}
	totalWithNew, sumOK := warmAdd(committed, bytes)
	if !sumOK {
		release()
		return nil, errors.New("warm RAM accounting overflow")
	}
	if totalWithNew > m.policy.RAMHardCapBytes-m.policy.RAMReserveBytes {
		release()
		return nil, errors.New("warm RAM would cross configured reserve or hard cap")
	}
	if m.policy.RAMTotalBytes > 0 && totalWithNew > m.policy.RAMTotalBytes-m.policy.RAMReserveBytes {
		release()
		return nil, errors.New("warm RAM would cross total RAM reserve")
	}
	unifiedTotal, unifiedOK := warmAdd(osAdditional, m.policy.UnifiedMemoryBytes)
	if !unifiedOK {
		release()
		return nil, errors.New("warm RAM accounting overflow")
	}
	if m.policy.UnifiedMemory && m.policy.UnifiedMemoryBytes > 0 && unifiedTotal > m.policy.RAMHardCapBytes-m.policy.RAMReserveBytes {
		release()
		return nil, errors.New("unified-memory accounting leaves insufficient RAM reserve")
	}
	snapshotFn := m.policy.Snapshot
	if snapshotFn == nil {
		snapshotFn = func() (int64, int64, int64, int64, float64, error) { return warmRAMSnapshot(m.policy) }
	}
	currentRAM, available, cgroup, memlock, pressure, err := snapshotFn()
	if err != nil {
		release()
		return nil, errors.New("warm RAM accounting unavailable")
	}
	measuredTotal, measuredOK := warmAdd(currentRAM, osAdditional)
	if !measuredOK {
		release()
		return nil, errors.New("warm RAM accounting overflow")
	}
	if currentRAM > 0 && m.policy.RAMTotalBytes > 0 && measuredTotal > m.policy.RAMTotalBytes-m.policy.RAMReserveBytes {
		release()
		return nil, errors.New("measured RAM reserve is too small")
	}
	availableNeed, availableOK := warmAdd(osAdditional, m.policy.RAMReserveBytes)
	if !availableOK {
		release()
		return nil, errors.New("warm RAM accounting overflow")
	}
	if available > 0 && available < availableNeed {
		release()
		return nil, errors.New("available RAM reserve is too small")
	}
	cgroupNeed, cgroupOK := warmAdd(cgroup, osAdditional)
	if !cgroupOK {
		release()
		return nil, errors.New("warm RAM accounting overflow")
	}
	if m.policy.CgroupLimitBytes > 0 && cgroupNeed > m.policy.CgroupLimitBytes {
		release()
		return nil, errors.New("cgroup memory limit would be exceeded")
	}
	if m.policy.CgroupMaxPath != "" {
		if max, err := warmRAMCgroupMax(m.policy.CgroupMaxPath); err != nil {
			release()
			return nil, errors.New("authoritative cgroup max unavailable")
		} else if max > 0 && cgroupNeed > max {
			release()
			return nil, errors.New("authoritative cgroup max would be exceeded")
		}
	}
	memlockNeed, memlockOK := warmAdd(memlock, osAdditional)
	if !memlockOK {
		release()
		return nil, errors.New("warm RAM accounting overflow")
	}
	if m.policy.MemlockLimitBytes > 0 && memlockNeed > m.policy.MemlockLimitBytes {
		release()
		return nil, errors.New("memlock limit would be exceeded")
	}
	memlockFn := m.policy.MemlockLimit
	if memlockFn == nil {
		memlockFn = warmRAMMemlockLimit
	}
	if actual, err := memlockFn(); err != nil {
		release()
		return nil, errors.New("authoritative memlock limit unavailable")
	} else if actual > 0 && memlockNeed > actual {
		release()
		return nil, errors.New("authoritative memlock limit would be exceeded")
	}
	threshold := m.policy.PressureRefusalPercent
	if threshold <= 0 {
		threshold = 80
	}
	if pressure >= threshold {
		release()
		return nil, ErrWarmRAMPressure
	}
	var oomEvents func() (int64, error)
	if m.policy.OOMEvents != nil {
		oomEvents = m.policy.OOMEvents
	} else {
		oomPath := m.policy.OOMEventsPath
		if oomPath == "" {
			oomPath = m.policy.CgroupEventsPath
		}
		if oomPath != "" {
			oomEvents = func() (int64, error) { return warmRAMOOMEvents(oomPath) }
		}
	}
	if oomEvents != nil {
		count, err := oomEvents()
		if err != nil {
			release()
			return nil, errors.New("warm OOM accounting unavailable")
		}
		if count > m.policy.OOMEventsBaseline {
			release()
			return nil, ErrWarmRAMPressure
		}
	}
	return release, nil
}

func (m *WarmRAMManager) evictLRULocked(need int64, markSideEffectArgs ...func()) error {
	var markSideEffect func()
	if len(markSideEffectArgs) > 0 {
		markSideEffect = markSideEffectArgs[0]
	}
	if m.policy.MaxWarmBytes <= 0 {
		return nil
	}
	rows := make([]*WarmRAMEntry, 0, len(m.entries))
	for _, e := range m.entries {
		if e.pin != nil && e.activeReferences == 0 && !e.protected {
			rows = append(rows, e)
		}
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].lastUsed.Equal(rows[j].lastUsed) {
			return rows[i].key < rows[j].key
		}
		return rows[i].lastUsed.Before(rows[j].lastUsed)
	})
	var total int64
	for _, e := range m.entries {
		if e.pin == nil {
			continue
		}
		total += e.Bytes
	}
	for _, e := range rows {
		if total+need <= m.policy.MaxWarmBytes {
			break
		}
		if e.pin == nil {
			delete(m.entries, e.key)
			total -= e.Bytes
			continue
		}
		if markSideEffect != nil {
			markSideEffect()
		}
		if e.pin.Close() == nil {
			delete(m.entries, e.key)
			total -= e.Bytes
		} else {
			// A failed close is a retained retry handle, never a verified
			// resident entry.  It remains protected from false LRU success.
			e.Verified = false
			e.VRAMReleased = false
			return errors.New("warm LRU victim cleanup failed; reconciliation required")
		}
	}
	return nil
}

func canonicalWarmModelPath(path string, roots []string) (string, error) {
	if path == "" || !filepath.IsAbs(path) {
		return "", errors.New("model path must be absolute")
	}
	abs, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return "", err
	}
	for _, root := range roots {
		if root == "" || !filepath.IsAbs(root) {
			continue
		}
		canonicalRoot, err := filepath.EvalSymlinks(root)
		if err != nil {
			continue
		}
		canonicalRoot, _ = filepath.Abs(filepath.Clean(canonicalRoot))
		candidate, err := filepath.EvalSymlinks(abs)
		if err != nil || candidate != abs {
			continue
		}
		rel, err := filepath.Rel(canonicalRoot, candidate)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
			continue
		}
		if err := rejectSymlinkComponents(canonicalRoot, candidate); err != nil {
			continue
		}
		return candidate, nil
	}
	return "", errors.New("model path is outside canonical allowlist or uses a symlink")
}

func canonicalWarmRootForPath(path string, roots []string) (string, error) {
	for _, root := range roots {
		if root == "" || !filepath.IsAbs(root) {
			continue
		}
		canonicalRoot, err := filepath.EvalSymlinks(root)
		if err != nil {
			continue
		}
		candidate, err := filepath.Abs(filepath.Clean(path))
		if err != nil {
			continue
		}
		rel, err := filepath.Rel(canonicalRoot, candidate)
		if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel) {
			return canonicalRoot, nil
		}
	}
	return "", errors.New("model path is outside canonical allowlist")
}

func rejectSymlinkComponents(root, path string) error {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return err
	}
	cur := root
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		if part == "" || part == "." {
			continue
		}
		cur = filepath.Join(cur, part)
		info, err := os.Lstat(cur)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("symlink component")
		}
	}
	return nil
}

func verifyWarmModelIdentity(path string, want warmFileIdentity) error {
	got, err := warmFileIdentityAt(path)
	if err != nil {
		return err
	}
	if got != want {
		return errors.New("model file identity changed during warm transition")
	}
	return nil
}
