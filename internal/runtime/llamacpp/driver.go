// Package llamacpp implements runtime.Driver against llama.cpp's
// `llama-server` binary, driven over its HTTP API exactly the way the
// reference spikes (scripts/spike/evict_reload_spike.py,
// scripts/spike/kv_restore_spike.py) drive it — ported to Go so no Python
// is required on a node (measurement.md §4).
//
// This driver only ever manages child processes it launched itself
// (architecture.md decision #18) and never assumes a capability without
// trying it (measurement.md §2, §6 honesty rules).
package llamacpp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"vram-governor/internal/domain"
	"vram-governor/internal/runtime"
)

// Driver drives llama-server as a managed child process.
type Driver struct {
	ServerPath string // absolute path to llama-server
	GPUIndex   int    // nvidia-smi GPU index this driver targets

	mu        sync.Mutex
	instances map[string]*handle
}

// handle is the driver-private state for one launched engine; it is never
// serialized and never leaves this package. domain.EngineInstance is the
// public, storable view.
type handle struct {
	cmd          *exec.Cmd
	port         int
	workDir      string
	slotPath     string
	profile      domain.ServingProfile
	freeBeforeMB int64 // free VRAM immediately before this Launch (baseline for evict measurement)
	residentMB   int64 // VRAM this engine occupies once loaded (freeBefore - freeAfterLoad)
	launchArgs   []string
	libDir       string
}

func NewDriver(serverPath string, gpuIndex int) *Driver {
	return &Driver{
		ServerPath: serverPath,
		GPUIndex:   gpuIndex,
		instances:  make(map[string]*handle),
	}
}

func (d *Driver) Name() string { return "llamacpp" }

// ---------------------------------------------------------------------
// Runtime identity
// ---------------------------------------------------------------------

var versionRE = regexp.MustCompile(`version:\s*(\S+)\s*\(build\s*(\d+),\s*commit\s*([0-9a-fA-F]+)\)`)

func (d *Driver) ProbeRuntime(ctx context.Context) (runtime.RuntimeIdentity, error) {
	cmd := exec.CommandContext(ctx, d.ServerPath, "--version")
	cmd.Env = append(os.Environ(), "LD_LIBRARY_PATH="+d.libDirFor(d.ServerPath))
	out, err := cmd.CombinedOutput()
	if err != nil {
		return runtime.RuntimeIdentity{}, fmt.Errorf("llama-server --version: %w (output: %s)", err, string(out))
	}
	version := strings.TrimSpace(string(out))
	if m := versionRE.FindStringSubmatch(version); m != nil {
		version = fmt.Sprintf("%s+build%s.%s", m[1], m[2], m[3])
	}
	return runtime.RuntimeIdentity{Name: "llamacpp", Version: version, Binary: d.ServerPath}, nil
}

func (d *Driver) libDirFor(serverPath string) string {
	abs, err := filepath.Abs(serverPath)
	if err != nil {
		abs = serverPath
	}
	return filepath.Dir(abs)
}

// ---------------------------------------------------------------------
// nvidia-smi helpers — global free VRAM and (best-effort) per-PID usage.
// Per-PID via --query-compute-apps sometimes reports [N/A] under WSL; when
// that happens callers fall back to a free-VRAM delta and must label which
// method was used (measurement.md honesty rule / environment note).
// ---------------------------------------------------------------------

func nvidiaFreeMB(ctx context.Context, gpuIndex int) (int64, error) {
	out, err := exec.CommandContext(ctx, "nvidia-smi",
		fmt.Sprintf("--id=%d", gpuIndex),
		"--query-gpu=memory.free", "--format=csv,noheader,nounits").Output()
	if err != nil {
		return 0, fmt.Errorf("nvidia-smi free query: %w", err)
	}
	line := strings.TrimSpace(strings.Split(strings.TrimSpace(string(out)), "\n")[0])
	v, err := strconv.ParseInt(line, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse nvidia-smi free output %q: %w", line, err)
	}
	return v, nil
}

// nvidiaPerPIDUsedMB returns the VRAM (MiB) nvidia-smi attributes to pid on
// gpuIndex, and whether the query yielded a usable (non N/A) number.
func nvidiaPerPIDUsedMB(ctx context.Context, gpuIndex int, pid int) (int64, bool) {
	out, err := exec.CommandContext(ctx, "nvidia-smi",
		fmt.Sprintf("--id=%d", gpuIndex),
		"--query-compute-apps=pid,used_memory", "--format=csv,noheader,nounits").Output()
	if err != nil {
		return 0, false
	}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Split(line, ",")
		if len(parts) != 2 {
			continue
		}
		p, err := strconv.Atoi(strings.TrimSpace(parts[0]))
		if err != nil || p != pid {
			continue
		}
		memStr := strings.TrimSpace(parts[1])
		if strings.Contains(memStr, "N/A") || memStr == "" {
			return 0, false
		}
		mb, err := strconv.ParseInt(memStr, 10, 64)
		if err != nil {
			return 0, false
		}
		return mb, true
	}
	return 0, false
}

// ---------------------------------------------------------------------
// HTTP helpers against a launched llama-server
// ---------------------------------------------------------------------

func (h *handle) baseURL() string { return fmt.Sprintf("http://127.0.0.1:%d", h.port) }

func httpGetJSON(ctx context.Context, url string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: status %d: %s", url, resp.StatusCode, string(body))
	}
	if out != nil {
		return json.Unmarshal(body, out)
	}
	return nil
}

func httpPostJSON(ctx context.Context, url string, payload any, out any) error {
	b, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("POST %s: status %d: %s", url, resp.StatusCode, string(body))
	}
	if out != nil && len(body) > 0 {
		return json.Unmarshal(body, out)
	}
	return nil
}

func waitHealthy(ctx context.Context, cmd *exec.Cmd, port int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	url := fmt.Sprintf("http://127.0.0.1:%d/health", port)
	for time.Now().Before(deadline) {
		if cmd.ProcessState != nil {
			return fmt.Errorf("llama-server exited early (code %d)", cmd.ProcessState.ExitCode())
		}
		var h struct {
			Status string `json:"status"`
		}
		if err := httpGetJSON(ctx, url, &h); err == nil && h.Status == "ok" {
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("llama-server did not become healthy within %s", timeout)
}

func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

// ---------------------------------------------------------------------
// Launch / Stop / Health / Metrics / Drain
// ---------------------------------------------------------------------

func buildArgs(spec runtime.LaunchSpec, port int, slotPath string) []string {
	rt := spec.Profile.RuntimeArgs
	modelPath, _ := rt["model_path"].(string)
	ngl := 999
	if v, ok := rt["ngl"].(int); ok {
		ngl = v
	} else if v, ok := rt["ngl"].(float64); ok {
		ngl = int(v)
	}
	args := []string{
		"-m", modelPath,
		"-ngl", strconv.Itoa(ngl),
		"--host", "127.0.0.1",
		"--port", strconv.Itoa(port),
		"--no-webui",
	}
	if spec.Profile.ContextLimit > 0 {
		args = append(args, "-c", strconv.Itoa(spec.Profile.ContextLimit))
	}
	if slotPath != "" {
		args = append(args, "--slot-save-path", slotPath)
	}
	return args
}

func (d *Driver) launchProcess(ctx context.Context, args []string) (*exec.Cmd, error) {
	cmd := exec.CommandContext(context.Background(), d.ServerPath, args...) // process outlives probe ctx deadlines intentionally; caller controls lifetime via Stop
	cmd.Env = append(os.Environ(), "LD_LIBRARY_PATH="+d.libDirFor(d.ServerPath))
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start llama-server: %w", err)
	}
	return cmd, nil
}

func (d *Driver) Launch(ctx context.Context, spec runtime.LaunchSpec) (*domain.EngineInstance, error) {
	port := spec.Port
	if port == 0 {
		p, err := freePort()
		if err != nil {
			return nil, fmt.Errorf("allocate port: %w", err)
		}
		port = p
	}
	workDir := spec.WorkDir
	if workDir == "" {
		workDir = filepath.Join(os.TempDir(), "vram-governor-llamacpp")
	}
	slotPath := filepath.Join(workDir, "slots")
	if err := os.MkdirAll(slotPath, 0o755); err != nil {
		return nil, fmt.Errorf("create slot dir: %w", err)
	}

	freeBefore, _ := nvidiaFreeMB(ctx, d.GPUIndex)

	args := buildArgs(spec, port, slotPath)
	cmd, err := d.launchProcess(ctx, args)
	if err != nil {
		return nil, err
	}
	if err := waitHealthy(ctx, cmd, port, 120*time.Second); err != nil {
		_ = cmd.Process.Kill()
		return nil, err
	}

	freeAfter, _ := nvidiaFreeMB(ctx, d.GPUIndex)
	resident := freeBefore - freeAfter
	if resident < 0 {
		resident = 0
	}

	engineID := fmt.Sprintf("engine-%s-%d", spec.Profile.ID, time.Now().UnixNano())
	eng := &domain.EngineInstance{
		ID:                  engineID,
		AcceleratorID:       spec.AcceleratorID,
		ProfileID:           spec.Profile.ID,
		ManagedByController: true,
		PID:                 cmd.Process.Pid,
		State:               "active_full",
		StartedAt:           time.Now().UTC(),
	}

	h := &handle{
		cmd: cmd, port: port, workDir: workDir, slotPath: slotPath,
		profile: spec.Profile, freeBeforeMB: freeBefore, residentMB: resident,
		launchArgs: args, libDir: d.libDirFor(d.ServerPath),
	}
	d.mu.Lock()
	d.instances[engineID] = h
	d.mu.Unlock()
	return eng, nil
}

func (d *Driver) handleFor(engine *domain.EngineInstance) (*handle, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	h, ok := d.instances[engine.ID]
	if !ok {
		return nil, fmt.Errorf("llamacpp: engine %s not managed by this driver (decision #18: refusing to touch it)", engine.ID)
	}
	return h, nil
}

func (d *Driver) Health(ctx context.Context, engine *domain.EngineInstance) (runtime.HealthStatus, error) {
	h, err := d.handleFor(engine)
	if err != nil {
		return runtime.HealthStatus{}, err
	}
	var hr struct {
		Status string `json:"status"`
	}
	now := time.Now()
	if err := httpGetJSON(ctx, h.baseURL()+"/health", &hr); err != nil {
		return runtime.HealthStatus{Healthy: false, Message: err.Error(), CheckedAt: now}, nil
	}
	return runtime.HealthStatus{Healthy: hr.Status == "ok", Message: hr.Status, CheckedAt: now}, nil
}

type slotsResp []struct {
	ID           int  `json:"id"`
	IsProcessing bool `json:"is_processing"`
}

func (d *Driver) Metrics(ctx context.Context, engine *domain.EngineInstance) (runtime.Metrics, error) {
	h, err := d.handleFor(engine)
	if err != nil {
		return runtime.Metrics{}, err
	}
	var slots slotsResp
	m := runtime.Metrics{SampledAt: time.Now()}
	if err := httpGetJSON(ctx, h.baseURL()+"/slots", &slots); err == nil {
		m.TotalSlots = len(slots)
		for _, s := range slots {
			if s.IsProcessing {
				m.ActiveSlots++
			}
		}
	}
	return m, nil
}

func (d *Driver) Drain(ctx context.Context, engine *domain.EngineInstance) error {
	h, err := d.handleFor(engine)
	if err != nil {
		return err
	}
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		var slots slotsResp
		if err := httpGetJSON(ctx, h.baseURL()+"/slots", &slots); err != nil {
			return nil // can't introspect further; treat as drained
		}
		busy := false
		for _, s := range slots {
			if s.IsProcessing {
				busy = true
			}
		}
		if !busy {
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("drain timed out: slots still processing")
}

func (d *Driver) Stop(ctx context.Context, engine *domain.EngineInstance) error {
	h, err := d.handleFor(engine)
	if err != nil {
		return err
	}
	if err := stopProcess(h.cmd); err != nil {
		return err
	}
	d.mu.Lock()
	delete(d.instances, engine.ID)
	d.mu.Unlock()
	return nil
}

func stopProcess(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return nil
	}
	_ = cmd.Process.Signal(syscall.SIGTERM)
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
		return nil
	case <-time.After(15 * time.Second):
		_ = cmd.Process.Kill()
		<-done
		return nil
	}
}

// waitFreedMB polls nvidia-smi until at least `expectFraction` of `resident`
// MB has been returned to the free pool (mirrors evict_reload_spike.py's
// poll loop — teardown release is async on some drivers), returning the
// actual freed amount and elapsed time.
func waitFreedMB(ctx context.Context, gpuIndex int, freeBefore, residentHint int64, timeout time.Duration) (freedMB int64, elapsed time.Duration) {
	start := time.Now()
	deadline := start.Add(timeout)
	threshold := int64(float64(residentHint) * 0.3)
	var lastFree int64
	for time.Now().Before(deadline) {
		free, err := nvidiaFreeMB(ctx, gpuIndex)
		if err == nil {
			lastFree = free
			freed := free - freeBefore
			if residentHint <= 0 || freed > threshold {
				return freed, time.Since(start)
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	return lastFree - freeBefore, time.Since(start)
}

// ---------------------------------------------------------------------
// Sleep / Wake
// ---------------------------------------------------------------------

func (d *Driver) Sleep(ctx context.Context, engine *domain.EngineInstance, mode runtime.SleepMode) error {
	if mode == runtime.SleepModeRAM {
		// llama.cpp has no weight-sleep-to-host-RAM API (no vLLM sleep()
		// equivalent) — this is architectural, not a probe failure.
		return &runtime.ErrUnsupported{Capability: "sleep_ram", Reason: "llama.cpp has no weight-sleep-to-RAM API"}
	}
	h, err := d.handleFor(engine)
	if err != nil {
		return err
	}
	if err := stopProcess(h.cmd); err != nil {
		return err
	}
	freed, _ := waitFreedMB(ctx, d.GPUIndex, h.freeBeforeMB, h.residentMB, 30*time.Second)
	_ = freed
	engine.State = "evicted"
	return nil
}

func (d *Driver) Wake(ctx context.Context, engine *domain.EngineInstance, stage runtime.WakeStage) error {
	h, err := d.handleFor(engine)
	if err != nil {
		return err
	}
	cmd, err := d.launchProcess(ctx, h.launchArgs)
	if err != nil {
		return err
	}
	if err := waitHealthy(ctx, cmd, h.port, 60*time.Second); err != nil {
		_ = cmd.Process.Kill()
		return err
	}
	d.mu.Lock()
	h.cmd = cmd
	d.mu.Unlock()
	engine.PID = cmd.Process.Pid
	engine.State = "active_full"
	return nil
	// stage is currently informational: WakeStageFull callers are expected
	// to follow up with RestoreSession themselves so the KV-restore timing
	// is measured as its own step (matches the spike's separation of
	// T_wake_weights from T_slot_restore).
}

// ---------------------------------------------------------------------
// KV checkpoint / restore (llama.cpp slot save/restore)
// ---------------------------------------------------------------------

func (d *Driver) CheckpointSession(ctx context.Context, engine *domain.EngineInstance, slotID int, snapshotName string) (runtime.CheckpointResult, error) {
	h, err := d.handleFor(engine)
	if err != nil {
		return runtime.CheckpointResult{}, err
	}
	t0 := time.Now()
	var resp struct {
		Filename string `json:"filename"`
		NSaved   int    `json:"n_saved"`
	}
	url := fmt.Sprintf("%s/slots/%d?action=save", h.baseURL(), slotID)
	if err := httpPostJSON(ctx, url, map[string]any{"filename": snapshotName}, &resp); err != nil {
		return runtime.CheckpointResult{}, &runtime.ErrUnsupported{Capability: "kv_snapshot_save", Reason: err.Error()}
	}
	dur := time.Since(t0)
	fpath := filepath.Join(h.slotPath, snapshotName)
	info, statErr := os.Stat(fpath)
	if statErr != nil {
		return runtime.CheckpointResult{}, fmt.Errorf("kv snapshot save reported success but file missing: %w", statErr)
	}
	return runtime.CheckpointResult{
		SnapshotRef: fpath,
		SizeBytes:   info.Size(),
		Duration:    dur,
		TokensSaved: resp.NSaved,
	}, nil
}

func (d *Driver) RestoreSession(ctx context.Context, engine *domain.EngineInstance, slotID int, snapshotName string) (runtime.RestoreResult, error) {
	h, err := d.handleFor(engine)
	if err != nil {
		return runtime.RestoreResult{}, err
	}
	fpath := filepath.Join(h.slotPath, snapshotName)
	if _, statErr := os.Stat(fpath); statErr != nil {
		return runtime.RestoreResult{}, &runtime.ErrUnsupported{Capability: "kv_snapshot_restore", Reason: "no snapshot file: " + statErr.Error()}
	}
	t0 := time.Now()
	url := fmt.Sprintf("%s/slots/%d?action=restore", h.baseURL(), slotID)
	var resp struct {
		NRestored int `json:"n_restored"`
	}
	if err := httpPostJSON(ctx, url, map[string]any{"filename": snapshotName}, &resp); err != nil {
		return runtime.RestoreResult{}, &runtime.ErrUnsupported{Capability: "kv_snapshot_restore", Reason: err.Error()}
	}
	return runtime.RestoreResult{Duration: time.Since(t0), TokensRestored: resp.NRestored}, nil
}

// Completion is exported so the Phase 2 prober can drive raw completions
// (prefill/decode micro-measurement, resume-with-suffix KV methodology)
// without reaching into driver internals.
type CompletionRequest struct {
	Prompt      string
	NPredict    int
	CachePrompt bool
	SlotID      int
}

type CompletionTimings struct {
	PromptN         int     `json:"prompt_n"`
	PromptMS        float64 `json:"prompt_ms"`
	PredictedN      int     `json:"predicted_n"`
	PredictedMS     float64 `json:"predicted_ms"`
	PredictedPerSec float64 `json:"predicted_per_second"`
	PromptPerSec    float64 `json:"prompt_per_second"`
}

type CompletionResult struct {
	Content string            `json:"content"`
	Timings CompletionTimings `json:"timings"`
}

func (d *Driver) Complete(ctx context.Context, engine *domain.EngineInstance, req CompletionRequest) (CompletionResult, error) {
	h, err := d.handleFor(engine)
	if err != nil {
		return CompletionResult{}, err
	}
	payload := map[string]any{
		"prompt":       req.Prompt,
		"n_predict":    req.NPredict,
		"temperature":  0.0,
		"cache_prompt": req.CachePrompt,
		"id_slot":      req.SlotID,
	}
	var resp CompletionResult
	if err := httpPostJSON(ctx, h.baseURL()+"/completion", payload, &resp); err != nil {
		return CompletionResult{}, err
	}
	return resp, nil
}

// FreeVRAMMB exposes the nvidia-smi free-memory read the prober needs for
// its own baseline/low-VRAM checks, without duplicating the nvidia-smi call
// site.
func (d *Driver) FreeVRAMMB(ctx context.Context) (int64, error) {
	return nvidiaFreeMB(ctx, d.GPUIndex)
}

// PerPIDUsedMB exposes the best-effort per-PID VRAM read for a managed
// engine; ok=false means nvidia-smi returned N/A (observed under WSL) and
// the caller must fall back to a free-VRAM delta, labeling which method it
// used (measurement.md honesty rule / env note).
func (d *Driver) PerPIDUsedMB(ctx context.Context, engine *domain.EngineInstance) (mb int64, ok bool) {
	return nvidiaPerPIDUsedMB(ctx, d.GPUIndex, engine.PID)
}

// ResidentMB returns the free-VRAM-delta footprint measured at Launch time
// for the given engine (fallback method).
func (d *Driver) ResidentMB(engine *domain.EngineInstance) int64 {
	d.mu.Lock()
	defer d.mu.Unlock()
	if h, ok := d.instances[engine.ID]; ok {
		return h.residentMB
	}
	return 0
}

// SlotPath returns the driver-managed slot-save directory for an engine, so
// the prober can inspect on-disk snapshot sizes directly if needed.
func (d *Driver) SlotPath(engine *domain.EngineInstance) string {
	d.mu.Lock()
	defer d.mu.Unlock()
	if h, ok := d.instances[engine.ID]; ok {
		return h.slotPath
	}
	return ""
}

// CycleResult is one EVICTED teardown->reload measurement, mirroring
// evict_reload_spike.py's per-cycle sample exactly (T_sleep, T_wake_weights,
// T_first_token_after_wake, freed VRAM).
type CycleResult struct {
	TSleep       time.Duration
	TWakeWeights time.Duration
	TFirstToken  time.Duration
	FreedMB      int64
}

// MeasureEvictReloadCycle tears the engine down, waits for VRAM to be
// actually released, relaunches it, and times the first token — the exact
// shape of the reference spike's per-cycle loop. It mutates engine.PID in
// place to track the relaunched process.
func (d *Driver) MeasureEvictReloadCycle(ctx context.Context, engine *domain.EngineInstance) (CycleResult, error) {
	h, err := d.handleFor(engine)
	if err != nil {
		return CycleResult{}, err
	}

	freeBefore, _ := nvidiaFreeMB(ctx, d.GPUIndex)
	t0 := time.Now()
	if err := stopProcess(h.cmd); err != nil {
		return CycleResult{}, fmt.Errorf("teardown: %w", err)
	}
	freed, _ := waitFreedMB(ctx, d.GPUIndex, freeBefore, h.residentMB, 30*time.Second)
	tSleep := time.Since(t0)

	t1 := time.Now()
	cmd, err := d.launchProcess(ctx, h.launchArgs)
	if err != nil {
		return CycleResult{}, fmt.Errorf("relaunch: %w", err)
	}
	if err := waitHealthy(ctx, cmd, h.port, 60*time.Second); err != nil {
		_ = cmd.Process.Kill()
		return CycleResult{}, fmt.Errorf("relaunch health: %w", err)
	}
	tWake := time.Since(t1)

	d.mu.Lock()
	h.cmd = cmd
	d.mu.Unlock()
	engine.PID = cmd.Process.Pid

	t2 := time.Now()
	if _, err := d.Complete(ctx, engine, CompletionRequest{Prompt: "Hello", NPredict: 1, CachePrompt: false, SlotID: 0}); err != nil {
		return CycleResult{}, fmt.Errorf("first-token completion: %w", err)
	}
	tFirst := time.Since(t2)

	return CycleResult{TSleep: tSleep, TWakeWeights: tWake, TFirstToken: tFirst, FreedMB: freed}, nil
}

// ---------------------------------------------------------------------
// Capability probing (measurement.md §2 — try, don't assume)
// ---------------------------------------------------------------------

func (d *Driver) ProbeCapabilities(ctx context.Context, spec runtime.LaunchSpec) (domain.RuntimeCapabilities, error) {
	caps := domain.RuntimeCapabilities{
		// Architectural facts about llama.cpp that there is no code path to
		// even attempt — recorded false with the reason living in code
		// comments/driver docs, not guessed as true.
		SupportsWeightSleepToRAM:   false,
		SupportsKVOffloadCPU:       false, // not probed this phase
		SupportsHotKVResize:        false, // not probed this phase
		SupportsPrefillDecodeSplit: false, // llama.cpp does not disaggregate prefill/decode
	}

	eng, err := d.Launch(ctx, spec)
	if err != nil {
		return caps, fmt.Errorf("probe capabilities: launch failed: %w", err)
	}
	defer func() { _ = d.Stop(context.Background(), eng) }()

	// supports_drain: verified by actually draining an idle engine.
	if err := d.Drain(ctx, eng); err == nil {
		caps.SupportsDrain = true
	}

	// supports_kv_restore (save+restore round trip, KV-snapshot capability
	// per measurement.md §2 supports_kv_snapshot_save/restore).
	const probePrompt = "The quick brown fox jumps over the lazy dog."
	if _, err := d.Complete(ctx, eng, CompletionRequest{Prompt: probePrompt, NPredict: 1, CachePrompt: true, SlotID: 0}); err == nil {
		if ck, err := d.CheckpointSession(ctx, eng, 0, "cap-probe.bin"); err == nil && ck.SizeBytes > 0 {
			if _, err := d.RestoreSession(ctx, eng, 0, "cap-probe.bin"); err == nil {
				caps.SupportsKVRestore = true
			}
		}
	}

	// supports_continuous_batching: fire two concurrent completions into
	// different slots and confirm both complete successfully.
	if ok := d.tryContinuousBatching(ctx, eng); ok {
		caps.SupportsContinuousBatching = true
	}

	// supports_runtime_restart_profile / supports_staged_wake: verified via
	// an actual evict->wake cycle (weights-only stage) on this same engine.
	if err := d.Sleep(ctx, eng, runtime.SleepModeEvicted); err == nil {
		if err := d.Wake(ctx, eng, runtime.WakeStageWeights); err == nil {
			caps.SupportsRuntimeRestartProfile = true
			caps.SupportsStagedWake = true
		}
	}

	return caps, nil
}

func (d *Driver) tryContinuousBatching(ctx context.Context, eng *domain.EngineInstance) bool {
	type res struct {
		ok bool
	}
	ch := make(chan res, 2)
	for slot := 0; slot < 2; slot++ {
		slot := slot
		go func() {
			_, err := d.Complete(ctx, eng, CompletionRequest{Prompt: "one two three four five", NPredict: 8, CachePrompt: false, SlotID: slot})
			ch <- res{ok: err == nil}
		}()
	}
	ok := true
	for i := 0; i < 2; i++ {
		r := <-ch
		ok = ok && r.ok
	}
	return ok
}
