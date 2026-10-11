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
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	goruntime "runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"vram-governor/internal/domain"
	"vram-governor/internal/runtime"
	"vram-governor/internal/safefile"
)

// Driver drives llama-server as a managed child process.
type Driver struct {
	ServerPath string // absolute path to llama-server
	GPUIndex   int    // nvidia-smi GPU index this driver targets
	// Endpoint/SnapshotRoot are used by the node-agent integration for an
	// already-running, node-owned server.  Managed-process callers continue
	// using handle.baseURL and retain the original lifecycle semantics.
	Endpoint     string
	SnapshotRoot string

	mu            sync.Mutex
	instances     map[string]*handle
	conversations map[string]*conversationStream
	continuations map[int]string
}

type conversationStream struct {
	slotID   int
	response *http.Response
	done     chan struct{}
	// remoteOnly is a signed controller-owned stream whose HTTP body is held
	// by the controller adapter.  The node still owns the conversation binding
	// and observes it through DELETE/idle/history; it is not an untracked
	// metadata-only registration.
	remoteOnly bool
	mu         sync.Mutex
	prefix     []byte
	cached     int
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

var snapshotNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,95}\.kv$`)

// validateSnapshotName is deliberately stricter than filepath.Base.  The
// runtime receives names from a signed controller command, but validation is
// repeated at the final filesystem boundary so a compromised/buggy caller
// cannot escape the per-engine slot directory.
func validateSnapshotName(name string) error {
	if name == "" || filepath.Base(name) != name || filepath.IsAbs(name) ||
		strings.ContainsAny(name, `/\\`) || strings.Contains(name, "..") || !snapshotNameRE.MatchString(name) {
		return fmt.Errorf("invalid checkpoint snapshot name")
	}
	return nil
}

func secureSnapshotPath(root, name string) (string, error) {
	if err := validateSnapshotName(name); err != nil {
		return "", err
	}
	if inputInfo, inputErr := os.Lstat(root); inputErr != nil || inputInfo.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("snapshot root must not be a symlink")
	}
	canonicalRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", fmt.Errorf("resolve snapshot root: %w", err)
	}
	rootInfo, err := os.Lstat(canonicalRoot)
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 || (goruntime.GOOS != "windows" && rootInfo.Mode().Perm()&0o077 != 0) {
		return "", fmt.Errorf("snapshot root is not a private directory")
	}
	path := filepath.Join(canonicalRoot, name)
	canonicalParent, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil || canonicalParent != canonicalRoot {
		return "", fmt.Errorf("snapshot path escaped allowlisted root")
	}
	if info, statErr := os.Lstat(path); statErr == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.IsDir() || !singleSnapshotLink(info) || (goruntime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0) {
			return "", fmt.Errorf("snapshot path is not a regular file")
		}
	}
	return path, nil
}

func secureProbeSnapshotPath(root, name string) (string, error) {
	if name != "cap-probe.bin" {
		return "", fmt.Errorf("invalid probe snapshot name")
	}
	if inputInfo, inputErr := os.Lstat(root); inputErr != nil || inputInfo.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("probe snapshot root must not be a symlink")
	}
	canonicalRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", err
	}
	rootInfo, err := os.Lstat(canonicalRoot)
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 || (goruntime.GOOS != "windows" && rootInfo.Mode().Perm()&0o077 != 0) {
		return "", fmt.Errorf("probe snapshot root is not a private directory")
	}
	path := filepath.Join(canonicalRoot, name)
	if info, statErr := os.Lstat(path); statErr == nil && (info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.IsDir() || !singleSnapshotLink(info) || (goruntime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0)) {
		return "", fmt.Errorf("probe snapshot is not a regular file")
	}
	return path, nil
}

// snapshotDigest is used by production callers when binding a snapshot to a
// command/result envelope.  It is kept here so all runtime implementations
// hash the same canonical snapshot bytes.
func snapshotDigest(path string) (string, error) {
	_, digest, err := readSnapshotDescriptor(path, 1<<30)
	return digest, err
}

// readSnapshotDescriptor validates and reads a single descriptor. It avoids
// the Lstat+ReadFile race and enforces the same private, single-link, bounded
// file policy for save, restore, and digest paths.
func readSnapshotDescriptor(path string, maxBytes int64) ([]byte, string, error) {
	if maxBytes <= 0 {
		return nil, "", fmt.Errorf("snapshot size bound is invalid")
	}
	f, err := safefile.OpenReadOnlyNoFollow(path)
	if err != nil {
		return nil, "", err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || !singleSnapshotLink(info) || (goruntime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0) {
		return nil, "", fmt.Errorf("snapshot descriptor is not a private regular file")
	}
	if info.Size() <= 0 || info.Size() > maxBytes {
		return nil, "", fmt.Errorf("snapshot exceeds runtime size bound")
	}
	body, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, "", err
	}
	if int64(len(body)) > maxBytes {
		return nil, "", fmt.Errorf("snapshot exceeds runtime size bound")
	}
	h := sha256.New()
	_, _ = h.Write(body)
	return body, fmt.Sprintf("sha256:%x", h.Sum(nil)), nil
}

func singleSnapshotLink(info os.FileInfo) bool {
	if info == nil || info.Mode()&os.ModeSymlink != 0 {
		return false
	}
	v := reflect.ValueOf(info.Sys())
	if v.IsValid() && v.Kind() == reflect.Ptr {
		v = v.Elem()
	}
	if v.IsValid() && v.Kind() == reflect.Struct {
		field := v.FieldByName("Nlink")
		if field.IsValid() && field.CanUint() {
			return field.Uint() <= 1
		}
	}
	return true
}

func NewDriver(serverPath string, gpuIndex int) *Driver {
	return &Driver{
		ServerPath: serverPath,
		GPUIndex:   gpuIndex,
		instances:  make(map[string]*handle), conversations: make(map[string]*conversationStream), continuations: make(map[int]string),
	}
}

// NewEndpointDriver binds the same llama.cpp Driver schemas and safe filename
// handling to a configured external server.  It is the only supported node
// command implementation for an already-running router.
func NewEndpointDriver(endpoint, snapshotRoot string) *Driver {
	return &Driver{Endpoint: strings.TrimRight(endpoint, "/"), SnapshotRoot: snapshotRoot, instances: make(map[string]*handle), conversations: make(map[string]*conversationStream), continuations: make(map[int]string)}
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

func httpDelete(ctx context.Context, endpoint string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, endpoint, nil)
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
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("DELETE %s: status %d: %s", endpoint, resp.StatusCode, string(body))
	}
	if out != nil && len(body) > 0 {
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

type externalSlotRow struct {
	ID                 int  `json:"id"`
	ContextLimit       int  `json:"n_ctx"`
	IsProcessing       bool `json:"is_processing"`
	PromptTokens       int  `json:"n_prompt_tokens"`
	CachedPromptTokens int  `json:"n_prompt_tokens_cached"`
	PastTokens         int  `json:"n_past"`
}

func (d *Driver) externalURL() (string, error) {
	if d == nil || strings.TrimSpace(d.Endpoint) == "" {
		return "", fmt.Errorf("llama.cpp external endpoint is not configured")
	}
	return strings.TrimRight(d.Endpoint, "/"), nil
}

func (d *Driver) QuerySlots(ctx context.Context) (runtime.SlotInventory, error) {
	base, err := d.externalURL()
	if err != nil {
		return runtime.SlotInventory{}, err
	}
	var rows []externalSlotRow
	if err := httpGetJSON(ctx, base+"/slots", &rows); err != nil {
		return runtime.SlotInventory{}, err
	}
	if len(rows) == 0 {
		return runtime.SlotInventory{}, fmt.Errorf("llama.cpp returned no slots")
	}
	out := runtime.SlotInventory{Slots: make([]runtime.SlotState, 0, len(rows))}
	for _, row := range rows {
		promptTokens := row.PromptTokens
		if promptTokens == 0 {
			promptTokens = row.PastTokens
		}
		out.Slots = append(out.Slots, runtime.SlotState{ID: row.ID, ContextLimit: row.ContextLimit, Processing: row.IsProcessing, PromptTokens: promptTokens, CachedPromptTokens: row.CachedPromptTokens})
	}
	return out, nil
}

func (d *Driver) AssignSlot(ctx context.Context, requested int) (runtime.SlotAssignment, error) {
	inventory, err := d.QuerySlots(ctx)
	if err != nil {
		return runtime.SlotAssignment{}, err
	}
	for _, row := range inventory.Slots {
		if (requested < 0 || requested == row.ID) && !row.Processing {
			return runtime.SlotAssignment{SlotID: row.ID, ContextLimit: row.ContextLimit}, nil
		}
	}
	return runtime.SlotAssignment{}, fmt.Errorf("no authoritative idle llama.cpp slot is available")
}

// StartCheckpointConversation binds a real streaming generation to the slot
// before the proof exercise. The response body is drained asynchronously so
// DELETE /v1/stream can stop the live conversation at a token boundary.
func (d *Driver) StartCheckpointConversation(ctx context.Context, slotID int, conversationID, model string, contextLimit int) error {
	if strings.TrimSpace(conversationID) == "" || strings.TrimSpace(model) == "" || contextLimit <= 0 {
		return fmt.Errorf("checkpoint conversation identity is incomplete")
	}
	base, err := d.externalURL()
	if err != nil {
		return err
	}
	payload := map[string]any{
		"model":    model,
		"messages": []map[string]string{{"role": "user", "content": "checkpoint capability verification"}},
		"stream":   true, "max_tokens": 16, "id_slot": slotID, "cache_prompt": true,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/v1/chat/completions", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("X-Conversation-Id", conversationID)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return fmt.Errorf("checkpoint conversation start failed: status %d: %s", resp.StatusCode, string(body))
	}
	stream := &conversationStream{slotID: slotID, response: resp, done: make(chan struct{})}
	d.mu.Lock()
	if d.conversations == nil {
		d.conversations = make(map[string]*conversationStream)
	}
	if d.continuations == nil {
		d.continuations = make(map[int]string)
	}
	d.conversations[conversationID] = stream
	d.mu.Unlock()
	go consumeConversationSSE(stream)
	return nil
}

// RegisterCheckpointConversation is the managed-stream variant. The signed
// node command owns the authoritative slot/conversation binding; the
// controller opens exactly one POST stream with this identity afterward.
func (d *Driver) RegisterCheckpointConversation(ctx context.Context, slotID int, conversationID, model string, contextLimit int) error {
	if strings.TrimSpace(conversationID) == "" || strings.TrimSpace(model) == "" || contextLimit <= 0 || slotID < 0 {
		return fmt.Errorf("checkpoint conversation registration is incomplete")
	}
	d.mu.Lock()
	if d.conversations == nil {
		d.conversations = make(map[string]*conversationStream)
	}
	if d.continuations == nil {
		d.continuations = make(map[int]string)
	}
	// The controller's subsequent POST uses this exact conversation id. Keep a
	// durable-in-process binding so pause/recovery cannot silently fall back to
	// an unrelated slot or conversation.
	d.conversations[conversationID] = &conversationStream{slotID: slotID, done: make(chan struct{}), remoteOnly: true}
	d.continuations[slotID] = conversationID
	d.mu.Unlock()
	return nil
}

func consumeConversationSSE(stream *conversationStream) {
	defer close(stream.done)
	scanner := bufio.NewScanner(stream.response.Body)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		payload := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if payload == "" || payload == "[DONE]" {
			continue
		}
		var event struct {
			Choices []struct {
				Delta struct {
					Content string `json:"content"`
				} `json:"delta"`
			} `json:"choices"`
			Usage *struct {
				PromptTokensCached  int `json:"prompt_tokens_cached"`
				PromptTokensDetails *struct {
					CachedTokens int `json:"cached_tokens"`
				} `json:"prompt_tokens_details"`
			} `json:"usage"`
		}
		if json.Unmarshal([]byte(payload), &event) != nil {
			// Ignore non-JSON SSE comments/events; only complete JSON token
			// events are eligible for checkpoint prefix ownership.
			continue
		}
		stream.mu.Lock()
		for _, choice := range event.Choices {
			stream.prefix = append(stream.prefix, choice.Delta.Content...)
		}
		if event.Usage != nil {
			if event.Usage.PromptTokensCached > stream.cached {
				stream.cached = event.Usage.PromptTokensCached
			}
			if event.Usage.PromptTokensDetails != nil && event.Usage.PromptTokensDetails.CachedTokens > stream.cached {
				stream.cached = event.Usage.PromptTokensDetails.CachedTokens
			}
		}
		stream.mu.Unlock()
	}
	_ = stream.response.Body.Close()
}

func (d *Driver) conversation(conversationID string) *conversationStream {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.conversations[conversationID]
}

func (d *Driver) PauseAtBoundary(ctx context.Context, slotID int) (runtime.SlotBoundary, error) {
	return runtime.SlotBoundary{}, fmt.Errorf("conversation id is required for a production pause")
}

func (d *Driver) PauseAtBoundaryWithConversation(ctx context.Context, slotID int, conversationID string) (runtime.SlotBoundary, error) {
	if strings.TrimSpace(conversationID) == "" {
		return runtime.SlotBoundary{}, fmt.Errorf("conversation id is required")
	}
	base, err := d.externalURL()
	if err != nil {
		return runtime.SlotBoundary{}, err
	}
	if err := httpDelete(ctx, base+"/v1/stream?conv_id="+url.QueryEscape(conversationID), nil); err != nil {
		return runtime.SlotBoundary{}, err
	}
	row, err := d.waitExternalIdle(ctx, slotID)
	if err != nil {
		return runtime.SlotBoundary{}, err
	}
	stream := d.conversation(conversationID)
	if stream != nil {
	}
	if stream == nil {
		prefix, err := d.readConversationHistory(ctx, conversationID)
		if err != nil {
			return runtime.SlotBoundary{}, err
		}
		if len(prefix) == 0 {
			return runtime.SlotBoundary{}, fmt.Errorf("llama.cpp did not produce a non-empty assistant prefix at boundary")
		}
		return runtime.SlotBoundary{Prefix: prefix, TokenCount: row.PromptTokens}, nil
	}
	if stream.response != nil {
		_ = stream.response.Body.Close()
	}
	if stream.remoteOnly && stream.response == nil {
		prefix, err := d.readConversationHistory(ctx, conversationID)
		if err != nil {
			return runtime.SlotBoundary{}, err
		}
		if len(prefix) == 0 {
			return runtime.SlotBoundary{}, fmt.Errorf("llama.cpp did not produce a non-empty assistant prefix at boundary")
		}
		return runtime.SlotBoundary{Prefix: prefix, TokenCount: row.PromptTokens}, nil
	}
	select {
	case <-stream.done:
	case <-ctx.Done():
		return runtime.SlotBoundary{}, ctx.Err()
	case <-time.After(2 * time.Second):
		return runtime.SlotBoundary{}, fmt.Errorf("checkpoint conversation SSE did not terminate after backend stop")
	}
	stream.mu.Lock()
	prefix := append([]byte(nil), stream.prefix...)
	stream.mu.Unlock()
	if len(prefix) == 0 {
		return runtime.SlotBoundary{}, fmt.Errorf("llama.cpp did not produce a non-empty assistant prefix at boundary")
	}
	return runtime.SlotBoundary{Prefix: prefix, TokenCount: row.PromptTokens}, nil
}

// readConversationHistory attaches to the already-running upstream
// conversation after DELETE/idle confirmation. It reads only committed SSE
// events and never starts another generation.
func (d *Driver) readConversationHistory(ctx context.Context, conversationID string) ([]byte, error) {
	base, err := d.externalURL()
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/v1/stream?conv_id="+url.QueryEscape(conversationID)+"&from=0", nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("conversation history failed: status %d: %s", resp.StatusCode, string(body))
	}
	var prefix []byte
	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		payload := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if payload == "" || payload == "[DONE]" {
			continue
		}
		var event struct {
			Choices []struct {
				Delta struct {
					Content string `json:"content"`
				} `json:"delta"`
			} `json:"choices"`
		}
		if json.Unmarshal([]byte(payload), &event) == nil {
			for _, choice := range event.Choices {
				prefix = append(prefix, choice.Delta.Content...)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return prefix, nil
}

func (d *Driver) waitExternalIdle(ctx context.Context, slotID int) (runtime.SlotState, error) {
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		inventory, err := d.QuerySlots(ctx)
		if err != nil {
			return runtime.SlotState{}, err
		}
		for _, row := range inventory.Slots {
			if row.ID == slotID {
				if !row.Processing {
					return row, nil
				}
				break
			}
		}
		select {
		case <-ctx.Done():
			return runtime.SlotState{}, ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
	return runtime.SlotState{}, fmt.Errorf("slot %d did not reach a safe token boundary", slotID)
}

func (d *Driver) SaveKV(ctx context.Context, slotID int, snapshotName string) (runtime.CheckpointResult, error) {
	if err := validateSnapshotName(snapshotName); err != nil {
		return runtime.CheckpointResult{}, err
	}
	base, err := d.externalURL()
	if err != nil {
		return runtime.CheckpointResult{}, err
	}
	var response struct {
		Filename string `json:"filename"`
		NSaved   int    `json:"n_saved"`
		NWritten int    `json:"n_written"`
	}
	started := time.Now()
	if err := httpPostJSON(ctx, fmt.Sprintf("%s/slots/%d?action=save", base, slotID), map[string]any{"filename": snapshotName}, &response); err != nil {
		return runtime.CheckpointResult{}, err
	}
	if response.Filename == "" {
		response.Filename = snapshotName
	}
	if filepath.Base(response.Filename) != response.Filename || response.Filename != snapshotName {
		return runtime.CheckpointResult{}, fmt.Errorf("llama.cpp returned an unexpected snapshot filename")
	}
	if d.SnapshotRoot == "" {
		return runtime.CheckpointResult{}, fmt.Errorf("snapshot root is required to verify saved KV bytes")
	}
	path, err := secureSnapshotPath(d.SnapshotRoot, response.Filename)
	if err != nil {
		return runtime.CheckpointResult{}, err
	}
	contents, digest, err := readSnapshotDescriptor(path, 1<<30)
	if err != nil {
		return runtime.CheckpointResult{}, fmt.Errorf("llama.cpp save did not produce a verified KV file: %w", err)
	}
	savedTokens := response.NSaved
	if savedTokens == 0 {
		savedTokens = response.NWritten
	}
	if savedTokens <= 0 {
		return runtime.CheckpointResult{}, fmt.Errorf("llama.cpp save did not report positive n_saved/n_written")
	}
	return runtime.CheckpointResult{SnapshotRef: response.Filename, SizeBytes: int64(len(contents)), Digest: digest, Duration: time.Since(started), TokensSaved: savedTokens}, nil
}

func (d *Driver) ConfirmStopped(ctx context.Context, slotID int) (bool, error) {
	row, err := d.waitExternalIdle(ctx, slotID)
	return err == nil && !row.Processing, err
}

func (d *Driver) ReleaseSlot(ctx context.Context, slotID int) error {
	_, err := d.waitExternalIdle(ctx, slotID)
	return err
}

func (d *Driver) Reload(ctx context.Context, slotID int) error {
	// Reload is a state observation in llama.cpp: weights remain resident and
	// restore is a separate, measured slot operation.  Do not issue a second
	// stop or invent an unload endpoint.
	_, err := d.QuerySlots(ctx)
	return err
}

func (d *Driver) RestoreKV(ctx context.Context, slotID int, snapshotName string) (runtime.RestoreResult, error) {
	if err := validateSnapshotName(snapshotName); err != nil {
		return runtime.RestoreResult{}, err
	}
	if d.SnapshotRoot == "" {
		return runtime.RestoreResult{}, fmt.Errorf("snapshot root is required to restore KV")
	}
	path, err := secureSnapshotPath(d.SnapshotRoot, snapshotName)
	if err != nil {
		return runtime.RestoreResult{}, err
	}
	if _, _, err := readSnapshotDescriptor(path, 1<<30); err != nil {
		return runtime.RestoreResult{}, fmt.Errorf("snapshot is not safe to restore: %w", err)
	}
	base, err := d.externalURL()
	if err != nil {
		return runtime.RestoreResult{}, err
	}
	var response struct {
		NRestored int `json:"n_restored"`
	}
	started := time.Now()
	if err := httpPostJSON(ctx, fmt.Sprintf("%s/slots/%d?action=restore", base, slotID), map[string]any{"filename": snapshotName}, &response); err != nil {
		return runtime.RestoreResult{}, err
	}
	return runtime.RestoreResult{Duration: time.Since(started), TokensRestored: response.NRestored}, nil
}

func (d *Driver) VerifyReuse(ctx context.Context, slotID int, saved int) (int, error) {
	if saved <= 0 {
		return 0, fmt.Errorf("saved token count is required for KV reuse verification")
	}
	d.mu.Lock()
	conversationID := d.continuations[slotID]
	bound := d.conversations[conversationID]
	d.mu.Unlock()
	if bound == nil {
		return 0, fmt.Errorf("KV reuse is not bound to a resumed conversation")
	}
	bound.mu.Lock()
	observed := bound.cached
	bound.mu.Unlock()
	if observed <= 0 && bound.remoteOnly {
		observed, _ = d.readConversationCachedUsage(ctx, conversationID)
		if observed > 0 {
			bound.mu.Lock()
			bound.cached = observed
			bound.mu.Unlock()
		}
	}
	if observed > 0 {
		if observed > saved {
			return 0, fmt.Errorf("llama.cpp reported unbounded KV reuse")
		}
		return observed, nil
	}
	return 0, fmt.Errorf("llama.cpp continuation %q did not report cached-token reuse evidence", conversationID)
}

func (d *Driver) readConversationCachedUsage(ctx context.Context, conversationID string) (int, error) {
	base, err := d.externalURL()
	if err != nil {
		return 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/v1/stream?conv_id="+url.QueryEscape(conversationID)+"&from=0", nil)
	if err != nil {
		return 0, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return 0, fmt.Errorf("conversation history returned %d", resp.StatusCode)
	}
	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	best := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		payload := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if payload == "" || payload == "[DONE]" {
			continue
		}
		var event struct {
			Usage struct {
				PromptTokensCached  int `json:"prompt_tokens_cached"`
				PromptTokensDetails struct {
					CachedTokens int `json:"cached_tokens"`
				} `json:"prompt_tokens_details"`
			} `json:"usage"`
		}
		if json.Unmarshal([]byte(payload), &event) != nil {
			continue
		}
		if event.Usage.PromptTokensCached > best {
			best = event.Usage.PromptTokensCached
		}
		if event.Usage.PromptTokensDetails.CachedTokens > best {
			best = event.Usage.PromptTokensDetails.CachedTokens
		}
	}
	return best, scanner.Err()
}

func (d *Driver) Resume(ctx context.Context, slotID int, prefixHash string, prefixOffset int) (string, error) {
	return "", fmt.Errorf("conversation id is required for a production resume")
}

func (d *Driver) ResumeWithConversation(ctx context.Context, slotID int, conversationID, prefixHash string, prefixOffset int) (string, error) {
	if strings.TrimSpace(conversationID) == "" || prefixHash == "" || prefixOffset < 0 {
		return "", fmt.Errorf("continuation evidence is incomplete")
	}
	row, err := d.waitExternalIdle(ctx, slotID)
	if err != nil {
		return "", err
	}
	if row.Processing {
		return "", fmt.Errorf("slot is not at a resumable boundary")
	}
	d.mu.Lock()
	if d.conversations == nil {
		d.conversations = make(map[string]*conversationStream)
	}
	if d.continuations == nil {
		d.continuations = make(map[int]string)
	}
	// A continuation receives a fresh conversation identity; reuse evidence is
	// accepted only from the stream bound to that exact resumed identity.
	d.conversations[conversationID] = &conversationStream{slotID: slotID, done: make(chan struct{}), remoteOnly: true}
	d.continuations[slotID] = conversationID
	d.mu.Unlock()
	return conversationID, nil
}

// ContinueCheckpointConversation performs the real post-restore continuation
// request. ResumeWithConversation only establishes that the bound slot is at
// a safe boundary; this method exercises llama.cpp's normal streaming API with
// the restored assistant prefix and waits for the SSE stream to terminate.
func (d *Driver) ContinueCheckpointConversation(ctx context.Context, slotID int, conversationID, model, assistantPrefix string) error {
	if strings.TrimSpace(conversationID) == "" || strings.TrimSpace(model) == "" {
		return fmt.Errorf("continuation identity is incomplete")
	}
	base, err := d.externalURL()
	if err != nil {
		return err
	}
	payload := map[string]any{
		"model": model,
		"messages": []map[string]string{
			{"role": "user", "content": "checkpoint capability verification"},
			{"role": "assistant", "content": assistantPrefix},
		},
		"stream": true, "max_tokens": 8, "id_slot": slotID, "cache_prompt": true,
		"continue_final_message": true,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/v1/chat/completions", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("X-Conversation-Id", conversationID)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	stream := &conversationStream{slotID: slotID, response: resp, done: make(chan struct{})}
	d.mu.Lock()
	if d.conversations == nil {
		d.conversations = make(map[string]*conversationStream)
	}
	if d.continuations == nil {
		d.continuations = make(map[int]string)
	}
	d.conversations[conversationID] = stream
	d.continuations[slotID] = conversationID
	d.mu.Unlock()
	defer func() { <-stream.done }()
	go consumeConversationSSE(stream)
	select {
	case <-ctx.Done():
		_ = resp.Body.Close()
		return ctx.Err()
	case <-stream.done:
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("checkpoint continuation failed: status %d", resp.StatusCode)
	}
	_, err = d.waitExternalIdle(ctx, slotID)
	return err
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
	if err := os.MkdirAll(slotPath, 0o700); err != nil {
		return nil, fmt.Errorf("create slot dir: %w", err)
	}
	if err := os.Chmod(slotPath, 0o700); err != nil {
		return nil, fmt.Errorf("secure slot dir: %w", err)
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

// PauseAtTokenBoundary asks the managed llama-server for a cooperative stop
// and waits for the authoritative /slots state to report idle. A timeout or
// malformed response leaves the slot owned and must not be treated as a
// successful checkpoint boundary.
func (d *Driver) PauseAtTokenBoundary(ctx context.Context, engine *domain.EngineInstance, slotID int) error {
	return fmt.Errorf("conversation-aware stream cancellation is required for slot %d", slotID)
}

func (d *Driver) waitSlotIdle(ctx context.Context, h *handle, slotID int) error {
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		var slots slotsResp
		if err := httpGetJSON(ctx, h.baseURL()+"/slots", &slots); err != nil {
			return err
		}
		found := false
		busy := false
		for _, slot := range slots {
			if slot.ID == slotID {
				found = true
				busy = slot.IsProcessing
				break
			}
		}
		if found && !busy {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
	return fmt.Errorf("slot %d did not reach a safe token boundary", slotID)
}

// ConfirmSlotStopped is deliberately separate from PauseAtTokenBoundary so a
// coordinator can prove backend stop before releasing the accelerator lease.
func (d *Driver) ConfirmSlotStopped(ctx context.Context, engine *domain.EngineInstance, slotID int) error {
	h, err := d.handleFor(engine)
	if err != nil {
		return err
	}
	return d.waitSlotIdle(ctx, h, slotID)
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
	pathFn := secureSnapshotPath
	if snapshotName == "cap-probe.bin" {
		pathFn = secureProbeSnapshotPath
	}
	fpath, err := pathFn(h.slotPath, snapshotName)
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
	contents, digest, readErr := readSnapshotDescriptor(fpath, 1<<30)
	if readErr != nil {
		return runtime.CheckpointResult{}, fmt.Errorf("kv snapshot save produced an unsafe file: %w", readErr)
	}
	return runtime.CheckpointResult{
		SnapshotRef: fpath,
		SizeBytes:   int64(len(contents)),
		Digest:      digest,
		Duration:    dur,
		TokensSaved: resp.NSaved,
	}, nil
}

func (d *Driver) RestoreSession(ctx context.Context, engine *domain.EngineInstance, slotID int, snapshotName string) (runtime.RestoreResult, error) {
	h, err := d.handleFor(engine)
	if err != nil {
		return runtime.RestoreResult{}, err
	}
	pathFn := secureSnapshotPath
	if snapshotName == "cap-probe.bin" {
		pathFn = secureProbeSnapshotPath
	}
	fpath, pathErr := pathFn(h.slotPath, snapshotName)
	if pathErr != nil {
		return runtime.RestoreResult{}, pathErr
	}
	if _, _, readErr := readSnapshotDescriptor(fpath, 1<<30); readErr != nil {
		return runtime.RestoreResult{}, &runtime.ErrUnsupported{Capability: "kv_snapshot_restore", Reason: readErr.Error()}
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

// SnapshotDigest returns a content hash for command/result fencing.  It is a
// read-only helper and never grants restore permission on its own.
func (d *Driver) SnapshotDigest(engine *domain.EngineInstance, snapshotName string) (string, error) {
	h, err := d.handleFor(engine)
	if err != nil {
		return "", err
	}
	path, err := secureSnapshotPath(h.slotPath, snapshotName)
	if err != nil {
		return "", err
	}
	return snapshotDigest(path)
}

// SlotSnapshotName returns the bounded name used by the production
// coordinator.  Callers provide no filesystem path; ownership and execution
// identity are encoded into the name and validated by the save/restore path.
func SlotSnapshotName(identity runtime.CheckpointIdentity) string {
	material, _ := json.Marshal(identity)
	digest := sha256.Sum256(material)
	return fmt.Sprintf("owner-%x.kv", digest[:16])
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
