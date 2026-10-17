// Package comfyharness provides a restricted cooperative execution wrapper
// around an existing ComfyUI instance. It schedules only submitted Comfy JSON
// chunks and exposes no shell, installation, or model-management capability.
package comfyharness

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const ProtocolVersion = "managed-comfy/v1"
const defaultMaxStateBytes int64 = 64 << 20
const restartRecoveryError = "restart custody unknown; reconcile before retry"
const comfyDiscoveryTimeout = 5 * time.Second
const maxObjectInfoBytes int64 = 64 << 20
const maxSystemStatsBytes int64 = 1 << 20

type Options struct {
	ComfyURL        string
	Authorization   string
	StateDirectory  string
	Client          *http.Client
	PollInterval    time.Duration
	StopTimeout     time.Duration
	MaxRequestBytes int64
	MaxStateBytes   int64
	writeState      func(string, []byte) error
}

type Server struct {
	mu          sync.Mutex
	options     Options
	executions  map[string]*execution
	idempotency map[string]string
	runtimes    map[string]*runtimeState
	// activeRuns counts this process's live run goroutines per execution; a
	// submission can only still be in flight while one is active.
	activeRuns map[string]int
	writeState func(string, []byte) error
	lockFile   *os.File
	wg         sync.WaitGroup
	closeOnce  sync.Once
	closeErr   error
	closed     bool
}

type runtimeState struct {
	cancel  context.CancelFunc
	waiters []chan struct{}
	epoch   uint64
}

type execution struct {
	ID              string                     `json:"id"`
	WorkloadID      string                     `json:"workload_id"`
	IdempotencyKey  string                     `json:"idempotency_key"`
	PlanHash        string                     `json:"plan_hash,omitempty"`
	PayloadHash     string                     `json:"payload_hash"`
	Chunks          []chunk                    `json:"chunks"`
	NextChunk       int                        `json:"next_chunk"`
	CurrentPrompt   string                     `json:"current_prompt,omitempty"`
	SubmittingChunk string                     `json:"submitting_chunk,omitempty"`
	Submission      string                     `json:"submission,omitempty"`
	Epoch           uint64                     `json:"epoch"`
	State           string                     `json:"state"`
	Requested       string                     `json:"requested,omitempty"`
	CheckpointRef   string                     `json:"checkpoint_ref,omitempty"`
	CheckpointChunk int                        `json:"checkpoint_chunk,omitempty"`
	CheckpointEpoch uint64                     `json:"checkpoint_epoch,omitempty"`
	Histories       map[string]json.RawMessage `json:"histories,omitempty"`
	ArtifactRefs    []string                   `json:"artifact_refs,omitempty"`
	Error           string                     `json:"error,omitempty"`
	CreatedAt       time.Time                  `json:"created_at"`
	UpdatedAt       time.Time                  `json:"updated_at"`
}

type chunk struct {
	ID     string          `json:"id"`
	Prompt json.RawMessage `json:"prompt"`
}

type startRequest struct {
	ProtocolVersion string          `json:"protocol_version"`
	WorkloadID      string          `json:"workload_id"`
	IdempotencyKey  string          `json:"idempotency_key"`
	Payload         json.RawMessage `json:"payload"`
	PlanHash        string          `json:"plan_hash,omitempty"`
	CheckpointRef   string          `json:"checkpoint_ref,omitempty"`
}

type stateResponse struct {
	ProtocolVersion string                     `json:"protocol_version"`
	ExecutionID     string                     `json:"execution_id,omitempty"`
	State           string                     `json:"state"`
	CheckpointRef   string                     `json:"checkpoint_ref,omitempty"`
	Progress        float64                    `json:"progress,omitempty"`
	ProgressStage   string                     `json:"progress_stage,omitempty"`
	ProgressCurrent int                        `json:"progress_current,omitempty"`
	ProgressTotal   int                        `json:"progress_total,omitempty"`
	Error           string                     `json:"error,omitempty"`
	Output          map[string]json.RawMessage `json:"output,omitempty"`
	ArtifactRefs    []string                   `json:"artifact_refs,omitempty"`
}

type persistedState struct {
	Version    string       `json:"version"`
	Executions []*execution `json:"executions"`
}

type historyObservation struct {
	Record   json.RawMessage
	Present  bool
	Terminal bool
}

func New(options Options) (*Server, error) {
	parsed, err := url.Parse(options.ComfyURL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return nil, fmt.Errorf("ComfyURL must be an absolute HTTP or HTTPS URL")
	}
	if strings.TrimSpace(options.Authorization) == "" {
		return nil, fmt.Errorf("harness authorization is required")
	}
	if options.StateDirectory == "" {
		return nil, fmt.Errorf("state directory is required")
	}
	if options.Client == nil {
		options.Client = &http.Client{Timeout: 10 * time.Minute}
	}
	if options.PollInterval <= 0 {
		options.PollInterval = 500 * time.Millisecond
	}
	if options.StopTimeout <= 0 {
		options.StopTimeout = 20 * time.Second
	}
	if options.MaxRequestBytes <= 0 {
		options.MaxRequestBytes = 32 << 20
	}
	if options.MaxStateBytes <= 0 {
		options.MaxStateBytes = defaultMaxStateBytes
	}
	absolute, err := filepath.Abs(options.StateDirectory)
	if err != nil {
		return nil, fmt.Errorf("resolve state directory: %w", err)
	}
	if err := os.MkdirAll(absolute, 0o700); err != nil {
		return nil, fmt.Errorf("create state directory: %w", err)
	}
	info, err := os.Lstat(absolute)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return nil, fmt.Errorf("state directory must be a real directory")
	}
	canonical, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return nil, fmt.Errorf("resolve canonical state directory: %w", err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("state directory permissions must exclude group and other access")
	}
	options.StateDirectory = canonical
	writer := options.writeState
	if writer == nil {
		writer = durableWriteState
	}
	s := &Server{options: options, executions: make(map[string]*execution), idempotency: make(map[string]string), runtimes: make(map[string]*runtimeState), activeRuns: make(map[string]int), writeState: writer}
	lockPath := filepath.Join(canonical, "state.lock")
	lock, err := acquireStateLock(lockPath)
	if err != nil {
		return nil, fmt.Errorf("state directory is already owned by another harness process: %w", err)
	}
	s.lockFile = lock
	if err := s.load(); err != nil {
		_ = s.Close()
		return nil, err
	}
	return s, nil
}

// Close releases this process's exclusive state-directory ownership. Stop the
// HTTP server before closing the harness so no new operations race shutdown.
func (s *Server) Close() error {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		for _, runtime := range s.runtimes {
			if runtime.cancel != nil {
				runtime.cancel()
				runtime.cancel = nil
			}
		}
		s.mu.Unlock()
		s.wg.Wait()
		s.mu.Lock()
		lock := s.lockFile
		s.lockFile = nil
		s.mu.Unlock()
		if lock == nil {
			return
		}
		s.closeErr = releaseStateLock(lock)
	})
	return s.closeErr
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/executions", s.handleStart)
	mux.HandleFunc("GET /v1/executions/{id}", s.handleGet)
	mux.HandleFunc("POST /v1/executions/{id}/{operation}", s.handleControl)
	mux.HandleFunc("GET /v1/executions/{id}/outputs", s.handleOutputs)
	mux.HandleFunc("GET /object_info", s.handleDiscovery)
	mux.HandleFunc("GET /system_stats", s.handleDiscovery)
	mux.HandleFunc("POST /upload/image", s.handleProxy)
	mux.HandleFunc("GET /view", s.handleProxy)
	mux.HandleFunc("POST /v1/reclaim", s.handleReclaim)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != s.options.Authorization {
			writeState(w, http.StatusUnauthorized, stateResponse{State: "failed", Error: "unauthorized"})
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func (s *Server) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeDiscoveryError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery || r.ContentLength > 0 || len(r.TransferEncoding) != 0 || (r.Body != nil && r.Body != http.NoBody) {
		writeDiscoveryError(w, http.StatusBadRequest, "discovery requests must not include a query or body")
		return
	}

	limit := maxObjectInfoBytes
	if r.URL.Path == "/system_stats" {
		limit = maxSystemStatsBytes
	}
	ctx, cancel := context.WithTimeout(r.Context(), comfyDiscoveryTimeout)
	defer cancel()
	backendURL, err := s.discoveryURL(r.URL.Path)
	if err != nil {
		writeDiscoveryError(w, http.StatusBadGateway, "Comfy discovery unavailable")
		return
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, backendURL, nil)
	if err != nil {
		writeDiscoveryError(w, http.StatusBadGateway, "Comfy discovery unavailable")
		return
	}
	client := *s.options.Client
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := client.Do(request)
	if err != nil {
		writeDiscoveryError(w, http.StatusBadGateway, "Comfy discovery unavailable")
		return
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		writeDiscoveryError(w, http.StatusBadGateway, "Comfy discovery unavailable")
		return
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil || int64(len(body)) > limit || !validDiscoveryObject(body) {
		writeDiscoveryError(w, http.StatusBadGateway, "Comfy discovery returned an invalid response")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func (s *Server) discoveryURL(route string) (string, error) {
	backend, err := url.Parse(s.options.ComfyURL)
	if err != nil || backend.RawQuery != "" || backend.ForceQuery || backend.Fragment != "" || backend.User != nil {
		return "", fmt.Errorf("registered Comfy URL is not valid for discovery")
	}
	escapedPath := strings.TrimRight(backend.EscapedPath(), "/") + route
	decodedPath, err := url.PathUnescape(escapedPath)
	if err != nil {
		return "", fmt.Errorf("registered Comfy path is invalid")
	}
	backend.Path, backend.RawPath = decodedPath, escapedPath
	return backend.String(), nil
}

func validDiscoveryObject(body []byte) bool {
	if !utf8.Valid(body) {
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	var object map[string]json.RawMessage
	if err := decoder.Decode(&object); err != nil || object == nil {
		return false
	}
	var extra any
	return errors.Is(decoder.Decode(&extra), io.EOF)
}

func writeDiscoveryError(w http.ResponseWriter, status int, message string) {
	http.Error(w, message, status)
}

func (s *Server) handleStart(w http.ResponseWriter, r *http.Request) {
	var request startRequest
	if err := decodeStrict(w, r, s.options.MaxRequestBytes, &request); err != nil {
		writeState(w, http.StatusBadRequest, stateResponse{State: "failed", Error: err.Error()})
		return
	}
	if request.ProtocolVersion != ProtocolVersion || request.WorkloadID == "" || request.IdempotencyKey == "" || len(request.Payload) == 0 {
		writeState(w, http.StatusBadRequest, stateResponse{State: "failed", Error: "protocol_version, workload_id, idempotency_key, and payload are required"})
		return
	}
	chunks, err := parseChunks(request.Payload)
	if err != nil {
		writeState(w, http.StatusBadRequest, stateResponse{State: "failed", Error: err.Error()})
		return
	}
	payloadHash, err := hashChunks(chunks)
	if err != nil {
		writeState(w, http.StatusBadRequest, stateResponse{State: "failed", Error: "could not identify payload"})
		return
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		writeState(w, http.StatusServiceUnavailable, stateResponse{State: "failed", Error: "harness is shutting down"})
		return
	}
	if id := s.idempotency[request.IdempotencyKey]; id != "" {
		existing := s.executions[id]
		if existing == nil || existing.WorkloadID != request.WorkloadID || existing.PlanHash != request.PlanHash || existing.PayloadHash != payloadHash {
			s.mu.Unlock()
			writeState(w, http.StatusConflict, stateResponse{State: "failed", Error: "idempotency key conflicts with another execution"})
			return
		}
		if request.CheckpointRef != "" && request.CheckpointRef != existing.CheckpointRef {
			s.mu.Unlock()
			writeState(w, http.StatusConflict, stateResponse{State: "failed", Error: "checkpoint reference does not match durable execution"})
			return
		}
		if existing.State == "yielded" || existing.State == "checkpointed" {
			if request.CheckpointRef == "" || request.CheckpointRef != existing.CheckpointRef {
				s.mu.Unlock()
				writeState(w, http.StatusConflict, stateResponse{ExecutionID: existing.ID, State: existing.State, Error: "explicit fresh checkpoint_ref is required to resume"})
				return
			}
			before := cloneExecution(existing)
			existing.State, existing.Requested, existing.Error = "running", "", ""
			existing.Submission, existing.SubmittingChunk = "", ""
			existing.CheckpointRef, existing.CheckpointChunk, existing.CheckpointEpoch = "", 0, 0
			existing.Epoch++
			existing.UpdatedAt = time.Now().UTC()
			if err := s.persistLocked(); err != nil {
				*existing = *before
				s.mu.Unlock()
				writeState(w, http.StatusInternalServerError, stateResponse{State: "failed", Error: "persist resume state"})
				return
			}
			s.launchLocked(existing.ID, existing.Epoch)
		}
		response := s.responseLocked(existing, false)
		s.mu.Unlock()
		writeState(w, http.StatusOK, response)
		return
	}
	if request.CheckpointRef != "" {
		s.mu.Unlock()
		writeState(w, http.StatusConflict, stateResponse{State: "failed", Error: "checkpoint execution is unavailable"})
		return
	}
	now := time.Now().UTC()
	execution := &execution{ID: newID(), WorkloadID: request.WorkloadID, IdempotencyKey: request.IdempotencyKey, PlanHash: request.PlanHash, PayloadHash: payloadHash, Chunks: chunks, State: "running", Epoch: 1, Histories: make(map[string]json.RawMessage), CreatedAt: now, UpdatedAt: now}
	s.executions[execution.ID] = execution
	s.idempotency[request.IdempotencyKey] = execution.ID
	if err := s.persistLocked(); err != nil {
		delete(s.executions, execution.ID)
		delete(s.idempotency, request.IdempotencyKey)
		s.mu.Unlock()
		writeState(w, http.StatusInternalServerError, stateResponse{State: "failed", Error: "persist execution"})
		return
	}
	s.launchLocked(execution.ID, execution.Epoch)
	response := s.responseLocked(execution, false)
	s.mu.Unlock()
	writeState(w, http.StatusAccepted, response)
}

func (s *Server) handleGet(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	execution := s.executions[r.PathValue("id")]
	if execution == nil {
		writeState(w, http.StatusNotFound, stateResponse{State: "failed", Error: "execution not found"})
		return
	}
	writeState(w, http.StatusOK, s.responseLocked(execution, false))
}

func (s *Server) handleOutputs(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	execution := s.executions[r.PathValue("id")]
	if execution == nil {
		writeState(w, http.StatusNotFound, stateResponse{State: "failed", Error: "execution not found"})
		return
	}
	if execution.State != "completed" {
		writeState(w, http.StatusConflict, stateResponse{ExecutionID: execution.ID, State: execution.State, Error: "outputs are not terminal"})
		return
	}
	writeState(w, http.StatusOK, s.responseLocked(execution, true))
}

func (s *Server) handleControl(w http.ResponseWriter, r *http.Request) {
	id, operation := r.PathValue("id"), r.PathValue("operation")
	if operation != "yield" && operation != "checkpoint" && operation != "cancel" {
		writeState(w, http.StatusNotFound, stateResponse{State: "failed", Error: "unknown operation"})
		return
	}
	s.mu.Lock()
	execution := s.executions[id]
	if execution == nil {
		s.mu.Unlock()
		writeState(w, http.StatusNotFound, stateResponse{State: "failed", Error: "execution not found"})
		return
	}
	if operation == "cancel" {
		switch execution.State {
		case "cancelled", "completed", "failed", "yielded", "checkpointed":
			response := s.responseLocked(execution, false)
			s.mu.Unlock()
			writeState(w, http.StatusOK, response)
			return
		}
		if execution.Submission == "" && execution.CurrentPrompt == "" {
			execution.State, execution.Requested, execution.Error, execution.UpdatedAt = "cancelled", "", "", time.Now().UTC()
			execution.Epoch++
			if err := s.persistLocked(); err != nil {
				execution.State, execution.Error = "uncertain", "could not durably commit cancellation before the next submission"
				s.mu.Unlock()
				writeState(w, http.StatusInternalServerError, stateResponse{ExecutionID: id, State: execution.State, Error: execution.Error})
				return
			}
			if runtime := s.runtimes[id]; runtime != nil && runtime.cancel != nil {
				runtime.cancel()
				runtime.cancel = nil
			}
			s.notifyLocked(id)
			response := s.responseLocked(execution, false)
			s.mu.Unlock()
			writeState(w, http.StatusOK, response)
			return
		}
		if execution.Submission == "submitting" || execution.Submission == "unknown" || execution.CurrentPrompt == "" {
			if s.activeRuns[id] == 0 {
				// No run of this execution is live in this process, so any earlier
				// submission belonged to a dead incarnation and cannot still be in
				// flight. If Comfy is idle, whatever it submitted has ended: the
				// cancellation is provable rather than a guess.
				epoch := execution.Epoch
				s.mu.Unlock()
				idle, queueErr := s.comfyQueueIdle(r.Context())
				s.mu.Lock()
				execution = s.executions[id]
				if queueErr == nil && idle && execution != nil && execution.Epoch == epoch && s.activeRuns[id] == 0 && execution.State != "cancelled" && execution.State != "completed" && execution.State != "failed" {
					before := cloneExecution(execution)
					execution.State, execution.Requested, execution.Error, execution.UpdatedAt = "cancelled", "", "", time.Now().UTC()
					execution.Submission, execution.SubmittingChunk, execution.CurrentPrompt = "", "", ""
					execution.Epoch++
					if err := s.persistLocked(); err != nil {
						*execution = *before
						s.mu.Unlock()
						writeState(w, http.StatusInternalServerError, stateResponse{ExecutionID: id, State: execution.State, Error: "could not durably record proven cancellation"})
						return
					}
					s.notifyLocked(id)
					response := s.responseLocked(execution, false)
					s.mu.Unlock()
					writeState(w, http.StatusOK, response)
					return
				}
				if execution == nil {
					s.mu.Unlock()
					writeState(w, http.StatusNotFound, stateResponse{State: "failed", Error: "execution not found"})
					return
				}
			}
			execution.State, execution.Error, execution.UpdatedAt = "uncertain", "submission may have reached Comfy; exact prompt identity is unavailable", time.Now().UTC()
			execution.Epoch++
			if err := s.persistLocked(); err != nil {
				execution.State, execution.Error = "uncertain", "submission may have reached Comfy; cancellation state could not be durably recorded"
				s.mu.Unlock()
				writeState(w, http.StatusInternalServerError, stateResponse{ExecutionID: id, State: execution.State, Error: execution.Error})
				return
			}
			if runtime := s.runtimes[id]; runtime != nil && runtime.cancel != nil {
				runtime.cancel()
				runtime.cancel = nil
			}
			response := s.responseLocked(execution, false)
			s.mu.Unlock()
			writeState(w, http.StatusConflict, response)
			return
		}
		before := cloneExecution(execution)
		execution.State, execution.Requested, execution.UpdatedAt = "cancelling", "cancel", time.Now().UTC()
		execution.Epoch++
		epoch, currentPrompt := execution.Epoch, execution.CurrentPrompt
		if err := s.persistLocked(); err != nil {
			*execution = *before
			response := s.responseLocked(execution, false)
			s.mu.Unlock()
			writeState(w, http.StatusInternalServerError, stateResponse{ExecutionID: id, State: response.State, Error: "could not durably record cancellation intent"})
			return
		}
		if runtime := s.runtimes[id]; runtime != nil && runtime.cancel != nil {
			runtime.cancel()
			runtime.cancel = nil
		}
		s.mu.Unlock()
		if err := s.stopComfyPrompt(r.Context(), currentPrompt); err != nil {
			s.mu.Lock()
			if current := s.executions[id]; current != nil && current.Epoch == epoch && current.State == "cancelling" {
				current.State, current.Error, current.UpdatedAt = "uncertain", err.Error(), time.Now().UTC()
				if persistErr := s.persistLocked(); persistErr != nil {
					current.Error += "; cancellation outcome also could not be journaled"
				}
			}
			response := s.responseLocked(s.executions[id], false)
			s.mu.Unlock()
			writeState(w, http.StatusConflict, response)
			return
		}
		s.mu.Lock()
		execution = s.executions[id]
		if execution == nil || execution.Epoch != epoch || execution.State != "cancelling" {
			s.mu.Unlock()
			writeState(w, http.StatusConflict, stateResponse{ExecutionID: id, State: "uncertain", Error: "execution changed while cancellation was being confirmed"})
			return
		}
		before = cloneExecution(execution)
		execution.State, execution.Requested, execution.CurrentPrompt, execution.Submission, execution.SubmittingChunk, execution.Error, execution.UpdatedAt = "cancelled", "", "", "", "", "", time.Now().UTC()
		if err := s.persistLocked(); err != nil {
			*execution = *before
			s.mu.Unlock()
			writeState(w, http.StatusInternalServerError, stateResponse{ExecutionID: id, State: "cancelling", Error: "backend stop was observed but cancellation could not be durably committed"})
			return
		}
		s.notifyLocked(id)
		response := s.responseLocked(execution, false)
		s.mu.Unlock()
		writeState(w, http.StatusOK, response)
		return
	}
	if execution.State == operation+"ed" || (operation == "yield" && execution.State == "yielded") {
		response := s.responseLocked(execution, false)
		s.mu.Unlock()
		writeState(w, http.StatusOK, response)
		return
	}
	if execution.State != "running" {
		response := s.responseLocked(execution, false)
		s.mu.Unlock()
		writeState(w, http.StatusConflict, response)
		return
	}
	before := cloneExecution(execution)
	execution.Requested, execution.UpdatedAt = operation, time.Now().UTC()
	if err := s.persistLocked(); err != nil {
		*execution = *before
		response := s.responseLocked(execution, false)
		s.mu.Unlock()
		writeState(w, http.StatusInternalServerError, response)
		return
	}
	wait := make(chan struct{})
	runtime := s.runtimes[id]
	if runtime == nil {
		runtime = &runtimeState{}
		s.runtimes[id] = runtime
	}
	runtime.waiters = append(runtime.waiters, wait)
	s.mu.Unlock()
	select {
	case <-r.Context().Done():
		writeState(w, http.StatusRequestTimeout, stateResponse{ExecutionID: id, State: "running", Error: "safe boundary not reached before request deadline"})
		return
	case <-wait:
	}
	s.mu.Lock()
	execution = s.executions[id]
	response := s.responseLocked(execution, false)
	s.mu.Unlock()
	want := "yielded"
	if operation == "checkpoint" {
		want = "checkpointed"
	}
	if response.State != want {
		writeState(w, http.StatusConflict, response)
		return
	}
	writeState(w, http.StatusOK, response)
}

func (s *Server) launchLocked(id string, epoch uint64) {
	ctx, cancel := context.WithCancel(context.Background())
	runtime := s.runtimes[id]
	if runtime == nil {
		runtime = &runtimeState{}
		s.runtimes[id] = runtime
	}
	runtime.cancel = cancel
	runtime.epoch = epoch
	s.activeRuns[id]++
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer func() { s.mu.Lock(); s.activeRuns[id]--; s.mu.Unlock() }()
		s.run(ctx, id, epoch)
	}()
}

func (s *Server) run(ctx context.Context, id string, epoch uint64) {
	for {
		s.mu.Lock()
		execution := s.executions[id]
		if execution == nil || execution.State != "running" || execution.Epoch != epoch {
			s.mu.Unlock()
			return
		}
		if execution.NextChunk >= len(execution.Chunks) {
			before := cloneExecution(execution)
			execution.State, execution.UpdatedAt = "completed", time.Now().UTC()
			if err := s.persistLocked(); err != nil {
				*execution = *before
				execution.State, execution.Error, execution.UpdatedAt = "uncertain", "completion was observed but could not be durably committed", time.Now().UTC()
				_ = s.persistLocked()
				s.notifyLocked(id)
				s.mu.Unlock()
				return
			}
			s.notifyLocked(id)
			s.mu.Unlock()
			return
		}
		current := execution.Chunks[execution.NextChunk]
		if execution.Submission != "" || execution.CurrentPrompt != "" {
			execution.State, execution.Error, execution.UpdatedAt = "uncertain", "an earlier Comfy submission has unresolved custody; refusing to resubmit", time.Now().UTC()
			_ = s.persistLocked()
			s.notifyLocked(id)
			s.mu.Unlock()
			return
		}
		before := cloneExecution(execution)
		execution.SubmittingChunk, execution.Submission, execution.UpdatedAt = current.ID, "submitting", time.Now().UTC()
		if err := s.persistLocked(); err != nil {
			*execution = *before
			execution.State, execution.Error, execution.UpdatedAt = "uncertain", "could not durably record submission intent; no Comfy request was sent", time.Now().UTC()
			_ = s.persistLocked()
			s.notifyLocked(id)
			s.mu.Unlock()
			return
		}
		s.mu.Unlock()

		promptID, history, err := s.executeChunk(ctx, id, epoch, current)
		s.mu.Lock()
		execution = s.executions[id]
		if execution == nil || execution.Epoch != epoch {
			s.mu.Unlock()
			return
		}
		if execution.State != "running" {
			s.mu.Unlock()
			return
		}
		var failure *comfyChunkFailure
		if errors.As(err, &failure) {
			// Comfy itself reported the chunk finished with an error (or
			// rejected it before queueing), so nothing is still running.
			before := cloneExecution(execution)
			execution.State, execution.Error, execution.UpdatedAt = "failed", failure.Message, time.Now().UTC()
			execution.Submission, execution.SubmittingChunk, execution.CurrentPrompt = "", "", ""
			if persistErr := s.persistLocked(); persistErr != nil {
				*execution = *before
				execution.State, execution.Submission = "uncertain", "unknown"
				execution.Error, execution.UpdatedAt = failure.Message+"; durable state update failed", time.Now().UTC()
			}
			s.notifyLocked(id)
			s.mu.Unlock()
			return
		}
		if err != nil {
			before := cloneExecution(execution)
			execution.State, execution.Submission = "uncertain", "unknown"
			execution.Error, execution.UpdatedAt = err.Error(), time.Now().UTC()
			if persistErr := s.persistLocked(); persistErr != nil {
				*execution = *before
				execution.State, execution.Error, execution.UpdatedAt = "uncertain", err.Error()+"; durable state update failed", time.Now().UTC()
			}
			s.notifyLocked(id)
			s.mu.Unlock()
			return
		}
		before = cloneExecution(execution)
		execution.Histories[promptID] = history
		execution.NextChunk++
		execution.CurrentPrompt, execution.SubmittingChunk, execution.Submission = "", "", ""
		execution.UpdatedAt = time.Now().UTC()
		if execution.Requested == "checkpoint" || execution.Requested == "yield" {
			checkpointRef, checkpointErr := newCheckpointRef()
			if checkpointErr != nil {
				*execution = *before
				execution.State, execution.Error, execution.UpdatedAt = "uncertain", "safe boundary observed but a fresh checkpoint reference could not be generated", time.Now().UTC()
				_ = s.persistLocked()
				s.notifyLocked(id)
				s.mu.Unlock()
				return
			}
			execution.CheckpointRef, execution.CheckpointChunk, execution.CheckpointEpoch = checkpointRef, execution.NextChunk, execution.Epoch
			if execution.Requested == "checkpoint" {
				execution.State = "checkpointed"
			} else {
				execution.State = "yielded"
			}
			execution.Requested = ""
			if err := s.persistLocked(); err != nil {
				*execution = *before
				execution.State, execution.Error, execution.UpdatedAt = "uncertain", "chunk output was observed but checkpoint boundary could not be durably committed", time.Now().UTC()
				_ = s.persistLocked()
				s.notifyLocked(id)
				s.mu.Unlock()
				return
			}
			s.notifyLocked(id)
			s.mu.Unlock()
			return
		}
		if err := s.persistLocked(); err != nil {
			*execution = *before
			execution.State, execution.Error, execution.UpdatedAt = "uncertain", "chunk output was observed but could not be durably committed", time.Now().UTC()
			_ = s.persistLocked()
			s.notifyLocked(id)
			s.mu.Unlock()
			return
		}
		s.mu.Unlock()
	}
}

func (s *Server) executeChunk(ctx context.Context, executionID string, epoch uint64, current chunk) (string, json.RawMessage, error) {
	body, _ := json.Marshal(map[string]any{"prompt": current.Prompt, "client_id": "managed-" + executionID})
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(s.options.ComfyURL, "/")+"/prompt", bytes.NewReader(body))
	if err != nil {
		return "", nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := s.options.Client.Do(request)
	if err != nil {
		s.markSubmissionUnknown(executionID, epoch, err)
		return "", nil, err
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusBadRequest {
		if rejection, ok := comfyPromptRejection(response.Body); ok {
			return "", nil, &comfyChunkFailure{Message: rejection, NotQueued: true}
		}
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		err := fmt.Errorf("Comfy prompt returned HTTP %d; acceptance remains ambiguous", response.StatusCode)
		s.markSubmissionUnknown(executionID, epoch, err)
		return "", nil, err
	}
	acceptanceBody, readErr := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
	if readErr != nil || len(acceptanceBody) > 1<<20 {
		err := errors.New("Comfy prompt response is unreadable or too large; acceptance remains ambiguous")
		s.markSubmissionUnknown(executionID, epoch, err)
		return "", nil, err
	}
	var accepted struct {
		PromptID string `json:"prompt_id"`
	}
	acceptanceDecoder := json.NewDecoder(bytes.NewReader(acceptanceBody))
	var extra any
	if acceptanceDecoder.Decode(&accepted) != nil || accepted.PromptID == "" || acceptanceDecoder.Decode(&extra) != io.EOF {
		err := errors.New("Comfy accepted prompt without a usable prompt_id; submission outcome is ambiguous")
		s.markSubmissionUnknown(executionID, epoch, err)
		return "", nil, err
	}
	s.mu.Lock()
	if execution := s.executions[executionID]; execution != nil && execution.Epoch == epoch && execution.Submission == "submitting" && execution.SubmittingChunk == current.ID {
		before := cloneExecution(execution)
		execution.CurrentPrompt, execution.Submission, execution.UpdatedAt = accepted.PromptID, "accepted", time.Now().UTC()
		if persistErr := s.persistLocked(); persistErr != nil {
			*execution = *before
			execution.CurrentPrompt, execution.Submission, execution.State, execution.Error = accepted.PromptID, "unknown", "uncertain", "Comfy accepted prompt but exact prompt identity could not be durably recorded"
			_ = s.persistLocked()
			s.mu.Unlock()
			return accepted.PromptID, nil, errors.New("Comfy accepted prompt; prompt identity journal failed")
		}
	} else {
		// The attempt was fenced by a concurrent operation. Keep exact custody
		// when possible, but never let its result advance the newer state.
		if execution != nil && execution.SubmittingChunk == current.ID && execution.CurrentPrompt == "" {
			execution.CurrentPrompt, execution.Submission = accepted.PromptID, "unknown"
			execution.Error = "late Comfy acceptance recorded after operation fence; manual reconciliation required"
			_ = s.persistLocked()
		}
		s.mu.Unlock()
		return accepted.PromptID, nil, context.Canceled
	}
	s.mu.Unlock()
	ticker := time.NewTicker(s.options.PollInterval)
	defer ticker.Stop()
	for {
		observation, err := s.comfyHistory(ctx, accepted.PromptID)
		if err != nil {
			return accepted.PromptID, nil, err
		}
		if observation.Present && observation.Terminal {
			return accepted.PromptID, observation.Record, nil
		}
		select {
		case <-ctx.Done():
			return accepted.PromptID, nil, ctx.Err()
		case <-ticker.C:
		}
	}
}

func (s *Server) markSubmissionUnknown(id string, epoch uint64, cause error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if execution := s.executions[id]; execution != nil && execution.Epoch == epoch && execution.Submission == "submitting" {
		before := cloneExecution(execution)
		execution.State, execution.Submission, execution.Error, execution.UpdatedAt = "uncertain", "unknown", cause.Error(), time.Now().UTC()
		if err := s.persistLocked(); err != nil {
			*execution = *before
			execution.State, execution.Error = "uncertain", cause.Error()+"; durable ambiguity journal failed"
		}
	}
}

func (s *Server) comfyHistory(ctx context.Context, promptID string) (historyObservation, error) {
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(s.options.ComfyURL, "/")+"/history/"+url.PathEscape(promptID), nil)
	response, err := s.options.Client.Do(request)
	if err != nil {
		return historyObservation{}, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return historyObservation{}, fmt.Errorf("Comfy history returned %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, s.options.MaxStateBytes+1))
	if err != nil || int64(len(body)) > s.options.MaxStateBytes {
		return historyObservation{}, fmt.Errorf("Comfy history response is unreadable or too large")
	}
	var histories map[string]json.RawMessage
	decoder := json.NewDecoder(bytes.NewReader(body))
	if decoder.Decode(&histories) != nil || histories == nil {
		return historyObservation{}, fmt.Errorf("Comfy history returned invalid JSON")
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return historyObservation{}, fmt.Errorf("Comfy history returned trailing JSON")
	}
	history, done := histories[promptID]
	if !done {
		return historyObservation{}, nil
	}
	observation := historyObservation{Record: history, Present: true}
	var status struct {
		Status struct {
			StatusStr string `json:"status_str"`
			Completed *bool  `json:"completed"`
		} `json:"status"`
	}
	if json.Unmarshal(history, &status) != nil || status.Status.StatusStr == "" || status.Status.Completed == nil {
		return historyObservation{}, fmt.Errorf("Comfy history for exact prompt %s is malformed", promptID)
	}
	if strings.EqualFold(status.Status.StatusStr, "error") {
		// Comfy reports a prompt that failed in execution as status "error"
		// with completed=false; the execution_error message is what marks it
		// as finished. Either signal means nothing is still running.
		if *status.Status.Completed || comfyHistoryHasExecutionError(history) {
			observation.Terminal = true
			return observation, &comfyChunkFailure{Message: comfyExecutionErrorMessage(history, promptID)}
		}
		return observation, fmt.Errorf("Comfy chunk %s failed", promptID)
	}
	if !*status.Status.Completed {
		return observation, nil
	}
	if !strings.EqualFold(status.Status.StatusStr, "success") {
		return historyObservation{}, fmt.Errorf("Comfy history for exact prompt %s has unsupported status %q", promptID, status.Status.StatusStr)
	}
	observation.Terminal = true
	return observation, nil
}

// comfyChunkFailure is a definite outcome reported by Comfy itself: the
// prompt finished with an execution error, or /prompt rejected the graph
// before queueing it. Unlike transport or journal failures it leaves no work
// running, so the execution fails instead of becoming uncertain.
type comfyChunkFailure struct {
	Message   string
	NotQueued bool
}

func (f *comfyChunkFailure) Error() string { return f.Message }

func comfyHistoryHasExecutionError(history json.RawMessage) bool {
	var record struct {
		Status struct {
			Messages []json.RawMessage `json:"messages"`
		} `json:"status"`
	}
	if json.Unmarshal(history, &record) != nil {
		return false
	}
	for _, raw := range record.Status.Messages {
		var message []json.RawMessage
		var kind string
		if json.Unmarshal(raw, &message) == nil && len(message) == 2 && json.Unmarshal(message[0], &kind) == nil && kind == "execution_error" {
			return true
		}
	}
	return false
}

// comfyExecutionErrorMessage extracts node and exception from the history
// record's execution_error message, e.g. "SaveVideo (node 75): Invalid argument".
func comfyExecutionErrorMessage(history json.RawMessage, promptID string) string {
	var record struct {
		Status struct {
			Messages []json.RawMessage `json:"messages"`
		} `json:"status"`
	}
	if json.Unmarshal(history, &record) == nil {
		for _, raw := range record.Status.Messages {
			var message []json.RawMessage
			var kind string
			if json.Unmarshal(raw, &message) != nil || len(message) != 2 || json.Unmarshal(message[0], &kind) != nil || kind != "execution_error" {
				continue
			}
			var detail struct {
				NodeID           string `json:"node_id"`
				NodeType         string `json:"node_type"`
				ExceptionType    string `json:"exception_type"`
				ExceptionMessage string `json:"exception_message"`
			}
			if json.Unmarshal(message[1], &detail) == nil && detail.ExceptionMessage != "" {
				return truncateComfyMessage(fmt.Sprintf("Comfy execution error in %s (node %s): %s", detail.NodeType, detail.NodeID, strings.TrimSpace(detail.ExceptionMessage)))
			}
		}
	}
	return fmt.Sprintf("Comfy chunk %s failed", promptID)
}

// comfyPromptRejection recognizes Comfy's validation response to /prompt,
// {"error": {...}, "node_errors": {...}}; anything else stays ambiguous.
func comfyPromptRejection(body io.Reader) (string, bool) {
	raw, err := io.ReadAll(io.LimitReader(body, 1<<20))
	if err != nil {
		return "", false
	}
	var rejection struct {
		Error *struct {
			Message string `json:"message"`
			Details string `json:"details"`
		} `json:"error"`
		NodeErrors map[string]struct {
			ClassType string `json:"class_type"`
			Errors    []struct {
				Message string `json:"message"`
				Details string `json:"details"`
			} `json:"errors"`
		} `json:"node_errors"`
	}
	if json.Unmarshal(raw, &rejection) != nil || rejection.Error == nil || rejection.NodeErrors == nil {
		return "", false
	}
	parts := []string{strings.TrimSpace(rejection.Error.Message + " " + rejection.Error.Details)}
	ids := make([]string, 0, len(rejection.NodeErrors))
	for id := range rejection.NodeErrors {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		for _, e := range rejection.NodeErrors[id].Errors {
			parts = append(parts, fmt.Sprintf("%s (node %s): %s %s", rejection.NodeErrors[id].ClassType, id, e.Message, e.Details))
		}
	}
	return truncateComfyMessage("Comfy rejected the prompt: " + strings.Join(parts, "; ")), true
}

func truncateComfyMessage(message string) string {
	message = strings.TrimSpace(message)
	if len(message) > 1000 {
		return message[:1000] + "..."
	}
	return message
}

func (s *Server) stopComfyPrompt(ctx context.Context, promptID string) error {
	stopCtx, cancel := context.WithTimeout(ctx, s.options.StopTimeout)
	defer cancel()
	if promptID == "" {
		return errors.New("exact Comfy prompt identity is unavailable")
	}
	queued, running, err := s.promptQueueState(stopCtx, promptID)
	if err != nil {
		return fmt.Errorf("observe exact Comfy prompt before cancellation: %w", err)
	}
	if running {
		return errors.New("exact prompt is running; this Comfy backend has no selective running-prompt cancellation")
	}
	if !queued {
		return errors.New("exact prompt is absent from the queue; cancellation cannot distinguish completion from an external removal")
	}
	body, _ := json.Marshal(map[string][]string{"delete": {promptID}})
	if err := s.comfyControl(stopCtx, "/queue", body); err != nil {
		return fmt.Errorf("delete exact queued prompt: %w", err)
	}
	ticker := time.NewTicker(s.options.PollInterval)
	defer ticker.Stop()
	for {
		queued, running, err = s.promptQueueState(stopCtx, promptID)
		if err != nil {
			return fmt.Errorf("confirm exact prompt queue state: %w", err)
		}
		if running {
			return errors.New("exact prompt started before queued deletion was confirmed")
		}
		if !queued {
			observation, historyErr := s.comfyHistory(stopCtx, promptID)
			if historyErr != nil {
				return fmt.Errorf("confirm exact prompt history after deletion: %w", historyErr)
			}
			if observation.Present && !observation.Terminal {
				return errors.New("exact prompt still has a nonterminal Comfy history record")
			}
			if observation.Present {
				return errors.New("exact prompt completed before cancellation was confirmed")
			}
			return nil
		}
		select {
		case <-stopCtx.Done():
			return stopCtx.Err()
		case <-ticker.C:
		}
	}
}

func (s *Server) comfyControl(ctx context.Context, path string, body []byte) error {
	request, _ := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(s.options.ComfyURL, "/")+path, bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response, err := s.options.Client.Do(request)
	if err != nil {
		return err
	}
	response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("Comfy control %s returned %d", path, response.StatusCode)
	}
	return nil
}

// comfyQueueIdle reports whether Comfy has no running and no pending prompt.
func (s *Server) comfyQueueIdle(ctx context.Context) (bool, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(s.options.ComfyURL, "/")+"/queue", nil)
	if err != nil {
		return false, err
	}
	response, err := s.options.Client.Do(request)
	if err != nil {
		return false, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return false, fmt.Errorf("Comfy queue returned %d", response.StatusCode)
	}
	var queue struct {
		Running *[]json.RawMessage `json:"queue_running"`
		Pending *[]json.RawMessage `json:"queue_pending"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 4<<20)).Decode(&queue); err != nil || queue.Running == nil || queue.Pending == nil {
		return false, fmt.Errorf("Comfy queue response is invalid")
	}
	return len(*queue.Running) == 0 && len(*queue.Pending) == 0, nil
}

func (s *Server) promptQueueState(ctx context.Context, promptID string) (queued, running bool, err error) {
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(s.options.ComfyURL, "/")+"/queue", nil)
	response, err := s.options.Client.Do(request)
	if err != nil {
		return false, false, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return false, false, fmt.Errorf("Comfy queue returned %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, (4<<20)+1))
	if err != nil || len(body) > 4<<20 {
		return false, false, fmt.Errorf("Comfy queue response is unreadable or too large")
	}
	var queue map[string]json.RawMessage
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&queue); err != nil {
		return false, false, fmt.Errorf("Comfy queue returned invalid JSON")
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return false, false, fmt.Errorf("Comfy queue returned trailing JSON")
	}
	decodeRows := func(name string) ([]json.RawMessage, error) {
		raw, ok := queue[name]
		if !ok || len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return nil, fmt.Errorf("Comfy queue omitted valid %s rows", name)
		}
		var rows []json.RawMessage
		if err := json.Unmarshal(raw, &rows); err != nil {
			return nil, fmt.Errorf("Comfy queue %s is invalid", name)
		}
		return rows, nil
	}
	runningRows, err := decodeRows("queue_running")
	if err != nil {
		return false, false, err
	}
	pendingRows, err := decodeRows("queue_pending")
	if err != nil {
		return false, false, err
	}
	match := func(rows []json.RawMessage) (bool, error) {
		for _, raw := range rows {
			var entry []json.RawMessage
			if err := json.Unmarshal(raw, &entry); err != nil || len(entry) < 2 {
				return false, fmt.Errorf("Comfy queue contains an invalid prompt tuple")
			}
			var id string
			if err := json.Unmarshal(entry[1], &id); err != nil || id == "" {
				return false, fmt.Errorf("Comfy queue contains an invalid prompt id")
			}
			if id == promptID {
				return true, nil
			}
		}
		return false, nil
	}
	queued, err = match(pendingRows)
	if err != nil {
		return false, false, err
	}
	running, err = match(runningRows)
	if err != nil {
		return false, false, err
	}
	return queued, running, nil
}

func (s *Server) handleProxy(w http.ResponseWriter, r *http.Request) {
	destination := strings.TrimRight(s.options.ComfyURL, "/") + r.URL.Path
	if r.URL.RawQuery != "" {
		destination += "?" + r.URL.RawQuery
	}
	requestBody := http.MaxBytesReader(w, r.Body, s.options.MaxRequestBytes)
	request, err := http.NewRequestWithContext(r.Context(), r.Method, destination, requestBody)
	if err != nil {
		http.Error(w, "invalid proxy request", http.StatusBadRequest)
		return
	}
	request.Header.Set("Content-Type", r.Header.Get("Content-Type"))
	response, err := s.options.Client.Do(request)
	if err != nil {
		http.Error(w, "Comfy proxy unavailable", http.StatusBadGateway)
		return
	}
	defer response.Body.Close()
	for _, header := range []string{"Content-Type", "Content-Length", "Content-Disposition"} {
		if value := response.Header.Get(header); value != "" {
			w.Header().Set(header, value)
		}
	}
	w.WriteHeader(response.StatusCode)
	_, _ = io.Copy(w, io.LimitReader(response.Body, 1<<30))
}

func parseChunks(payload json.RawMessage) ([]chunk, error) {
	var envelope struct {
		Prompt        json.RawMessage `json:"prompt"`
		ManagedChunks []chunk         `json:"managed_chunks"`
	}
	if err := json.Unmarshal(payload, &envelope); err != nil {
		return nil, fmt.Errorf("payload must be valid JSON: %w", err)
	}
	chunks := envelope.ManagedChunks
	if len(chunks) == 0 && len(envelope.Prompt) > 0 && string(envelope.Prompt) != "null" {
		chunks = []chunk{{ID: "chunk-0001", Prompt: envelope.Prompt}}
	}
	if len(chunks) == 0 {
		return nil, fmt.Errorf("payload requires prompt or managed_chunks")
	}
	seen := make(map[string]struct{}, len(chunks))
	for index := range chunks {
		if chunks[index].ID == "" {
			chunks[index].ID = fmt.Sprintf("chunk-%04d", index+1)
		}
		if _, exists := seen[chunks[index].ID]; exists {
			return nil, fmt.Errorf("duplicate chunk id %q", chunks[index].ID)
		}
		seen[chunks[index].ID] = struct{}{}
		var prompt map[string]json.RawMessage
		if json.Unmarshal(chunks[index].Prompt, &prompt) != nil || len(prompt) == 0 {
			return nil, fmt.Errorf("chunk %q requires a non-empty Comfy prompt object", chunks[index].ID)
		}
	}
	return chunks, nil
}

func (s *Server) responseLocked(execution *execution, includeOutput bool) stateResponse {
	response := stateResponse{ProtocolVersion: ProtocolVersion, ExecutionID: execution.ID, State: execution.State, CheckpointRef: execution.CheckpointRef, ProgressStage: "chunk", ProgressCurrent: execution.NextChunk, ProgressTotal: len(execution.Chunks), Error: execution.Error, ArtifactRefs: append([]string(nil), execution.ArtifactRefs...)}
	if len(execution.Chunks) > 0 {
		response.Progress = float64(execution.NextChunk) / float64(len(execution.Chunks))
	}
	if includeOutput {
		response.Output = make(map[string]json.RawMessage, len(execution.Histories))
		for id, history := range execution.Histories {
			response.Output[id] = append(json.RawMessage(nil), history...)
		}
	}
	return response
}

func (s *Server) notifyLocked(id string) {
	if runtime := s.runtimes[id]; runtime != nil {
		for _, waiter := range runtime.waiters {
			close(waiter)
		}
		runtime.waiters = nil
		if runtime.cancel != nil {
			runtime.cancel()
			runtime.cancel = nil
		}
	}
}

func (s *Server) persistLocked() error {
	rows := make([]*execution, 0, len(s.executions))
	recoveryRows := make([]*execution, 0, len(s.executions))
	for _, execution := range s.executions {
		rows = append(rows, execution)
		recoveryCopy := *execution
		if requiresRestartRecovery(execution) {
			recoveryCopy.State, recoveryCopy.Error = "uncertain", restartRecoveryError
		}
		recoveryRows = append(recoveryRows, &recoveryCopy)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].ID < rows[j].ID })
	body, err := json.MarshalIndent(persistedState{Version: ProtocolVersion, Executions: rows}, "", "  ")
	if err != nil {
		return err
	}
	if int64(len(body)+1) > s.options.MaxStateBytes {
		return fmt.Errorf("durable harness state exceeds configured %d-byte limit", s.options.MaxStateBytes)
	}
	sort.Slice(recoveryRows, func(i, j int) bool { return recoveryRows[i].ID < recoveryRows[j].ID })
	recoveryBody, err := json.MarshalIndent(persistedState{Version: ProtocolVersion, Executions: recoveryRows}, "", "  ")
	if err != nil {
		return err
	}
	if int64(len(recoveryBody)+1) > s.options.MaxStateBytes {
		return fmt.Errorf("durable harness state has insufficient recovery headroom within configured %d-byte limit", s.options.MaxStateBytes)
	}
	final := filepath.Join(s.options.StateDirectory, "state.json")
	return s.writeState(final, append(body, '\n'))
}

func requiresRestartRecovery(execution *execution) bool {
	return execution.State == "running" || execution.State == "cancelling" || execution.Submission != "" || execution.CurrentPrompt != ""
}

func durableWriteState(final string, body []byte) error {
	directory := filepath.Dir(final)
	if info, err := os.Lstat(final); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || !singleLinkFile(final, info) {
			return fmt.Errorf("state file is linked or not a regular file")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	file, err := os.CreateTemp(directory, ".state-*.tmp")
	if err != nil {
		return err
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		return err
	}
	if _, err := file.Write(body); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporary, final); err != nil {
		return err
	}
	if runtime.GOOS == "windows" {
		return nil
	}
	directoryFile, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer directoryFile.Close()
	if err := directoryFile.Sync(); err != nil {
		return err
	}
	return nil
}

func readStateFile(path string, limit int64) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() || !singleLinkFile(path, before) || before.Size() > limit {
		return nil, fmt.Errorf("state file is linked, special, or oversized")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return nil, fmt.Errorf("state file changed while opening")
	}
	body, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(body)) > limit {
		return nil, fmt.Errorf("state file is unreadable or oversized")
	}
	after, err := os.Lstat(path)
	if err != nil || after.Mode()&os.ModeSymlink != 0 || !os.SameFile(opened, after) || !singleLinkFile(path, after) {
		return nil, fmt.Errorf("state file changed while reading")
	}
	return body, nil
}

func cloneExecution(source *execution) *execution {
	if source == nil {
		return nil
	}
	body, err := json.Marshal(source)
	if err != nil {
		panic(err)
	}
	var clone execution
	if err := json.Unmarshal(body, &clone); err != nil {
		panic(err)
	}
	return &clone
}

func hashChunks(chunks []chunk) (string, error) {
	body, err := json.Marshal(chunks)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(body)
	return hex.EncodeToString(digest[:]), nil
}

func legacyTerminalState(state string) bool {
	return state == "completed" || state == "failed" || state == "cancelled"
}

func canonicalJSON(raw json.RawMessage) ([]byte, error) {
	var compact bytes.Buffer
	if err := json.Compact(&compact, raw); err != nil {
		return nil, err
	}
	return compact.Bytes(), nil
}

func (s *Server) load() error {
	path := filepath.Join(s.options.StateDirectory, "state.json")
	body, err := readStateFile(path, s.options.MaxStateBytes)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read harness state: %w", err)
	}
	var state persistedState
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&state); err != nil || state.Version != ProtocolVersion {
		return fmt.Errorf("invalid harness state file")
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return fmt.Errorf("harness state file contains trailing data")
	}
	recovered := false
	for _, execution := range state.Executions {
		if execution == nil || execution.ID == "" || execution.IdempotencyKey == "" {
			return fmt.Errorf("invalid durable execution")
		}
		if s.executions[execution.ID] != nil {
			return fmt.Errorf("duplicate durable execution id")
		}
		if existing := s.idempotency[execution.IdempotencyKey]; existing != "" {
			return fmt.Errorf("duplicate durable idempotency key")
		}
		if execution.NextChunk < 0 || execution.NextChunk > len(execution.Chunks) || len(execution.Histories) != execution.NextChunk {
			return fmt.Errorf("invalid durable chunk progress")
		}
		chunkPayload, err := json.Marshal(map[string]any{"managed_chunks": execution.Chunks})
		if err != nil {
			return fmt.Errorf("invalid durable chunks")
		}
		validatedChunks, err := parseChunks(chunkPayload)
		if err != nil || len(validatedChunks) != len(execution.Chunks) {
			return fmt.Errorf("invalid durable chunks")
		}
		for index := range validatedChunks {
			left, leftErr := canonicalJSON(validatedChunks[index].Prompt)
			right, rightErr := canonicalJSON(execution.Chunks[index].Prompt)
			if leftErr != nil || rightErr != nil || validatedChunks[index].ID != execution.Chunks[index].ID || !bytes.Equal(left, right) {
				return fmt.Errorf("durable chunk identity changed")
			}
		}
		for promptID, history := range execution.Histories {
			if promptID == "" || len(history) == 0 || !json.Valid(history) {
				return fmt.Errorf("invalid durable output history")
			}
		}
		hash, err := hashChunks(execution.Chunks)
		if err == nil && execution.PayloadHash == "" && legacyTerminalState(execution.State) {
			// Harness builds before payload hashing persisted no payload_hash.
			// A terminal legacy execution can never be resubmitted, so binding
			// it to its own validated chunks is a lossless format upgrade.
			execution.PayloadHash = hash
			recovered = true
		}
		if err != nil || hash != execution.PayloadHash {
			return fmt.Errorf("durable payload identity mismatch")
		}
		if execution.State != "running" && execution.State != "cancelling" && execution.State != "uncertain" && execution.State != "cancelled" && execution.State != "completed" && execution.State != "failed" && execution.State != "yielded" && execution.State != "checkpointed" {
			return fmt.Errorf("invalid durable execution state")
		}
		if execution.Submission != "" && execution.Submission != "submitting" && execution.Submission != "accepted" && execution.Submission != "unknown" {
			return fmt.Errorf("invalid durable submission state")
		}
		if execution.Submission != "" && (execution.NextChunk >= len(execution.Chunks) || execution.SubmittingChunk != execution.Chunks[execution.NextChunk].ID) {
			return fmt.Errorf("invalid durable submission chunk")
		}
		if execution.CurrentPrompt != "" && execution.Submission != "accepted" && execution.Submission != "unknown" {
			return fmt.Errorf("durable prompt lacks submission custody")
		}
		if execution.State == "completed" && execution.NextChunk != len(execution.Chunks) {
			return fmt.Errorf("completed execution has uncommitted chunks")
		}
		if execution.CheckpointRef != "" {
			if (execution.State != "checkpointed" && execution.State != "yielded") || !validCheckpointRef(execution.CheckpointRef) || execution.CheckpointChunk != execution.NextChunk || execution.CheckpointEpoch == 0 || execution.CheckpointEpoch != execution.Epoch {
				return fmt.Errorf("invalid durable checkpoint reference or epoch")
			}
		} else if execution.CheckpointChunk != 0 || execution.CheckpointEpoch != 0 {
			return fmt.Errorf("durable checkpoint metadata lacks reference")
		}
		if (execution.State == "checkpointed" || execution.State == "yielded") && execution.CheckpointRef == "" {
			return fmt.Errorf("durable checkpoint or yield lacks a fresh resume reference")
		}
		if execution.State == "cancelling" && execution.Requested != "cancel" {
			return fmt.Errorf("cancelling execution lacks durable cancel intent")
		}
		if requiresRestartRecovery(execution) {
			execution.State, execution.Error = "uncertain", restartRecoveryError
			recovered = true
		}
		if execution.Histories == nil {
			execution.Histories = make(map[string]json.RawMessage)
		}
		if _, exists := s.idempotency[execution.IdempotencyKey]; exists {
			return fmt.Errorf("duplicate durable idempotency key")
		}
		s.executions[execution.ID] = execution
		s.idempotency[execution.IdempotencyKey] = execution.ID
	}
	if recovered {
		return s.persistLocked()
	}
	return nil
}

func decodeStrict(w http.ResponseWriter, r *http.Request, limit int64, destination any) error {
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return fmt.Errorf("request must contain exactly one JSON document")
	}
	return nil
}

func writeState(w http.ResponseWriter, status int, response stateResponse) {
	response.ProtocolVersion = ProtocolVersion
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(response)
}

func newID() string {
	var value [16]byte
	if _, err := rand.Read(value[:]); err == nil {
		return "exec-" + hex.EncodeToString(value[:])
	}
	return fmt.Sprintf("exec-%d", time.Now().UnixNano())
}

func newCheckpointRef() (string, error) {
	var token [32]byte
	if _, err := rand.Read(token[:]); err != nil {
		return "", fmt.Errorf("generate checkpoint reference: %w", err)
	}
	return "checkpoint://" + hex.EncodeToString(token[:]), nil
}

func validCheckpointRef(reference string) bool {
	if !strings.HasPrefix(reference, "checkpoint://") {
		return false
	}
	token := strings.TrimPrefix(reference, "checkpoint://")
	if len(token) != 64 {
		return false
	}
	decoded, err := hex.DecodeString(token)
	return err == nil && len(decoded) == 32
}
