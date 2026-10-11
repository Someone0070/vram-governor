package comfyharness

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeComfy struct {
	mu             sync.Mutex
	next           int
	running        map[string]bool
	pending        map[string]bool
	completed      map[string]bool
	started        chan string
	interrupts     int
	acceptGate     chan struct{}
	acceptSeen     chan struct{}
	ignoreDelete   bool
	queueRaw       string
	historyRaw     string
	promptRaw      string
	promptStatus   int
	historyPadding int
}

func newFakeComfy() *fakeComfy {
	return &fakeComfy{running: make(map[string]bool), pending: make(map[string]bool), completed: make(map[string]bool), started: make(chan string, 10)}
}

func (f *fakeComfy) handler(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/prompt":
		f.next++
		id := fmt.Sprintf("prompt-%d", f.next)
		f.running[id] = true
		gate, seen := f.acceptGate, f.acceptSeen
		f.mu.Unlock()
		if seen != nil {
			close(seen)
		}
		if gate != nil {
			<-gate
		}
		f.mu.Lock()
		if f.promptStatus != 0 {
			w.WriteHeader(f.promptStatus)
		}
		if f.promptRaw != "" {
			_, _ = w.Write([]byte(f.promptRaw))
		} else {
			_ = json.NewEncoder(w).Encode(map[string]string{"prompt_id": id})
		}
		f.started <- id
	case r.Method == http.MethodGet && len(r.URL.Path) > len("/history/") && r.URL.Path[:len("/history/")] == "/history/":
		id := r.URL.Path[len("/history/"):]
		if f.historyRaw != "" {
			_, _ = w.Write([]byte(f.historyRaw))
			return
		}
		if !f.completed[id] {
			_ = json.NewEncoder(w).Encode(map[string]any{})
			return
		}
		delete(f.running, id)
		_ = json.NewEncoder(w).Encode(map[string]any{id: map[string]any{"status": map[string]any{"status_str": "success", "completed": true}, "outputs": map[string]any{"1": map[string]any{"images": []map[string]string{{"filename": id + ".png", "type": "output"}}}}, "padding": strings.Repeat("z", f.historyPadding)}})
	case r.Method == http.MethodPost && r.URL.Path == "/queue":
		var request struct {
			Delete []string `json:"delete"`
		}
		_ = json.NewDecoder(r.Body).Decode(&request)
		for _, id := range request.Delete {
			if !f.ignoreDelete {
				delete(f.pending, id)
			}
		}
		w.WriteHeader(http.StatusOK)
	case r.Method == http.MethodGet && r.URL.Path == "/queue":
		if f.queueRaw != "" {
			_, _ = w.Write([]byte(f.queueRaw))
			return
		}
		rows := make([][]any, 0, len(f.running))
		for id := range f.running {
			rows = append(rows, []any{0, id})
		}
		pending := make([][]any, 0, len(f.pending))
		for id := range f.pending {
			pending = append(pending, []any{0, id})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"queue_running": rows, "queue_pending": pending})
	case r.Method == http.MethodPost && r.URL.Path == "/interrupt":
		f.interrupts++
		f.running = make(map[string]bool)
		w.WriteHeader(http.StatusOK)
	case r.Method == http.MethodGet && r.URL.Path == "/view":
		w.Header().Set("Content-Type", "image/png")
		_, _ = w.Write([]byte("png-data"))
	case r.Method == http.MethodPost && r.URL.Path == "/upload/image":
		_ = json.NewEncoder(w).Encode(map[string]string{"name": "uploaded.png"})
	default:
		http.NotFound(w, r)
	}
}

func (f *fakeComfy) complete(id string) {
	f.mu.Lock()
	f.completed[id] = true
	f.mu.Unlock()
}

func (f *fakeComfy) queue(id string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.running, id)
	f.pending[id] = true
}

func newHarnessTestServer(t *testing.T, comfyURL, directory string) (*Server, *httptest.Server) {
	t.Helper()
	harness, err := New(Options{ComfyURL: comfyURL, Authorization: "Bearer harness-test", StateDirectory: directory, PollInterval: 5 * time.Millisecond, StopTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = harness.Close() })
	server := httptest.NewServer(harness.Handler())
	t.Cleanup(server.Close)
	return harness, server
}

func privateStateDirectory(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	return directory
}

func waitForPrompt(t *testing.T, harness *Server, executionID string) string {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		harness.mu.Lock()
		execution := harness.executions[executionID]
		if execution != nil && execution.CurrentPrompt != "" {
			prompt := execution.CurrentPrompt
			harness.mu.Unlock()
			return prompt
		}
		if execution != nil && execution.State == "uncertain" {
			state, message := execution.State, execution.Error
			harness.mu.Unlock()
			t.Fatalf("prompt acceptance became uncertain before durable ownership: %s: %s", state, message)
		}
		harness.mu.Unlock()
		time.Sleep(time.Millisecond)
	}
	t.Fatal("accepted prompt identity was not durably recorded")
	return ""
}

func harnessRequest(t *testing.T, client *http.Client, method, endpoint string, body any) (*http.Response, stateResponse) {
	t.Helper()
	response, state, err := doHarnessRequest(client, method, endpoint, body)
	if err != nil {
		t.Fatal(err)
	}
	return response, state
}

func doHarnessRequest(client *http.Client, method, endpoint string, body any) (*http.Response, stateResponse, error) {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return nil, stateResponse{}, err
		}
		reader = bytes.NewReader(encoded)
	}
	request, err := http.NewRequest(method, endpoint, reader)
	if err != nil {
		return nil, stateResponse{}, err
	}
	request.Header.Set("Authorization", "Bearer harness-test")
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return nil, stateResponse{}, err
	}
	var state stateResponse
	if err := json.NewDecoder(response.Body).Decode(&state); err != nil {
		response.Body.Close()
		return nil, stateResponse{}, err
	}
	response.Body.Close()
	return response, state, nil
}

func managedStartBody() startRequest {
	payload, _ := json.Marshal(map[string]any{"managed_chunks": []map[string]any{{"id": "chunk-1", "prompt": map[string]any{"1": map[string]any{"class_type": "Image", "inputs": map[string]any{}}}}, {"id": "chunk-2", "prompt": map[string]any{"1": map[string]any{"class_type": "Image", "inputs": map[string]any{}}}}}})
	return startRequest{ProtocolVersion: ProtocolVersion, WorkloadID: "workload-1", IdempotencyKey: "idempotency-1", PlanHash: "plan-1", Payload: payload}
}

func TestManagedComfySafeBoundaryAndResume(t *testing.T) {
	comfy := newFakeComfy()
	comfyServer := httptest.NewServer(http.HandlerFunc(comfy.handler))
	defer comfyServer.Close()
	directory := privateStateDirectory(t)
	firstHarness, firstServer := newHarnessTestServer(t, comfyServer.URL, directory)
	response, started := harnessRequest(t, firstServer.Client(), http.MethodPost, firstServer.URL+"/v1/executions", managedStartBody())
	if response.StatusCode != http.StatusAccepted || started.State != "running" || started.ExecutionID == "" {
		t.Fatalf("unexpected start: status=%d state=%+v", response.StatusCode, started)
	}
	<-comfy.started
	firstPrompt := waitForPrompt(t, firstHarness, started.ExecutionID)

	type controlResult struct {
		response *http.Response
		state    stateResponse
		err      error
	}
	checkpointed := make(chan controlResult, 1)
	go func() {
		response, state, err := doHarnessRequest(firstServer.Client(), http.MethodPost, firstServer.URL+"/v1/executions/"+started.ExecutionID+"/checkpoint", map[string]any{})
		checkpointed <- controlResult{response, state, err}
	}()
	select {
	case result := <-checkpointed:
		t.Fatalf("checkpoint returned before a safe chunk boundary: %+v", result.state)
	case <-time.After(30 * time.Millisecond):
	}
	comfy.complete(firstPrompt)
	result := <-checkpointed
	if result.err != nil {
		t.Fatal(result.err)
	}
	if result.response.StatusCode != http.StatusOK || result.state.State != "checkpointed" || result.state.CheckpointRef == "" || result.state.ProgressCurrent != 1 {
		t.Fatalf("checkpoint was not durable: %+v", result.state)
	}
	response, delayedOriginal := harnessRequest(t, firstServer.Client(), http.MethodPost, firstServer.URL+"/v1/executions", managedStartBody())
	if response.StatusCode != http.StatusConflict {
		t.Fatalf("STALE_START_RETRY_ASSERTION: delayed original start request resumed checkpointed execution: status=%d state=%+v", response.StatusCode, delayedOriginal)
	}
	_, unchanged := harnessRequest(t, firstServer.Client(), http.MethodGet, firstServer.URL+"/v1/executions/"+started.ExecutionID, nil)
	if unchanged.State != "checkpointed" || unchanged.CheckpointRef != result.state.CheckpointRef {
		t.Fatalf("delayed original start mutated checkpoint boundary: %+v", unchanged)
	}
	firstServer.Close()
	if err := firstHarness.Close(); err != nil {
		t.Fatal(err)
	}

	_, resumedServer := newHarnessTestServer(t, comfyServer.URL, directory)
	resume := managedStartBody()
	resume.CheckpointRef = result.state.CheckpointRef
	response, resumed := harnessRequest(t, resumedServer.Client(), http.MethodPost, resumedServer.URL+"/v1/executions", resume)
	if response.StatusCode != http.StatusOK || resumed.State != "running" || resumed.ExecutionID != started.ExecutionID {
		t.Fatalf("resume failed: status=%d state=%+v", response.StatusCode, resumed)
	}
	secondPrompt := <-comfy.started
	comfy.complete(secondPrompt)
	deadline := time.Now().Add(2 * time.Second)
	for {
		_, state := harnessRequest(t, resumedServer.Client(), http.MethodGet, resumedServer.URL+"/v1/executions/"+resumed.ExecutionID, nil)
		if state.State == "completed" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("resumed execution did not complete: %+v", state)
		}
		time.Sleep(5 * time.Millisecond)
	}
	response, outputs := harnessRequest(t, resumedServer.Client(), http.MethodGet, resumedServer.URL+"/v1/executions/"+resumed.ExecutionID+"/outputs", nil)
	if response.StatusCode != http.StatusOK || len(outputs.Output) != 2 || outputs.Progress != 1 {
		t.Fatalf("outputs were incomplete: %+v", outputs)
	}
}

func TestManagedComfyYieldAndResume(t *testing.T) {
	comfy := newFakeComfy()
	comfyServer := httptest.NewServer(http.HandlerFunc(comfy.handler))
	defer comfyServer.Close()
	harness, server := newHarnessTestServer(t, comfyServer.URL, privateStateDirectory(t))
	_, started := harnessRequest(t, server.Client(), http.MethodPost, server.URL+"/v1/executions", managedStartBody())
	prompt := <-comfy.started
	waitForPrompt(t, harness, started.ExecutionID)
	yielded := make(chan stateResponse, 1)
	go func() {
		_, state, err := doHarnessRequest(server.Client(), http.MethodPost, server.URL+"/v1/executions/"+started.ExecutionID+"/yield", map[string]any{})
		if err != nil {
			yielded <- stateResponse{State: "request-error", Error: err.Error()}
			return
		}
		yielded <- state
	}()
	time.Sleep(20 * time.Millisecond)
	comfy.complete(prompt)
	state := <-yielded
	if state.State != "yielded" || state.ProgressCurrent != 1 || state.CheckpointRef == "" {
		t.Fatalf("yield was not confirmed at boundary: %+v", state)
	}
	response, delayedOriginal := harnessRequest(t, server.Client(), http.MethodPost, server.URL+"/v1/executions", managedStartBody())
	if response.StatusCode != http.StatusConflict {
		t.Fatalf("STALE_START_RETRY_ASSERTION: delayed original start request resumed yielded execution: status=%d state=%+v", response.StatusCode, delayedOriginal)
	}
	resume := managedStartBody()
	resume.CheckpointRef = state.CheckpointRef
	response, resumed := harnessRequest(t, server.Client(), http.MethodPost, server.URL+"/v1/executions", resume)
	if response.StatusCode != http.StatusOK || resumed.State != "running" {
		t.Fatalf("yielded execution did not resume: %+v", resumed)
	}
}

func TestManagedComfyCheckpointReferenceIsFreshPerEpoch(t *testing.T) {
	comfy := newFakeComfy()
	comfyServer := httptest.NewServer(http.HandlerFunc(comfy.handler))
	defer comfyServer.Close()
	harness, server := newHarnessTestServer(t, comfyServer.URL, privateStateDirectory(t))
	_, started := harnessRequest(t, server.Client(), http.MethodPost, server.URL+"/v1/executions", managedStartBody())
	firstPrompt := <-comfy.started
	waitForPrompt(t, harness, started.ExecutionID)
	yielded := make(chan stateResponse, 1)
	go func() {
		_, state, err := doHarnessRequest(server.Client(), http.MethodPost, server.URL+"/v1/executions/"+started.ExecutionID+"/yield", map[string]any{})
		if err != nil {
			yielded <- stateResponse{State: "request-error", Error: err.Error()}
			return
		}
		yielded <- state
	}()
	time.Sleep(20 * time.Millisecond)
	comfy.complete(firstPrompt)
	firstBoundary := <-yielded
	if firstBoundary.State != "yielded" || firstBoundary.ProgressCurrent != 1 || firstBoundary.CheckpointRef == "" {
		t.Fatalf("first yield boundary lacks fresh reference: %+v", firstBoundary)
	}

	// Model a second persisted boundary epoch without changing progress. This
	// catches references derived only from NextChunk and makes stale-token replay
	// observable before any new Comfy prompt is submitted.
	harness.mu.Lock()
	execution := harness.executions[started.ExecutionID]
	oldRef, oldChunk := execution.CheckpointRef, execution.NextChunk
	execution.Epoch++
	newRef, err := newCheckpointRef()
	if err != nil {
		harness.mu.Unlock()
		t.Fatal(err)
	}
	execution.CheckpointRef, execution.CheckpointChunk, execution.CheckpointEpoch = newRef, execution.NextChunk, execution.Epoch
	if err := harness.persistLocked(); err != nil {
		harness.mu.Unlock()
		t.Fatal(err)
	}
	harness.mu.Unlock()
	if oldChunk != execution.NextChunk || oldRef == newRef {
		t.Fatalf("checkpoint reference was not fresh for the new epoch at unchanged progress: old=%q new=%q chunk=%d/%d", oldRef, newRef, oldChunk, execution.NextChunk)
	}

	stale := managedStartBody()
	stale.CheckpointRef = oldRef
	response, staleState := harnessRequest(t, server.Client(), http.MethodPost, server.URL+"/v1/executions", stale)
	if response.StatusCode != http.StatusConflict || staleState.State != "failed" {
		t.Fatalf("old resume ref replayed against a newer same-progress boundary: status=%d state=%+v", response.StatusCode, staleState)
	}
	_, unchanged := harnessRequest(t, server.Client(), http.MethodGet, server.URL+"/v1/executions/"+started.ExecutionID, nil)
	if unchanged.State != "yielded" || unchanged.ProgressCurrent != oldChunk || unchanged.CheckpointRef != newRef {
		t.Fatalf("stale reference mutated the newer boundary: %+v", unchanged)
	}
	comfy.mu.Lock()
	posts := comfy.next
	comfy.mu.Unlock()
	if posts != 1 {
		t.Fatalf("stale reference replay submitted Comfy work: posts=%d", posts)
	}
	resume := managedStartBody()
	resume.CheckpointRef = newRef
	response, resumed := harnessRequest(t, server.Client(), http.MethodPost, server.URL+"/v1/executions", resume)
	if response.StatusCode != http.StatusOK || resumed.State != "running" || resumed.CheckpointRef != "" {
		t.Fatalf("fresh epoch reference did not authorize resume: status=%d state=%+v", response.StatusCode, resumed)
	}
	secondPrompt := <-comfy.started
	waitForPrompt(t, harness, started.ExecutionID)
	_, repeatedOld := harnessRequest(t, server.Client(), http.MethodPost, server.URL+"/v1/executions", stale)
	if repeatedOld.State != "failed" {
		t.Fatalf("consumed resume reference remained valid after resume: %+v", repeatedOld)
	}
	comfy.mu.Lock()
	posts = comfy.next
	comfy.mu.Unlock()
	if posts != 2 {
		t.Fatalf("replayed consumed reference submitted another prompt: posts=%d", posts)
	}
	comfy.complete(secondPrompt)
}

func TestManagedComfyRejectsLegacyCheckpointWithoutFreshReference(t *testing.T) {
	chunks := []chunk{{ID: "chunk-1", Prompt: json.RawMessage(`{"1":{"class_type":"Image","inputs":{}}}`)}}
	payloadHash, err := hashChunks(chunks)
	if err != nil {
		t.Fatal(err)
	}
	executionRecord := &execution{
		ID: "legacy-checkpoint", WorkloadID: "legacy-workload", IdempotencyKey: "legacy-key", PayloadHash: payloadHash,
		Chunks: chunks, NextChunk: 1, Histories: map[string]json.RawMessage{"prompt-old": json.RawMessage(`{"status":{"status_str":"success","completed":true}}`)},
		Epoch: 1, State: "checkpointed", CheckpointRef: "checkpoint://legacy-checkpoint/1", CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
	}
	directory := privateStateDirectory(t)
	body, err := json.MarshalIndent(persistedState{Version: ProtocolVersion, Executions: []*execution{executionRecord}}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "state.json"), append(body, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(Options{ComfyURL: "http://127.0.0.1:1", Authorization: "Bearer harness-test", StateDirectory: directory}); err == nil {
		t.Fatal("legacy checkpoint without valid opaque ref and epoch was accepted")
	}
}

func TestManagedComfyCancelConfirmsBackendStop(t *testing.T) {
	comfy := newFakeComfy()
	comfyServer := httptest.NewServer(http.HandlerFunc(comfy.handler))
	defer comfyServer.Close()
	harness, server := newHarnessTestServer(t, comfyServer.URL, privateStateDirectory(t))
	_, started := harnessRequest(t, server.Client(), http.MethodPost, server.URL+"/v1/executions", managedStartBody())
	prompt := <-comfy.started
	waitForPrompt(t, harness, started.ExecutionID)
	comfy.queue(prompt)
	response, cancelled := harnessRequest(t, server.Client(), http.MethodPost, server.URL+"/v1/executions/"+started.ExecutionID+"/cancel", map[string]any{})
	if response.StatusCode != http.StatusOK || cancelled.State != "cancelled" {
		t.Fatalf("cancel was not confirmed: %+v", cancelled)
	}
	comfy.mu.Lock()
	defer comfy.mu.Unlock()
	if comfy.interrupts != 0 || len(comfy.running) != 0 || len(comfy.pending) != 0 {
		t.Fatalf("backend remained active: interrupts=%d running=%v", comfy.interrupts, comfy.running)
	}
}

func TestManagedComfyCancelDoesNotInterruptExactRunningPrompt(t *testing.T) {
	comfy := newFakeComfy()
	comfyServer := httptest.NewServer(http.HandlerFunc(comfy.handler))
	defer comfyServer.Close()
	harness, server := newHarnessTestServer(t, comfyServer.URL, privateStateDirectory(t))
	_, started := harnessRequest(t, server.Client(), http.MethodPost, server.URL+"/v1/executions", managedStartBody())
	prompt := <-comfy.started
	waitForPrompt(t, harness, started.ExecutionID)
	comfy.mu.Lock()
	comfy.running["native-workflow"] = true
	comfy.mu.Unlock()
	response, state := harnessRequest(t, server.Client(), http.MethodPost, server.URL+"/v1/executions/"+started.ExecutionID+"/cancel", map[string]any{})
	if response.StatusCode != http.StatusConflict || state.State != "uncertain" {
		t.Fatalf("running prompt cancellation was overstated: status=%d state=%+v", response.StatusCode, state)
	}
	comfy.mu.Lock()
	if comfy.interrupts != 0 || !comfy.running[prompt] || !comfy.running["native-workflow"] {
		comfy.mu.Unlock()
		t.Fatalf("cancel affected native/running work: interrupts=%d running=%v", comfy.interrupts, comfy.running)
	}
	comfy.mu.Unlock()
	comfy.complete(prompt)
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		_, state = harnessRequest(t, server.Client(), http.MethodGet, server.URL+"/v1/executions/"+started.ExecutionID, nil)
		if state.State == "uncertain" {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if state.State != "uncertain" || state.ProgressCurrent != 0 {
		t.Fatalf("late completion overwrote cancellation custody: %+v", state)
	}
}

func TestManagedComfyCancelDuringAcceptancePreservesUncertainCustody(t *testing.T) {
	comfy := newFakeComfy()
	comfy.acceptGate, comfy.acceptSeen = make(chan struct{}), make(chan struct{})
	comfyServer := httptest.NewServer(http.HandlerFunc(comfy.handler))
	defer comfyServer.Close()
	harness, server := newHarnessTestServer(t, comfyServer.URL, privateStateDirectory(t))
	_, started := harnessRequest(t, server.Client(), http.MethodPost, server.URL+"/v1/executions", managedStartBody())
	<-comfy.acceptSeen
	response, state := harnessRequest(t, server.Client(), http.MethodPost, server.URL+"/v1/executions/"+started.ExecutionID+"/cancel", map[string]any{})
	if response.StatusCode != http.StatusConflict || state.State != "uncertain" {
		t.Fatalf("accepted-but-unrecorded cancellation was overstated: status=%d state=%+v", response.StatusCode, state)
	}
	close(comfy.acceptGate)
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		harness.mu.Lock()
		execution := harness.executions[started.ExecutionID]
		recorded := execution != nil && execution.State == "uncertain" && execution.Epoch > 1
		harness.mu.Unlock()
		if recorded {
			break
		}
		time.Sleep(time.Millisecond)
	}
	harness.mu.Lock()
	execution := harness.executions[started.ExecutionID]
	finalState, next := execution.State, execution.NextChunk
	harness.mu.Unlock()
	if finalState != "uncertain" || next != 0 {
		t.Fatalf("late response overwrote newer uncertain state: state=%s next=%d", finalState, next)
	}
	comfy.mu.Lock()
	defer comfy.mu.Unlock()
	if comfy.interrupts != 0 || len(comfy.running) != 1 {
		t.Fatalf("ambiguous prompt was interrupted or lost: interrupts=%d running=%v", comfy.interrupts, comfy.running)
	}
}

func TestManagedComfyPayloadMismatchCannotResumeIdempotencyKey(t *testing.T) {
	comfy := newFakeComfy()
	comfyServer := httptest.NewServer(http.HandlerFunc(comfy.handler))
	defer comfyServer.Close()
	_, server := newHarnessTestServer(t, comfyServer.URL, privateStateDirectory(t))
	_, _ = harnessRequest(t, server.Client(), http.MethodPost, server.URL+"/v1/executions", managedStartBody())
	<-comfy.started
	changed := managedStartBody()
	changed.Payload = json.RawMessage(`{"prompt":{"1":{"class_type":"Different","inputs":{}}}}`)
	response, state := harnessRequest(t, server.Client(), http.MethodPost, server.URL+"/v1/executions", changed)
	if response.StatusCode != http.StatusConflict || state.State != "failed" {
		t.Fatalf("idempotency key accepted a different actual payload: status=%d state=%+v", response.StatusCode, state)
	}
}

func TestManagedComfyChunkCommitFailureIsNotAcknowledgedOrRepeated(t *testing.T) {
	comfy := newFakeComfy()
	comfyServer := httptest.NewServer(http.HandlerFunc(comfy.handler))
	defer comfyServer.Close()
	directory := privateStateDirectory(t)
	harness, server := newHarnessTestServer(t, comfyServer.URL, directory)
	_, started := harnessRequest(t, server.Client(), http.MethodPost, server.URL+"/v1/executions", managedStartBody())
	prompt := <-comfy.started
	waitForPrompt(t, harness, started.ExecutionID)
	harness.mu.Lock()
	harness.writeState = func(string, []byte) error { return errors.New("injected durable storage fault") }
	harness.mu.Unlock()
	comfy.complete(prompt)
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		harness.mu.Lock()
		execution := harness.executions[started.ExecutionID]
		state, next := execution.State, execution.NextChunk
		harness.mu.Unlock()
		if state == "uncertain" {
			if next != 0 {
				t.Fatalf("uncommitted chunk was acknowledged in memory: next=%d", next)
			}
			break
		}
		time.Sleep(time.Millisecond)
	}
	harness.mu.Lock()
	state, next := harness.executions[started.ExecutionID].State, harness.executions[started.ExecutionID].NextChunk
	harness.mu.Unlock()
	if state != "uncertain" || next != 0 {
		t.Fatalf("storage failure was not surfaced truthfully: state=%s next=%d", state, next)
	}
	_, response := harnessRequest(t, server.Client(), http.MethodGet, server.URL+"/v1/executions/"+started.ExecutionID, nil)
	if response.State != "uncertain" {
		t.Fatalf("in-memory state hid failed commit: %+v", response)
	}
	server.Close()
	if err := harness.Close(); err != nil {
		t.Fatal(err)
	}
	_, recoveredServer := newHarnessTestServer(t, comfyServer.URL, directory)
	_, recovered := harnessRequest(t, recoveredServer.Client(), http.MethodGet, recoveredServer.URL+"/v1/executions/"+started.ExecutionID, nil)
	if recovered.State != "uncertain" {
		t.Fatalf("restart did not conservatively recover custody: %+v", recovered)
	}
	comfy.mu.Lock()
	starts := comfy.next
	comfy.mu.Unlock()
	if starts != 1 {
		t.Fatalf("recovery resubmitted an already accepted chunk: starts=%d", starts)
	}
}

func TestManagedComfyLostPromptResponseIsNeverResubmitted(t *testing.T) {
	comfy := newFakeComfy()
	comfyServer := httptest.NewServer(http.HandlerFunc(comfy.handler))
	defer comfyServer.Close()
	harness, err := New(Options{ComfyURL: comfyServer.URL, Authorization: "Bearer harness-test", StateDirectory: privateStateDirectory(t), PollInterval: 5 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = harness.Close() }()
	harness.options.Client = &http.Client{Transport: losePromptResponseTransport{base: http.DefaultTransport}}
	server := httptest.NewServer(harness.Handler())
	defer server.Close()
	_, started := harnessRequest(t, server.Client(), http.MethodPost, server.URL+"/v1/executions", managedStartBody())
	<-comfy.started
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		_, state := harnessRequest(t, server.Client(), http.MethodGet, server.URL+"/v1/executions/"+started.ExecutionID, nil)
		if state.State == "uncertain" {
			break
		}
		time.Sleep(time.Millisecond)
	}
	_, state := harnessRequest(t, server.Client(), http.MethodPost, server.URL+"/v1/executions", managedStartBody())
	if state.State != "uncertain" {
		t.Fatalf("lost prompt response did not retain uncertainty: %+v", state)
	}
	comfy.mu.Lock()
	starts := comfy.next
	comfy.mu.Unlock()
	if starts != 1 {
		t.Fatalf("ambiguous prompt was resubmitted: starts=%d", starts)
	}
}

func TestManagedComfyAcceptedThenServerErrorIsNeverResubmitted(t *testing.T) {
	comfy := newFakeComfy()
	comfy.promptStatus = http.StatusInternalServerError
	comfyServer := httptest.NewServer(http.HandlerFunc(comfy.handler))
	defer comfyServer.Close()
	_, server := newHarnessTestServer(t, comfyServer.URL, privateStateDirectory(t))
	_, started := harnessRequest(t, server.Client(), http.MethodPost, server.URL+"/v1/executions", managedStartBody())
	<-comfy.started
	deadline := time.Now().Add(time.Second)
	var state stateResponse
	for time.Now().Before(deadline) {
		_, state = harnessRequest(t, server.Client(), http.MethodGet, server.URL+"/v1/executions/"+started.ExecutionID, nil)
		if state.State == "uncertain" {
			break
		}
		time.Sleep(time.Millisecond)
	}
	_, retry := harnessRequest(t, server.Client(), http.MethodPost, server.URL+"/v1/executions", managedStartBody())
	if state.State != "uncertain" || retry.State != "uncertain" {
		t.Fatalf("HTTP 500 after acceptance was treated as safely rejected: state=%+v retry=%+v", state, retry)
	}
	comfy.mu.Lock()
	starts := comfy.next
	comfy.mu.Unlock()
	if starts != 1 {
		t.Fatalf("ambiguous 500 was resubmitted: starts=%d", starts)
	}
}

func TestManagedComfySubmissionIntentFaultPreventsPromptPost(t *testing.T) {
	comfy := newFakeComfy()
	comfyServer := httptest.NewServer(http.HandlerFunc(comfy.handler))
	defer comfyServer.Close()
	directory := privateStateDirectory(t)
	writes := 0
	harness, err := New(Options{ComfyURL: comfyServer.URL, Authorization: "Bearer harness-test", StateDirectory: directory, PollInterval: 5 * time.Millisecond, writeState: func(final string, body []byte) error {
		writes++
		if writes == 2 {
			return errors.New("injected submission intent fault")
		}
		return durableWriteState(final, body)
	}})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(harness.Handler())
	t.Cleanup(server.Close)
	t.Cleanup(func() { _ = harness.Close() })
	_, started := harnessRequest(t, server.Client(), http.MethodPost, server.URL+"/v1/executions", managedStartBody())
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		_, state := harnessRequest(t, server.Client(), http.MethodGet, server.URL+"/v1/executions/"+started.ExecutionID, nil)
		if state.State == "uncertain" {
			break
		}
		time.Sleep(time.Millisecond)
	}
	comfy.mu.Lock()
	starts := comfy.next
	comfy.mu.Unlock()
	if starts != 0 {
		t.Fatalf("Comfy prompt was posted without durable submission intent: starts=%d", starts)
	}
	server.Close()
	if err := harness.Close(); err != nil {
		t.Fatal(err)
	}
	_, recovered := newHarnessTestServer(t, comfyServer.URL, directory)
	_, state := harnessRequest(t, recovered.Client(), http.MethodGet, recovered.URL+"/v1/executions/"+started.ExecutionID, nil)
	if state.State != "uncertain" {
		t.Fatalf("intent fault was not preserved through recovery: %+v", state)
	}
}

type losePromptResponseTransport struct{ base http.RoundTripper }

func (t losePromptResponseTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := t.base.RoundTrip(request)
	if err != nil || request.Method != http.MethodPost || request.URL.Path != "/prompt" {
		return response, err
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	return nil, errors.New("injected lost Comfy prompt response after backend acceptance")
}

func TestManagedComfyCheckpointCommitFailureStaysUncertain(t *testing.T) {
	comfy := newFakeComfy()
	comfyServer := httptest.NewServer(http.HandlerFunc(comfy.handler))
	defer comfyServer.Close()
	directory := privateStateDirectory(t)
	harness, server := newHarnessTestServer(t, comfyServer.URL, directory)
	_, started := harnessRequest(t, server.Client(), http.MethodPost, server.URL+"/v1/executions", managedStartBody())
	prompt := <-comfy.started
	waitForPrompt(t, harness, started.ExecutionID)
	checkpointed := make(chan stateResponse, 1)
	go func() {
		_, state, err := doHarnessRequest(server.Client(), http.MethodPost, server.URL+"/v1/executions/"+started.ExecutionID+"/checkpoint", map[string]any{})
		if err != nil {
			checkpointed <- stateResponse{State: "request-error", Error: err.Error()}
			return
		}
		checkpointed <- state
	}()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		harness.mu.Lock()
		requested := harness.executions[started.ExecutionID].Requested == "checkpoint"
		harness.mu.Unlock()
		if requested {
			break
		}
		time.Sleep(time.Millisecond)
	}
	harness.mu.Lock()
	harness.writeState = func(final string, body []byte) error {
		if bytes.Contains(body, []byte(`"state": "checkpointed"`)) {
			return errors.New("injected checkpoint commit fault")
		}
		return durableWriteState(final, body)
	}
	harness.mu.Unlock()
	comfy.complete(prompt)
	state := <-checkpointed
	if state.State != "uncertain" {
		t.Fatalf("failed checkpoint commit was acknowledged: %+v", state)
	}
	server.Close()
	if err := harness.Close(); err != nil {
		t.Fatal(err)
	}
	_, recoveredServer := newHarnessTestServer(t, comfyServer.URL, directory)
	_, recovered := harnessRequest(t, recoveredServer.Client(), http.MethodGet, recoveredServer.URL+"/v1/executions/"+started.ExecutionID, nil)
	if recovered.State != "uncertain" {
		t.Fatalf("checkpoint failure lost custody across restart: %+v", recovered)
	}
}

func TestManagedComfyResumePersistFailureRollsBackMemory(t *testing.T) {
	comfy := newFakeComfy()
	comfyServer := httptest.NewServer(http.HandlerFunc(comfy.handler))
	defer comfyServer.Close()
	directory := privateStateDirectory(t)
	firstHarness, firstServer := newHarnessTestServer(t, comfyServer.URL, directory)
	_, started := harnessRequest(t, firstServer.Client(), http.MethodPost, firstServer.URL+"/v1/executions", managedStartBody())
	prompt := <-comfy.started
	waitForPrompt(t, firstHarness, started.ExecutionID)
	checkpointed := make(chan stateResponse, 1)
	go func() {
		_, result, err := doHarnessRequest(firstServer.Client(), http.MethodPost, firstServer.URL+"/v1/executions/"+started.ExecutionID+"/checkpoint", map[string]any{})
		if err != nil {
			checkpointed <- stateResponse{State: "request-error", Error: err.Error()}
			return
		}
		checkpointed <- result
	}()
	time.Sleep(10 * time.Millisecond)
	comfy.complete(prompt)
	checkpoint := <-checkpointed
	if checkpoint.State != "checkpointed" || checkpoint.ProgressCurrent != 1 || checkpoint.CheckpointRef == "" {
		t.Fatalf("first checkpoint did not commit: %+v", checkpoint)
	}
	firstServer.Close()
	if err := firstHarness.Close(); err != nil {
		t.Fatal(err)
	}
	resumeHarness, err := New(Options{ComfyURL: comfyServer.URL, Authorization: "Bearer harness-test", StateDirectory: directory, writeState: func(string, []byte) error { return errors.New("injected resume persistence fault") }})
	if err != nil {
		t.Fatal(err)
	}
	resumeServer := httptest.NewServer(resumeHarness.Handler())
	defer resumeServer.Close()
	defer resumeHarness.Close()
	resume := managedStartBody()
	resume.CheckpointRef = checkpoint.CheckpointRef
	response, failed := harnessRequest(t, resumeServer.Client(), http.MethodPost, resumeServer.URL+"/v1/executions", resume)
	if response.StatusCode != http.StatusInternalServerError {
		t.Fatalf("resume persistence fault status=%d state=%+v", response.StatusCode, failed)
	}
	_, durable := harnessRequest(t, resumeServer.Client(), http.MethodGet, resumeServer.URL+"/v1/executions/"+started.ExecutionID, nil)
	if durable.State != "checkpointed" || durable.ProgressCurrent != 1 {
		t.Fatalf("failed resume mutated memory: %+v", durable)
	}
	comfy.mu.Lock()
	starts := comfy.next
	comfy.mu.Unlock()
	if starts != 1 {
		t.Fatalf("resume persistence failure started another prompt: starts=%d", starts)
	}
}

func TestManagedComfyCancelCommitFailureIsNotAcknowledged(t *testing.T) {
	comfy := newFakeComfy()
	comfyServer := httptest.NewServer(http.HandlerFunc(comfy.handler))
	defer comfyServer.Close()
	harness, server := newHarnessTestServer(t, comfyServer.URL, privateStateDirectory(t))
	_, started := harnessRequest(t, server.Client(), http.MethodPost, server.URL+"/v1/executions", managedStartBody())
	prompt := <-comfy.started
	waitForPrompt(t, harness, started.ExecutionID)
	comfy.queue(prompt)
	harness.mu.Lock()
	harness.writeState = func(final string, body []byte) error {
		if bytes.Contains(body, []byte(`"state": "cancelled"`)) {
			return errors.New("injected cancellation commit fault")
		}
		return durableWriteState(final, body)
	}
	harness.mu.Unlock()
	response, state := harnessRequest(t, server.Client(), http.MethodPost, server.URL+"/v1/executions/"+started.ExecutionID+"/cancel", map[string]any{})
	if response.StatusCode != http.StatusInternalServerError || state.State != "cancelling" {
		t.Fatalf("failed cancellation commit was overstated: status=%d state=%+v", response.StatusCode, state)
	}
}

func TestManagedComfyStopTimeoutStaysUncertain(t *testing.T) {
	comfy := newFakeComfy()
	comfyServer := httptest.NewServer(http.HandlerFunc(comfy.handler))
	defer comfyServer.Close()
	harness, server := newHarnessTestServer(t, comfyServer.URL, privateStateDirectory(t))
	_, started := harnessRequest(t, server.Client(), http.MethodPost, server.URL+"/v1/executions", managedStartBody())
	prompt := <-comfy.started
	waitForPrompt(t, harness, started.ExecutionID)
	comfy.queue(prompt)
	comfy.mu.Lock()
	comfy.ignoreDelete = true
	comfy.mu.Unlock()
	response, state := harnessRequest(t, server.Client(), http.MethodPost, server.URL+"/v1/executions/"+started.ExecutionID+"/cancel", map[string]any{})
	if response.StatusCode != http.StatusConflict || state.State != "uncertain" {
		t.Fatalf("stop timeout was overstated: status=%d state=%+v", response.StatusCode, state)
	}
	comfy.mu.Lock()
	defer comfy.mu.Unlock()
	if !comfy.pending[prompt] || comfy.interrupts != 0 {
		t.Fatalf("timeout changed unrelated backend work: pending=%v interrupts=%d", comfy.pending, comfy.interrupts)
	}
}

func TestManagedComfyMalformedQueueOrHistoryCannotConfirmCancel(t *testing.T) {
	cases := []struct{ name, queue, history string }{
		{name: "missing-arrays", queue: `{}`},
		{name: "null-running", queue: `{"queue_running":null,"queue_pending":[]}`},
		{name: "malformed-tuple", queue: `{"queue_running":[{}],"queue_pending":[]}`},
		{name: "invalid-exact-history", history: `{"prompt-1":{"outputs":{}}}`},
		{name: "present-nonterminal-history", history: `{"prompt-1":{"status":{"status_str":"success","completed":false}}}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			comfy := newFakeComfy()
			comfyServer := httptest.NewServer(http.HandlerFunc(comfy.handler))
			defer comfyServer.Close()
			harness, server := newHarnessTestServer(t, comfyServer.URL, privateStateDirectory(t))
			_, started := harnessRequest(t, server.Client(), http.MethodPost, server.URL+"/v1/executions", managedStartBody())
			prompt := <-comfy.started
			waitForPrompt(t, harness, started.ExecutionID)
			comfy.queue(prompt)
			comfy.mu.Lock()
			comfy.queueRaw, comfy.historyRaw = tc.queue, tc.history
			comfy.mu.Unlock()
			response, state := harnessRequest(t, server.Client(), http.MethodPost, server.URL+"/v1/executions/"+started.ExecutionID+"/cancel", map[string]any{})
			if response.StatusCode != http.StatusConflict || state.State != "uncertain" {
				t.Fatalf("malformed backend observation confirmed cancel: status=%d state=%+v", response.StatusCode, state)
			}
		})
	}
}

func TestManagedComfyRejectsCorruptDurableSnapshot(t *testing.T) {
	comfy := newFakeComfy()
	comfyServer := httptest.NewServer(http.HandlerFunc(comfy.handler))
	defer comfyServer.Close()
	directory := privateStateDirectory(t)
	harness, server := newHarnessTestServer(t, comfyServer.URL, directory)
	_, started := harnessRequest(t, server.Client(), http.MethodPost, server.URL+"/v1/executions", managedStartBody())
	<-comfy.started
	server.Close()
	if err := harness.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "state.json")
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var state persistedState
	if err := json.Unmarshal(body, &state); err != nil {
		t.Fatal(err)
	}
	state.Executions[0].PayloadHash = "corrupted"
	body, err = json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(Options{ComfyURL: comfyServer.URL, Authorization: "Bearer harness-test", StateDirectory: directory}); err == nil {
		t.Fatal("corrupt durable identity was accepted")
	}
	_ = started
}

func TestManagedComfyRejectsConcurrentStateOwner(t *testing.T) {
	comfy := newFakeComfy()
	comfyServer := httptest.NewServer(http.HandlerFunc(comfy.handler))
	defer comfyServer.Close()
	directory := privateStateDirectory(t)
	harness, err := New(Options{ComfyURL: comfyServer.URL, Authorization: "Bearer harness-test", StateDirectory: directory})
	if err != nil {
		t.Fatal(err)
	}
	defer harness.Close()
	if _, err := New(Options{ComfyURL: comfyServer.URL, Authorization: "Bearer harness-test", StateDirectory: directory}); err == nil {
		t.Fatal("second state owner was accepted")
	}
}

func TestManagedComfyStateOwnerLockReleasesAfterAbruptExit(t *testing.T) {
	if os.Getenv("COMFY_HARNESS_LOCK_OWNER_CHILD") == "1" {
		server, err := New(Options{ComfyURL: "http://127.0.0.1:1", Authorization: "Bearer harness-test", StateDirectory: os.Getenv("COMFY_HARNESS_LOCK_DIRECTORY")})
		if err != nil {
			os.Exit(11)
		}
		// Intentionally emulate a process disappearing without Close. The OS
		// must release the held file lock; the lock file itself may remain.
		_ = server
		os.Exit(0)
	}
	directory := privateStateDirectory(t)
	command := exec.Command(os.Args[0], "-test.run=^TestManagedComfyStateOwnerLockReleasesAfterAbruptExit$", "-test.count=1")
	command.Env = append(os.Environ(), "COMFY_HARNESS_LOCK_OWNER_CHILD=1", "COMFY_HARNESS_LOCK_DIRECTORY="+directory)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("lock-owner child did not exit intentionally: %v: %s", err, output)
	}
	server, err := New(Options{ComfyURL: "http://127.0.0.1:1", Authorization: "Bearer harness-test", StateDirectory: directory})
	if err != nil {
		t.Fatalf("OS-held state lock remained after owner exit: %v", err)
	}
	server.Close()
}

func TestManagedComfyStateBudgetCannotAcknowledgeUnrecoverableSnapshot(t *testing.T) {
	comfy := newFakeComfy()
	comfyServer := httptest.NewServer(http.HandlerFunc(comfy.handler))
	defer comfyServer.Close()
	directory := privateStateDirectory(t)
	const maxStateBytes = int64(2200)
	harness, err := New(Options{ComfyURL: comfyServer.URL, Authorization: "Bearer harness-test", StateDirectory: directory, PollInterval: 5 * time.Millisecond, StopTimeout: time.Second, MaxStateBytes: maxStateBytes})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(harness.Handler())
	response, started := harnessRequest(t, server.Client(), http.MethodPost, server.URL+"/v1/executions", managedStartBody())
	if response.StatusCode != http.StatusAccepted {
		t.Fatalf("start did not fit configured durable-state budget: status=%d state=%+v", response.StatusCode, started)
	}
	prompt := <-comfy.started
	waitForPrompt(t, harness, started.ExecutionID)
	comfy.mu.Lock()
	comfy.historyPadding = 1550
	comfy.mu.Unlock()
	comfy.complete(prompt)
	deadline := time.Now().Add(time.Second)
	observedUncertain := false
	for time.Now().Before(deadline) {
		_, state := harnessRequest(t, server.Client(), http.MethodGet, server.URL+"/v1/executions/"+started.ExecutionID, nil)
		if state.State == "uncertain" {
			if state.Output != nil || state.CheckpointRef != "" {
				t.Fatalf("state overflow was falsely acknowledged: %+v", state)
			}
			observedUncertain = true
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !observedUncertain {
		t.Fatal("overflowing execution never exposed uncertainty")
	}
	stored, err := os.ReadFile(filepath.Join(directory, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if int64(len(stored)) > maxStateBytes {
		t.Fatalf("oversized snapshot was written: %d > %d", len(stored), maxStateBytes)
	}
	server.Close()
	if err := harness.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := New(Options{ComfyURL: comfyServer.URL, Authorization: "Bearer harness-test", StateDirectory: directory, MaxStateBytes: maxStateBytes})
	if err != nil {
		t.Fatalf("last durable state could not be recovered within same budget: %v", err)
	}
	defer restarted.Close()
	restartedServer := httptest.NewServer(restarted.Handler())
	defer restartedServer.Close()
	_, state := harnessRequest(t, restartedServer.Client(), http.MethodGet, restartedServer.URL+"/v1/executions/"+started.ExecutionID, nil)
	if state.State != "uncertain" || state.Output != nil || state.CheckpointRef != "" {
		t.Fatalf("restart falsely recovered uncommitted output: %+v", state)
	}
	_, retry := harnessRequest(t, restartedServer.Client(), http.MethodPost, restartedServer.URL+"/v1/executions", managedStartBody())
	if retry.ExecutionID != started.ExecutionID || retry.State != "uncertain" {
		t.Fatalf("retry changed unresolved durable execution: %+v", retry)
	}
	comfy.mu.Lock()
	posted := comfy.next
	comfy.mu.Unlock()
	if posted != 1 {
		t.Fatalf("durable overflow retry resubmitted work: prompt posts=%d", posted)
	}
}

func TestManagedComfyNearQuotaAcceptedSnapshotRecoversAndDeduplicates(t *testing.T) {
	comfy := newFakeComfy()
	comfyServer := httptest.NewServer(http.HandlerFunc(comfy.handler))
	defer comfyServer.Close()
	directory := privateStateDirectory(t)
	const maxStateBytes = int64(14000)
	payload, err := json.Marshal(map[string]any{"managed_chunks": []map[string]any{{"id": "large-chunk", "prompt": map[string]any{"1": map[string]any{"class_type": "Image", "inputs": map[string]any{"padding": strings.Repeat("x", 13000)}}}}}})
	if err != nil {
		t.Fatal(err)
	}
	startBody := startRequest{ProtocolVersion: ProtocolVersion, WorkloadID: "near-quota", IdempotencyKey: "near-quota-key", PlanHash: "near-quota-plan", Payload: payload}
	harness, err := New(Options{ComfyURL: comfyServer.URL, Authorization: "Bearer harness-test", StateDirectory: directory, PollInterval: 5 * time.Millisecond, MaxStateBytes: maxStateBytes})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(harness.Handler())
	t.Cleanup(func() {
		server.Close()
		_ = harness.Close()
	})
	response, started := harnessRequest(t, server.Client(), http.MethodPost, server.URL+"/v1/executions", startBody)
	if response.StatusCode != http.StatusAccepted || started.State != "running" {
		t.Fatalf("near-quota durable start was not acknowledged: status=%d state=%+v", response.StatusCode, started)
	}
	<-comfy.started
	waitForPrompt(t, harness, started.ExecutionID)
	before, err := os.ReadFile(filepath.Join(directory, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if int64(len(before)) > maxStateBytes || int64(len(before)) <= maxStateBytes-512 {
		t.Fatalf("fixture is not a valid near-quota snapshot: size=%d limit=%d", len(before), maxStateBytes)
	}
	server.Close()
	if err := harness.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := New(Options{ComfyURL: comfyServer.URL, Authorization: "Bearer harness-test", StateDirectory: directory, MaxStateBytes: maxStateBytes})
	if err != nil {
		t.Fatalf("near-quota acknowledged snapshot did not recover within the same limit: %v", err)
	}
	t.Cleanup(func() { _ = restarted.Close() })
	restartedServer := httptest.NewServer(restarted.Handler())
	_, recovered := harnessRequest(t, restartedServer.Client(), http.MethodGet, restartedServer.URL+"/v1/executions/"+started.ExecutionID, nil)
	if recovered.State != "uncertain" || recovered.Error == "" {
		t.Fatalf("near-quota restart did not retain uncertain custody: %+v", recovered)
	}
	after, err := os.ReadFile(filepath.Join(directory, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if int64(len(after)) > maxStateBytes {
		t.Fatalf("recovery exceeded the unchanged state limit: size=%d limit=%d", len(after), maxStateBytes)
	}
	_, duplicate := harnessRequest(t, restartedServer.Client(), http.MethodPost, restartedServer.URL+"/v1/executions", startBody)
	if duplicate.ExecutionID != started.ExecutionID || duplicate.State != "uncertain" {
		t.Fatalf("same idempotency key did not resolve to recovered execution: %+v", duplicate)
	}
	comfy.mu.Lock()
	posts := comfy.next
	comfy.mu.Unlock()
	if posts != 1 {
		t.Fatalf("same idempotency key resubmitted after recovery: posts=%d", posts)
	}
	restartedServer.Close()
	if err := restarted.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestManagedComfyRestartRecoveryHeadroomRequired(t *testing.T) {
	executionRecord := &execution{
		ID: "recovery-headroom-execution", WorkloadID: "recovery-headroom-workload", IdempotencyKey: "recovery-headroom-key",
		PlanHash:  "recovery-headroom-plan",
		Chunks:    []chunk{{ID: "chunk-1", Prompt: json.RawMessage(`{"1":{"class_type":"Image","inputs":{}}}`)}},
		Histories: map[string]json.RawMessage{}, State: "running", CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
	}
	executionRecord.PayloadHash, _ = hashChunks(executionRecord.Chunks)
	currentBody, err := json.MarshalIndent(persistedState{Version: ProtocolVersion, Executions: []*execution{executionRecord}}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	recovered := *executionRecord
	recovered.State, recovered.Error = "uncertain", restartRecoveryError
	recoveryBody, err := json.MarshalIndent(persistedState{Version: ProtocolVersion, Executions: []*execution{&recovered}}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	currentBytes, recoveryBytes := int64(len(currentBody)+1), int64(len(recoveryBody)+1)
	if recoveryBytes <= currentBytes {
		t.Fatalf("fixture lacks recovery growth: current=%d recovery=%d", currentBytes, recoveryBytes)
	}
	writes := 0
	server := &Server{
		options:    Options{StateDirectory: privateStateDirectory(t), MaxStateBytes: currentBytes},
		executions: map[string]*execution{executionRecord.ID: executionRecord},
		writeState: func(string, []byte) error { writes++; return nil },
	}
	if err := server.persistLocked(); err == nil || !strings.Contains(err.Error(), "recovery headroom") || writes != 0 {
		t.Fatalf("RESTART_RECOVERY_HEADROOM_ASSERTION: near-cap active state was acknowledged without room to reconcile (err=%v writes=%d current=%d recovery=%d)", err, writes, currentBytes, recoveryBytes)
	}
}

func TestComfyVerifierNegativeControl(t *testing.T) {
	if os.Getenv("COMFY_HARNESS_NEGATIVE_CONTROL") != "1" {
		t.Skip("verifier-only negative control")
	}
	t.Fatalf("COMFY_HARNESS_NEGATIVE_CONTROL_ASSERTION")
}

func TestManagedComfyRestartFailsUnconfirmedRun(t *testing.T) {
	comfy := newFakeComfy()
	comfyServer := httptest.NewServer(http.HandlerFunc(comfy.handler))
	defer comfyServer.Close()
	directory := privateStateDirectory(t)
	firstHarness, first := newHarnessTestServer(t, comfyServer.URL, directory)
	_, started := harnessRequest(t, first.Client(), http.MethodPost, first.URL+"/v1/executions", managedStartBody())
	<-comfy.started
	first.Close()
	if err := firstHarness.Close(); err != nil {
		t.Fatal(err)
	}
	_, recovered := newHarnessTestServer(t, comfyServer.URL, directory)
	_, state := harnessRequest(t, recovered.Client(), http.MethodGet, recovered.URL+"/v1/executions/"+started.ExecutionID, nil)
	if state.State != "uncertain" || state.Error == "" {
		t.Fatalf("unconfirmed restart custody was not preserved: %+v", state)
	}
}

func TestManagedComfyRequiresAuthorization(t *testing.T) {
	comfy := newFakeComfy()
	comfyServer := httptest.NewServer(http.HandlerFunc(comfy.handler))
	defer comfyServer.Close()
	_, server := newHarnessTestServer(t, comfyServer.URL, privateStateDirectory(t))
	request, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL+"/v1/executions/missing", nil)
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthorized request returned %d", response.StatusCode)
	}
}

type discoveryRoundTripper func(*http.Request) (*http.Response, error)

func (roundTrip discoveryRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return roundTrip(request)
}

func newDiscoveryTestHarness(t *testing.T, backendURL string, client *http.Client) (*Server, http.Handler) {
	t.Helper()
	server, err := New(Options{ComfyURL: backendURL, Authorization: "Bearer harness-secret", StateDirectory: privateStateDirectory(t), Client: client})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	return server, server.Handler()
}

func discoveryRequest(handler http.Handler, method, path, authorization string, body io.Reader) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, path, body)
	if authorization != "" {
		request.Header.Set("Authorization", authorization)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func discoveryResponse(status int, body string, headers http.Header) *http.Response {
	return &http.Response{StatusCode: status, Header: headers, Body: io.NopCloser(strings.NewReader(body)), Request: &http.Request{}}
}

func TestComfyDiscoveryObjectInfoPreservesSchema(t *testing.T) {
	const payload = `{"KSampler":{"input":{"required":{"steps":["INT",{"default":20,"min":1}]},"optional":{"seed":["INT"]}},"output":["LATENT"],"output_node":false}}`
	client := &http.Client{Transport: discoveryRoundTripper(func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodGet || request.URL.Path != "/object_info" || request.URL.RawQuery != "" {
			t.Fatalf("unexpected backend request: %s %s", request.Method, request.URL)
		}
		return discoveryResponse(http.StatusOK, payload, make(http.Header)), nil
	})}
	_, handler := newDiscoveryTestHarness(t, "http://comfy.invalid", client)
	response := discoveryRequest(handler, http.MethodGet, "/object_info", "Bearer harness-secret", nil)
	if response.Code != http.StatusOK || response.Body.String() != payload || response.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("object_info was not preserved: status=%d headers=%v body=%s", response.Code, response.Header(), response.Body.String())
	}
}

func TestComfyDiscoverySystemStatsPreservesDeviceStats(t *testing.T) {
	const payload = `{"devices":[{"name":"NVIDIA RTX","type":"cuda","vram_total":24576,"vram_free":18000}],"system":{"ram_total":64000}}`
	client := &http.Client{Transport: discoveryRoundTripper(func(request *http.Request) (*http.Response, error) {
		if request.URL.Path != "/system_stats" {
			t.Fatalf("unexpected backend path %q", request.URL.Path)
		}
		return discoveryResponse(http.StatusOK, payload, make(http.Header)), nil
	})}
	_, handler := newDiscoveryTestHarness(t, "http://comfy.invalid", client)
	response := discoveryRequest(handler, http.MethodGet, "/system_stats", "Bearer harness-secret", nil)
	if response.Code != http.StatusOK || response.Body.String() != payload {
		t.Fatalf("system_stats was not preserved: status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestComfyDiscoveryRequiresAuthorization(t *testing.T) {
	calls := 0
	client := &http.Client{Transport: discoveryRoundTripper(func(*http.Request) (*http.Response, error) {
		calls++
		return discoveryResponse(http.StatusOK, `{}`, make(http.Header)), nil
	})}
	_, handler := newDiscoveryTestHarness(t, "http://comfy.invalid", client)
	response := discoveryRequest(handler, http.MethodGet, "/object_info", "", nil)
	if response.Code != http.StatusUnauthorized || calls != 0 {
		t.Fatalf("COMFY_DISCOVERY_AUTH_MUTANT_ASSERTION: unauthorized request reached backend: status=%d calls=%d", response.Code, calls)
	}
}

func TestComfyDiscoveryRejectsQueryBodyAndUnsupportedRoutes(t *testing.T) {
	calls := 0
	client := &http.Client{Transport: discoveryRoundTripper(func(*http.Request) (*http.Response, error) {
		calls++
		return discoveryResponse(http.StatusOK, `{}`, make(http.Header)), nil
	})}
	_, handler := newDiscoveryTestHarness(t, "http://comfy.invalid", client)
	checks := []struct {
		method, path string
		body         io.Reader
	}{
		{method: http.MethodGet, path: "/object_info?url=http://attacker.invalid"},
		{method: http.MethodGet, path: "/system_stats", body: strings.NewReader("{}")},
		{method: http.MethodPost, path: "/object_info", body: strings.NewReader("{}")},
		{method: http.MethodHead, path: "/object_info"},
		{method: http.MethodGet, path: "/object_info/extra"},
		{method: http.MethodGet, path: "/proxy/http:/attacker.invalid"},
	}
	for _, check := range checks {
		response := discoveryRequest(handler, check.method, check.path, "Bearer harness-secret", check.body)
		if response.Code < 400 {
			t.Errorf("unexpectedly accepted %s %s: %d", check.method, check.path, response.Code)
		}
	}

	redirected := discoveryRequest(handler, http.MethodGet, "/proxy/http://attacker.invalid", "Bearer harness-secret", nil)
	location := redirected.Header().Get("Location")
	if redirected.Code < 300 || redirected.Code >= 400 || location != "/proxy/http:/attacker.invalid" {
		t.Fatalf("unsafe canonical-path redirect: status=%d location=%q", redirected.Code, location)
	}
	canonical := discoveryRequest(handler, http.MethodGet, location, "Bearer harness-secret", nil)
	if canonical.Code != http.StatusNotFound {
		t.Fatalf("canonical arbitrary-looking path did not terminate at the local 404: status=%d location=%q", canonical.Code, location)
	}
	if calls != 0 {
		t.Fatalf("rejected request reached backend %d times", calls)
	}
}

func TestComfyDiscoveryUsesFixedBackendPathAndIsolatesCredentials(t *testing.T) {
	for _, route := range []string{"/object_info", "/system_stats"} {
		t.Run(route, func(t *testing.T) {
			calls := 0
			client := &http.Client{Transport: discoveryRoundTripper(func(request *http.Request) (*http.Response, error) {
				calls++
				if request.URL.Scheme != "http" || request.URL.Host != "comfy.invalid" || request.URL.Path != "/base/nested"+route || request.URL.RawQuery != "" || request.URL.ForceQuery || request.URL.User != nil {
					t.Fatalf("backend destination was not fixed: %#v", request.URL)
				}
				for _, name := range []string{"Authorization", "Cookie", "X-Caller-Secret"} {
					if request.Header.Get(name) != "" {
						t.Fatalf("caller credential/header %s was forwarded", name)
					}
				}
				return discoveryResponse(http.StatusOK, `{"nodes":{}}`, make(http.Header)), nil
			})}
			_, handler := newDiscoveryTestHarness(t, "http://comfy.invalid/base/nested", client)
			request := httptest.NewRequest(http.MethodGet, route, nil)
			request.Header.Set("Authorization", "Bearer harness-secret")
			request.Header.Set("Cookie", "session=private")
			request.Header.Set("X-Caller-Secret", "private")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusOK || calls != 1 {
				t.Fatalf("discovery did not complete at fixed path: status=%d calls=%d", response.Code, calls)
			}
		})
	}
}

func TestComfyDiscoveryRejectsBaseURLComponents(t *testing.T) {
	for _, backendURL := range []string{
		"http://comfy.invalid/base?token=private",
		"http://comfy.invalid/base?",
		"http://comfy.invalid/base#fragment",
		"http://user:secret@comfy.invalid/base",
	} {
		for _, route := range []string{"/object_info", "/system_stats"} {
			t.Run(backendURL+route, func(t *testing.T) {
				calls := 0
				client := &http.Client{Transport: discoveryRoundTripper(func(request *http.Request) (*http.Response, error) {
					calls++
					if request.URL.User != nil || request.URL.RawQuery != "" || request.URL.ForceQuery || request.URL.Fragment != "" || request.Header.Get("Authorization") != "" {
						t.Fatalf("unsafe registered URL component reached backend: url=%s authorization=%q", request.URL, request.Header.Get("Authorization"))
					}
					return discoveryResponse(http.StatusOK, `{}`, make(http.Header)), nil
				})}
				_, handler := newDiscoveryTestHarness(t, backendURL, client)
				response := discoveryRequest(handler, http.MethodGet, route, "Bearer harness-secret", nil)
				if response.Code != http.StatusBadGateway || calls != 0 {
					t.Fatalf("unsafe registered Comfy URL was accepted: base=%q route=%s status=%d calls=%d", backendURL, route, response.Code, calls)
				}
			})
		}
	}

	client := &http.Client{Transport: discoveryRoundTripper(func(*http.Request) (*http.Response, error) {
		t.Fatal("ForceQuery request reached backend")
		return nil, errors.New("unreachable")
	})}
	_, handler := newDiscoveryTestHarness(t, "http://comfy.invalid/base", client)
	request := httptest.NewRequest(http.MethodGet, "/object_info", nil)
	request.URL.ForceQuery = true
	request.Header.Set("Authorization", "Bearer harness-secret")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("ForceQuery caller URL was accepted: status=%d", response.Code)
	}
}

func TestComfyDiscoveryRejectsRedirectWithoutFollowing(t *testing.T) {
	calls := 0
	redirectPolicy := func(*http.Request, []*http.Request) error { return errors.New("original policy") }
	client := &http.Client{Transport: discoveryRoundTripper(func(request *http.Request) (*http.Response, error) {
		calls++
		if request.URL.Path != "/object_info" {
			t.Fatalf("unexpected redirect destination contacted: %s", request.URL)
		}
		headers := make(http.Header)
		headers.Set("Location", "http://redirect.invalid/steal")
		return discoveryResponse(http.StatusFound, "redirect detail", headers), nil
	}), CheckRedirect: redirectPolicy}
	_, handler := newDiscoveryTestHarness(t, "http://comfy.invalid", client)
	response := discoveryRequest(handler, http.MethodGet, "/object_info", "Bearer harness-secret", nil)
	if response.Code != http.StatusBadGateway || calls != 1 || !strings.Contains(response.Body.String(), "Comfy discovery unavailable") || strings.Contains(response.Body.String(), "redirect detail") {
		t.Fatalf("redirect was followed or leaked: status=%d calls=%d body=%s", response.Code, calls, response.Body.String())
	}
	if client.CheckRedirect == nil || fmt.Sprintf("%p", client.CheckRedirect) != fmt.Sprintf("%p", redirectPolicy) {
		t.Fatal("shared client's redirect policy changed")
	}
}

type endlessDiscoveryReader struct{}

func (endlessDiscoveryReader) Read(buffer []byte) (int, error) {
	for index := range buffer {
		buffer[index] = ' '
	}
	return len(buffer), nil
}

func TestComfyDiscoveryRejectsOversizedBodies(t *testing.T) {
	for _, check := range []struct {
		path string
		limit int64
	}{{path: "/object_info", limit: maxObjectInfoBytes}, {path: "/system_stats", limit: maxSystemStatsBytes}} {
		t.Run(check.path, func(t *testing.T) {
			client := &http.Client{Transport: discoveryRoundTripper(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(io.LimitReader(endlessDiscoveryReader{}, check.limit+1))}, nil
			})}
			_, handler := newDiscoveryTestHarness(t, "http://comfy.invalid", client)
			response := discoveryRequest(handler, http.MethodGet, check.path, "Bearer harness-secret", nil)
			if response.Code != http.StatusBadGateway || !strings.Contains(response.Body.String(), "invalid response") {
				t.Fatalf("oversized response was accepted: status=%d body=%s", response.Code, response.Body.String())
			}
		})
	}
}

func TestComfyDiscoveryRejectsInvalidJSON(t *testing.T) {
	for _, payload := range []string{"{", "[]", "null", `"string"`, `123`, `true`, `{"ok":true} {"extra":true}`} {
		t.Run(fmt.Sprintf("payload-%d", len(payload)), func(t *testing.T) {
			client := &http.Client{Transport: discoveryRoundTripper(func(*http.Request) (*http.Response, error) {
				return discoveryResponse(http.StatusOK, payload, make(http.Header)), nil
			})}
			_, handler := newDiscoveryTestHarness(t, "http://comfy.invalid", client)
			response := discoveryRequest(handler, http.MethodGet, "/object_info", "Bearer harness-secret", nil)
			if response.Code != http.StatusBadGateway || !strings.Contains(response.Body.String(), "invalid response") || strings.Contains(response.Body.String(), payload) {
				t.Fatalf("invalid upstream body was exposed or accepted: status=%d body=%s", response.Code, response.Body.String())
			}
		})
	}
}

func TestComfyDiscoveryRejectsNon2xx(t *testing.T) {
	client := &http.Client{Transport: discoveryRoundTripper(func(*http.Request) (*http.Response, error) {
		return discoveryResponse(http.StatusInternalServerError, "private backend diagnostic", make(http.Header)), nil
	})}
	_, handler := newDiscoveryTestHarness(t, "http://comfy.invalid", client)
	response := discoveryRequest(handler, http.MethodGet, "/system_stats", "Bearer harness-secret", nil)
	if response.Code != http.StatusBadGateway || strings.Contains(response.Body.String(), "private backend diagnostic") || strings.Contains(response.Body.String(), "Bearer") {
		t.Fatalf("non-2xx response was exposed or accepted: status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestComfyDiscoveryUsesBoundedRequestContext(t *testing.T) {
	observed := false
	var upstreamDeadline time.Time
	client := &http.Client{Transport: discoveryRoundTripper(func(request *http.Request) (*http.Response, error) {
		var hasDeadline bool
		upstreamDeadline, hasDeadline = request.Context().Deadline()
		if !hasDeadline {
			t.Error("discovery request has no deadline")
		}
		observed = true
		return discoveryResponse(http.StatusOK, `{}`, make(http.Header)), nil
	})}
	_, handler := newDiscoveryTestHarness(t, "http://comfy.invalid", client)
	started := time.Now()
	response := discoveryRequest(handler, http.MethodGet, "/object_info", "Bearer harness-secret", nil)
	if !observed || response.Code != http.StatusOK || upstreamDeadline.IsZero() || upstreamDeadline.After(started.Add(5*time.Second+100*time.Millisecond)) {
		t.Fatalf("discovery deadline exceeded five-second bound: observed=%v deadline=%s start=%s status=%d", observed, upstreamDeadline, started, response.Code)
	}
}

func TestComfyDiscoveryHonorsParentDeadline(t *testing.T) {
	var parentDeadline time.Time
	observed := false
	client := &http.Client{Transport: discoveryRoundTripper(func(request *http.Request) (*http.Response, error) {
		deadline, ok := request.Context().Deadline()
		if !ok || deadline.After(parentDeadline) {
			t.Errorf("discovery ignored parent deadline: hasDeadline=%v deadline=%s parent=%s", ok, deadline, parentDeadline)
		}
		observed = true
		<-request.Context().Done()
		return nil, request.Context().Err()
	})}
	_, handler := newDiscoveryTestHarness(t, "http://comfy.invalid", client)
	request := httptest.NewRequest(http.MethodGet, "/system_stats", nil)
	request.Header.Set("Authorization", "Bearer harness-secret")
	parentDeadline = time.Now().Add(100 * time.Millisecond)
	ctx, cancel := context.WithDeadline(request.Context(), parentDeadline)
	defer cancel()
	request = request.WithContext(ctx)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if !observed || response.Code != http.StatusBadGateway || strings.Contains(response.Body.String(), "context deadline exceeded") {
		t.Fatalf("expired parent deadline was not bounded and sanitized: observed=%v status=%d body=%s", observed, response.Code, response.Body.String())
	}
}

func TestComfyDiscoveryLeavesSharedClientUnchanged(t *testing.T) {
	redirectPolicy := func(*http.Request, []*http.Request) error { return errors.New("shared policy") }
	transport := discoveryRoundTripper(func(*http.Request) (*http.Response, error) {
		return discoveryResponse(http.StatusOK, `{}`, make(http.Header)), nil
	})
	client := &http.Client{Transport: transport, CheckRedirect: redirectPolicy, Timeout: 17 * time.Second}
	_, handler := newDiscoveryTestHarness(t, "http://comfy.invalid", client)
	response := discoveryRequest(handler, http.MethodGet, "/object_info", "Bearer harness-secret", nil)
	if response.Code != http.StatusOK || fmt.Sprintf("%p", client.Transport) != fmt.Sprintf("%p", transport) || client.Timeout != 17*time.Second || fmt.Sprintf("%p", client.CheckRedirect) != fmt.Sprintf("%p", redirectPolicy) {
		t.Fatalf("discovery mutated the shared client: status=%d timeout=%s", response.Code, client.Timeout)
	}
}
