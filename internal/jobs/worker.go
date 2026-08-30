// Package jobs implements the Phase 3 work queue engine (architecture.md
// §12 Work Item Reliability, §29 Jobs View, §33 Jobs API, §47 Phase 3), built
// by porting the proven lb-proxy mechanisms documented in
// docs/gateway-and-queue.md: zero-gap dispatch, cross-backend retry via a
// "tried" set, and client-abort/late-duplicate drop.
package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"sync"
	"sync/atomic"
	"time"

	"vram-governor/internal/domain"
	"vram-governor/internal/runtime/llamacpp"
)

// Result is what a Worker returns for one completed WorkItem.
type Result struct {
	Output string `json:"output"`
	Tokens int    `json:"tokens,omitempty"`
}

// Worker executes one WorkItem to completion (or failure). Implementations
// must be safe for concurrent use — the manager may dispatch multiple items
// to the same Worker in parallel up to its registered slot count.
type Worker interface {
	ID() string
	Execute(ctx context.Context, item domain.WorkItem) (Result, error)
}

// ---------------------------------------------------------------------
// MockWorker — deterministic, in-process stand-in used for all Phase 3
// verification. No GPU, no real engine, per the hard environment
// constraint. Configurable latency and failure injection let tests exercise
// lease-expiry, cross-worker retry, and capacity enforcement deterministically.
// ---------------------------------------------------------------------

// MockWorkerConfig configures a MockWorker.
type MockWorkerConfig struct {
	// MinLatency/MaxLatency bound a uniformly-random per-call sleep. If both
	// are zero, Execute returns immediately (after respecting ctx).
	MinLatency time.Duration
	MaxLatency time.Duration

	// AlwaysFail makes every call fail — used to prove cross-worker retry
	// redistributes work away from a permanently bad worker.
	AlwaysFail bool

	// FailEveryN, if > 0, fails every Nth call (1-indexed: calls 1, N+1,
	// 2N+1, ... fail if FailEveryN==N... actually calls number%N==0 fail).
	FailEveryN int

	// ConcurrencyLimit is the number of calls this worker will allow to run
	// at once. It is self-enforced: a call that arrives when the limit is
	// already saturated fails immediately with ErrConcurrencyExceeded. Tests
	// use this to prove the manager never over-dispatches to a worker.
	ConcurrencyLimit int
}

// ErrConcurrencyExceeded is returned by MockWorker.Execute when the caller
// (the manager) dispatched more concurrent work than ConcurrencyLimit
// allows — a self-enforced proof that capacity was violated.
var ErrConcurrencyExceeded = errors.New("mock worker: concurrency limit exceeded")

// ErrInjectedFailure is returned for deliberately-injected failures
// (AlwaysFail / FailEveryN).
var ErrInjectedFailure = errors.New("mock worker: injected failure")

type MockWorker struct {
	id  string
	cfg MockWorkerConfig

	active    int64 // current in-flight calls (atomic)
	maxActive int64 // high-water mark observed (atomic) — for test assertions
	callCount int64 // total calls (atomic), used for FailEveryN

	mu  sync.Mutex
	rng *rand.Rand
}

func NewMockWorker(id string, cfg MockWorkerConfig) *MockWorker {
	return &MockWorker{id: id, cfg: cfg, rng: rand.New(rand.NewSource(time.Now().UnixNano() + int64(len(id))))}
}

func (w *MockWorker) ID() string { return w.id }

// MaxActiveObserved returns the highest number of concurrent Execute calls
// this worker has ever seen — used by capacity tests.
func (w *MockWorker) MaxActiveObserved() int64 { return atomic.LoadInt64(&w.maxActive) }

func (w *MockWorker) Execute(ctx context.Context, item domain.WorkItem) (Result, error) {
	cur := atomic.AddInt64(&w.active, 1)
	defer atomic.AddInt64(&w.active, -1)
	for {
		prevMax := atomic.LoadInt64(&w.maxActive)
		if cur <= prevMax || atomic.CompareAndSwapInt64(&w.maxActive, prevMax, cur) {
			break
		}
	}

	if w.cfg.ConcurrencyLimit > 0 && cur > int64(w.cfg.ConcurrencyLimit) {
		return Result{}, fmt.Errorf("%w: worker=%s active=%d limit=%d", ErrConcurrencyExceeded, w.id, cur, w.cfg.ConcurrencyLimit)
	}

	call := atomic.AddInt64(&w.callCount, 1)

	// Simulate latency, honoring cancellation.
	if w.cfg.MaxLatency > 0 || w.cfg.MinLatency > 0 {
		lat := w.cfg.MinLatency
		if w.cfg.MaxLatency > w.cfg.MinLatency {
			w.mu.Lock()
			lat = w.cfg.MinLatency + time.Duration(w.rng.Int63n(int64(w.cfg.MaxLatency-w.cfg.MinLatency)+1))
			w.mu.Unlock()
		}
		select {
		case <-time.After(lat):
		case <-ctx.Done():
			return Result{}, ctx.Err()
		}
	}

	if w.cfg.AlwaysFail {
		return Result{}, fmt.Errorf("%w: worker=%s (always-fail)", ErrInjectedFailure, w.id)
	}
	if w.cfg.FailEveryN > 0 && call%int64(w.cfg.FailEveryN) == 0 {
		return Result{}, fmt.Errorf("%w: worker=%s (call %d)", ErrInjectedFailure, w.id, call)
	}

	prompt, _ := item.Payload["prompt"].(string)
	return Result{Output: "mock-completion-for:" + prompt, Tokens: len(prompt)}, nil
}

// ---------------------------------------------------------------------
// LlamaCppWorker — thin adapter over the Phase 2 llama.cpp driver's
// completion path. It compiles and satisfies Worker, but per the hard
// environment constraint (no GPU / no real engine in this phase) it is
// NEVER constructed or registered by the Phase 3 verification server, and
// is not exercised by any test in this phase. It is wired here purely so a
// later phase can register a pool of these instead of MockWorkers without
// changing the Worker interface or the manager.
// ---------------------------------------------------------------------

// LlamaCppWorker executes a WorkItem as a completion request against a
// managed llama.cpp engine instance via internal/runtime/llamacpp.Driver.Complete
// (the same call path the Phase 2 prober uses for throughput measurement).
type LlamaCppWorker struct {
	id     string
	driver *llamacpp.Driver
	engine *domain.EngineInstance
	slotID int
}

// NewLlamaCppWorker builds a real-engine worker bound to an already-launched
// engine instance. Intentionally unused/untested in Phase 3 — see package
// comment and worker_test.go for why (no GPU in this environment).
func NewLlamaCppWorker(id string, driver *llamacpp.Driver, engine *domain.EngineInstance, slotID int) *LlamaCppWorker {
	return &LlamaCppWorker{id: id, driver: driver, engine: engine, slotID: slotID}
}

func (w *LlamaCppWorker) ID() string { return w.id }

func (w *LlamaCppWorker) Execute(ctx context.Context, item domain.WorkItem) (Result, error) {
	prompt, _ := item.Payload["prompt"].(string)
	nPredict := 128
	if v, ok := positiveInt(item.Payload["n_predict"]); ok {
		nPredict = v
	}
	res, err := w.driver.Complete(ctx, w.engine, llamacpp.CompletionRequest{
		Prompt:      prompt,
		NPredict:    nPredict,
		CachePrompt: true,
		SlotID:      w.slotID,
	})
	if err != nil {
		return Result{}, err
	}
	return Result{Output: res.Content, Tokens: res.Timings.PredictedN}, nil
}

func positiveInt(v any) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, n > 0
	case int64:
		return int(n), n > 0
	case float64:
		return int(n), n > 0 && n == float64(int(n))
	case json.Number:
		i, err := n.Int64()
		return int(i), err == nil && i > 0
	default:
		return 0, false
	}
}
