package nodeagent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestCheckpointCustodyRejectsUnboundedAndForgedSourceRequests(t *testing.T) {
	s := &CheckpointCustodyStore{maxBytes: 32}
	if _, err := s.Prepare(context.Background(), CheckpointCustodySource{Path: "/tmp/model", ApprovedSHA256: "not-a-digest", ExpectedBytes: 1}); err == nil {
		t.Fatal("accepted malformed allowlist digest")
	}
	if _, err := s.Prepare(context.Background(), CheckpointCustodySource{Path: "/tmp/model", ApprovedSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ExpectedBytes: 33}); err == nil {
		t.Fatal("accepted source above explicit byte quota")
	}
}

func TestCheckpointCustodyStoreMutexHonorsContext(t *testing.T) {
	s := &CheckpointCustodyStore{}
	release, err := s.acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	if _, err = s.acquire(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("in-process store lock ignored acquisition deadline: %v", err)
	}
}

func TestCheckpointCustodyBeginRequiresExactlyOneModelPlaceholder(t *testing.T) {
	s := &CheckpointCustodyStore{}
	m := &CheckpointPreparedModel{store: s, path: "/private/model.gguf"}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	bytes, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(bytes)
	cmd := exec.Command(exe)
	if _, err := s.Begin(m, CheckpointCustodyLaunchRequest{Command: cmd, Endpoint: "http://127.0.0.1:1234", ServiceUnit: checkpointIdentityServiceUnit, ActualAlias: "test", ExpectedExecutableSHA256: hex.EncodeToString(sum[:])}); err == nil || !strings.Contains(err.Error(), "must name the prepared model") {
		t.Fatalf("custody rejection assertion: missing model placeholder was not rejected by model-argument validation (err=%v)", err)
	}
}

func TestCheckpointCustodyRejectsDuplicateModelPlaceholder(t *testing.T) {
	s := &CheckpointCustodyStore{}
	m := &CheckpointPreparedModel{store: s, path: "/private/model.gguf"}
	cmd := exec.Command("true", "{CHECKPOINT_MODEL}", "{CHECKPOINT_MODEL}")
	if _, err := s.Begin(m, CheckpointCustodyLaunchRequest{Command: cmd, Endpoint: "http://127.0.0.1:1234", ServiceUnit: checkpointIdentityServiceUnit, ActualAlias: "test", ExpectedExecutableSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}); err == nil {
		t.Fatal("accepted ambiguous model argument")
	}
}

func TestCheckpointCustodyIgnoresArgv0WhenParsingModelOptions(t *testing.T) {
	s := &CheckpointCustodyStore{}
	m := &CheckpointPreparedModel{store: s, path: "/private/model.gguf"}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := &exec.Cmd{Path: exe, Args: []string{"-m", "{CHECKPOINT_MODEL}"}}
	_, err = s.Begin(m, CheckpointCustodyLaunchRequest{Command: cmd, Endpoint: "http://127.0.0.1:1234", ServiceUnit: checkpointIdentityServiceUnit, ActualAlias: "test", ExpectedExecutableSHA256: strings.Repeat("a", 64)})
	if err == nil || !strings.Contains(err.Error(), "ambiguous model") {
		t.Fatalf("custody rejection assertion: argv0 was parsed as a model option: %v", err)
	}
	cmd.Args[0] = ""
	if _, err = s.Begin(m, CheckpointCustodyLaunchRequest{Command: cmd, Endpoint: "http://127.0.0.1:1234", ServiceUnit: checkpointIdentityServiceUnit, ActualAlias: "test", ExpectedExecutableSHA256: strings.Repeat("a", 64)}); err == nil || !strings.Contains(err.Error(), "argv0") {
		t.Fatalf("custody rejection assertion: empty argv0 was accepted: %v", err)
	}
}

func TestCheckpointCustodyQuotaArithmeticRejectsOverflowCases(t *testing.T) {
	max := int64(1<<63 - 1)
	cases := []struct {
		used, requested, reserve, limit int64
		want                            bool
	}{
		{used: 3, requested: 5, reserve: 2, limit: 10, want: true},
		{used: max, requested: 1, reserve: 0, limit: max},
		{used: 0, requested: max, reserve: 1, limit: max},
		{used: -1, requested: 0, reserve: 0, limit: max},
		{used: 1, requested: 1, reserve: -1, limit: max},
		{used: 0, requested: 0, reserve: 0, limit: -1},
	}
	for _, tc := range cases {
		if got := custodyQuotaFits(tc.used, tc.requested, tc.reserve, tc.limit); got != tc.want {
			t.Fatalf("custody quota arithmetic mismatch for %+v: got %v", tc, got)
		}
	}
}

func TestCheckpointCustodyAbortRejectsZeroValueLaunch(t *testing.T) {
	launch := &CheckpointControlledLaunch{}
	launch.mu.Lock()
	if err := launch.releaseUnstartedLocked(); err != nil {
		launch.mu.Unlock()
		t.Fatalf("nil command cleanup was not safe for a zero-value launch: %v", err)
	}
	launch.mu.Unlock()
	if err := launch.Abort(); err == nil {
		t.Fatal("custody rejection assertion: zero-value launch was treated as an authorized permit")
	}
	if launch.permit != nil {
		t.Fatal("zero-value launch unexpectedly acquired controlled-launch authority")
	}
}
