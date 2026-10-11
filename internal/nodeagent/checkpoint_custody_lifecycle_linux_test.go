//go:build linux

package nodeagent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func acquireCustodyTerminalReleaseTestGate(t *testing.T, launch *CheckpointControlledLaunch) func() {
	t.Helper()
	select {
	case <-launch.releaseGate:
		return func() { launch.releaseGate <- struct{}{} }
	case <-time.After(5 * time.Second):
		t.Fatal("terminal release worker did not return its serialization gate")
		return func() {}
	}
}

func acquireCustodyExecutableCleanupTestGate(t *testing.T, launch *CheckpointControlledLaunch) func() {
	t.Helper()
	select {
	case launch.executableCleanupGate <- struct{}{}:
		return func() { <-launch.executableCleanupGate }
	case <-time.After(5 * time.Second):
		t.Fatal("executable cleanup worker did not return its serialization gate")
		return func() {}
	}
}

func TestCheckpointCustodyLifecycleExactReleaseCycles(t *testing.T) {
	fixture := os.Getenv("CHECKPOINT_CUSTODY_TEST_DIR")
	if fixture == "" {
		t.Skip("kernel provisioning not requested")
	}
	base := filepath.Join(fixture, "source-lifecycle")
	if err := os.Mkdir(base, 0700); err != nil {
		t.Fatal(err)
	}
	sourcePath := filepath.Join(base, "source.gguf")
	payload := bytes.Repeat([]byte("x"), 2<<20)
	if err := os.WriteFile(sourcePath, payload, 0600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(payload)
	digest := hex.EncodeToString(sum[:])
	store, err := OpenCheckpointCustodyStore(CheckpointCustodyConfig{Root: filepath.Join(base, "custody"), MaxArtifactBytes: 20 << 20, MaxStagingBytes: 48 << 20, ReserveBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	prepare := func() *CheckpointPreparedModel {
		t.Helper()
		m, e := store.Prepare(context.Background(), CheckpointCustodySource{Path: sourcePath, ApprovedSHA256: digest, ExpectedBytes: int64(len(payload))})
		if e != nil {
			t.Fatalf("prepare lifecycle model: %v", e)
		}
		return m
	}
	assertEmpty := func() {
		t.Helper()
		for _, name := range []string{"models", "launchers", "receipts"} {
			entries, e := os.ReadDir(filepath.Join(store.root, name))
			if e != nil || len(entries) != 0 {
				t.Fatalf("lifecycle quota assertion: %s bytes remain after settled cleanup: entries=%v err=%v", name, entries, e)
			}
		}
	}
	quotaStore, err := OpenCheckpointCustodyStore(CheckpointCustodyConfig{Root: filepath.Join(base, "quota-custody"), MaxArtifactBytes: 3 << 20, MaxStagingBytes: 6 << 20, ReserveBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	var cumulativePrepared int64
	for cycle := 0; cycle < 4; cycle++ {
		m, e := quotaStore.Prepare(context.Background(), CheckpointCustodySource{Path: sourcePath, ApprovedSHA256: digest, ExpectedBytes: int64(len(payload))})
		if e != nil {
			t.Fatalf("quota lifecycle prepare %d: %v", cycle, e)
		}
		cumulativePrepared += m.identity.Size
		if e = m.Discard(context.Background()); e != nil {
			t.Fatalf("quota lifecycle discard %d: %v", cycle, e)
		}
		entries, e := os.ReadDir(filepath.Join(quotaStore.root, "models"))
		if e != nil || len(entries) != 0 {
			t.Fatalf("quota lifecycle flatness assertion: cycle=%d entries=%v err=%v", cycle, entries, e)
		}
	}
	if cumulativePrepared <= quotaStore.maxStagingBytes {
		t.Fatalf("quota lifecycle assertion: cumulative prepared bytes %d did not exceed staging limit %d", cumulativePrepared, quotaStore.maxStagingBytes)
	}

	unused := prepare()
	gateUnlock, err := unused.acquireLifecycle(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	discardCtx, discardCancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	if err = unused.Discard(discardCtx); !errors.Is(err, context.DeadlineExceeded) {
		discardCancel()
		gateUnlock()
		t.Fatalf("lifecycle race assertion: Discard ignored bounded Begin ownership wait: %v", err)
	}
	discardCancel()
	gateUnlock()
	if err = unused.Discard(context.Background()); err != nil {
		t.Fatalf("discard unused source: %v", err)
	}
	if err = unused.Discard(context.Background()); err != nil {
		t.Fatalf("repeat discard: %v", err)
	}
	assertEmpty()

	// An unsuccessful Begin consumes the source but returns ownership explicitly
	// to Discard once the call has settled.
	failedBegin := prepare()
	_, err = store.Begin(failedBegin, CheckpointCustodyLaunchRequest{Command: exec.Command(filepath.Join(base, "missing-executable"), "-m", "{CHECKPOINT_MODEL}"), Endpoint: "http://127.0.0.1:1", ServiceUnit: checkpointIdentityServiceUnit, ActualAlias: "lifecycle", ExpectedExecutableSHA256: strings.Repeat("a", 64)})
	if err == nil {
		t.Fatal("lifecycle rejection assertion: nonexistent executable completed Begin")
	}
	if err = failedBegin.Discard(context.Background()); err != nil {
		t.Fatalf("discard settled failed Begin source: %v", err)
	}
	if _, err = store.Begin(failedBegin, CheckpointCustodyLaunchRequest{Command: exec.Command(filepath.Join(base, "missing-executable"), "-m", "{CHECKPOINT_MODEL}"), Endpoint: "http://127.0.0.1:1", ServiceUnit: checkpointIdentityServiceUnit, ActualAlias: "lifecycle", ExpectedExecutableSHA256: strings.Repeat("a", 64)}); err == nil {
		t.Fatal("lifecycle rejection assertion: discarded failed-Begin source became reusable")
	}
	assertEmpty()

	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	executableBytes, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	executableSum := sha256.Sum256(executableBytes)
	executableDigest := hex.EncodeToString(executableSum[:])
	branchCounts := map[string]int{"failed-start-reclaim": 0, "receipt-replacement": 0, "concurrent-commit-settlement": 0, "model-sync-retry": 0, "receipt-pin-failure": 0, "receipt-sync-retry": 0}
	for _, failurePoint := range []string{"stage-after-pin", "begin-after-stage", "stage-directory-sync"} {
		failedModel := prepare()
		stageSyncHit := false
		if failurePoint == "stage-after-pin" {
			store.stageExecutableAfterPinTest = func(string) error { return errors.New("injected post-pin executable staging failure") }
		} else if failurePoint == "begin-after-stage" {
			store.beginAfterStageTest = func(string) error { return errors.New("injected post-stage Begin failure") }
		} else {
			store.syncTest = func(p string) error {
				if p == filepath.Join(store.root, "launchers") && !stageSyncHit {
					stageSyncHit = true
					return errors.New("injected post-publication executable directory sync failure")
				}
				return syncCustodyDir(p)
			}
		}
		_, beginErr := store.Begin(failedModel, CheckpointCustodyLaunchRequest{Command: exec.Command(executable, "-m", "{CHECKPOINT_MODEL}"), Endpoint: "http://127.0.0.1:1", ServiceUnit: checkpointIdentityServiceUnit, ActualAlias: "lifecycle-stage-failure", ExpectedExecutableSHA256: executableDigest})
		store.stageExecutableAfterPinTest = nil
		store.beginAfterStageTest = nil
		store.syncTest = nil
		if beginErr == nil {
			t.Fatalf("lifecycle staged-executable ownership assertion: %s failure unexpectedly returned a launch", failurePoint)
		}
		if failurePoint == "stage-directory-sync" && !stageSyncHit {
			t.Fatal("lifecycle staged-executable ownership assertion: directory-sync failure injection was not reached")
		}
		if failedModel.failedExecutableFD == nil || failedModel.failedExecutablePath == "" {
			t.Fatalf("lifecycle staged-executable ownership assertion: %s failure lost the original executable pin", failurePoint)
		}
		failedPath := failedModel.failedExecutablePath
		if err = failedModel.Discard(context.Background()); err != nil {
			t.Fatalf("discard %s failed-Begin executable and model: %v", failurePoint, err)
		}
		if _, e := os.Lstat(failedPath); !errors.Is(e, os.ErrNotExist) {
			t.Fatalf("lifecycle staged-executable cleanup assertion: %s path remains: %v", failurePoint, e)
		}
		launcherEntries, e := os.ReadDir(filepath.Join(store.root, "launchers"))
		if e != nil || len(launcherEntries) != 0 {
			t.Fatalf("lifecycle staged-executable quota assertion: %s entries=%v err=%v", failurePoint, launcherEntries, e)
		}
	}
	abortModel := prepare()
	abortCmd := exec.Command(executable, "-test.run=^TestCustodyChildProcess$", "--", "-m", "{CHECKPOINT_MODEL}")
	abortLaunch, err := store.Begin(abortModel, CheckpointCustodyLaunchRequest{Command: abortCmd, Endpoint: "http://127.0.0.1:1", ServiceUnit: checkpointIdentityServiceUnit, ActualAlias: "lifecycle-abort", ExpectedExecutableSHA256: executableDigest})
	if err != nil {
		t.Fatalf("begin abort fixture: %v", err)
	}
	if err = abortLaunch.Abort(); err != nil {
		t.Fatalf("abort unstarted launch: %v", err)
	}
	if err = abortLaunch.ReleaseTerminal(context.Background()); err != nil {
		t.Fatalf("release aborted launch: %v", err)
	}
	assertEmpty()
	for cycle := 0; cycle < 6; cycle++ {
		model := prepare()
		probe, e := net.Listen("tcp", "127.0.0.1:0")
		if e != nil {
			t.Fatal(e)
		}
		addr := probe.Addr().String()
		_ = probe.Close()
		cmd := exec.Command(executable, "-test.run=^TestCustodyChildProcess$", "--", "-m", "{CHECKPOINT_MODEL}")
		cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
		cmd.Env = append(os.Environ(), "CHECKPOINT_CUSTODY_CHILD=1", "CHECKPOINT_CUSTODY_ENDPOINT="+addr)
		launch, e := store.Begin(model, CheckpointCustodyLaunchRequest{Command: cmd, Endpoint: "http://" + addr, ServiceUnit: checkpointIdentityServiceUnit, ActualAlias: "lifecycle", ExpectedExecutableSHA256: executableDigest})
		if e != nil {
			t.Fatalf("begin lifecycle launch: %v", e)
		}
		if e = model.Discard(context.Background()); e == nil {
			t.Fatal("lifecycle rejection assertion: Begin-consumed source was discarded")
		}
		if cycle == 0 {
			launch.cmd.Args = []string{launch.cmd.Args[0]}
			if e = launch.Start(); e == nil {
				t.Fatal("lifecycle rejection assertion: malformed Start unexpectedly launched")
			}
			if e = launch.ReleaseTerminal(context.Background()); e != nil {
				t.Fatalf("release failed Start source: %v", e)
			}
			branchCounts["failed-start-reclaim"]++
			assertEmpty()
			continue
		}
		if e = launch.Start(); e != nil {
			t.Fatalf("start lifecycle child: %v", e)
		}
		if e = model.Discard(context.Background()); e == nil {
			_ = stopCustodyTestChild(launch)
			t.Fatal("lifecycle rejection assertion: active child's model source was discarded")
		}
		if !waitForCustodyEndpoint(addr, 5*time.Second) {
			_ = stopCustodyTestChild(launch)
			t.Fatal("lifecycle child did not bind endpoint")
		}
		if cycle == 2 {
			barrier := make(chan struct{})
			entered := make(chan struct{})
			launch.commitTestBarrier, launch.commitTestEntered = barrier, entered
			commitDone := make(chan error, 1)
			go func() { commitDone <- launch.Commit(context.Background()) }()
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				_ = stopCustodyTestChild(launch)
				t.Fatal("commit lifecycle barrier was not reached")
			}
			if e = launch.ReleaseTerminal(context.Background()); e == nil {
				close(barrier)
				_ = stopCustodyTestChild(launch)
				t.Fatal("lifecycle rejection assertion: release raced unsettled Commit")
			}
			close(barrier)
			if e = <-commitDone; e != nil {
				_ = stopCustodyTestChild(launch)
				t.Fatalf("settle concurrent lifecycle Commit: %v", e)
			}
			branchCounts["concurrent-commit-settlement"]++
		} else if cycle == 4 {
			launch.receiptPinFailureTest = true
			if e = launch.Commit(context.Background()); e == nil {
				_ = stopCustodyTestChild(launch)
				t.Fatal("lifecycle receipt-pin assertion: Commit succeeded without retaining the original receipt inode before publication")
			}
		} else if cycle == 5 {
			receiptDir := filepath.Join(store.root, "receipts")
			syncFailures := 0
			store.syncTest = func(p string) error {
				if p == receiptDir && syncFailures < 2 {
					syncFailures++
					return errors.New("test post-publication receipt directory sync failure")
				}
				return syncCustodyDir(p)
			}
			if e = launch.Commit(context.Background()); e == nil {
				_ = stopCustodyTestChild(launch)
				t.Fatal("lifecycle receipt-sync assertion: Commit hid post-publication directory sync and cleanup failures")
			}
			store.syncTest = nil
			if e = launch.Commit(context.Background()); e == nil {
				_ = stopCustodyTestChild(launch)
				t.Fatal("lifecycle receipt-sync assertion: a failed Commit attempt was retried with stale receipt cleanup state")
			}
			if _, e = os.Lstat(custodyReceiptPath(store.root, launch.nonce)); !errors.Is(e, os.ErrNotExist) {
				_ = stopCustodyTestChild(launch)
				t.Fatalf("lifecycle receipt-sync assertion: rejected repeated Commit published another receipt: %v", e)
			}
			if _, e = os.Lstat(model.path); e != nil {
				_ = stopCustodyTestChild(launch)
				t.Fatalf("lifecycle receipt-sync assertion: model was released before original receipt cleanup settled: %v", e)
			}
			if _, e = os.Lstat(custodyReceiptPath(store.root, launch.nonce)); !errors.Is(e, os.ErrNotExist) {
				_ = stopCustodyTestChild(launch)
				t.Fatalf("lifecycle receipt-sync assertion: expected original receipt unlink with unsettled directory sync, got %v", e)
			}
		} else if e = launch.Commit(context.Background()); e != nil {
			_ = stopCustodyTestChild(launch)
			t.Fatalf("commit lifecycle receipt: %v", e)
		}
		if e = launch.ReleaseTerminal(context.Background()); e == nil {
			_ = stopCustodyTestChild(launch)
			t.Fatal("lifecycle rejection assertion: active child source released before exact reap")
		}
		receiptPath := custodyReceiptPath(store.root, launch.nonce)
		if cycle == 1 {
			originalReceipt, e := os.ReadFile(receiptPath)
			if e != nil {
				t.Fatal(e)
			}
			var signed custodySignedReceipt
			if e = json.Unmarshal(originalReceipt, &signed); e != nil {
				t.Fatal(e)
			}
			signed.Signature = strings.Repeat("00", ed25519.SignatureSize)
			badSignature, e := json.Marshal(signed)
			if e != nil {
				t.Fatal(e)
			}
			if e = os.WriteFile(receiptPath, badSignature, 0600); e != nil {
				t.Fatal(e)
			}
			if e = stopCustodyTestChild(launch); !errors.Is(e, context.DeadlineExceeded) {
				t.Fatalf("expected bounded exact reap after cancellation, got %v", e)
			}
			if e = launch.ReleaseTerminal(context.Background()); e == nil {
				t.Fatal("lifecycle rejection assertion: invalid receipt signature bytes were released")
			}
			if e = os.WriteFile(receiptPath, originalReceipt, 0600); e != nil {
				t.Fatal(e)
			}
			if e = os.Chown(receiptPath, os.Getuid()+1, os.Getgid()+1); e != nil {
				t.Fatalf("change fixture receipt owner: %v", e)
			}
			if e = launch.ReleaseTerminal(context.Background()); e == nil {
				t.Fatal("lifecycle rejection assertion: wrong-owner receipt inode was released")
			}
			if e = os.Chown(receiptPath, os.Getuid(), os.Getgid()); e != nil {
				t.Fatalf("restore fixture receipt owner: %v", e)
			}
			saved := receiptPath + ".saved"
			if e = os.Rename(receiptPath, saved); e != nil {
				t.Fatal(e)
			}
			if e = syscall.Mkfifo(receiptPath, 0600); e != nil {
				_ = os.Rename(saved, receiptPath)
				t.Fatal(e)
			}
			if e = launch.ReleaseTerminal(context.Background()); e == nil {
				t.Fatal("lifecycle rejection assertion: FIFO receipt path was released")
			}
			if e = os.Remove(receiptPath); e != nil {
				t.Fatal(e)
			}
			if e = os.Symlink(saved, receiptPath); e != nil {
				_ = os.Rename(saved, receiptPath)
				t.Fatal(e)
			}
			if e = launch.ReleaseTerminal(context.Background()); e == nil {
				t.Fatal("lifecycle rejection assertion: symlink receipt replacement was released")
			}
			if e = os.Remove(receiptPath); e != nil {
				t.Fatal(e)
			}
			if e = os.WriteFile(receiptPath, originalReceipt, 0600); e != nil {
				t.Fatal(e)
			}
			if e = launch.ReleaseTerminal(context.Background()); e == nil {
				t.Fatal("lifecycle rejection assertion: replacement receipt inode was released")
			}
			if e = os.Remove(receiptPath); e != nil {
				t.Fatal(e)
			}
			if e = os.Rename(saved, receiptPath); e != nil {
				t.Fatal(e)
			}
			branchCounts["receipt-replacement"]++
		} else if cycle == 3 {
			movedExecutable := launch.executablePath + ".reaper-original"
			if e = os.Rename(launch.executablePath, movedExecutable); e != nil {
				t.Fatal(e)
			}
			if e = os.WriteFile(launch.executablePath, []byte("reaper replacement executable"), 0500); e != nil {
				_ = os.Rename(movedExecutable, launch.executablePath)
				t.Fatal(e)
			}
			launch.mu.Lock()
			killErr := killCheckpointChildPlatform(launch.pidfd)
			launch.mu.Unlock()
			if killErr != nil {
				t.Fatalf("signal exact child before reaper cleanup cancellation: %v", killErr)
			}
			e = launch.WaitContext(context.Background())
			if e == nil || !strings.Contains(e.Error(), "captured entry identity differs from original held inode") {
				t.Fatalf("lifecycle executable reaper pin assertion: replaced path did not make automatic cleanup fail closed: %v", e)
			}
			if got, readErr := os.ReadFile(launch.executablePath); readErr != nil || string(got) != "reaper replacement executable" {
				t.Fatalf("lifecycle executable reaper preservation assertion: replacement was removed or changed: %q err=%v", got, readErr)
			}
			if e = os.Remove(launch.executablePath); e != nil {
				t.Fatal(e)
			}
			if e = os.Rename(movedExecutable, launch.executablePath); e != nil {
				t.Fatal(e)
			}
			launch.mu.Lock()
			reaperRetainedAuthority := launch.reaped && launch.terminal && launch.executableFD != nil
			launch.mu.Unlock()
			if !reaperRetainedAuthority {
				t.Fatal("lifecycle executable reaper pin assertion: failed automatic cleanup lost exact reap or executable pin")
			}

			ctx, cancel := context.WithCancel(context.Background())
			captureHit := make(chan struct{}, 1)
			store.cleanupAfterCaptureTest = func(candidate, _ string) {
				if candidate == launch.executablePath {
					store.cleanupAfterCaptureTest = nil
					captureHit <- struct{}{}
					cancel()
				}
			}
			e = launch.ReleaseTerminal(ctx)
			cancel()
			if !errors.Is(e, context.Canceled) {
				t.Fatalf("lifecycle executable terminal cancellation assertion: expected cancellation after capture, got %v", e)
			}
			select {
			case <-captureHit:
			case <-time.After(5 * time.Second):
				t.Fatal("lifecycle executable terminal cancellation callback was not reached")
			}
			func() {
				releaseOuter := acquireCustodyTerminalReleaseTestGate(t, launch)
				defer releaseOuter()
				releaseExecutable := acquireCustodyExecutableCleanupTestGate(t, launch)
				defer releaseExecutable()
				captured, removed := launch.executableCleanup.Captured, launch.executableCleanup.Removed
				launch.mu.Lock()
				pinned := launch.executableFD != nil
				reaped, terminal := launch.reaped, launch.terminal
				launch.mu.Unlock()
				store.cleanupAfterCaptureTest = nil
				if !captured || removed || !pinned || !reaped || !terminal {
					t.Fatalf("lifecycle executable terminal cancellation lost exact retry authority: captured=%t removed=%t pinned=%t reaped=%t terminal=%t", captured, removed, pinned, reaped, terminal)
				}
			}()
		} else {
			if e = stopCustodyTestChild(launch); !errors.Is(e, context.DeadlineExceeded) {
				t.Fatalf("expected bounded exact reap after cancellation, got %v", e)
			}
		}
		if cycle == 3 {
			ctx, cancel := context.WithCancel(context.Background())
			captureHit := make(chan struct{}, 1)
			store.cleanupAfterCaptureTest = func(candidate, _ string) {
				if candidate == receiptPath {
					store.cleanupAfterCaptureTest = nil
					captureHit <- struct{}{}
					cancel()
				}
			}
			if e = launch.ReleaseTerminal(ctx); !errors.Is(e, context.Canceled) {
				cancel()
				t.Fatalf("lifecycle receipt capture cancellation assertion: expected cancellation after receipt capture, got %v", e)
			}
			cancel()
			select {
			case <-captureHit:
			case <-time.After(5 * time.Second):
				t.Fatal("lifecycle receipt cancellation callback was not reached")
			}
			func() {
				releaseOuter := acquireCustodyTerminalReleaseTestGate(t, launch)
				defer releaseOuter()
				captured, removed := launch.receiptCleanup.Captured, launch.receiptCleanup.Removed
				store.cleanupAfterCaptureTest = nil
				if !captured || removed {
					t.Fatalf("lifecycle receipt capture cancellation lost retry state: captured=%t removed=%t", captured, removed)
				}
			}()
		}
		if cycle == 4 {
			if _, e = os.Lstat(custodyReceiptPath(store.root, launch.nonce)); !errors.Is(e, os.ErrNotExist) {
				t.Fatalf("lifecycle receipt-pin assertion: failed pre-publication pin left a receipt behind: %v", e)
			}
			if _, e = os.Lstat(model.path); e != nil {
				t.Fatalf("lifecycle receipt-pin assertion: model disappeared before failed Commit settled: %v", e)
			}
		}
		if cycle == 4 || cycle == 5 {
			if e = launch.ReleaseTerminal(context.Background()); e != nil {
				t.Fatalf("release failed receipt publication fixture after exact reap: %v", e)
			}
			assertEmpty()
			if cycle == 4 {
				branchCounts["receipt-pin-failure"]++
			} else {
				branchCounts["receipt-sync-retry"]++
			}
			continue
		}
		if cycle == 2 {
			receiptDir := filepath.Join(store.root, "receipts")
			failed := false
			store.syncTest = func(p string) error {
				if p == receiptDir && !failed {
					failed = true
					return errors.New("test receipt directory sync failure")
				}
				return syncCustodyDir(p)
			}
			if e = launch.ReleaseTerminal(context.Background()); e == nil {
				t.Fatal("lifecycle retry assertion: receipt directory sync failure was hidden")
			}
			if _, e = os.Lstat(receiptPath); !errors.Is(e, os.ErrNotExist) {
				t.Fatalf("lifecycle partial receipt removal assertion: expected removed receipt, got %v", e)
			}
			if _, e = os.Lstat(model.path); e != nil {
				t.Fatalf("lifecycle partial receipt removal assertion: model was removed before receipt sync settled: %v", e)
			}
			store.syncTest = nil
		} else if cycle == 3 {
			modelDir := filepath.Join(store.root, "models")
			failed := false
			store.syncTest = func(p string) error {
				if p == modelDir && !failed {
					failed = true
					return errors.New("test model directory sync failure")
				}
				return syncCustodyDir(p)
			}
			if e = launch.ReleaseTerminal(context.Background()); e == nil {
				t.Fatal("lifecycle retry assertion: model directory sync failure was hidden")
			}
			if _, e = os.Lstat(receiptPath); !errors.Is(e, os.ErrNotExist) {
				t.Fatalf("lifecycle partial model removal assertion: receipt remains: %v", e)
			}
			if _, e = os.Lstat(model.path); !errors.Is(e, os.ErrNotExist) {
				t.Fatalf("lifecycle partial model removal assertion: expected removed model, got %v", e)
			}
			store.syncTest = nil
			branchCounts["model-sync-retry"]++
		}
		if cycle == 1 {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			if e = launch.ReleaseTerminal(ctx); !errors.Is(e, context.Canceled) {
				t.Fatalf("lifecycle cancellation assertion: canceled release was not rejected: %v", e)
			}
		}
		if e = launch.ReleaseTerminal(context.Background()); e != nil {
			t.Fatalf("release exactly reaped launch: %v", e)
		}
		if e = launch.ReleaseTerminal(context.Background()); e != nil {
			t.Fatalf("idempotent terminal release: %v", e)
		}
		assertEmpty()
	}
	for scenario, count := range branchCounts {
		if count != 1 {
			t.Fatalf("lifecycle observable scenario assertion: %s ran %d times, want exactly 1", scenario, count)
		}
	}
	t.Logf("lifecycle observable scenario counts: failed-start-reclaim=%d receipt-replacement=%d concurrent-commit-settlement=%d model-sync-retry=%d receipt-pin-failure=%d receipt-sync-retry=%d",
		branchCounts["failed-start-reclaim"], branchCounts["receipt-replacement"], branchCounts["concurrent-commit-settlement"], branchCounts["model-sync-retry"], branchCounts["receipt-pin-failure"], branchCounts["receipt-sync-retry"])
}

func TestCheckpointCustodyLifecycleRejectsReplacedModel(t *testing.T) {
	fixture := os.Getenv("CHECKPOINT_CUSTODY_TEST_DIR")
	if fixture == "" {
		t.Skip("kernel provisioning not requested")
	}
	base := filepath.Join(fixture, "source-lifecycle-replacement")
	if err := os.Mkdir(base, 0700); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(base, "source.gguf")
	payload := []byte("replacement lifecycle fixture\n")
	if err := os.WriteFile(source, payload, 0600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(payload)
	store, err := OpenCheckpointCustodyStore(CheckpointCustodyConfig{Root: filepath.Join(base, "custody"), MaxArtifactBytes: 1 << 20, MaxStagingBytes: 8 << 20, ReserveBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	model, err := store.Prepare(context.Background(), CheckpointCustodySource{Path: source, ApprovedSHA256: hex.EncodeToString(sum[:]), ExpectedBytes: int64(len(payload))})
	if err != nil {
		t.Fatal(err)
	}
	moved := model.path + ".saved"
	if err = os.Rename(model.path, moved); err != nil {
		t.Fatal(err)
	}
	if err = syscall.Mkfifo(model.path, 0600); err != nil {
		t.Fatal(err)
	}
	if err = model.Discard(context.Background()); err == nil {
		t.Fatal("lifecycle rejection assertion: FIFO model path was discarded")
	}
	if err = os.Remove(model.path); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(model.path, []byte("replacement inode\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = verifyCustodyModelPath(model); err == nil {
		t.Fatal("lifecycle rejection assertion: replaced model inode passed exact path verification")
	}
	if err = model.Discard(context.Background()); err == nil {
		t.Fatal("lifecycle rejection assertion: replaced model inode was discarded")
	}
	if _, err = os.Lstat(moved); err != nil {
		t.Fatalf("lifecycle preservation assertion: original model inode was removed: %v", err)
	}
	if err = os.Remove(model.path); err != nil {
		t.Fatal(err)
	}
	if err = os.Rename(moved, model.path); err != nil {
		t.Fatal(err)
	}
	store.cleanupBeforeCaptureTest = func(path, _ string) {
		if path != model.path {
			return
		}
		store.cleanupBeforeCaptureTest = nil
		if e := os.Rename(path, moved); e != nil {
			t.Fatalf("replace source immediately before atomic capture: %v", e)
		}
		if e := os.WriteFile(path, []byte("pre-capture replacement\n"), 0600); e != nil {
			t.Fatalf("install pre-capture replacement: %v", e)
		}
	}
	if err = model.Discard(context.Background()); err == nil {
		t.Fatal("lifecycle capture assertion: pre-capture replacement was discarded as the original model")
	}
	if got, e := os.ReadFile(model.path); e != nil || string(got) != "pre-capture replacement\n" {
		t.Fatalf("lifecycle capture preservation assertion: replacement was lost or changed: %q err=%v", got, e)
	}
	if err = os.Remove(model.path); err != nil {
		t.Fatal(err)
	}
	if err = os.Rename(moved, model.path); err != nil {
		t.Fatal(err)
	}
	modelDir := filepath.Join(store.root, "models")
	failedSync := false
	store.syncTest = func(p string) error {
		if p == modelDir && !failedSync {
			failedSync = true
			return errors.New("test model capture directory sync failure")
		}
		return syncCustodyDir(p)
	}
	if err = model.Discard(context.Background()); err == nil {
		t.Fatal("lifecycle capture retry assertion: model capture directory sync failure was hidden")
	}
	if !model.discardCleanup.Captured || model.discardCleanup.Removed {
		t.Fatalf("lifecycle model capture sync failure lost retry state: %+v", model.discardCleanup)
	}
	store.syncTest = nil
	if err = model.Discard(context.Background()); err != nil {
		t.Fatalf("same fixture positive control: restored original model inode was not discarded after captured sync retry: %v", err)
	}
}

func TestCheckpointCustodyLifecycleCapturePreservesPreCaptureReplacement(t *testing.T) {
	fixture := os.Getenv("CHECKPOINT_CUSTODY_TEST_DIR")
	if fixture == "" {
		t.Skip("kernel provisioning not requested")
	}
	root := filepath.Join(fixture, "source-lifecycle-capture-race")
	store, err := OpenCheckpointCustodyStore(CheckpointCustodyConfig{Root: root, MaxArtifactBytes: 1 << 20, MaxStagingBytes: 8 << 20, ReserveBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	for _, category := range []struct{ name, dir string }{
		{"shared-helper", filepath.Join(root, "models")},
		{"receipt", filepath.Join(root, "receipts")},
		{"executable", filepath.Join(root, "launchers")},
	} {
		t.Run(category.name, func(t *testing.T) {
			path := filepath.Join(category.dir, "capture-race-object")
			original := path + ".original"
			if err := os.WriteFile(path, []byte("pinned original bytes"), 0600); err != nil {
				t.Fatal(err)
			}
			held, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer held.Close()
			store.cleanupBeforeCaptureTest = func(candidate, _ string) {
				if candidate != path {
					return
				}
				store.cleanupBeforeCaptureTest = nil
				if e := os.Rename(path, original); e != nil {
					t.Fatalf("move original immediately before capture: %v", e)
				}
				if e := os.WriteFile(path, []byte("replacement bytes"), 0600); e != nil {
					t.Fatalf("install replacement before capture: %v", e)
				}
			}
			state := custodyCleanupState{}
			syncDir := func() error { return syncCustodyDir(category.dir) }
			if err = captureAndRemoveCustodyPath(context.Background(), store, path, held, &state, nil, syncDir); err == nil {
				t.Fatal("lifecycle capture assertion: pre-capture replacement was removed")
			}
			if got, e := os.ReadFile(path); e != nil || string(got) != "replacement bytes" {
				t.Fatalf("replacement was not restored intact: %q err=%v", got, e)
			}
			if e := verifyCustodyEntryAgainstHeld(original, held); e != nil {
				t.Fatalf("pinned original was not preserved: %v", e)
			}
			if state.Captured || state.Removed || state.CaptureName != "" {
				t.Fatalf("wrong-object capture state was not reset after restore: %+v", state)
			}
			if err = os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err = os.Rename(original, path); err != nil {
				t.Fatal(err)
			}
			store.cleanupBeforeCaptureTest = nil
			if err = captureAndRemoveCustodyPath(context.Background(), store, path, held, &state, nil, syncDir); err != nil {
				t.Fatalf("capture and remove restored original: %v", err)
			}
			if !state.Removed || !state.Synced {
				t.Fatalf("cleanup state did not settle after retry: %+v", state)
			}
		})
	}
	t.Run("cancel-after-capture-retry", func(t *testing.T) {
		path := filepath.Join(root, "models", "cancel-capture-object")
		if err := os.WriteFile(path, []byte("cancel retry bytes"), 0600); err != nil {
			t.Fatal(err)
		}
		held, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		defer held.Close()
		state := custodyCleanupState{}
		ctx, cancel := context.WithCancel(context.Background())
		store.cleanupAfterCaptureTest = func(candidate, capture string) {
			if candidate == path {
				store.cleanupAfterCaptureTest = nil
				cancel()
			}
		}
		if err = captureAndRemoveCustodyPath(ctx, store, path, held, &state, nil, nil); !errors.Is(err, context.Canceled) {
			t.Fatalf("expected cancellation after atomic capture, got %v", err)
		}
		if !state.Captured || state.Removed {
			t.Fatalf("cancellation lost recoverable capture state: %+v", state)
		}
		if _, err = os.Lstat(filepath.Join(filepath.Dir(path), state.CaptureName)); err != nil {
			t.Fatalf("captured object was not retained: %v", err)
		}
		store.cleanupAfterCaptureTest = nil
		if err = captureAndRemoveCustodyPath(context.Background(), store, path, held, &state, nil, nil); err != nil {
			t.Fatalf("retry after captured cancellation: %v", err)
		}
		if !state.Removed || !state.Synced {
			t.Fatalf("cancellation retry did not settle: %+v", state)
		}
	})
	t.Run("capture-sync-failure-retry", func(t *testing.T) {
		path := filepath.Join(root, "models", "sync-capture-object")
		if err := os.WriteFile(path, []byte("sync retry bytes"), 0600); err != nil {
			t.Fatal(err)
		}
		held, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		defer held.Close()
		state := custodyCleanupState{}
		calls := 0
		syncDir := func() error {
			calls++
			if calls == 1 {
				return errors.New("injected capture sync failure")
			}
			return syncCustodyDir(filepath.Dir(path))
		}
		if err = captureAndRemoveCustodyPath(context.Background(), store, path, held, &state, nil, syncDir); err == nil {
			t.Fatal("capture directory sync failure was hidden")
		}
		if !state.Captured || state.Removed {
			t.Fatalf("capture sync failure lost retry state: %+v", state)
		}
		if err = captureAndRemoveCustodyPath(context.Background(), store, path, held, &state, nil, syncDir); err != nil {
			t.Fatalf("retry after capture sync failure: %v", err)
		}
		if !state.Removed || !state.Synced {
			t.Fatalf("capture sync retry did not settle: %+v", state)
		}
	})
	t.Run("captured-fifo-preserved", func(t *testing.T) {
		path := filepath.Join(root, "models", "fifo-capture-object")
		original := path + ".original"
		if err := os.WriteFile(path, []byte("pinned fifo fixture bytes"), 0600); err != nil {
			t.Fatal(err)
		}
		held, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		defer held.Close()
		store.cleanupBeforeCaptureTest = func(candidate, _ string) {
			if candidate != path {
				return
			}
			store.cleanupBeforeCaptureTest = nil
			if e := os.Rename(path, original); e != nil {
				t.Fatalf("move original before FIFO replacement: %v", e)
			}
			if e := syscall.Mkfifo(path, 0600); e != nil {
				t.Fatalf("install FIFO replacement: %v", e)
			}
		}
		state := custodyCleanupState{}
		if err = captureAndRemoveCustodyPath(context.Background(), store, path, held, &state, nil, nil); err == nil {
			t.Fatal("captured FIFO replacement was accepted as the original object")
		}
		fi, e := os.Lstat(path)
		if e != nil || fi.Mode()&os.ModeNamedPipe == 0 {
			t.Fatalf("wrong captured FIFO was not restored and preserved: info=%v err=%v", fi, e)
		}
		if e = verifyCustodyEntryAgainstHeld(original, held); e != nil {
			t.Fatalf("original pinned inode was not preserved beside FIFO: %v", e)
		}
		if e = os.Remove(path); e != nil {
			t.Fatal(e)
		}
		if e = os.Rename(original, path); e != nil {
			t.Fatal(e)
		}
		if err = captureAndRemoveCustodyPath(context.Background(), store, path, held, &state, nil, nil); err != nil {
			t.Fatalf("retry original after FIFO preservation: %v", err)
		}
	})
	t.Run("executable-sync-retry", func(t *testing.T) {
		path := filepath.Join(root, "launchers", "executable-capture-object")
		if err := os.WriteFile(path, []byte("executable fixture bytes"), 0600); err != nil {
			t.Fatal(err)
		}
		held, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		defer held.Close()
		state := custodyCleanupState{}
		failedSync := false
		store.syncTest = func(p string) error {
			if p == filepath.Join(root, "launchers") && !failedSync {
				failedSync = true
				return errors.New("test executable capture sync failure")
			}
			return syncCustodyDir(p)
		}
		if err = releaseCheckpointExecutablePlatform(store, path, held, &state); err == nil {
			t.Fatal("executable capture directory sync failure was hidden")
		}
		if !state.Captured || state.Removed {
			t.Fatalf("executable capture sync failure lost retry state: %+v", state)
		}
		store.syncTest = nil
		if err = releaseCheckpointExecutablePlatform(store, path, held, &state); err != nil {
			t.Fatalf("retry executable capture cleanup: %v", err)
		}
		if !state.Removed || !state.Synced {
			t.Fatalf("executable cleanup retry did not settle: %+v", state)
		}
	})
	t.Run("executable-cancel-after-capture-retry", func(t *testing.T) {
		path := filepath.Join(root, "launchers", "executable-cancel-object")
		if err := os.WriteFile(path, []byte("executable cancel bytes"), 0600); err != nil {
			t.Fatal(err)
		}
		held, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		defer held.Close()
		state := custodyCleanupState{}
		ctx, cancel := context.WithCancel(context.Background())
		store.cleanupAfterCaptureTest = func(candidate, _ string) {
			if candidate == path {
				store.cleanupAfterCaptureTest = nil
				cancel()
			}
		}
		if err = releaseCheckpointExecutableContextPlatform(ctx, store, path, held, &state); !errors.Is(err, context.Canceled) {
			cancel()
			t.Fatalf("executable capture cancellation was ignored: %v", err)
		}
		cancel()
		store.cleanupAfterCaptureTest = nil
		if !state.Captured || state.Removed {
			t.Fatalf("executable capture cancellation lost retry state: %+v", state)
		}
		if err = releaseCheckpointExecutableContextPlatform(context.Background(), store, path, held, &state); err != nil {
			t.Fatalf("retry executable after captured cancellation: %v", err)
		}
		if !state.Removed || !state.Synced {
			t.Fatalf("executable capture cancellation retry did not settle: %+v", state)
		}
	})
}

func TestCheckpointCustodyLifecycleExecutableAlreadyUnlinked(t *testing.T) {
	fixture := os.Getenv("CHECKPOINT_CUSTODY_TEST_DIR")
	if fixture == "" {
		t.Skip("kernel provisioning not requested")
	}
	root := filepath.Join(fixture, "source-lifecycle-unlinked-executable")
	store, err := OpenCheckpointCustodyStore(CheckpointCustodyConfig{Root: root, MaxArtifactBytes: 1 << 20, MaxStagingBytes: 8 << 20, ReserveBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	launcherDir := filepath.Join(root, "launchers")
	path := filepath.Join(launcherDir, "already-unlinked-executable")
	if err = os.WriteFile(path, []byte("pinned executable bytes"), 0500); err != nil {
		t.Fatal(err)
	}
	held, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	if err = os.Remove(path); err != nil {
		t.Fatal(err)
	}
	state := custodyCleanupState{}
	if err = releaseCheckpointExecutableContextPlatform(context.Background(), store, path, held, &state); err != nil {
		t.Fatalf("settle already-unlinked exact executable pin: %v", err)
	}
	if !state.Removed || !state.Synced {
		t.Fatalf("already-unlinked executable cleanup did not sync and settle: %+v", state)
	}
	if _, err = os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("positive control: unexpected executable path after settlement: %v", err)
	}

	replacementPath := filepath.Join(launcherDir, "unlinked-executable-replacement")
	if err = os.WriteFile(replacementPath, []byte("original executable bytes"), 0500); err != nil {
		t.Fatal(err)
	}
	replacementPin, err := os.Open(replacementPath)
	if err != nil {
		t.Fatal(err)
	}
	defer replacementPin.Close()
	if err = os.Remove(replacementPath); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(replacementPath, []byte("unrelated replacement"), 0500); err != nil {
		t.Fatal(err)
	}
	replacementState := custodyCleanupState{}
	if err = releaseCheckpointExecutableContextPlatform(context.Background(), store, replacementPath, replacementPin, &replacementState); err == nil {
		t.Fatal("lifecycle executable cleanup assertion: already-unlinked pin authorized cleanup with a replacement path")
	}
	if got, readErr := os.ReadFile(replacementPath); readErr != nil || string(got) != "unrelated replacement" {
		t.Fatalf("lifecycle executable preservation assertion: replacement was removed or changed: %q err=%v", got, readErr)
	}
}

func TestCheckpointCustodyLifecycleAbortRetryRejectsReplacement(t *testing.T) {
	fixture := os.Getenv("CHECKPOINT_CUSTODY_TEST_DIR")
	if fixture == "" {
		t.Skip("kernel provisioning not requested")
	}
	base := filepath.Join(fixture, "source-lifecycle-abort-retry")
	if err := os.Mkdir(base, 0700); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(base, "source.gguf")
	payload := []byte("abort retry lifecycle source\n")
	if err := os.WriteFile(source, payload, 0600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(payload)
	store, err := OpenCheckpointCustodyStore(CheckpointCustodyConfig{Root: filepath.Join(base, "custody"), MaxArtifactBytes: 1 << 20, MaxStagingBytes: 48 << 20, ReserveBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	model, err := store.Prepare(context.Background(), CheckpointCustodySource{Path: source, ApprovedSHA256: hex.EncodeToString(sum[:]), ExpectedBytes: int64(len(payload))})
	if err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	executableBytes, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	executableSum := sha256.Sum256(executableBytes)
	launch, err := store.Begin(model, CheckpointCustodyLaunchRequest{Command: exec.Command(executable, "-test.run=^TestCustodyChildProcess$", "--", "-m", "{CHECKPOINT_MODEL}"), Endpoint: "http://127.0.0.1:1", ServiceUnit: checkpointIdentityServiceUnit, ActualAlias: "lifecycle-abort-retry", ExpectedExecutableSHA256: hex.EncodeToString(executableSum[:])})
	if err != nil {
		t.Fatalf("begin abort retry fixture: %v", err)
	}
	saved := launch.executablePath + ".original"
	if err = os.Rename(launch.executablePath, saved); err != nil {
		t.Fatal(err)
	}
	replacement := []byte("replacement inode must survive failed cleanup\n")
	if err = os.WriteFile(launch.executablePath, replacement, 0600); err != nil {
		t.Fatal(err)
	}
	if err = launch.Abort(); err == nil {
		t.Fatal("lifecycle rejection assertion: replaced executable path was removed")
	}
	if launch.executableFD == nil {
		t.Fatal("lifecycle pin assertion: failed Abort discarded its original executable inode pin")
	}
	got, err := os.ReadFile(launch.executablePath)
	if err != nil || !bytes.Equal(got, replacement) {
		t.Fatalf("lifecycle replacement assertion: replacement changed after failed Abort: bytes=%q err=%v", got, err)
	}
	if err = os.Remove(launch.executablePath); err != nil {
		t.Fatal(err)
	}
	if err = os.Rename(saved, launch.executablePath); err != nil {
		t.Fatal(err)
	}
	if err = launch.Abort(); err != nil {
		t.Fatalf("retry Abort after restoring original executable inode: %v", err)
	}
	if err = launch.ReleaseTerminal(context.Background()); err != nil {
		t.Fatalf("release restored abort fixture: %v", err)
	}
}

func TestCheckpointCustodyLifecycleUnknownWaitRetainsPins(t *testing.T) {
	fixture := os.Getenv("CHECKPOINT_CUSTODY_TEST_DIR")
	if fixture == "" {
		t.Skip("kernel provisioning not requested")
	}
	base := filepath.Join(fixture, "source-lifecycle-unknown-wait")
	if err := os.Mkdir(base, 0700); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(base, "source.gguf")
	payload := []byte("unknown wait lifecycle source\n")
	if err := os.WriteFile(source, payload, 0600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(payload)
	store, err := OpenCheckpointCustodyStore(CheckpointCustodyConfig{Root: filepath.Join(base, "custody"), MaxArtifactBytes: 1 << 20, MaxStagingBytes: 48 << 20, ReserveBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	model, err := store.Prepare(context.Background(), CheckpointCustodySource{Path: source, ApprovedSHA256: hex.EncodeToString(sum[:]), ExpectedBytes: int64(len(payload))})
	if err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	executableBytes, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	executableSum := sha256.Sum256(executableBytes)
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := probe.Addr().String()
	_ = probe.Close()
	cmd := exec.Command(executable, "-test.run=^TestCustodyChildProcess$", "--", "-m", "{CHECKPOINT_MODEL}")
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	cmd.Env = append(os.Environ(), "CHECKPOINT_CUSTODY_CHILD=1", "CHECKPOINT_CUSTODY_ENDPOINT="+addr)
	launch, err := store.Begin(model, CheckpointCustodyLaunchRequest{Command: cmd, Endpoint: "http://" + addr, ServiceUnit: checkpointIdentityServiceUnit, ActualAlias: "lifecycle-unknown-wait", ExpectedExecutableSHA256: hex.EncodeToString(executableSum[:])})
	if err != nil {
		t.Fatalf("begin unknown wait fixture: %v", err)
	}
	if err = launch.Start(); err != nil {
		t.Fatal(err)
	}
	if !waitForCustodyEndpoint(addr, 5*time.Second) {
		_ = stopCustodyTestChild(launch)
		t.Fatal("unknown wait child did not bind endpoint")
	}
	launch.waitUnknownTest = true
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	err = launch.WaitContext(ctx)
	cancel()
	if err == nil || !strings.Contains(err.Error(), "reap could not be confirmed") {
		t.Fatalf("lifecycle ambiguity assertion: synthetic unknown reap was treated as confirmed: %v", err)
	}
	launch.mu.Lock()
	pidfdRetained, executablePinRetained, terminal := launch.pidfd >= 0, launch.executableFD != nil, launch.terminal
	processStateObserved := launch.cmd.ProcessState != nil
	launcherPath := launch.executablePath
	launch.mu.Unlock()
	if !pidfdRetained || !executablePinRetained || terminal || !processStateObserved {
		t.Fatalf("lifecycle pin assertion: ambiguous waiter state lost authority: pidfd=%v exePin=%v terminal=%v ProcessState=%v", pidfdRetained, executablePinRetained, terminal, processStateObserved)
	}
	if _, err = os.Lstat(launcherPath); err != nil {
		t.Fatalf("lifecycle pin assertion: ambiguous waiter removed its launcher: %v", err)
	}
	if err = launch.ReleaseTerminal(context.Background()); err == nil {
		t.Fatal("lifecycle rejection assertion: ambiguous WaitContext released the source")
	}
	// The test seam withheld an otherwise exact ProcessState. Restore only that
	// directly observed fact so the fixture can prove the normal exact cleanup.
	launch.mu.Lock()
	launch.waitUnknownTest = false
	launch.reaped, launch.terminal = processStateObserved, processStateObserved
	launch.mu.Unlock()
	if !processStateObserved {
		t.Fatal("test fixture lost cmd.ProcessState; cannot safely settle cleanup")
	}
	if err = launch.ReleaseTerminal(context.Background()); err != nil {
		t.Fatalf("release after test restores exact observed ProcessState: %v", err)
	}
}

func TestCheckpointCustodyLifecycleCommitCleanupSettlesBeforeRelease(t *testing.T) {
	fixture := os.Getenv("CHECKPOINT_CUSTODY_TEST_DIR")
	if fixture == "" {
		t.Skip("kernel provisioning not requested")
	}
	base := filepath.Join(fixture, "source-lifecycle-commit-settlement")
	if err := os.Mkdir(base, 0700); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(base, "source.gguf")
	payload := []byte("commit cleanup settlement fixture\n")
	if err := os.WriteFile(source, payload, 0600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(payload)
	store, err := OpenCheckpointCustodyStore(CheckpointCustodyConfig{Root: filepath.Join(base, "custody"), MaxArtifactBytes: 1 << 20, MaxStagingBytes: 64 << 20, ReserveBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	model, err := store.Prepare(context.Background(), CheckpointCustodySource{Path: source, ApprovedSHA256: hex.EncodeToString(sum[:]), ExpectedBytes: int64(len(payload))})
	if err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	executableBytes, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	executableSum := sha256.Sum256(executableBytes)
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := probe.Addr().String()
	_ = probe.Close()
	cmd := exec.Command(executable, "-test.run=^TestCustodyChildProcess$", "--", "-m", "{CHECKPOINT_MODEL}")
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	cmd.Env = append(os.Environ(), "CHECKPOINT_CUSTODY_CHILD=1", "CHECKPOINT_CUSTODY_ENDPOINT="+addr)
	launch, err := store.Begin(model, CheckpointCustodyLaunchRequest{Command: cmd, Endpoint: "http://" + addr, ServiceUnit: checkpointIdentityServiceUnit, ActualAlias: "lifecycle-settlement", ExpectedExecutableSHA256: hex.EncodeToString(executableSum[:])})
	if err != nil {
		t.Fatal(err)
	}
	if err = launch.Start(); err != nil {
		t.Fatal(err)
	}
	if !waitForCustodyEndpoint(addr, 5*time.Second) {
		_ = stopCustodyTestChild(launch)
		t.Fatal("settlement child did not bind endpoint")
	}
	afterPublish, publishEntered := make(chan struct{}), make(chan struct{})
	cleanup, cleanupEntered := make(chan struct{}), make(chan struct{})
	afterPublishClosed, cleanupClosed := false, false
	defer func() {
		if !afterPublishClosed {
			close(afterPublish)
		}
		if !cleanupClosed {
			close(cleanup)
		}
	}()
	launch.commitAfterPublishTestBarrier, launch.commitAfterPublishTestEntered = afterPublish, publishEntered
	launch.commitCleanupTestBarrier, launch.commitCleanupTestEntered = cleanup, cleanupEntered
	commitCtx, cancelCommit := context.WithCancel(context.Background())
	defer cancelCommit()
	commitResult := make(chan error, 1)
	go func() { commitResult <- launch.Commit(commitCtx) }()
	select {
	case <-publishEntered:
	case <-time.After(10 * time.Second):
		cancelCommit()
		close(afterPublish)
		afterPublishClosed = true
		_ = stopCustodyTestChild(launch)
		t.Fatal("Commit did not pause after publishing the signed receipt")
	}
	receiptPath := custodyReceiptPath(store.root, launch.nonce)
	if _, err = os.Lstat(receiptPath); err != nil {
		cancelCommit()
		close(afterPublish)
		afterPublishClosed = true
		_ = stopCustodyTestChild(launch)
		t.Fatalf("signed receipt missing inside Commit: %v", err)
	}
	if err = launch.ReleaseTerminal(context.Background()); err == nil {
		cancelCommit()
		close(afterPublish)
		afterPublishClosed = true
		_ = stopCustodyTestChild(launch)
		t.Fatal("lifecycle rejection assertion: Commit-in-progress launch was released")
	}
	cancelCommit()
	close(afterPublish)
	afterPublishClosed = true
	select {
	case <-cleanupEntered:
	case <-time.After(5 * time.Second):
		_ = stopCustodyTestChild(launch)
		close(cleanup)
		cleanupClosed = true
		t.Fatal("Commit did not enter receipt cleanup window")
	}
	waitCtx, cancelWait := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancelWait()
	waitResult := make(chan error, 1)
	go func() { waitResult <- launch.WaitContext(waitCtx) }()
	reapedBy := time.After(5 * time.Second)
	for {
		launch.mu.Lock()
		reaped := launch.reaped
		launch.mu.Unlock()
		if reaped {
			break
		}
		select {
		case <-reapedBy:
			cancelWait()
			close(cleanup)
			cleanupClosed = true
			t.Fatal("WaitContext did not confirm exact child reap during Commit cleanup")
		case <-time.After(10 * time.Millisecond):
		}
	}
	if err = launch.ReleaseTerminal(context.Background()); err == nil {
		close(cleanup)
		cleanupClosed = true
		cancelWait()
		t.Fatal("lifecycle rejection assertion: terminal cleanup raced unsettled Commit receipt removal")
	}
	if _, err = os.Lstat(receiptPath); err != nil {
		close(cleanup)
		cleanupClosed = true
		cancelWait()
		t.Fatalf("receipt removed before Commit cleanup settled: %v", err)
	}
	if _, err = os.Lstat(model.path); err != nil {
		close(cleanup)
		cleanupClosed = true
		cancelWait()
		t.Fatalf("model removed before Commit cleanup settled: %v", err)
	}
	close(cleanup)
	cleanupClosed = true
	if err = <-commitResult; err == nil {
		cancelWait()
		t.Fatal("canceled Commit unexpectedly succeeded")
	}
	cancelWait()
	if err = <-waitResult; !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("WaitContext cancellation after exact reap was not reported: %v", err)
	}
	if _, err = os.Lstat(receiptPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Commit cancellation failed to remove its exact receipt: %v", err)
	}
	if err = launch.ReleaseTerminal(context.Background()); err != nil {
		t.Fatalf("release after settled Commit cleanup and exact reap: %v", err)
	}
}
