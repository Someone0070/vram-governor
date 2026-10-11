//go:build linux

package nodeagent

import (
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestWarmRAMLinuxAuthoritativeParsersFailClosed(t *testing.T) {
	root := t.TempDir()
	meminfo := filepath.Join(root, "meminfo")
	write := func(path, body string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(meminfo, "MemTotal: 1024 kB\nMemAvailable: 512 kB\nOther: 1 kB\n")
	if total, available, err := linuxMemInfoPath(meminfo); err != nil || total != 1024*1024 || available != 512*1024 {
		t.Fatalf("valid meminfo rejected: total=%d available=%d err=%v", total, available, err)
	}
	for _, body := range []string{
		"MemTotal: nope kB\nMemAvailable: 512 kB\n",
		"MemTotal: 1024 MB\nMemAvailable: 512 kB\n",
		"MemTotal: 1024 kB\nMemAvailable: 512\n",
		"MemTotal: 1024 kB\nMemAvailable: 2048 kB\n",
	} {
		write(meminfo, body)
		if _, _, err := linuxMemInfoPath(meminfo); err == nil {
			t.Fatalf("malformed meminfo was accepted: %q", body)
		}
	}

	pressure := filepath.Join(root, "pressure")
	write(pressure, "some avg10=12.5 avg60=1.0 avg300=0.0 total=2\n")
	if value, err := linuxPressurePercentPath(pressure); err != nil || value != 12.5 {
		t.Fatalf("valid PSI rejected: value=%v err=%v", value, err)
	}
	for _, body := range []string{"some avg10=NaN avg60=1 avg300=1 total=1\n", "some avg10=101 avg60=1 avg300=1 total=1\n", "full avg10=1 avg60=1 avg300=1 total=1\n"} {
		write(pressure, body)
		if _, err := linuxPressurePercentPath(pressure); err == nil {
			t.Fatalf("malformed PSI was accepted: %q", body)
		}
	}

	events := filepath.Join(root, "events")
	write(events, "oom 2\noom_kill 3\noom_group_kill 4\n")
	if count, err := warmRAMOOMEvents(events); err != nil || count != 9 {
		t.Fatalf("valid OOM counters rejected: count=%d err=%v", count, err)
	}
	for _, body := range []string{"oomish 4\n", "oom nope\n", "oom_group_kill nope\n", "oom 1\noom_group_kill\n", "memory 1\n"} {
		write(events, body)
		if _, err := warmRAMOOMEvents(events); err == nil {
			t.Fatalf("malformed OOM counters were accepted: %q", strings.TrimSpace(body))
		}
	}
}

func TestWarmRAMLinuxSyscallIntegration(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "small-model.bin")
	data := make([]byte, 3*os.Getpagesize()+17)
	for i := range data {
		data[i] = byte(i)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	identity, err := warmSecureFileIdentity(path, []string{root})
	if err != nil {
		t.Fatalf("secure identity failed: %v", err)
	}
	if identity.Size != int64(len(data)) || identity.Hash == "" {
		t.Fatalf("incomplete opened identity: %+v", identity)
	}
	limit, err := warmRAMMemlockLimit()
	if err != nil {
		t.Fatalf("RLIMIT_MEMLOCK query failed: %v", err)
	}
	if limit > 0 && limit < identity.Size {
		t.Fatalf("RLIMIT_MEMLOCK cannot admit integration file: limit=%d size=%d", limit, identity.Size)
	}
	beforeLocked, err := linuxLockedBytes()
	if err != nil {
		t.Fatalf("VmLck baseline failed: %v", err)
	}
	pin, opened, err := pinWarmModelFileExpected(path, []string{root}, identity)
	if err != nil {
		t.Fatalf("openat2/mincore/mlock integration failed: %v", err)
	}
	if opened != identity || pin.ResidentBytes() < identity.Size || pin.LockedBytes() < identity.Size {
		t.Fatalf("resident-and-locked proof incomplete: opened=%+v pin=(%d,%d)", opened, pin.ResidentBytes(), pin.LockedBytes())
	}
	duringLocked, err := linuxLockedBytes()
	if err != nil || duringLocked < beforeLocked+int64(os.Getpagesize()) {
		t.Fatalf("VmLck did not rise after mlock: before=%d during=%d err=%v", beforeLocked, duringLocked, err)
	}
	if err := pin.Close(); err != nil {
		t.Fatalf("integration cleanup failed: %v", err)
	}
	deadline := time.Now().Add(750 * time.Millisecond)
	for {
		afterLocked, readErr := linuxLockedBytes()
		if readErr == nil && afterLocked <= beforeLocked {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("VmLck did not return after cleanup: before=%d last=%d err=%v", beforeLocked, afterLocked, readErr)
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Exercise the admission-side RLIMIT refusal without changing the hard
	// limit.  Restoring Cur is deferred even if the assertion fails.
	var oldLimit unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &oldLimit); err != nil {
		t.Fatalf("RLIMIT_MEMLOCK read failed: %v", err)
	}
	defer func() { _ = unix.Setrlimit(unix.RLIMIT_MEMLOCK, &oldLimit) }()
	if oldLimit.Cur > 0 {
		lowered := oldLimit
		lowered.Cur = 0
		if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &lowered); err == nil {
			failedPin, _, pinErr := pinWarmModelFileExpected(path, []string{root}, identity)
			if pinErr == nil {
				_ = failedPin.Close()
				// A privileged Linux test process may hold CAP_IPC_LOCK and
				// legitimately bypass RLIMIT_MEMLOCK.  The deterministic
				// policy tests cover refusal; here require cleanup and accept
				// the kernel's documented privilege override.
				if os.Geteuid() != 0 {
					t.Fatal("mlock succeeded after RLIMIT_MEMLOCK was lowered to zero")
				}
			}
			if locked, readErr := linuxLockedBytes(); readErr != nil || locked > beforeLocked {
				t.Fatalf("failed mlock leaked locked bytes: locked=%d baseline=%d err=%v", locked, beforeLocked, readErr)
			}
		}
	}

	link := filepath.Join(root, "model-link.bin")
	if err := os.Symlink(path, link); err != nil {
		t.Fatalf("symlink fixture could not be created: %v", err)
	}
	if _, err := warmSecureFileIdentity(link, []string{root}); err == nil {
		t.Fatal("symlink model path was accepted")
	}
	ancestor := filepath.Join(t.TempDir(), "ancestor")
	if err := os.Symlink(root, ancestor); err != nil {
		t.Fatalf("ancestor symlink fixture could not be created: %v", err)
	}
	if _, err := warmSecureFileIdentity(filepath.Join(ancestor, filepath.Base(path)), []string{root, filepath.Dir(ancestor)}); err == nil {
		t.Fatal("symlink ancestor model path was accepted")
	}
}

func TestWarmRAMLinuxUnprivilegedIntegration(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "oversized-model.bin")
	limit, err := warmRAMMemlockLimit()
	if err != nil || limit <= 0 {
		t.Fatalf("non-root RLIMIT_MEMLOCK must be finite for refusal test: limit=%d err=%v", limit, err)
	}
	size := limit + int64(os.Getpagesize())
	if size > 128<<20 {
		t.Fatalf("RLIMIT_MEMLOCK fixture unexpectedly large: %d", size)
	}
	if err := os.WriteFile(path, make([]byte, size), 0o600); err != nil {
		t.Fatal(err)
	}
	identity, err := warmSecureFileIdentity(path, []string{root})
	if err != nil {
		t.Fatal(err)
	}
	pin, _, pinErr := pinWarmModelFileExpected(path, []string{root}, identity)
	if pinErr == nil {
		_ = pin.Close()
		t.Fatal("non-root mlock succeeded above RLIMIT_MEMLOCK")
	}
}

func TestWarmRAMLinuxSecureOpenPathReplacementRace(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	insideDir := filepath.Join(root, "candidate")
	if err := os.Mkdir(insideDir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(insideDir, "model.bin")
	outsidePath := filepath.Join(outside, "model.bin")
	if err := os.WriteFile(path, []byte("inside-model"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(outsidePath, []byte("outside-model"), 0o600); err != nil {
		t.Fatal(err)
	}
	outsideIdentity, err := warmFileIdentityAt(outsidePath)
	if err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	var attempts, outsideSuccesses, successfulSwaps, swapReads atomic.Int64
	var swapActive atomic.Bool
	ready := make(chan struct{}, 1)
	readerDone := make(chan struct{}, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		hidden := filepath.Join(root, "candidate.hidden")
		for {
			select {
			case <-stop:
				return
			default:
			}
			if os.Rename(insideDir, hidden) != nil || os.Symlink(outside, insideDir) != nil {
				_ = os.Remove(insideDir)
				_ = os.Rename(hidden, insideDir)
				continue
			}
			successfulSwaps.Add(1)
			swapActive.Store(true)
			ready <- struct{}{}
			select {
			case <-readerDone:
			case <-time.After(time.Second):
				return
			}
			swapActive.Store(false)
			_ = os.Remove(insideDir)
			_ = os.Rename(hidden, insideDir)
		}
	}()
	for i := 0; i < 10000 && swapReads.Load() == 0; i++ {
		attempts.Add(1)
		identity, identityErr := warmSecureFileIdentity(path, []string{root})
		if identityErr == nil && identity == outsideIdentity {
			outsideSuccesses.Add(1)
		}
		select {
		case <-ready:
			swapReads.Add(1)
			// This read occurs only after the mutator has installed the
			// ancestor symlink and before it is allowed to restore it.
			identity, identityErr = warmSecureFileIdentity(path, []string{root})
			if identityErr == nil && identity == outsideIdentity {
				outsideSuccesses.Add(1)
			}
			readerDone <- struct{}{}
		default:
		}
		time.Sleep(100 * time.Microsecond)
	}
	close(stop)
	<-done
	if attempts.Load() == 0 {
		t.Fatal("path-race fixture made zero secure-open attempts")
	}
	if successfulSwaps.Load() == 0 || swapReads.Load() == 0 {
		t.Fatalf("path-race fixture did not synchronize a confirmed swap window: swaps=%d reads=%d", successfulSwaps.Load(), swapReads.Load())
	}
	if outsideSuccesses.Load() != 0 {
		t.Fatalf("secure-open path race accepted outside identity %d times", outsideSuccesses.Load())
	}
}
