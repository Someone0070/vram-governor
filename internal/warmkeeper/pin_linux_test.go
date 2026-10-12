//go:build linux

package warmkeeper

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func lockedBytes(t *testing.T) int64 {
	t.Helper()
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(b), "\n") {
		if f := strings.Fields(line); len(f) == 3 && f[0] == "VmLck:" {
			n, _ := strconv.ParseInt(f[1], 10, 64)
			return n * 1024
		}
	}
	t.Fatal("VmLck missing")
	return 0
}

func TestPinFileLocksWholeFileAndReleases(t *testing.T) {
	const size = 600 << 20 // spans three mlock chunks
	path := filepath.Join(t.TempDir(), "model.gguf")
	if err := os.WriteFile(path, make([]byte, size), 0o644); err != nil {
		t.Fatal(err)
	}
	before := lockedBytes(t)
	chunks := 0
	pin, err := PinFile(path, func() bool { chunks++; return false })
	if errors.Is(err, unix.EPERM) || errors.Is(err, unix.ENOMEM) || errors.Is(err, unix.EAGAIN) {
		t.Skipf("memlock not permitted here: %v", err)
	}
	if err != nil {
		t.Fatal(err)
	}
	if got := lockedBytes(t) - before; got < size {
		t.Fatalf("locked %d bytes, want >= %d", got, size)
	}
	if chunks != 3 {
		t.Fatalf("abort polled %d times, want 3", chunks)
	}
	if err := pin.Close(); err != nil {
		t.Fatal(err)
	}
	if got := lockedBytes(t); got != before {
		t.Fatalf("after Close VmLck = %d, want %d", got, before)
	}
}

func TestPinFileAbortReleasesPartialLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "model.gguf")
	if err := os.WriteFile(path, make([]byte, 600<<20), 0o644); err != nil {
		t.Fatal(err)
	}
	before := lockedBytes(t)
	calls := 0
	_, err := PinFile(path, func() bool { calls++; return calls == 2 })
	if !errors.Is(err, ErrAborted) {
		t.Skipf("abort path not reached: %v", err)
	}
	if got := lockedBytes(t); got != before {
		t.Fatalf("after abort VmLck = %d, want %d", got, before)
	}
}

func TestMemAvailableAndStat(t *testing.T) {
	if n, err := MemAvailable(); err != nil || n <= 0 {
		t.Fatalf("MemAvailable = %d, %v", n, err)
	}
	path := filepath.Join(t.TempDir(), "f")
	os.WriteFile(path, []byte("abc"), 0o644)
	id, err := statFile(path)
	if err != nil || id.Size != 3 || id.Inode == 0 {
		t.Fatalf("statFile = %+v, %v", id, err)
	}
	if _, err := statFile(filepath.Dir(path)); err == nil {
		t.Fatal("directory accepted")
	}
}
