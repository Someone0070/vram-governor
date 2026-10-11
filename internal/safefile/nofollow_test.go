package safefile

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestOpenReadOnlyNoFollowReadsTheOpenedDescriptor(t *testing.T) {
	path := filepath.Join(t.TempDir(), "snapshot.kv")
	const want = "checkpoint-bytes"
	if err := os.WriteFile(path, []byte(want), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := OpenReadOnlyNoFollow(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	got, err := io.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("read=%q want %q", got, want)
	}
}

func TestOpenReadOnlyNoFollowRejectsEmptyPath(t *testing.T) {
	if _, err := OpenReadOnlyNoFollow(""); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("empty path error=%v", err)
	}
}

func TestOpenReadOnlyNoFollowRejectsObservedSymlink(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target.kv")
	link := filepath.Join(root, "link.kv")
	if err := os.WriteFile(target, []byte("private"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if f, err := OpenReadOnlyNoFollow(link); err == nil {
		_ = f.Close()
		t.Fatal("observed symlink was followed")
	}
}

func TestOpenReadOnlyNoFollowRejectsStationaryWindowsJunction(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows junction test")
	}
	root := t.TempDir()
	target := filepath.Join(root, "target")
	junction := filepath.Join(root, "junction")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := createDirectoryJunction(junction, target); err != nil {
		t.Logf("junction creation unavailable (often policy/privilege related): %v", err)
		testOpenedHandleMetadata(t, root)
		return
	}
	if f, err := OpenReadOnlyNoFollow(junction); err == nil {
		_ = f.Close()
		t.Fatal("stationary junction was followed")
	}
}

func TestOpenReadOnlyNoFollowRejectsDeterministicWindowsReparseSwap(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows reparse swap test")
	}
	root := t.TempDir()
	candidate := filepath.Join(root, "candidate")
	original := filepath.Join(root, "candidate.original")
	target := filepath.Join(root, "target")
	if err := os.Mkdir(candidate, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}

	var swapErr, junctionErr error
	previousHook := beforeOpenReadOnlyNoFollowHook
	defer func() { beforeOpenReadOnlyNoFollowHook = previousHook }()
	beforeOpenReadOnlyNoFollowHook = func() {
		if swapErr = os.Rename(candidate, original); swapErr != nil {
			return
		}
		junctionErr = createDirectoryJunction(candidate, target)
	}
	f, err := OpenReadOnlyNoFollow(candidate)
	if swapErr != nil {
		if f != nil {
			_ = f.Close()
		}
		t.Fatalf("deterministic swap setup failed: %v", swapErr)
	}
	if junctionErr != nil {
		if f != nil {
			_ = f.Close()
		}
		t.Logf("junction creation unavailable (often policy/privilege related): %v", junctionErr)
		testOpenedHandleMetadata(t, root)
		return
	}
	if f != nil {
		_ = f.Close()
	}
	if err == nil {
		t.Fatal("reparse point installed by the pre-open hook was accepted")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "reparse") {
		t.Fatalf("reparse swap error=%v", err)
	}
}

func createDirectoryJunction(link, target string) error {
	output, err := exec.Command("cmd.exe", "/d", "/c", "mklink", "/J", link, target).CombinedOutput()
	if err != nil {
		return fmt.Errorf("mklink /J: %w (%s)", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func testOpenedHandleMetadata(t *testing.T, root string) {
	t.Helper()
	path := filepath.Join(root, "regular.kv")
	const want = "regular-file"
	if err := os.WriteFile(path, []byte(want), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := OpenReadOnlyNoFollow(path)
	if err != nil {
		t.Fatalf("regular file after junction setup: %v", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("opened handle metadata=%v; want regular file", info.Mode())
	}
	got, err := io.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("read=%q want %q", got, want)
	}
}
