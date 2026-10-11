package llamacpp

import (
	"os"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"testing"
	"vram-governor/internal/runtime"
)

func TestSnapshotNameAndPathAreBounded(t *testing.T) {
	for _, name := range []string{"../escape.kv", "x/y.kv", "/tmp/x.kv", "..x.kv", "bad.txt", ""} {
		if err := validateSnapshotName(name); err == nil {
			t.Fatalf("accepted unsafe snapshot name %q", name)
		}
	}
	if err := validateSnapshotName("owner-abc.kv"); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	path, err := secureSnapshotPath(root, "owner-abc.kv")
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(path) != root {
		t.Fatal(path)
	}
	outside := filepath.Join(root, "outside")
	if err := os.WriteFile(outside, []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "owner-abc.kv")); err == nil {
		if _, e := secureSnapshotPath(root, "owner-abc.kv"); e == nil {
			t.Fatal("symlink escape accepted")
		}
	}
}

func TestReadSnapshotDescriptorRejectsHardlinks(t *testing.T) {
	if goruntime.GOOS == "windows" {
		t.Skip("descriptor nlink is not exposed by the Windows os.FileInfo implementation")
	}
	root := t.TempDir()
	path := filepath.Join(root, "owner-abc.kv")
	linked := filepath.Join(root, "owner-linked.kv")
	if err := os.WriteFile(path, []byte("private-kv"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(path, linked); err != nil {
		t.Skipf("hard links unavailable: %v", err)
	}
	if _, _, err := readSnapshotDescriptor(path, 1024); err == nil {
		t.Fatal("hardlinked snapshot was accepted")
	}
}

func TestSlotSnapshotNameDoesNotContainOwnerPath(t *testing.T) {
	name := SlotSnapshotName(runtime.CheckpointIdentity{OwnerID: "owner", WorkloadID: "work", Generation: 1, RuntimeIdentity: "build", ModelFingerprint: "model", ProfileFingerprint: "profile", ContextLimit: 4096, SlotID: 2})
	if !strings.HasSuffix(name, ".kv") || strings.ContainsAny(name, "/\\") || strings.Contains(name, "..") {
		t.Fatalf("unsafe name %q", name)
	}
}
