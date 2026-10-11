//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package safefile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOpenReadOnlyNoFollowRejectsLastComponentSymlink(t *testing.T) {
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
		t.Fatal("last-component symlink was followed")
	}
}
