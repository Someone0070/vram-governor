//go:build linux

package nodeagent

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"syscall"

	"golang.org/x/sys/unix"
)

func openCheckpointLaunchPlan(ctx context.Context, path string, expectedUID uint32) (*PinnedCheckpointLaunchPlan, error) {
	if ctx == nil {
		return nil, errors.New("launch plan context is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := validateCanonicalPathSyntax(path); err != nil {
		return nil, err
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return nil, errors.New("launch plan path is not canonical")
	}
	// Parent directories always remain root-owned trusted infrastructure. The
	// private test seam may vary only the pinned plan file's expected owner.
	parents, err := checkpointLaunchParents(filepath.Dir(path), 0)
	if err != nil {
		return nil, err
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open pinned launch plan: %w", err)
	}
	f := os.NewFile(uintptr(fd), path)
	if f == nil {
		_ = unix.Close(fd)
		return nil, errors.New("launch plan descriptor unavailable")
	}
	ok := false
	defer func() {
		if !ok {
			_ = f.Close()
		}
	}()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	dev, ino, size, uid, mode, nlink, err := launchStat(info)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || uid != expectedUID || nlink != 1 || mode&0022 != 0 || size < 1 || size > checkpointLaunchPlanMaxBytes {
		return nil, errors.New("launch plan file ownership, mode, type, links, or size is unsafe")
	}
	raw, err := readPinnedLaunchBytes(ctx, f, size)
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) != size {
		return nil, errors.New("launch plan size changed while reading")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := verifyLaunchPathIdentity(path, dev, ino, size, expectedUID); err != nil {
		return nil, err
	}
	if err := verifyCheckpointLaunchParents(parents, 0); err != nil {
		return nil, err
	}
	plan, err := ParseCheckpointLaunchPlan(raw)
	if err != nil {
		return nil, err
	}
	ok = true
	return &PinnedCheckpointLaunchPlan{plan: plan, args: fixedCheckpointLaunchArguments(plan), path: path, file: f, device: dev, inode: ino, size: size, expectedUID: expectedUID, contentSHA256: sha256.Sum256(raw), parents: parents}, nil
}

// privateOpenCheckpointLaunchPlan is the only owner-policy seam. It is
// unexported and accepts an explicit UID solely for root-owned test fixtures.
func privateOpenCheckpointLaunchPlan(ctx context.Context, path string, expectedUID uint32) (*PinnedCheckpointLaunchPlan, error) {
	return openCheckpointLaunchPlan(ctx, path, expectedUID)
}

func (p *PinnedCheckpointLaunchPlan) Recheck(ctx context.Context) error {
	if p == nil {
		return errors.New("pinned launch plan is nil")
	}
	if ctx == nil {
		return errors.New("recheck context is required")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.file == nil {
		return errors.New("pinned launch plan is closed")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	info, err := p.file.Stat()
	if err != nil {
		return err
	}
	dev, ino, size, uid, mode, nlink, err := launchStat(info)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || dev != p.device || ino != p.inode || size != p.size || uid != p.expectedUID || nlink != 1 || mode&0022 != 0 {
		return errors.New("pinned launch descriptor identity or policy changed")
	}
	raw, err := readPinnedLaunchBytes(ctx, p.file, p.size)
	if err != nil {
		return err
	}
	if int64(len(raw)) != p.size || sha256.Sum256(raw) != p.contentSHA256 {
		return errors.New("pinned launch plan bytes changed")
	}
	if err := verifyLaunchPathIdentity(p.path, p.device, p.inode, p.size, p.expectedUID); err != nil {
		return err
	}
	if err := verifyCheckpointLaunchParents(p.parents, 0); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return nil
}

func readPinnedLaunchBytes(ctx context.Context, f *os.File, size int64) ([]byte, error) {
	if size < 0 || size > checkpointLaunchPlanMaxBytes {
		return nil, errors.New("launch plan exceeds read bound")
	}
	b := make([]byte, size)
	for off := 0; off < len(b); {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		n, err := f.ReadAt(b[off:], int64(off))
		off += n
		if err != nil && err != io.EOF {
			return nil, err
		}
		if n == 0 && off < len(b) {
			return nil, io.ErrUnexpectedEOF
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return b, nil
}

func launchStat(info os.FileInfo) (dev, ino uint64, size int64, uid, mode uint32, nlink uint64, err error) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, 0, 0, 0, 0, errors.New("launch plan stat identity is unavailable")
	}
	return uint64(st.Dev), st.Ino, info.Size(), st.Uid, uint32(info.Mode().Perm()), uint64(st.Nlink), nil
}
func verifyLaunchPathIdentity(path string, dev, ino uint64, size int64, uid uint32) error {
	i, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !i.Mode().IsRegular() || i.Mode()&os.ModeSymlink != 0 {
		return errors.New("launch plan pathname is no longer a regular file")
	}
	d, n, s, u, m, l, e := launchStat(i)
	if e != nil {
		return e
	}
	if d != dev || n != ino || s != size || u != uid || l != 1 || m&0022 != 0 {
		return errors.New("launch plan pathname no longer identifies the pinned safe file")
	}
	return nil
}
func checkpointLaunchParents(dir string, uid uint32) ([]checkpointLaunchParent, error) {
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
		return nil, errors.New("launch plan parent is not canonical")
	}
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil || resolved != dir {
		return nil, errors.New("launch plan parent path is not canonical")
	}
	var paths []string
	cur := dir
	for {
		paths = append(paths, cur)
		next := filepath.Dir(cur)
		if next == cur {
			break
		}
		cur = next
	}
	sort.Slice(paths, func(i, j int) bool { return len(paths[i]) < len(paths[j]) })
	out := make([]checkpointLaunchParent, 0, len(paths))
	for _, path := range paths {
		i, e := os.Lstat(path)
		if e != nil {
			return nil, e
		}
		if !i.IsDir() || i.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("launch plan parent is not a real directory")
		}
		d, n, _, u, m, _, e := launchStat(i)
		if e != nil {
			return nil, e
		}
		if u != uid || m&0022 != 0 {
			return nil, fmt.Errorf("launch plan parent %s is not trusted", path)
		}
		out = append(out, checkpointLaunchParent{path: path, device: d, inode: n, uid: u, mode: m})
	}
	return out, nil
}
func verifyCheckpointLaunchParents(expected []checkpointLaunchParent, uid uint32) error {
	for _, old := range expected {
		i, err := os.Lstat(old.path)
		if err != nil {
			return err
		}
		if !i.IsDir() || i.Mode()&os.ModeSymlink != 0 {
			return errors.New("trusted launch plan parent changed type")
		}
		d, n, _, u, m, _, err := launchStat(i)
		if err != nil {
			return err
		}
		if d != old.device || n != old.inode || u != uid || u != old.uid || m&0022 != 0 || m != old.mode {
			return errors.New("trusted launch plan parent identity or mode changed")
		}
	}
	return nil
}
