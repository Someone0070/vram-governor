//go:build linux

package nodeagent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

const (
	checkpointObserverRouteTmpfsMagic = 0x01021994
	checkpointObserverRouteTmpfsSize  = "size=128M,nr_inodes=128,mode=0711,uid=0,gid=0"
)

// This ordinary Linux-test helper deliberately uses only primitive descriptor
// identities so builds without the tagged kernel fixture need no kernel-only
// custody types.
type checkpointObserverRouteTmpfsMount struct {
	path       string
	fd         int
	dev        uint64
	inode      uint64
	mountID    uint64
	attempted  bool
	mounted    bool
	unmountTry bool
	heldRefs   int
}

type checkpointObserverRouteMountedCleanup struct {
	mount          *checkpointObserverRouteTmpfsMount
	rootPath       string
	rootFD         int
	rootDev        uint64
	rootIno        uint64
	underlyingPath string
	underlyingFD   int
	underlyingDev  uint64
	underlyingIno  uint64
	clientFD       *int
	mountedRootFD  *int
	childrenClear  bool
}

type checkpointObserverRouteTmpfsUnmountProof struct {
	mount              *checkpointObserverRouteTmpfsMount
	mountID            uint64
	dev, inode         uint64
	underlyingDev      uint64
	underlyingIno      uint64
	parentDev          uint64
	parentIno          uint64
	remainingRefs      int
	childrenClear      bool
	underlyingHeld     bool
	parentPathCurrent  bool
	mountPathCurrent   bool
}

func checkpointObserverRouteUnderlyingBinCurrent(cleanup *checkpointObserverRouteMountedCleanup) bool {
	if cleanup == nil || cleanup.underlyingFD < 0 || cleanup.underlyingPath == "" || cleanup.underlyingDev == 0 || cleanup.underlyingIno == 0 { return false }
	var held unix.Stat_t
	if unix.Fstat(cleanup.underlyingFD, &held) != nil || uint64(held.Dev) != cleanup.underlyingDev || held.Ino != cleanup.underlyingIno || held.Uid != 0 || held.Gid != 0 || held.Mode&unix.S_IFMT != unix.S_IFDIR || held.Mode&07777 != 0711 { return false }
	return true
}

func checkpointObserverRouteRevealedUnderlyingBinCurrent(cleanup *checkpointObserverRouteMountedCleanup) bool {
	if !checkpointObserverRouteUnderlyingBinCurrent(cleanup) { return false }
	info, err := os.Lstat(cleanup.underlyingPath)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() { return false }
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || uint64(stat.Dev) != cleanup.underlyingDev || stat.Ino != cleanup.underlyingIno || stat.Uid != 0 || stat.Mode&07777 != 0711 { return false }
	entries, err := os.ReadDir(cleanup.underlyingPath)
	return err == nil && len(entries) == 0
}

func checkpointObserverRouteTmpfsOptions() string { return checkpointObserverRouteTmpfsSize }

func checkpointObserverRouteTmpfsMountInfo(raw, target string) (uint64, bool) {
	for _, line := range strings.Split(raw, "\n") {
		fields := strings.Fields(line)
		separator := -1
		for i, field := range fields {
			if field == "-" { separator = i; break }
		}
		if separator < 6 || len(fields) < separator+4 || fields[4] != target || fields[separator+1] != "tmpfs" { continue }
		mountOptions, superOptions := strings.Split(fields[5], ","), strings.Split(fields[separator+3], ",")
		seenMount := make(map[string]bool)
		for _, option := range mountOptions {
			if seenMount[option] || (option != "rw" && option != "relatime" && option != "nosuid" && option != "nodev") { return 0, false }
			seenMount[option] = true
		}
		if len(seenMount) != 4 || !seenMount["rw"] || !seenMount["relatime"] || !seenMount["nosuid"] || !seenMount["nodev"] { return 0, false }
		seenSuper, superValues := make(map[string]bool), make(map[string]string)
		for _, option := range superOptions {
			key, value, hasValue := strings.Cut(option, "=")
			if key == "" || seenSuper[key] { return 0, false }
			seenSuper[key] = true
			if !hasValue { if key != "rw" && key != "inode32" && key != "inode64" { return 0, false }; continue }
			switch key { case "size", "nr_inodes", "mode", "uid", "gid": superValues[key] = value; default: return 0, false }
		}
		if seenSuper["inode32"] && seenSuper["inode64"] || !seenSuper["rw"] || !seenSuper["size"] || !seenSuper["nr_inodes"] || !seenSuper["mode"] || superValues["size"] != "131072k" || superValues["nr_inodes"] != "128" || superValues["mode"] != "711" ||
			(seenSuper["uid"] && superValues["uid"] != "0") || (seenSuper["gid"] && superValues["gid"] != "0") { return 0, false }
		id, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil || id == 0 { return 0, false }
		return id, true
	}
	return 0, false
}

func checkpointObserverRouteMountNamespacePrivate() bool {
	self, selfErr := os.Stat("/proc/self/ns/mnt")
	init, initErr := os.Stat("/proc/1/ns/mnt")
	if selfErr != nil || initErr != nil || !os.SameFile(self, init) { return false }
	raw, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil { return false }
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 6 || fields[4] != "/" { continue }
		for _, optional := range fields[6:] {
			if strings.HasPrefix(optional, "shared:") || strings.HasPrefix(optional, "master:") || strings.HasPrefix(optional, "propagate_from:") { return false }
		}
		return true
	}
	return false
}

func checkpointObserverRouteMountPrivateExecutableBin(root, bin string, rootFD int, rootDev, rootInode uint64, binFD int, binDev, binInode uint64) (*checkpointObserverRouteTmpfsMount, error) {
	if os.Getpid() != 1 || os.Geteuid() != 0 || !checkpointObserverRouteMountNamespacePrivate() || !strings.HasPrefix(root, "/run/checkpoint-observer-route-local-") || root == "" || filepath.Clean(root) != root || bin != filepath.Join(root, "bin") ||
		rootFD < 0 || binFD < 0 || rootDev == 0 || rootInode == 0 || binDev == 0 || binInode == 0 {
		return nil, errors.New("private executable tmpfs requires exact root PID1 and held local-root/bin custody")
	}
	var heldRoot, heldBin unix.Stat_t
	if err := unix.Fstat(rootFD, &heldRoot); err != nil || uint64(heldRoot.Dev) != rootDev || heldRoot.Ino != rootInode || heldRoot.Uid != 0 || heldRoot.Gid != 0 || heldRoot.Mode&unix.S_IFMT != unix.S_IFDIR {
		return nil, errors.New("held local-root descriptor identity is not exact")
	}
	if err := unix.Fstat(binFD, &heldBin); err != nil || uint64(heldBin.Dev) != binDev || heldBin.Ino != binInode || heldBin.Uid != 0 || heldBin.Gid != 0 || heldBin.Mode&unix.S_IFMT != unix.S_IFDIR || heldBin.Mode&07777 != 0711 {
		return nil, errors.New("held underlying bin descriptor identity is not exact")
	}
	for path, expected := range map[string]*unix.Stat_t{root: &heldRoot, bin: &heldBin} {
		info, err := os.Lstat(path)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() { return nil, errors.New("local root/bin path no longer names its held directory") }
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || uint64(stat.Dev) != uint64(expected.Dev) || stat.Ino != expected.Ino { return nil, errors.New("local root/bin path identity differs from held descriptor") }
	}
	entries, err := os.ReadDir(bin)
	if err != nil || len(entries) != 0 { return nil, errors.New("underlying owned bin is not empty before mount") }
	rootInfo, err := os.Lstat(root)
	if err != nil || rootInfo.Mode().Perm() != 0711 { return nil, errors.New("private local root mode is not the exact fixture mode") }
	mount := &checkpointObserverRouteTmpfsMount{path: bin, fd: -1, attempted: true}
	if err := unix.Mount("tmpfs", bin, "tmpfs", unix.MS_NOSUID|unix.MS_NODEV, checkpointObserverRouteTmpfsOptions()); err != nil {
		return mount, fmt.Errorf("mount bounded executable tmpfs on exact private bin: %w", err)
	}
	mount.mounted = true
	mount.fd, err = unix.Open(bin, unix.O_PATH|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_DIRECTORY, 0)
	if err != nil { return mount, errors.New("mounted bin root descriptor could not be retained") }
	mount.heldRefs = 1
	var mounted unix.Stat_t
	if err := unix.Fstat(mount.fd, &mounted); err != nil || mounted.Uid != 0 || mounted.Gid != 0 || mounted.Mode&unix.S_IFMT != unix.S_IFDIR || mounted.Mode&07777 != 0711 {
		return mount, errors.New("mounted tmpfs root owner or mode is not exact")
	}
	info, err := os.Lstat(bin)
	if err != nil || info.Mode()&os.ModeSymlink != 0 { return mount, errors.New("mounted bin path is not the held mounted directory") }
	pathStat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || uint64(pathStat.Dev) != uint64(mounted.Dev) || pathStat.Ino != mounted.Ino { return mount, errors.New("mounted bin path and held descriptor identities differ") }
	var fs unix.Statfs_t
	if err := unix.Fstatfs(mount.fd, &fs); err != nil || uint64(fs.Type) != checkpointObserverRouteTmpfsMagic || fs.Blocks*uint64(fs.Bsize) != 128<<20 || fs.Files != 128 {
		return mount, errors.New("mounted filesystem is not the finite bounded tmpfs")
	}
	mountInfo, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil { return mount, errors.New("current mount identity could not be read") }
	mount.mountID, ok = checkpointObserverRouteTmpfsMountInfo(string(mountInfo), bin)
	if !ok { return mount, errors.New("current mount is not exact nosuid,nodev executable bounded tmpfs") }
	mount.dev, mount.inode = uint64(mounted.Dev), mounted.Ino
	return mount, nil
}

func checkpointObserverRouteTmpfsCurrent(mount *checkpointObserverRouteTmpfsMount) bool {
	if mount == nil || !mount.mounted || mount.fd < 0 || mount.mountID == 0 { return false }
	var held unix.Stat_t
	if unix.Fstat(mount.fd, &held) != nil || uint64(held.Dev) != mount.dev || held.Ino != mount.inode { return false }
	info, err := os.Lstat(mount.path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 { return false }
	path, ok := info.Sys().(*syscall.Stat_t)
	if !ok || uint64(path.Dev) != mount.dev || path.Ino != mount.inode { return false }
	raw, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil { return false }
	id, valid := checkpointObserverRouteTmpfsMountInfo(string(raw), mount.path)
	return valid && id == mount.mountID
}

func checkpointObserverRouteTmpfsTrackReference(mount *checkpointObserverRouteTmpfsMount) error {
	if mount == nil || !mount.mounted || mount.fd < 0 || mount.heldRefs < 1 { return errors.New("mounted-root reference cannot be transferred") }
	mount.heldRefs++
	return nil
}

func checkpointObserverRouteTmpfsCloseReferenceUsing(mount *checkpointObserverRouteTmpfsMount, descriptor *int, closeFD func(int) error) error {
	if mount == nil || descriptor == nil || *descriptor < 0 || closeFD == nil { return errors.New("mounted-root descriptor owner is unavailable") }
	owned := *descriptor
	*descriptor = -1
	if err := closeFD(owned); err != nil { return err }
	if mount.heldRefs < 1 { return errors.New("mounted-root reference accounting underflow") }
	mount.heldRefs--
	return nil
}

func checkpointObserverRouteTmpfsSettleReferencesUsing(mount *checkpointObserverRouteTmpfsMount, clientFD, mountedRootFD *int, closeFD func(int) error) error {
	if err := checkpointObserverRouteTmpfsCloseReferenceUsing(mount, clientFD, closeFD); err != nil { return fmt.Errorf("client mount-reference close failed: %w", err) }
	if err := checkpointObserverRouteTmpfsCloseReferenceUsing(mount, mountedRootFD, closeFD); err != nil { return fmt.Errorf("mounted-root pin close failed: %w", err) }
	return checkpointObserverRouteTmpfsCloseReferenceUsing(mount, &mount.fd, closeFD)
}

func checkpointObserverRouteTmpfsClose(mount *checkpointObserverRouteTmpfsMount) error {
	if mount == nil || mount.fd < 0 { return nil }
	return checkpointObserverRouteTmpfsCloseReferenceUsing(mount, &mount.fd, unix.Close)
}

func checkpointObserverRouteTmpfsSettledProof(cleanup *checkpointObserverRouteMountedCleanup) (*checkpointObserverRouteTmpfsUnmountProof, error) {
	if cleanup == nil || cleanup.mount == nil || !cleanup.childrenClear || cleanup.mount.heldRefs != 0 || cleanup.mount.fd >= 0 || !cleanup.mount.mounted || cleanup.mount.mountID == 0 ||
		cleanup.rootFD < 0 || cleanup.underlyingFD < 0 || filepath.Dir(cleanup.mount.path) != cleanup.rootPath || filepath.Base(cleanup.mount.path) != "bin" ||
		cleanup.underlyingPath != cleanup.mount.path || cleanup.rootDev == 0 || cleanup.rootIno == 0 || cleanup.underlyingDev == 0 || cleanup.underlyingIno == 0 {
		return nil, errors.New("mount references or dual custody are not settled for exact unmount")
	}
	var root, underlying unix.Stat_t
	if unix.Fstat(cleanup.rootFD, &root) != nil || uint64(root.Dev) != cleanup.rootDev || root.Ino != cleanup.rootIno || root.Uid != 0 || root.Gid != 0 || root.Mode&unix.S_IFMT != unix.S_IFDIR || root.Mode&07777 != 0711 { return nil, errors.New("held local-root parent identity changed before unmount") }
	if !checkpointObserverRouteUnderlyingBinCurrent(cleanup) { return nil, errors.New("held underlying bin custody changed before unmount") }
	if unix.Fstat(cleanup.underlyingFD, &underlying) != nil || uint64(underlying.Dev) != cleanup.underlyingDev || underlying.Ino != cleanup.underlyingIno { return nil, errors.New("underlying bin descriptor identity changed before unmount") }
	rootInfo, err := os.Lstat(cleanup.rootPath)
	if err != nil || rootInfo.Mode()&os.ModeSymlink != 0 { return nil, errors.New("local-root parent path is unavailable before unmount") }
	rootStat, ok := rootInfo.Sys().(*syscall.Stat_t)
	if !ok || uint64(rootStat.Dev) != cleanup.rootDev || rootStat.Ino != cleanup.rootIno || rootStat.Uid != 0 || rootStat.Gid != 0 || rootStat.Mode&07777 != 0711 { return nil, errors.New("local-root parent path no longer matches held identity") }
	mountInfo, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil { return nil, errors.New("fresh mount identity cannot be read after descriptor settlement") }
	id, valid := checkpointObserverRouteTmpfsMountInfo(string(mountInfo), cleanup.mount.path)
	if !valid || id != cleanup.mount.mountID { return nil, errors.New("fresh mountpoint identity changed after descriptor settlement") }
	info, err := os.Lstat(cleanup.mount.path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 { return nil, errors.New("settled mountpoint path is unavailable") }
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || uint64(stat.Dev) != cleanup.mount.dev || stat.Ino != cleanup.mount.inode || stat.Uid != 0 || stat.Gid != 0 || stat.Mode&07777 != 0711 { return nil, errors.New("settled mountpoint path identity changed") }
	var fs unix.Statfs_t
	if err := unix.Statfs(cleanup.mount.path, &fs); err != nil || uint64(fs.Type) != checkpointObserverRouteTmpfsMagic || fs.Blocks*uint64(fs.Bsize) != 128<<20 || fs.Files != 128 { return nil, errors.New("settled mountpoint filesystem geometry changed") }
	return &checkpointObserverRouteTmpfsUnmountProof{mount: cleanup.mount, mountID: id, dev: cleanup.mount.dev, inode: cleanup.mount.inode, underlyingDev: cleanup.underlyingDev, underlyingIno: cleanup.underlyingIno, parentDev: cleanup.rootDev, parentIno: cleanup.rootIno, remainingRefs: cleanup.mount.heldRefs, childrenClear: cleanup.childrenClear, underlyingHeld: true, parentPathCurrent: true, mountPathCurrent: true}, nil
}

func checkpointObserverRouteTmpfsUnmountEligible(mount *checkpointObserverRouteTmpfsMount, proof *checkpointObserverRouteTmpfsUnmountProof) bool {
	return mount != nil && proof != nil && proof.mount == mount && mount.attempted && mount.mounted && !mount.unmountTry && mount.heldRefs == 0 && mount.fd < 0 &&
		proof.remainingRefs == 0 && proof.childrenClear && proof.underlyingHeld && proof.parentPathCurrent && proof.mountPathCurrent && proof.mountID == mount.mountID &&
		proof.dev == mount.dev && proof.inode == mount.inode && proof.underlyingDev != 0 && proof.underlyingIno != 0 && proof.parentDev != 0 && proof.parentIno != 0
}

func checkpointObserverRouteTmpfsUnmountUsing(mount *checkpointObserverRouteTmpfsMount, proof *checkpointObserverRouteTmpfsUnmountProof, unmount func(string, int) error) error {
	if !checkpointObserverRouteTmpfsUnmountEligible(mount, proof) { return errors.New("exact mounted-bin cleanup preconditions are not proven") }
	if unmount == nil { return errors.New("exact unmount operation is unavailable") }
	mount.unmountTry = true
	if err := unmount(mount.path, 0); err != nil { return fmt.Errorf("exact private executable tmpfs unmount failed: %w", err) }
	mount.mounted = false
	return nil
}

func TestCheckpointObserverRouteTmpfsCustodyControls(t *testing.T) {
	positiveInfo := "41 25 0:52 / /run/checkpoint-observer-route-local-abc/bin rw,nosuid,nodev,relatime - tmpfs tmpfs rw,size=131072k,nr_inodes=128,mode=711,inode64"
	if got := checkpointObserverRouteTmpfsOptions(); got != "size=128M,nr_inodes=128,mode=0711,uid=0,gid=0" { t.Fatalf("finite executable tmpfs options changed: %q", got) }
	if id, ok := checkpointObserverRouteTmpfsMountInfo(positiveInfo, "/run/checkpoint-observer-route-local-abc/bin"); !ok || id != 41 { t.Fatalf("exact positive mountinfo rejected: id=%d valid=%t", id, ok) }
	noInodeMode := strings.Replace(positiveInfo, ",inode64", "", 1)
	if id, ok := checkpointObserverRouteTmpfsMountInfo(noInodeMode, "/run/checkpoint-observer-route-local-abc/bin"); !ok || id != 41 { t.Fatalf("mountinfo without an optional inode mode rejected: id=%d valid=%t", id, ok) }
	inode32Info := strings.Replace(positiveInfo, ",inode64", ",inode32", 1)
	if id, ok := checkpointObserverRouteTmpfsMountInfo(inode32Info, "/run/checkpoint-observer-route-local-abc/bin"); !ok || id != 41 { t.Fatalf("equivalent inode32 mountinfo rejected: id=%d valid=%t", id, ok) }
	explicitRoot := strings.Replace(positiveInfo, "mode=711", "mode=711,uid=0,gid=0", 1)
	if id, ok := checkpointObserverRouteTmpfsMountInfo(explicitRoot, "/run/checkpoint-observer-route-local-abc/bin"); !ok || id != 41 { t.Fatalf("equivalent explicit root identity rejected: id=%d valid=%t", id, ok) }
	for name, raw := range map[string]string{
		"noexec": strings.Replace(positiveInfo, "rw,nosuid,nodev,relatime", "rw,nosuid,nodev,noexec,relatime", 1),
		"readonly": strings.Replace(positiveInfo, "rw,nosuid,nodev,relatime", "ro,nosuid,nodev,relatime", 1),
		"missing-nosuid": strings.Replace(positiveInfo, "rw,nosuid,nodev,relatime", "rw,nodev,relatime", 1),
		"missing-nodev": strings.Replace(positiveInfo, "rw,nosuid,nodev,relatime", "rw,nosuid,relatime", 1),
		"unbounded-size": strings.Replace(positiveInfo, "size=131072k", "size=262144k", 1),
		"malformed-size": strings.Replace(positiveInfo, "size=131072k", "size=128M", 1),
		"missing-size": strings.Replace(positiveInfo, "size=131072k,", "", 1),
		"duplicate-size": strings.Replace(positiveInfo, "size=131072k,", "size=131072k,size=131072k,", 1),
		"unbounded-inodes": strings.Replace(positiveInfo, "nr_inodes=128", "nr_inodes=0", 1),
		"duplicate-inodes": strings.Replace(positiveInfo, "nr_inodes=128", "nr_inodes=128,nr_inodes=128", 1),
		"conflicting-inode-modes": strings.Replace(positiveInfo, ",inode64", ",inode32,inode64", 1),
		"duplicate-inode64": strings.Replace(positiveInfo, ",inode64", ",inode64,inode64", 1),
		"duplicate-inode32": strings.Replace(positiveInfo, ",inode64", ",inode32,inode32", 1),
		"malformed-inode64": strings.Replace(positiveInfo, ",inode64", ",inode64=1", 1),
		"malformed-inode32": strings.Replace(positiveInfo, ",inode64", ",inode32=", 1),
		"wrong-mode": strings.Replace(positiveInfo, "mode=711", "mode=755", 1),
		"nonroot-uid": strings.Replace(positiveInfo, "mode=711", "mode=711,uid=1000", 1),
		"nonroot-gid": strings.Replace(positiveInfo, "mode=711", "mode=711,gid=1000", 1),
		"duplicate-uid": strings.Replace(positiveInfo, "mode=711", "mode=711,uid=0,uid=0", 1),
		"conflicting-uid": strings.Replace(positiveInfo, "mode=711", "mode=711,uid=0,uid=1000", 1),
		"wrong-filesystem": strings.Replace(positiveInfo, "- tmpfs tmpfs", "- ext4 ext4", 1),
		"zero-mount-id": strings.Replace(positiveInfo, "41 25", "0 25", 1),
		"malformed-mount-id": strings.Replace(positiveInfo, "41 25", "41x 25", 1),
		"wrong-target": positiveInfo,
	} {
		t.Run(name, func(t *testing.T) {
			target := "/run/checkpoint-observer-route-local-abc/bin"
			if name == "wrong-target" { target += "-substitute" }
			if _, ok := checkpointObserverRouteTmpfsMountInfo(raw, target); ok { t.Fatalf("mutated %s mount identity/options were accepted", name) }
		})
	}
	valid := &checkpointObserverRouteTmpfsMount{path: "/run/checkpoint-observer-route-local-abc/bin", fd: -1, mountID: 41, dev: 52, inode: 99, attempted: true, mounted: true}
	proof := &checkpointObserverRouteTmpfsUnmountProof{mount: valid, mountID: 41, dev: 52, inode: 99, underlyingDev: 52, underlyingIno: 88, parentDev: 52, parentIno: 77, remainingRefs: 0, childrenClear: true, underlyingHeld: true, parentPathCurrent: true, mountPathCurrent: true}
	if !checkpointObserverRouteTmpfsUnmountEligible(valid, proof) { t.Fatal("exact refs-settled/current-identity unmount proof was rejected") }
	for name, mutate := range map[string]func(*checkpointObserverRouteTmpfsMount, *checkpointObserverRouteTmpfsUnmountProof){
		"not-attempted": func(m *checkpointObserverRouteTmpfsMount, _ *checkpointObserverRouteTmpfsUnmountProof) { m.attempted = false },
		"not-mounted": func(m *checkpointObserverRouteTmpfsMount, _ *checkpointObserverRouteTmpfsUnmountProof) { m.mounted = false },
		"attempt-latched": func(m *checkpointObserverRouteTmpfsMount, _ *checkpointObserverRouteTmpfsUnmountProof) { m.unmountTry = true },
		"outstanding-references": func(m *checkpointObserverRouteTmpfsMount, p *checkpointObserverRouteTmpfsUnmountProof) { m.heldRefs = 1; p.remainingRefs = 1 },
		"wrong-proof-mount": func(_ *checkpointObserverRouteTmpfsMount, p *checkpointObserverRouteTmpfsUnmountProof) { p.mount = valid },
		"wrong-mount-id": func(_ *checkpointObserverRouteTmpfsMount, p *checkpointObserverRouteTmpfsUnmountProof) { p.mountID++ },
		"missing-children-clear": func(_ *checkpointObserverRouteTmpfsMount, p *checkpointObserverRouteTmpfsUnmountProof) { p.childrenClear = false },
		"missing-underlying-custody": func(_ *checkpointObserverRouteTmpfsMount, p *checkpointObserverRouteTmpfsUnmountProof) { p.underlyingHeld = false },
		"stale-parent": func(_ *checkpointObserverRouteTmpfsMount, p *checkpointObserverRouteTmpfsUnmountProof) { p.parentPathCurrent = false },
		"stale-mount-path": func(_ *checkpointObserverRouteTmpfsMount, p *checkpointObserverRouteTmpfsUnmountProof) { p.mountPathCurrent = false },
	} {
		t.Run("unmount-"+name, func(t *testing.T) { m, p := *valid, *proof; p.mount = &m; if !checkpointObserverRouteTmpfsUnmountEligible(&m, &p) { t.Fatal("unmutated copied proof was not positive") }; mutate(&m, &p); if checkpointObserverRouteTmpfsUnmountEligible(&m, &p) { t.Fatalf("unmount mutation %s was admitted", name) } })
	}
	underlyingFD := 44
	for failAt := 0; failAt <= 3; failAt++ {
		m := *valid; m.fd, m.heldRefs = 10, 3; clientFD, mountedRootFD, calls := 30, 20, 0; order := []int{}
		closeFake := func(fd int) error { calls++; order = append(order, fd); if failAt != 0 && calls == failAt { return errors.New("injected descriptor close failure") }; return nil }
		err := checkpointObserverRouteTmpfsSettleReferencesUsing(&m, &clientFD, &mountedRootFD, closeFake)
		if failAt == 0 {
			if err != nil || strings.Trim(fmt.Sprint(order), "[]") != "30 20 10" || m.heldRefs != 0 || clientFD != -1 || mountedRootFD != -1 || m.fd != -1 || underlyingFD != 44 { t.Fatal("mounted-reference successful settlement order or underlying custody changed") }
			continue
		}
		if err == nil || calls != failAt || m.heldRefs != 3-(failAt-1) || underlyingFD != 44 { t.Fatalf("close failure %d did not stop settlement with outstanding custody intact", failAt) }
		blocked := m; p := *proof; p.mount = &blocked; p.remainingRefs = blocked.heldRefs
		attempts := 0
		if checkpointObserverRouteTmpfsUnmountUsing(&blocked, &p, func(string, int) error { attempts++; return nil }) == nil || attempts != 0 { t.Fatalf("unmount followed close failure %d", failAt) }
	}
	ops := *valid; opsProof := *proof; opsProof.mount = &ops; var attempts int
	if !checkpointObserverRouteTmpfsUnmountEligible(&ops, &opsProof) { t.Fatal("copied positive unmount proof was not bound to its operation") }
	if err := checkpointObserverRouteTmpfsUnmountUsing(&ops, &opsProof, func(path string, flags int) error { attempts++; if path != ops.path || flags != 0 { return errors.New("wrong exact unmount request") }; return nil }); err != nil || attempts != 1 || ops.mounted { t.Fatal("settled references did not unmount exactly once with flags zero") }
	failed := *valid; failedProof := *proof; failedProof.mount = &failed; injected := errors.New("injected exact unmount failure"); attempts = 0
	if !checkpointObserverRouteTmpfsUnmountEligible(&failed, &failedProof) { t.Fatal("copied error-case proof was not bound to its operation") }
	if err := checkpointObserverRouteTmpfsUnmountUsing(&failed, &failedProof, func(path string, flags int) error { attempts++; if path != failed.path || flags != 0 { return errors.New("wrong exact unmount request") }; return injected }); !errors.Is(err, injected) || attempts != 1 || !failed.unmountTry || !failed.mounted { t.Fatal("unmount error, one-attempt latch, or mounted uncertainty was not preserved") }
	if err := checkpointObserverRouteTmpfsUnmountUsing(&failed, &failedProof, func(string, int) error { attempts++; return nil }); err == nil || attempts != 1 { t.Fatal("uncertain unmount retried after the attempt latch") }
}

func checkpointLocalObserverFixtureWrongGID(actual uint32) uint32 {
	for _, candidate := range []uint32{65533, 65532, 65531, 65530, 65529} {
		if candidate != actual {
			return candidate
		}
	}
	return actual ^ 1
}

func TestCheckpointLocalObserverPolicyCanonicalDecoder(t *testing.T) {
	policy := checkpointLocalObserverPolicy{Version: checkpointLocalObserverVersion, PeerUID: 65534, PeerGID: 65534, ExecutablePath: "/usr/local/libexec/node-agent", ExecutableSHA256: strings.Repeat("a", 64), ControlGroup: "/system.slice/vram-governor-node-agent.service"}
	canonical, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	got, err := checkpointLocalObserverDecodePolicy(canonical)
	if err != nil || got != policy {
		t.Fatalf("typed canonical policy positive rejected: %#v %v", got, err)
	}
	mutants := map[string][]byte{
		"duplicate":    append([]byte(`{"version":1,"version":1,"peer_uid":65534,"peer_gid":65534,"executable_path":"/usr/local/libexec/node-agent","executable_sha256":"`+strings.Repeat("a", 64)+`","control_group":"/system.slice/vram-governor-node-agent.service"}`), nil...),
		"unknown":      append(append([]byte(nil), canonical[:len(canonical)-1]...), []byte(`,"pid":1}`)...),
		"case-variant": bytes.Replace(canonical, []byte(`"version"`), []byte(`"Version"`), 1),
		"null":         bytes.Replace(canonical, []byte(`"peer_uid":65534`), []byte(`"peer_uid":null`), 1),
		"whitespace":   append([]byte{' '}, canonical...),
		"trailing":     append(append([]byte(nil), canonical...), []byte(` {}`)...),
	}
	for name, raw := range mutants {
		t.Run(name, func(t *testing.T) {
			if _, err := checkpointLocalObserverDecodePolicy(raw); err == nil {
				t.Fatalf("noncanonical %s policy was accepted", name)
			}
		})
	}
	stageCalls := 0
	stageConfig := checkpointLocalObserverRuntimeConfig{fixtureAnchor: true, fixtureStageSink: func(stage checkpointLocalObserverStage) {
		if stage != checkpointLocalObserverStageC14 { t.Fatalf("unexpected fixture stage: %s", checkpointLocalObserverStageCode(stage)) }
		stageCalls++
	}}
	sentinel := errors.New("sentinel identity")
	if got := checkpointLocalObserverReportStage(stageConfig, checkpointLocalObserverStageC14, sentinel); got != sentinel || stageCalls != 1 {
		t.Fatal("fixture stage callback changed error identity or callback count")
	}
	stageConfig.fixtureStageSink = func(checkpointLocalObserverStage) { panic("callback panic") }
	if got := checkpointLocalObserverReportStage(stageConfig, checkpointLocalObserverStageC14, sentinel); got != sentinel {
		t.Fatal("fixture callback panic changed the original error identity")
	}
	stageConfig.fixtureStageSink = func(checkpointLocalObserverStage) { stageCalls++ }
	if got := checkpointLocalObserverReportStage(stageConfig, checkpointLocalObserverStageC14, nil); got != nil || stageCalls != 1 {
		t.Fatal("successful operation invoked the fixture stage callback")
	}
	falseAnchor := checkpointLocalObserverRuntimeConfig{fixtureStageSink: func(checkpointLocalObserverStage) { stageCalls++ }}
	if got := checkpointLocalObserverReportStage(falseAnchor, checkpointLocalObserverStageC14, sentinel); got != sentinel || stageCalls != 1 {
		t.Fatal("false fixture anchor invoked the fixture stage callback")
	}
	nilSink := checkpointLocalObserverRuntimeConfig{fixtureAnchor: true}
	if got := checkpointLocalObserverReportStage(nilSink, checkpointLocalObserverStageC14, sentinel); got != sentinel || stageCalls != 1 {
		t.Fatal("nil fixture sink changed error identity or callback count")
	}
	operationPanicked := false
	panicCallbacksBefore := stageCalls
	func() {
		defer func() { operationPanicked = recover() == "operation panic" }()
		resultErr := sentinel
		defer func() { resultErr = checkpointLocalObserverReportStage(stageConfig, checkpointLocalObserverStageC14, resultErr) }()
		panic("operation panic")
	}()
	if !operationPanicked || stageCalls != panicCallbacksBefore+1 {
		t.Fatal("fixture reporter swallowed an original operation panic")
	}
	nilErrorPanicPropagated := false
	nilErrorPanicCallbacksBefore := stageCalls
	func() {
		defer func() { nilErrorPanicPropagated = recover() == "nil result operation panic" }()
		var resultErr error
		defer func() { resultErr = checkpointLocalObserverReportStage(stageConfig, checkpointLocalObserverStageC14, resultErr) }()
		panic("nil result operation panic")
	}()
	if !nilErrorPanicPropagated || stageCalls != nilErrorPanicCallbacksBefore {
		t.Fatal("nil named result panic was swallowed or reported as an operation error")
	}
	if err := checkpointObserverRouteCollectorTraceControls(); err != nil {
		t.Fatal(err)
	}
	if got := checkpointLocalObserverReportStage(checkpointLocalObserverProductionConfig(), checkpointLocalObserverStageC14, sentinel); got != sentinel || stageCalls != panicCallbacksBefore+1 {
		t.Fatal("production configuration enabled fixture stage reporting")
	}
	binding := CheckpointManagedBinding{Version: checkpointLaunchPlanVersion2, CurrentIncarnation: "incarnation", GPUBytes: 128 << 20}
	if got := checkpointObserverRouteClientFailureRecord(sentinel, binding, checkpointLocalObserverStageC14); got != "client=observer_error stage=C14" {
		t.Fatalf("client error diagnostic positive changed: %s", got)
	}
	if got := checkpointObserverRouteClientFailureRecord(nil, CheckpointManagedBinding{CurrentIncarnation: "", GPUBytes: 0}, checkpointLocalObserverStageC14); got != "client=binding_version stage=unavailable" {
		t.Fatalf("binding diagnostic priority changed: %s", got)
	}
	if got := checkpointObserverRouteClientFailureRecord(nil, CheckpointManagedBinding{Version: checkpointLaunchPlanVersion2, GPUBytes: 0}, checkpointLocalObserverStageC14); got != "client=binding_incarnation stage=unavailable" {
		t.Fatalf("incarnation diagnostic priority changed: %s", got)
	}
	if got := checkpointObserverRouteClientFailureRecord(nil, CheckpointManagedBinding{Version: checkpointLaunchPlanVersion2, CurrentIncarnation: "incarnation", GPUBytes: 0}, checkpointLocalObserverStageC14); got != "client=binding_bytes stage=unavailable" {
		t.Fatalf("bytes diagnostic changed: %s", got)
	}
	if got := checkpointObserverRouteClientFailureRecord(nil, binding, checkpointLocalObserverStageC14); got != "" {
		t.Fatalf("successful client diagnostic emitted a failure record: %s", got)
	}
	clientRaw := []byte("=== RUN   TestCheckpointObserverRouteComposedClientChild\nREMOTE_OBSERVER_ROUTE_CLIENT client=observer_error stage=C14\n    checkpoint_local_observer_kernel_linux_test.go:1346: fixed signed local managed route did not return the held root binding: err=opaque\n--- FAIL: TestCheckpointObserverRouteComposedClientChild (0.01s)\nFAIL\n")
	if got := checkpointObserverRouteClientStageFromOutput(clientRaw, false); got != "C14" {
		t.Fatalf("owned client failure positive rejected: %s", got)
	}
	clientReordered := []byte("--- FAIL: TestCheckpointObserverRouteComposedClientChild (0.01s)\n=== RUN   TestCheckpointObserverRouteComposedClientChild\nREMOTE_OBSERVER_ROUTE_CLIENT client=observer_error stage=C14\n    checkpoint_local_observer_kernel_linux_test.go:1346: fixed signed local managed route did not return the held root binding: err=opaque\nFAIL\n")
	if got := checkpointObserverRouteClientStageFromOutput(clientReordered, false); got != "unavailable" {
		t.Fatalf("reordered client records were accepted: %s", got)
	}
	if got := checkpointObserverRouteClientStageFromOutput(append(clientRaw, []byte("foreign extra content\n")...), false); got != "unavailable" {
		t.Fatalf("extra client record was accepted: %s", got)
	}
	if got := checkpointObserverRouteClientStageFromOutput(append(clientRaw, []byte("REMOTE_OBSERVER_ROUTE_CLIENT client=observer_error stage=C15\n")...), false); got != "unavailable" {
		t.Fatalf("duplicate client marker was accepted: %s", got)
	}
	brokerRaw := []byte("=== RUN   TestCheckpointObserverRouteComposedBrokerChild\nCHECKPOINT_OBSERVER_ROUTE_ROOT_BROKER_CHILD_PASS\nREMOTE_OBSERVER_ROUTE_BROKER stage=B03\n")
	if got := checkpointObserverRouteBrokerStageFromOutput(brokerRaw, false); got != "B03" {
		t.Fatalf("owned active broker failure positive rejected: %s", got)
	}
	if got := checkpointObserverRouteBrokerStageFromOutput(append(brokerRaw, []byte("--- PASS: TestCheckpointObserverRouteComposedBrokerChild (0.01s)\n")...), false); got != "unavailable" {
		t.Fatalf("future broker completion record was accepted: %s", got)
	}
	if got := checkpointObserverRouteBrokerStageFromOutput([]byte("REMOTE_OBSERVER_ROUTE_BROKER stage=B03\n=== RUN   TestCheckpointObserverRouteComposedBrokerChild\nCHECKPOINT_OBSERVER_ROUTE_ROOT_BROKER_CHILD_PASS\n"), false); got != "unavailable" {
		t.Fatalf("reordered broker records were accepted: %s", got)
	}
	if got := checkpointObserverRouteBrokerStageFromOutput(append(brokerRaw, []byte("foreign extra content\n")...), false); got != "unavailable" {
		t.Fatalf("extra broker record was accepted: %s", got)
	}
	if got := checkpointObserverRouteBrokerStageFromOutput(append(brokerRaw, []byte("REMOTE_OBSERVER_ROUTE_BROKER stage=B04\n")...), false); got != "unavailable" {
		t.Fatalf("duplicate broker marker was accepted: %s", got)
	}
	if client, broker := checkpointObserverRoutePID1StageRecords(clientRaw, false, brokerRaw, false); client != "C14" || broker != "B03" {
		t.Fatalf("PID1 diagnostic pairing positive rejected: client=%s broker=%s", client, broker)
	}
	if client, broker := checkpointObserverRoutePID1StageRecords(clientRaw, false, brokerRaw, true); client != "C14" || broker != "unavailable" {
		t.Fatalf("overflowed broker evidence was accepted: client=%s broker=%s", client, broker)
	}
	collectorRaw := []byte("=== RUN   TestCheckpointObserverRouteComposedBrokerChild\nCHECKPOINT_OBSERVER_ROUTE_ROOT_BROKER_CHILD_PASS\nCHECKPOINT_OBSERVER_ROUTE_COLLECTOR_ENTER\nCHECKPOINT_OBSERVER_ROUTE_COLLECTOR_COMPLETE k=K2\nREMOTE_OBSERVER_ROUTE_BROKER stage=B15\n")
	if stage, phase, valid := checkpointObserverRouteCollectorEvidence(collectorRaw, false); !valid || stage != "B15" || phase != "K2" {
		t.Fatalf("ordered collector K2 evidence positive rejected: stage=%s phase=%s valid=%t", stage, phase, valid)
	}
	collectorB14Raw := []byte("=== RUN   TestCheckpointObserverRouteComposedBrokerChild\nCHECKPOINT_OBSERVER_ROUTE_ROOT_BROKER_CHILD_PASS\nCHECKPOINT_OBSERVER_ROUTE_COLLECTOR_ENTER\nCHECKPOINT_OBSERVER_ROUTE_COLLECTOR_COMPLETE k=K2\nREMOTE_OBSERVER_ROUTE_BROKER stage=B14\n")
	if stage, phase, valid := checkpointObserverRouteCollectorEvidence(collectorB14Raw, false); !valid || stage != "B14" || phase != "unavailable" {
		t.Fatalf("valid one-pair non-B15 phase suppression positive rejected: stage=%s phase=%s valid=%t", stage, phase, valid)
	}
	twoPairRaw := []byte("=== RUN   TestCheckpointObserverRouteComposedBrokerChild\nCHECKPOINT_OBSERVER_ROUTE_ROOT_BROKER_CHILD_PASS\nCHECKPOINT_OBSERVER_ROUTE_COLLECTOR_ENTER\nCHECKPOINT_OBSERVER_ROUTE_COLLECTOR_COMPLETE k=unavailable\nCHECKPOINT_OBSERVER_ROUTE_COLLECTOR_ENTER\nCHECKPOINT_OBSERVER_ROUTE_COLLECTOR_COMPLETE k=unavailable\nREMOTE_OBSERVER_ROUTE_BROKER stage=B19\n")
	if stage, phase, valid := checkpointObserverRouteCollectorEvidence(twoPairRaw, false); !valid || stage != "B19" || phase != "unavailable" {
		t.Fatalf("identical two-collection unavailable evidence positive rejected: stage=%s phase=%s valid=%t", stage, phase, valid)
	}
	collectorRejects := [][]byte{
		[]byte("=== RUN   TestCheckpointObserverRouteComposedBrokerChild\nCHECKPOINT_OBSERVER_ROUTE_ROOT_BROKER_CHILD_PASS\nCHECKPOINT_OBSERVER_ROUTE_COLLECTOR_COMPLETE k=K2\nCHECKPOINT_OBSERVER_ROUTE_COLLECTOR_ENTER\nREMOTE_OBSERVER_ROUTE_BROKER stage=B15\n"),
		[]byte("=== RUN   TestCheckpointObserverRouteComposedBrokerChild\nCHECKPOINT_OBSERVER_ROUTE_ROOT_BROKER_CHILD_PASS\nCHECKPOINT_OBSERVER_ROUTE_COLLECTOR_ENTER\nREMOTE_OBSERVER_ROUTE_BROKER stage=B15\n"),
		[]byte("=== RUN   TestCheckpointObserverRouteComposedBrokerChild\nCHECKPOINT_OBSERVER_ROUTE_ROOT_BROKER_CHILD_PASS\nCHECKPOINT_OBSERVER_ROUTE_COLLECTOR_ENTER\nCHECKPOINT_OBSERVER_ROUTE_COLLECTOR_COMPLETE k=K2\nCHECKPOINT_OBSERVER_ROUTE_COLLECTOR_ENTER\nCHECKPOINT_OBSERVER_ROUTE_COLLECTOR_COMPLETE k=K1\nREMOTE_OBSERVER_ROUTE_BROKER stage=B15\n"),
		[]byte("=== RUN   TestCheckpointObserverRouteComposedBrokerChild\nCHECKPOINT_OBSERVER_ROUTE_ROOT_BROKER_CHILD_PASS\nCHECKPOINT_OBSERVER_ROUTE_COLLECTOR_ENTER\nCHECKPOINT_OBSERVER_ROUTE_COLLECTOR_COMPLETE k=K9\nREMOTE_OBSERVER_ROUTE_BROKER stage=B15\n"),
		[]byte("=== RUN   TestCheckpointObserverRouteComposedBrokerChild\nCHECKPOINT_OBSERVER_ROUTE_ROOT_BROKER_CHILD_PASS\nCHECKPOINT_OBSERVER_ROUTE_COLLECTOR_ENTER\nCHECKPOINT_OBSERVER_ROUTE_COLLECTOR_COMPLETE k=K1\nCHECKPOINT_OBSERVER_ROUTE_COLLECTOR_ENTER\nCHECKPOINT_OBSERVER_ROUTE_COLLECTOR_COMPLETE k=K1\nREMOTE_OBSERVER_ROUTE_BROKER stage=B18\n"),
		[]byte("=== RUN   TestCheckpointObserverRouteComposedBrokerChild\nCHECKPOINT_OBSERVER_ROUTE_ROOT_BROKER_CHILD_PASS\nCHECKPOINT_OBSERVER_ROUTE_COLLECTOR_COMPLETE k=K1\nCHECKPOINT_OBSERVER_ROUTE_COLLECTOR_ENTER\nCHECKPOINT_OBSERVER_ROUTE_COLLECTOR_ENTER\nCHECKPOINT_OBSERVER_ROUTE_COLLECTOR_COMPLETE k=K1\nREMOTE_OBSERVER_ROUTE_BROKER stage=B19\n"),
		[]byte("=== RUN   TestCheckpointObserverRouteComposedBrokerChild\nCHECKPOINT_OBSERVER_ROUTE_ROOT_BROKER_CHILD_PASS\nCHECKPOINT_OBSERVER_ROUTE_COLLECTOR_ENTER\nCHECKPOINT_OBSERVER_ROUTE_COLLECTOR_COMPLETE k=K1\nCHECKPOINT_OBSERVER_ROUTE_COLLECTOR_ENTER\nCHECKPOINT_OBSERVER_ROUTE_COLLECTOR_COMPLETE k=K1\nCHECKPOINT_OBSERVER_ROUTE_COLLECTOR_ENTER\nCHECKPOINT_OBSERVER_ROUTE_COLLECTOR_COMPLETE k=K1\nREMOTE_OBSERVER_ROUTE_BROKER stage=B19\n"),
	}
	for _, raw := range collectorRejects { if _, phase, valid := checkpointObserverRouteCollectorEvidence(raw, false); valid { t.Fatalf("malformed collector evidence was accepted with phase %s", phase) } }
	nestedSites := "1988,1346"
	kRaw := []byte("=== RUN   TestCheckpointObserverRouteComposedKernelFixture\n    checkpoint_local_observer_kernel_linux_test.go:1988: REMOTE_OBSERVER_ROUTE_PID1 client=C14 broker=B15 k=K2\n            checkpoint_local_observer_kernel_linux_test.go:1346: client=C14\n--- FAIL: TestCheckpointObserverRouteComposedKernelFixture (0.01s)\nFAIL\n")
	if client, broker, phase := checkpointObserverRouteNestedStageRecords(kRaw, false, nestedSites); client != "C14" || broker != "B15" || phase != "K2" { t.Fatalf("owned client/B15 optional-K transport rejected: %s %s %s", client, broker, phase) }
	if client, broker, phase, source := checkpointObserverRoutePID1FailureRecord(clientRaw, false, collectorRaw, false); client != "C14" || broker != "B15" || phase != " k=K2" || !strings.Contains(source, ":1346: client=C14") { t.Fatalf("PID1 marker did not preserve validated collector phase and client association: %s %s %s", client, broker, phase) }
	if len(checkpointObserverRouteNestedDiagnosticRecord("code:1", "no", "1988,1346", "C18", "B15", "K2")) != 119 || len(checkpointObserverRouteNestedDiagnosticRecord("code:1", "no", "1988,1346,449", "C18", "B15", "K2")) != 123 { t.Fatal("actual optional-K nested wire geometry changed") }
	kFallback := checkpointObserverRouteNestedDiagnosticRecord("signal:64", "no", "4799,4798,1988,1346", "C34", "B15", "K2")
	if len(kFallback) > 128 || !strings.Contains(kFallback, " client=C34 broker=B15") || strings.Contains(kFallback, " k=") { t.Fatal("overlong optional K did not fall back by omitting K before legacy broker suffix") }
	nestedRaw := []byte("=== RUN   TestCheckpointObserverRouteComposedKernelFixture\n    checkpoint_local_observer_kernel_linux_test.go:1988: REMOTE_OBSERVER_ROUTE_PID1 client=C14 broker=B03\n            checkpoint_local_observer_kernel_linux_test.go:1346: client=C14\n--- FAIL: TestCheckpointObserverRouteComposedKernelFixture (0.01s)\nFAIL\n")
	if client, broker, phase := checkpointObserverRouteNestedStageRecords(nestedRaw, false, nestedSites); client != "C14" || broker != "B03" || phase != "unavailable" {
		t.Fatalf("nested owned-site stage positive rejected: client=%s broker=%s sites=%s", client, broker, nestedSites)
	}
	for _, raw := range [][]byte{append(append([]byte(nil), nestedRaw...), []byte("foreign extra content\n")...), []byte("    checkpoint_local_observer_kernel_linux_test.go:1988: REMOTE_OBSERVER_ROUTE_PID1 client=C14 broker=B03\n=== RUN   TestCheckpointObserverRouteComposedKernelFixture\n--- FAIL: TestCheckpointObserverRouteComposedKernelFixture (0.01s)\nFAIL\n"), []byte("=== RUN   TestCheckpointObserverRouteComposedKernelFixture\n    checkpoint_local_observer_kernel_linux_test.go:1988: REMOTE_OBSERVER_ROUTE_PID1 client=C14 broker=B03\n            checkpoint_local_observer_kernel_linux_test.go:1346: client=C15\n--- FAIL: TestCheckpointObserverRouteComposedKernelFixture (0.01s)\nFAIL\n"), []byte("=== RUN   TestCheckpointObserverRouteComposedKernelFixture\n    checkpoint_local_observer_kernel_linux_test.go:1988: REMOTE_OBSERVER_ROUTE_PID1 client=C14 broker=B03\n    checkpoint_local_observer_kernel_linux_test.go:1346: client=C14\n--- FAIL: TestCheckpointObserverRouteComposedKernelFixture (0.01s)\nFAIL\n"), []byte("=== RUN   TestCheckpointObserverRouteComposedKernelFixture\nCHECKPOINT_OBSERVER_ROUTE_LOCAL_TREE_CLEANUP_PASS\n    checkpoint_local_observer_kernel_linux_test.go:1988: REMOTE_OBSERVER_ROUTE_PID1 client=C14 broker=B03\n            checkpoint_local_observer_kernel_linux_test.go:1346: client=C14\n--- FAIL: TestCheckpointObserverRouteComposedKernelFixture (0.01s)\nFAIL\n"), []byte("=== RUN   TestCheckpointObserverRouteComposedKernelFixture\n    checkpoint_local_observer_kernel_linux_test.go:1988: REMOTE_OBSERVER_ROUTE_PID1 client=C14 broker=B03\n            checkpoint_local_observer_kernel_linux_test.go:1346: client=C14\nCHECKPOINT_OBSERVER_ROUTE_COMPOSED_KERNEL_PASS_SYNTHETIC_GPU_ONLY\n--- FAIL: TestCheckpointObserverRouteComposedKernelFixture (0.01s)\nFAIL\n"), []byte("=== RUN   TestCheckpointObserverRouteComposedKernelFixture\nCHECKPOINT_OBSERVER_ROUTE_OUTSIDE_SENTINEL_PRESERVED_PASS\nCHECKPOINT_OBSERVER_ROUTE_OUTSIDE_SENTINEL_PRESERVED_PASS\n    checkpoint_local_observer_kernel_linux_test.go:1988: REMOTE_OBSERVER_ROUTE_PID1 client=C14 broker=B03\n            checkpoint_local_observer_kernel_linux_test.go:1346: client=C14\n--- FAIL: TestCheckpointObserverRouteComposedKernelFixture (0.01s)\nFAIL\n")} {
		if client, broker, phase := checkpointObserverRouteNestedStageRecords(raw, false, nestedSites); client != "unavailable" || broker != "unavailable" || phase != "unavailable" {
			t.Fatalf("malformed nested transcript retained stages: client=%s broker=%s", client, broker)
		}
	}
	for _, raw := range [][]byte{[]byte("=== RUN   TestCheckpointObserverRouteComposedKernelFixture\n--- FAIL: TestCheckpointObserverRouteComposedKernelFixture (0.01s)\n    checkpoint_local_observer_kernel_linux_test.go:1988: REMOTE_OBSERVER_ROUTE_PID1 client=C14 broker=B03\nFAIL\n"), []byte("=== RUN   TestCheckpointObserverRouteComposedKernelFixture\n    checkpoint_local_observer_kernel_linux_test.go:1988: REMOTE_OBSERVER_ROUTE_PID1 client=C14 broker=B03\n    checkpoint_local_observer_kernel_linux_test.go:1346: client=C14\n--- FAIL: OtherTest (0.01s)\nFAIL\n"), []byte("=== RUN   TestCheckpointObserverRouteComposedKernelFixture\n    checkpoint_local_observer_kernel_linux_test.go:1988: REMOTE_OBSERVER_ROUTE_PID1 client=C14 broker=B03\n    checkpoint_local_observer_kernel_linux_test.go:1988: REMOTE_OBSERVER_ROUTE_PID1 client=C14 broker=B03\n    checkpoint_local_observer_kernel_linux_test.go:1346: client=C14\n--- FAIL: TestCheckpointObserverRouteComposedKernelFixture (0.01s)\nFAIL\n"), []byte("=== RUN   TestCheckpointObserverRouteComposedKernelFixture\n    checkpoint_local_observer_kernel_linux_test.go:1988: REMOTE_OBSERVER_ROUTE_PID1 client=unavailable broker=B03\n    checkpoint_local_observer_kernel_linux_test.go:1346: client=unavailable\n--- FAIL: TestCheckpointObserverRouteComposedKernelFixture (0.01s)\nFAIL\n"), []byte("=== RUN   TestCheckpointObserverRouteComposedKernelFixture\n    checkpoint_local_observer_kernel_linux_test.go:1988: REMOTE_OBSERVER_ROUTE_PID1 client=C14 broker=B03\n    checkpoint_local_observer_kernel_linux_test.go:1346: client=C14\n--- PASS: TestCheckpointObserverRouteComposedKernelFixture (0.01s)\nPASS\n")} {
		if client, broker, phase := checkpointObserverRouteNestedStageRecords(raw, false, nestedSites); client != "unavailable" || broker != "unavailable" || phase != "unavailable" {
			t.Fatalf("reordered, foreign-header, duplicate, impossible, or success nested transcript retained stages: client=%s broker=%s", client, broker)
		}
	}
	if client, broker, phase := checkpointObserverRouteNestedStageRecords(nestedRaw, true, nestedSites); client != "unavailable" || broker != "unavailable" || phase != "unavailable" {
		t.Fatalf("overflow nested transcript retained stages: client=%s broker=%s", client, broker)
	}
	maxRecord := checkpointObserverRouteNestedDiagnosticRecord("signal:64", "no", "4799,4798,1988,1346", "C34", "B38", "unavailable")
	if len(maxRecord) > 128 || !strings.HasSuffix(maxRecord, " client=C34 broker=B38") {
		t.Fatalf("maximum bounded nested record lost its compatible full suffix: %s", maxRecord)
	}
	fallbackRecord := checkpointObserverRouteNestedDiagnosticRecord("unavailable", "no", "4799,4798,1988,1346", "C34", "B38", "unavailable")
	if len(fallbackRecord) > 128 || !strings.HasSuffix(fallbackRecord, " client=C34") || strings.Contains(fallbackRecord, "broker=") {
		t.Fatalf("overlong nested suffix did not fall back by omitting broker first: %s", fallbackRecord)
	}
	legacyRecord := checkpointObserverRouteNestedDiagnosticRecord("code:1", "no", "245", "unavailable", "unavailable", "unavailable")
	if legacyRecord != "REMOTE_OBSERVER_ROUTE_NESTED stage=test_nonzero exit=code:1 overflow=no assertions=245" {
		t.Fatalf("legacy nested diagnostic prefix changed: %s", legacyRecord)
	}
}

type checkpointObserverRouteCollectorRun func(context.Context, checkpointManagedObservationSource) (CheckpointManagedBinding, error)

func checkpointObserverRouteSameErrorIdentity(left, right error) bool {
	if left == nil || right == nil {
		return false
	}
	leftValue, rightValue := reflect.ValueOf(left), reflect.ValueOf(right)
	return leftValue.Comparable() && rightValue.Comparable() && left == right
}

func checkpointObserverRouteCollectorTrace(ctx context.Context, source checkpointManagedObservationSource, fixtureAnchor bool, sink func(string), run checkpointObserverRouteCollectorRun) (CheckpointManagedBinding, error, bool) {
	emissionValid := fixtureAnchor && sink != nil
	emit := func(record string) {
		if !fixtureAnchor || sink == nil {
			emissionValid = false
			return
		}
		completed := false
		func() {
			defer func() {
				if recover() != nil {
					completed = false
				}
			}()
			sink(record)
			completed = true
		}()
		if !completed {
			emissionValid = false
		}
	}
	emit("CHECKPOINT_OBSERVER_ROUTE_COLLECTOR_ENTER")
	entries, completions := 0, 0
	var nestedErr error
	originalNested := source.nestedFootprint
	if originalNested != nil {
		source.nestedFootprint = func(callCtx context.Context, pid int, start uint64, plan CheckpointLaunchPlan, placement CheckpointDevicePlacement) (int64, int64, error) {
			if entries < 2 {
				entries++
			}
			used, free, err := originalNested(callCtx, pid, start, plan, placement)
			if completions < 2 {
				completions++
			}
			if entries == 1 && completions == 1 {
				nestedErr = err
			}
			return used, free, err
		}
	}
	binding, collectErr := run(ctx, source)
	phase := "unavailable"
	if emissionValid && originalNested != nil && collectErr != nil {
		switch {
		case entries == 0 && completions == 0:
			phase = "K1"
		case entries == 1 && completions == 1 && checkpointObserverRouteSameErrorIdentity(nestedErr, collectErr):
			phase = "K2"
		case entries == 1 && completions == 1 && nestedErr == nil:
			phase = "K3"
		}
	}
	emit("CHECKPOINT_OBSERVER_ROUTE_COLLECTOR_COMPLETE k=" + phase)
	return binding, collectErr, emissionValid
}

func checkpointObserverRouteDrainCollectorTrace(records [2]string, recordCount int, sinkOverflow, traceValid bool) []string {
	if !traceValid || sinkOverflow || recordCount != len(records) || records[0] != "CHECKPOINT_OBSERVER_ROUTE_COLLECTOR_ENTER" || !regexp.MustCompile(`^CHECKPOINT_OBSERVER_ROUTE_COLLECTOR_COMPLETE k=(K[1-3]|unavailable)$`).MatchString(records[1]) {
		return nil
	}
	return records[:]
}

func checkpointObserverRouteCollectorTraceControls() error {
	ctx := context.Background()
	plan, placement := CheckpointLaunchPlan{}, CheckpointDevicePlacement{}
	sentinel := errors.New("collector identity sentinel")
	var traces []string
	sink := func(record string) { traces = append(traces, record) }
	makeSource := func(nested func(context.Context, int, uint64, CheckpointLaunchPlan, CheckpointDevicePlacement) (int64, int64, error)) checkpointManagedObservationSource {
		return checkpointManagedObservationSource{nestedFootprint: nested}
	}
	runFor := func(binding CheckpointManagedBinding, err, nestedWant error, nestedCalls int, forwarded *int, badArgs *bool) checkpointObserverRouteCollectorRun {
		return func(callCtx context.Context, copied checkpointManagedObservationSource) (CheckpointManagedBinding, error) {
			for index := 0; index < nestedCalls; index++ {
				used, free, nestedErr := copied.nestedFootprint(callCtx, 7, 11, plan, placement)
				if used != 17 || free != 19 {
					return CheckpointManagedBinding{}, errors.New("collector wrapper changed nested return values")
				}
				preserved := (nestedErr == nil) == (nestedWant == nil)
				if preserved && nestedWant != nil {
					value := reflect.ValueOf(nestedWant)
					if value.Comparable() { preserved = checkpointObserverRouteSameErrorIdentity(nestedErr, nestedWant) } else { preserved = reflect.DeepEqual(nestedErr, nestedWant) }
				}
				if !preserved {
					return CheckpointManagedBinding{}, errors.New("collector wrapper changed nested error")
				}
			}
			if (forwarded != nil && *forwarded != nestedCalls) || (badArgs != nil && *badArgs) {
				return CheckpointManagedBinding{}, errors.New("collector wrapper changed nested call count or arguments")
			}
			return binding, err
		}
	}
	phaseFrom := func() string {
		if len(traces) != 2 || traces[0] != "CHECKPOINT_OBSERVER_ROUTE_COLLECTOR_ENTER" || !strings.HasPrefix(traces[1], "CHECKPOINT_OBSERVER_ROUTE_COLLECTOR_COMPLETE k=") {
			return "invalid"
		}
		return strings.TrimPrefix(traces[1], "CHECKPOINT_OBSERVER_ROUTE_COLLECTOR_COMPLETE k=")
	}
	for _, test := range []struct {
		name, want string
		nestedErr error
		nestedCalls int
	}{
		{name: "K1 full receiver path", want: "K1"},
		{name: "K2 full receiver path", want: "K2", nestedErr: sentinel, nestedCalls: 1},
		{name: "K3 full receiver path", want: "K3", nestedCalls: 1},
	} {
		collectorCalls, nestedCalls := 0, 0
		var records [2]string
		recordCount, sinkOverflow := 0, false
		binding := CheckpointManagedBinding{GPUBytes: 313}
		collectErr := sentinel
		source := makeSource(func(context.Context, int, uint64, CheckpointLaunchPlan, CheckpointDevicePlacement) (int64, int64, error) { nestedCalls++; return 17, 19, test.nestedErr })
		collector := func(callCtx context.Context, copied checkpointManagedObservationSource) (CheckpointManagedBinding, error) {
			collectorCalls++
			if test.nestedCalls == 1 {
				used, free, gotNestedErr := copied.nestedFootprint(callCtx, 7, 11, plan, placement)
				preservedNested := (gotNestedErr == nil) == (test.nestedErr == nil)
				if preservedNested && test.nestedErr != nil { value := reflect.ValueOf(test.nestedErr); if value.Comparable() { preservedNested = checkpointObserverRouteSameErrorIdentity(gotNestedErr, test.nestedErr) } else { preservedNested = reflect.DeepEqual(gotNestedErr, test.nestedErr) } }
				if used != 17 || free != 19 || !preservedNested { return CheckpointManagedBinding{}, errors.New("integrated collector changed nested result/error") }
			}
			return binding, collectErr
		}
		got, gotErr, traceValid := checkpointObserverRouteCollectorTrace(ctx, source, true, func(record string) {
			if recordCount >= len(records) { sinkOverflow = true; return }
			records[recordCount] = record; recordCount++
		}, collector)
		published := checkpointObserverRouteDrainCollectorTrace(records, recordCount, sinkOverflow, traceValid)
		raw := []byte("=== RUN   TestCheckpointObserverRouteComposedBrokerChild\nCHECKPOINT_OBSERVER_ROUTE_ROOT_BROKER_CHILD_PASS\n" + strings.Join(published, "\n"))
		if len(published) != 0 { raw = append(raw, '\n') }
		raw = append(raw, []byte("REMOTE_OBSERVER_ROUTE_BROKER stage=B15\n")...)
		stage, phase, valid := checkpointObserverRouteCollectorEvidence(raw, false)
		if got.GPUBytes != binding.GPUBytes || !checkpointObserverRouteSameErrorIdentity(gotErr, collectErr) || collectorCalls != 1 || nestedCalls != test.nestedCalls || !valid || stage != "B15" || phase != test.want {
			return fmt.Errorf("actual collector/drain/receiver positive %s failed: stage=%s phase=%s valid=%t", test.name, stage, phase, valid)
		}
	}
	collectPair := func(collectErr error) ([2]string, bool) {
		var records [2]string
		recordCount, sinkOverflow := 0, false
		source := makeSource(func(context.Context, int, uint64, CheckpointLaunchPlan, CheckpointDevicePlacement) (int64, int64, error) { return 17, 19, nil })
		binding, gotErr, traceValid := checkpointObserverRouteCollectorTrace(ctx, source, true, func(record string) {
			if recordCount >= len(records) { sinkOverflow = true; return }
			records[recordCount] = record
			recordCount++
		}, func(callCtx context.Context, copied checkpointManagedObservationSource) (CheckpointManagedBinding, error) {
			used, free, nestedErr := copied.nestedFootprint(callCtx, 7, 11, plan, placement)
			if used != 17 || free != 19 || nestedErr != nil { return CheckpointManagedBinding{}, errors.New("two-collection helper changed nested result") }
			return CheckpointManagedBinding{GPUBytes: 313}, collectErr
		})
		published := checkpointObserverRouteDrainCollectorTrace(records, recordCount, sinkOverflow, traceValid)
		return records, traceValid && len(published) == 2 && binding.GPUBytes == 313 && gotErr == collectErr
	}
	firstSuccess, firstValid := collectPair(nil)
	secondSuccess, secondSuccessValid := collectPair(nil)
	secondError, secondErrorValid := collectPair(sentinel)
	for _, test := range []struct { name string; second [2]string; finalStage, wantPhase string; secondValid bool }{
		{name: "two collect first-success second-success", second: secondSuccess, finalStage: "B20", wantPhase: "unavailable", secondValid: secondSuccessValid},
		{name: "two collect first-success second-error", second: secondError, finalStage: "B19", wantPhase: "unavailable", secondValid: secondErrorValid},
	} {
		if !firstValid || !test.secondValid { return fmt.Errorf("actual %s helper/drain positive failed", test.name) }
		raw := []byte("=== RUN   TestCheckpointObserverRouteComposedBrokerChild\nCHECKPOINT_OBSERVER_ROUTE_ROOT_BROKER_CHILD_PASS\n" + strings.Join(append(firstSuccess[:], test.second[:]...), "\n") + "\nREMOTE_OBSERVER_ROUTE_BROKER stage=" + test.finalStage + "\n")
		stage, phase, valid := checkpointObserverRouteCollectorEvidence(raw, false)
		if !valid || stage != test.finalStage || phase != test.wantPhase { return fmt.Errorf("actual %s receiver positive failed: stage=%s phase=%s valid=%t", test.name, stage, phase, valid) }
	}
	validTraceRecords := [2]string{"CHECKPOINT_OBSERVER_ROUTE_COLLECTOR_ENTER", "CHECKPOINT_OBSERVER_ROUTE_COLLECTOR_COMPLETE k=K2"}
	for _, invalid := range []struct {
		name string
		records [2]string
		count int
		overflow, traceValid bool
	}{
		{name: "invalid anchor", records: validTraceRecords, count: 2, traceValid: true},
		{name: "incomplete record pair", records: validTraceRecords, count: 1, traceValid: true},
		{name: "overflowed sink", records: validTraceRecords, count: 2, overflow: true, traceValid: true},
		{name: "malformed completion grammar", records: [2]string{"CHECKPOINT_OBSERVER_ROUTE_COLLECTOR_ENTER", "CHECKPOINT_OBSERVER_ROUTE_COLLECTOR_COMPLETE k=K4"}, count: 2, traceValid: true},
	} {
		if invalid.name == "invalid anchor" { invalid.records[0] = "FOREIGN" }
		if got := checkpointObserverRouteDrainCollectorTrace(invalid.records, invalid.count, invalid.overflow, invalid.traceValid); len(got) != 0 {
			return fmt.Errorf("bounded collector drain retained %s", invalid.name)
		}
		raw := []byte("=== RUN   TestCheckpointObserverRouteComposedBrokerChild\nCHECKPOINT_OBSERVER_ROUTE_ROOT_BROKER_CHILD_PASS\n" + strings.Join(checkpointObserverRouteDrainCollectorTrace(invalid.records, invalid.count, invalid.overflow, invalid.traceValid), "\n") + "REMOTE_OBSERVER_ROUTE_BROKER stage=B15\n")
		_, phase, valid := checkpointObserverRouteCollectorEvidence(raw, false)
		if valid && phase != "unavailable" { return fmt.Errorf("invalid collector trace %s produced finite receiver evidence", invalid.name) }
	}
	for _, test := range []struct {
		name, want string
		nestedErr error
		collectErr error
		nestedCalls int
	}{
		{name: "K1 before nested callback", want: "K1", collectErr: sentinel},
		{name: "K2 exact nested error", want: "K2", nestedErr: sentinel, collectErr: sentinel, nestedCalls: 1},
		{name: "K3 successful nested then collect error", want: "K3", collectErr: sentinel, nestedCalls: 1},
		{name: "success unavailable", want: "unavailable", nestedCalls: 1},
		{name: "mismatched nested error", want: "unavailable", nestedErr: errors.New("different nested error"), collectErr: sentinel, nestedCalls: 1},
		{name: "typed-nil error identity", want: "K2", nestedErr: error((*checkpointObserverRouteTypedNilError)(nil)), collectErr: error((*checkpointObserverRouteTypedNilError)(nil)), nestedCalls: 1},
		{name: "repeated nested invocation", want: "unavailable", nestedErr: sentinel, collectErr: sentinel, nestedCalls: 2},
	} {
		traces = nil
		binding := CheckpointManagedBinding{GPUBytes: 123}
		forwarded, badArgs := 0, false
		source := makeSource(func(callCtx context.Context, pid int, start uint64, gotPlan CheckpointLaunchPlan, gotPlacement CheckpointDevicePlacement) (int64, int64, error) {
			forwarded++
			badArgs = callCtx != ctx || pid != 7 || start != 11 || !reflect.DeepEqual(gotPlan, plan) || !reflect.DeepEqual(gotPlacement, placement)
			return 17, 19, test.nestedErr
		})
		got, gotErr, traceValid := checkpointObserverRouteCollectorTrace(ctx, source, true, sink, runFor(binding, test.collectErr, test.nestedErr, test.nestedCalls, &forwarded, &badArgs))
		preserved := (gotErr == nil) == (test.collectErr == nil)
		if preserved && test.collectErr != nil { value := reflect.ValueOf(test.collectErr); if value.Comparable() { preserved = checkpointObserverRouteSameErrorIdentity(gotErr, test.collectErr) } else { preserved = reflect.DeepEqual(gotErr, test.collectErr) } }
		if got.GPUBytes != binding.GPUBytes || !preserved || phaseFrom() != test.want || !traceValid {
			return fmt.Errorf("collector trace positive %s: phase=%s errPreserved=%t", test.name, phaseFrom(), gotErr == test.collectErr)
		}
	}
	nonComparable := error(checkpointObserverRouteNonComparableError{Value: []byte("not comparable")})
	traces = nil
	forwarded, badArgs := 0, false
	_, gotErr, traceValid := checkpointObserverRouteCollectorTrace(ctx, makeSource(func(callCtx context.Context, pid int, start uint64, gotPlan CheckpointLaunchPlan, gotPlacement CheckpointDevicePlacement) (int64, int64, error) { forwarded++; badArgs = callCtx != ctx || pid != 7 || start != 11 || !reflect.DeepEqual(gotPlan, plan) || !reflect.DeepEqual(gotPlacement, placement); return 17, 19, nonComparable }), true, sink, runFor(CheckpointManagedBinding{}, nonComparable, nonComparable, 1, &forwarded, &badArgs))
	if !reflect.DeepEqual(gotErr, nonComparable) || phaseFrom() != "unavailable" || !traceValid {
		return errors.New("nested interface payload noncomparability produced finite K2")
	}
	directSlice := checkpointObserverRouteSliceError([]byte("direct slice error"))
	traces = nil
	_, gotErr, traceValid = checkpointObserverRouteCollectorTrace(ctx, makeSource(func(context.Context, int, uint64, CheckpointLaunchPlan, CheckpointDevicePlacement) (int64, int64, error) { return 17, 19, directSlice }), true, sink, runFor(CheckpointManagedBinding{}, directSlice, directSlice, 1, nil, nil))
	if !reflect.DeepEqual(gotErr, directSlice) || phaseFrom() != "unavailable" || !traceValid {
		return errors.New("direct noncomparable error was not preserved as unavailable")
	}
	for _, test := range []struct {
		name string
		anchor bool
		sink func(string)
		wantEmissions int
	}{
		{name: "disabled anchor", anchor: false, sink: sink, wantEmissions: 0},
		{name: "nil sink", anchor: true, wantEmissions: 0},
		{name: "panicking ENTER sink", anchor: true, sink: func(string) { panic("enter sink") }, wantEmissions: 0},
		{name: "panicking COMPLETE sink", anchor: true, sink: func(record string) { traces = append(traces, record); if strings.Contains(record, "COMPLETE") { panic("complete sink") } }, wantEmissions: 2},
	} {
		traces = nil
		calls := 0
		binding := CheckpointManagedBinding{GPUBytes: 77}
		forwarded, badArgs := 0, false
		got, gotErr, traceValid := checkpointObserverRouteCollectorTrace(ctx, makeSource(func(callCtx context.Context, pid int, start uint64, gotPlan CheckpointLaunchPlan, gotPlacement CheckpointDevicePlacement) (int64, int64, error) { calls++; forwarded++; badArgs = callCtx != ctx || pid != 7 || start != 11 || !reflect.DeepEqual(gotPlan, plan) || !reflect.DeepEqual(gotPlacement, placement); return 17, 19, nil }), test.anchor, test.sink, runFor(binding, sentinel, nil, 1, &forwarded, &badArgs))
		if got.GPUBytes != binding.GPUBytes || gotErr != sentinel || calls != 1 || len(traces) != test.wantEmissions || traceValid {
			return fmt.Errorf("collector trace %s changed operation or emission behavior", test.name)
		}
	}
	for _, panicRecord := range []string{"CHECKPOINT_OBSERVER_ROUTE_COLLECTOR_ENTER", "CHECKPOINT_OBSERVER_ROUTE_COLLECTOR_COMPLETE k=K1"} {
		var records [2]string
		recordCount, sinkOverflow, panicOccurred := 0, false, false
		_, _, traceValid := checkpointObserverRouteCollectorTrace(ctx, makeSource(func(context.Context, int, uint64, CheckpointLaunchPlan, CheckpointDevicePlacement) (int64, int64, error) { return 17, 19, nil }), true, func(record string) {
			if recordCount >= len(records) { sinkOverflow = true; return }
			records[recordCount] = record; recordCount++
			if record == panicRecord { panicOccurred = true; panic("append then sink panic") }
		}, func(context.Context, checkpointManagedObservationSource) (CheckpointManagedBinding, error) { return CheckpointManagedBinding{}, sentinel })
		published := checkpointObserverRouteDrainCollectorTrace(records, recordCount, sinkOverflow, traceValid)
		raw := []byte("=== RUN   TestCheckpointObserverRouteComposedBrokerChild\nCHECKPOINT_OBSERVER_ROUTE_ROOT_BROKER_CHILD_PASS\n" + strings.Join(published, "\n"))
		if len(published) != 0 { raw = append(raw, '\n') }
		raw = append(raw, []byte("REMOTE_OBSERVER_ROUTE_BROKER stage=B15\n")...)
		broker, phase, valid := checkpointObserverRouteCollectorEvidence(raw, false)
		if !panicOccurred || traceValid || !valid || broker != "B15" || phase != "unavailable" { return fmt.Errorf("append-then-panic %s published finite evidence", panicRecord) }
	}
	traces = nil
	operationPanicPropagated := false
	func() {
		defer func() { operationPanicPropagated = recover() == "collector operation panic" }()
		_, _, _ = checkpointObserverRouteCollectorTrace(ctx, makeSource(func(context.Context, int, uint64, CheckpointLaunchPlan, CheckpointDevicePlacement) (int64, int64, error) { panic("collector operation panic") }), true, sink, func(context.Context, checkpointManagedObservationSource) (CheckpointManagedBinding, error) { panic("collector operation panic") })
	}()
	if !operationPanicPropagated || len(traces) != 1 || traces[0] != "CHECKPOINT_OBSERVER_ROUTE_COLLECTOR_ENTER" {
		return errors.New("collector operation panic was recovered or emitted a false COMPLETE")
	}
	traces = nil
	nestedForwarded, nestedPanicPropagated := 0, false
	func() {
		defer func() { nestedPanicPropagated = recover() == "nested operation panic" }()
		_, _, _ = checkpointObserverRouteCollectorTrace(ctx, makeSource(func(context.Context, int, uint64, CheckpointLaunchPlan, CheckpointDevicePlacement) (int64, int64, error) { nestedForwarded++; panic("nested operation panic") }), true, sink, func(callCtx context.Context, copied checkpointManagedObservationSource) (CheckpointManagedBinding, error) { _, _, _ = copied.nestedFootprint(callCtx, 7, 11, plan, placement); return CheckpointManagedBinding{}, nil })
	}()
	if !nestedPanicPropagated || nestedForwarded != 1 || len(traces) != 1 || traces[0] != "CHECKPOINT_OBSERVER_ROUTE_COLLECTOR_ENTER" {
		return errors.New("nested callback panic was recovered, suppressed, or emitted a false COMPLETE")
	}
	return nil
}

type checkpointObserverRouteNonComparableError struct{ Value any }

func (checkpointObserverRouteNonComparableError) Error() string { return "noncomparable payload" }

type checkpointObserverRouteSliceError []byte

func (checkpointObserverRouteSliceError) Error() string { return "direct slice error" }

type checkpointObserverRouteTypedNilError struct{}

func (*checkpointObserverRouteTypedNilError) Error() string { return "typed nil error" }

func checkpointObserverRouteCollectorEvidence(raw []byte, overflow bool) (string, string, bool) {
	if overflow || len(raw) == 0 || len(raw) > 4096 {
		return "unavailable", "unavailable", false
	}
	lines, ok := checkpointObserverRouteDiagnosticLines(raw)
	if !ok {
		return "unavailable", "unavailable", false
	}
	if len(lines) == 3 && lines[0] == "=== RUN   TestCheckpointObserverRouteComposedBrokerChild" && lines[1] == "CHECKPOINT_OBSERVER_ROUTE_ROOT_BROKER_CHILD_PASS" {
		match := regexp.MustCompile(`^REMOTE_OBSERVER_ROUTE_BROKER stage=(B[0-9]{2})$`).FindStringSubmatch(lines[2])
		if match != nil && match[1] >= "B01" && match[1] <= "B38" {
			return match[1], "unavailable", true
		}
		return "unavailable", "unavailable", false
	}
	if len(lines) < 2 {
		return "unavailable", "unavailable", false
	}
	if lines[0] != "=== RUN   TestCheckpointObserverRouteComposedBrokerChild" || lines[1] != "CHECKPOINT_OBSERVER_ROUTE_ROOT_BROKER_CHILD_PASS" {
		return "unavailable", "unavailable", false
	}
	if len(lines) == 7 {
		if lines[2] != "CHECKPOINT_OBSERVER_ROUTE_COLLECTOR_ENTER" || lines[4] != "CHECKPOINT_OBSERVER_ROUTE_COLLECTOR_ENTER" {
			return "unavailable", "unavailable", false
		}
		for _, index := range []int{3, 5} {
			if !regexp.MustCompile(`^CHECKPOINT_OBSERVER_ROUTE_COLLECTOR_COMPLETE k=(K[1-3]|unavailable)$`).MatchString(lines[index]) {
				return "unavailable", "unavailable", false
			}
		}
		stageMatch := regexp.MustCompile(`^REMOTE_OBSERVER_ROUTE_BROKER stage=(B[0-9]{2})$`).FindStringSubmatch(lines[6])
		if stageMatch == nil || stageMatch[1] < "B19" || stageMatch[1] > "B38" {
			return "unavailable", "unavailable", false
		}
		return stageMatch[1], "unavailable", true
	}
	if len(lines) != 5 || lines[2] != "CHECKPOINT_OBSERVER_ROUTE_COLLECTOR_ENTER" {
		return "unavailable", "unavailable", false
	}
	phaseMatch := regexp.MustCompile(`^CHECKPOINT_OBSERVER_ROUTE_COLLECTOR_COMPLETE k=(K[1-3]|unavailable)$`).FindStringSubmatch(lines[3])
	stageMatch := regexp.MustCompile(`^REMOTE_OBSERVER_ROUTE_BROKER stage=(B[0-9]{2})$`).FindStringSubmatch(lines[4])
	if phaseMatch == nil || stageMatch == nil || stageMatch[1] < "B01" || stageMatch[1] > "B38" {
		return "unavailable", "unavailable", false
	}
	phase := phaseMatch[1]
	if stageMatch[1] != "B15" {
		phase = "unavailable"
	}
	return stageMatch[1], phase, true
}

func checkpointObserverRouteNestedDiagnosticRecord(exit, overflow, assertions, client, broker, phase string) string {
	base := fmt.Sprintf("REMOTE_OBSERVER_ROUTE_NESTED stage=test_nonzero exit=%s overflow=%s assertions=%s", exit, overflow, assertions)
	if overflow != "no" || client < "C01" || client > "C34" || assertions == "unavailable" { return base }
	sites := strings.Split(assertions, ",")
	seen, has1988, has1346 := make(map[string]bool), false, false
	if len(sites) == 0 || len(sites) > 4 { return base }
	for _, site := range sites { value, err := strconv.Atoi(site); if err != nil || value < 1 || value > 4800 || fmt.Sprintf("%d", value) != site || seen[site] { return base }; seen[site] = true; has1988 = has1988 || site == "1988"; has1346 = has1346 || site == "1346" }
	if !has1988 || !has1346 { return base }
	suffix := " client=" + client
	if broker >= "B01" && broker <= "B38" { suffix += " broker=" + broker }
	if (phase == "K1" || phase == "K2" || phase == "K3") && broker == "B15" { suffix += " k=" + phase }
	if len(base+suffix) <= 128 { return base+suffix }
	if phase == "K1" || phase == "K2" || phase == "K3" { suffix = " client=" + client; if broker >= "B01" && broker <= "B38" { suffix += " broker=" + broker }; if len(base+suffix) <= 128 { return base+suffix } }
	if broker >= "B01" && broker <= "B38" { suffix = " client=" + client }
	if len(base+suffix) <= 128 { return base+suffix }
	return base
}

func checkpointObserverRouteClientFailureRecord(err error, binding CheckpointManagedBinding, stage checkpointLocalObserverStage) string {
	diagnostic, stageCode := "", "unavailable"
	if err != nil {
		diagnostic = "observer_error"
		code := checkpointLocalObserverStageCode(stage)
		if strings.HasPrefix(code, "C") { stageCode = code }
	} else if binding.Version != checkpointLaunchPlanVersion2 {
		diagnostic = "binding_version"
	} else if binding.CurrentIncarnation == "" {
		diagnostic = "binding_incarnation"
	} else if binding.GPUBytes != 128<<20 {
		diagnostic = "binding_bytes"
	}
	if diagnostic == "" { return "" }
	return "client=" + diagnostic + " stage=" + stageCode
}

func checkpointObserverRouteClientStageFromOutput(raw []byte, overflow bool) string {
	stage, _ := checkpointObserverRouteClientEvidence(raw, overflow)
	return stage
}

func checkpointObserverRouteClientEvidence(raw []byte, overflow bool) (string, bool) {
	if overflow || len(raw) == 0 || len(raw) > 4096 { return "unavailable", false }
	lines, ok := checkpointObserverRouteDiagnosticLines(raw)
	if !ok || len(lines) != 5 || lines[0] != "=== RUN   TestCheckpointObserverRouteComposedClientChild" || lines[4] != "FAIL" { return "unavailable", false }
	match := regexp.MustCompile(`^REMOTE_OBSERVER_ROUTE_CLIENT client=(observer_error|binding_version|binding_incarnation|binding_bytes) stage=(C[0-9]{2}|unavailable)$`).FindStringSubmatch(lines[1])
	if match == nil { return "unavailable", false }
	if !strings.HasPrefix(lines[2], "    checkpoint_local_observer_kernel_linux_test.go:1346: fixed signed local managed route did not return the held root binding: err=") || lines[2] == "    checkpoint_local_observer_kernel_linux_test.go:1346: fixed signed local managed route did not return the held root binding: err=" { return "unavailable", false }
	if !checkpointObserverRouteOwnedFailureHeader(lines[3], "TestCheckpointObserverRouteComposedClientChild") { return "unavailable", false }
	stage := "unavailable"
	if match[1] == "observer_error" && match[2] >= "C01" && match[2] <= "C34" { stage = match[2] } else if match[2] != "unavailable" { return "unavailable", false }
	return stage, true
}

func checkpointObserverRouteBrokerStageFromOutput(raw []byte, overflow bool) string {
	stage, _, valid := checkpointObserverRouteCollectorEvidence(raw, overflow)
	if !valid { return "unavailable" }
	return stage
}

func checkpointObserverRouteDiagnosticLines(raw []byte) ([]string, bool) {
	if bytes.IndexByte(raw, '\r') >= 0 { return nil, false }
	lines := strings.Split(string(raw), "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" { lines = lines[:len(lines)-1] }
	for _, line := range lines { if line == "" { return nil, false } }
	return lines, len(lines) > 0
}

func checkpointObserverRouteOwnedFailureHeader(line, name string) bool {
	match := regexp.MustCompile(`^--- FAIL: ` + regexp.QuoteMeta(name) + ` \(([0-9]+(?:\.[0-9]+)?)s\)$`).FindStringSubmatch(line)
	return match != nil
}

func checkpointObserverRoutePID1StageRecords(clientRaw []byte, clientOverflow bool, brokerRaw []byte, brokerOverflow bool) (string, string) {
	client, validClient := checkpointObserverRouteClientEvidence(clientRaw, clientOverflow)
	broker := checkpointObserverRouteBrokerStageFromOutput(brokerRaw, brokerOverflow)
	if client < "C01" || client > "C34" || !validClient { broker = "unavailable" }
	return client, broker
}

func checkpointObserverRoutePID1FailureRecord(clientRaw []byte, clientOverflow bool, brokerRaw []byte, brokerOverflow bool) (string, string, string, string) {
	client, validClient := checkpointObserverRouteClientEvidence(clientRaw, clientOverflow)
	broker := checkpointObserverRouteBrokerStageFromOutput(brokerRaw, brokerOverflow)
	if !validClient || client < "C01" || client > "C34" { broker = "unavailable" }
	_, phase, validCollector := checkpointObserverRouteCollectorEvidence(brokerRaw, brokerOverflow)
	if !validCollector || broker != "B15" || client == "unavailable" { phase = "unavailable" }
	source := ""
	if validClient { source = "\n    checkpoint_local_observer_kernel_linux_test.go:1346: client=" + client }
	phaseSuffix := ""
	if phase == "K1" || phase == "K2" || phase == "K3" { phaseSuffix = " k=" + phase }
	return client, broker, phaseSuffix, source
}

func checkpointObserverRouteNestedStageRecords(raw []byte, overflow bool, assertions string) (string, string, string) {
	if overflow || len(raw) == 0 || len(raw) > 4096 { return "unavailable", "unavailable", "unavailable" }
	lines, ok := checkpointObserverRouteDiagnosticLines(raw)
	if !ok { return "unavailable", "unavailable", "unavailable" }
	markers, clientSources, headers, summaries, runCount, state := 0, 0, 0, 0, 0, 0
	client, broker, phase := "unavailable", "unavailable", "unavailable"
	for _, line := range lines {
		if strings.HasPrefix(line, "=== RUN") {
			runCount++; if state != 0 || runCount != 1 || line != "=== RUN   TestCheckpointObserverRouteComposedKernelFixture" { return "unavailable", "unavailable", "unavailable" }; state = 1; continue
		}
		if checkpointObserverRouteOwnedFailureHeader(line, "TestCheckpointObserverRouteComposedKernelFixture") {
			if state != 3 || markers != 1 || clientSources != 1 { return "unavailable", "unavailable", "unavailable" }; headers++; state = 4; continue
		}
		if line == "FAIL" {
			if state != 4 { return "unavailable", "unavailable", "unavailable" }; summaries++; state = 5; continue
		}
		if state == 1 && strings.HasPrefix(line, "    checkpoint_local_observer_kernel_linux_test.go:1988: REMOTE_OBSERVER_ROUTE_PID1 ") {
			markers++
			match := regexp.MustCompile(`^    checkpoint_local_observer_kernel_linux_test\.go:1988: REMOTE_OBSERVER_ROUTE_PID1 client=(C[0-9]{2}|unavailable) broker=(B[0-9]{2}|unavailable)(?: k=(K[1-3]))?$`).FindStringSubmatch(line)
			if match == nil { return "unavailable", "unavailable", "unavailable" }; client, broker, phase = match[1], match[2], match[3]; if phase == "" { phase = "unavailable" }; state = 2; continue
		}
		if state == 2 && line == "            checkpoint_local_observer_kernel_linux_test.go:1346: client="+client {
			clientSources++; state = 3; continue
		}
		return "unavailable", "unavailable", "unavailable"
	}
	if runCount != 1 || markers != 1 || clientSources != 1 || headers != 1 || summaries != 1 || state != 5 || !strings.Contains(","+assertions+",", ",1988,") || !strings.Contains(","+assertions+",", ",1346,") || (client != "unavailable" && (client < "C01" || client > "C34")) || (broker != "unavailable" && (broker < "B01" || broker > "B38")) || (broker != "unavailable" && client == "unavailable") {
		return "unavailable", "unavailable", "unavailable"
	}
	if phase != "unavailable" && ((phase != "K1" && phase != "K2" && phase != "K3") || overflow || client == "unavailable" || broker != "B15") { return "unavailable", "unavailable", "unavailable" }
	return client, broker, phase
}

func TestCheckpointLocalObserverHeldFileIdentityComparison(t *testing.T) {
	first := unix.Stat_t{Dev: 4, Ino: 9, Uid: 0, Gid: 42, Nlink: 1, Mode: unix.S_IFREG | 0600, Size: 64, Mtim: unix.Timespec{Sec: 1}, Ctim: unix.Timespec{Sec: 2}}
	second := first
	if !checkpointLocalObserverSameStat(&first, &second) {
		t.Fatal("unchanged held file identity did not compare equal")
	}
	for name, mutate := range map[string]func(*unix.Stat_t){
		"inode": func(s *unix.Stat_t) { s.Ino++ },
		"owner": func(s *unix.Stat_t) { s.Uid = 65534 },
		"group": func(s *unix.Stat_t) { s.Gid++ },
		"links": func(s *unix.Stat_t) { s.Nlink++ },
		"mode":  func(s *unix.Stat_t) { s.Mode ^= 0001 },
		"size":  func(s *unix.Stat_t) { s.Size++ },
		"mtime": func(s *unix.Stat_t) { s.Mtim.Sec++ },
		"ctime": func(s *unix.Stat_t) { s.Ctim.Sec++ },
	} {
		t.Run(name, func(t *testing.T) {
			changed := first
			mutate(&changed)
			if checkpointLocalObserverSameStat(&first, &changed) {
				t.Fatalf("changed %s metadata compared equal", name)
			}
		})
	}
}

func TestCheckpointLocalObserverPeerCredentialAdmission(t *testing.T) {
	const fixtureGID = uint32(988)
	actualGID := fixtureGID
	wrongGID := checkpointLocalObserverFixtureWrongGID(actualGID)
	policy := checkpointLocalObserverPolicy{PeerUID: 65534, PeerGID: actualGID}
	if !checkpointLocalObserverPeerMatches(65534, actualGID, policy) {
		t.Fatal("known exact peer UID/GID positive was rejected")
	}
	for _, tc := range []struct {
		name string
		uid  uint32
		gid  uint32
	}{{"wrong-uid", 65533, actualGID}, {"wrong-gid", 65534, wrongGID}} {
		t.Run(tc.name, func(t *testing.T) {
			if checkpointLocalObserverPeerMatches(tc.uid, tc.gid, policy) {
				t.Fatalf("mutated peer credentials were allowed: uid=%d gid=%d", tc.uid, tc.gid)
			}
		})
	}
}

func TestCheckpointLocalObserverIdentityMatchesCurrentness(t *testing.T) {
	base := CheckpointLocalObserverIdentity{PID: 4321, UID: 0, GID: 988, StartTicks: 991, PIDNamespaceInode: 4026531836, ExecutablePath: "/usr/bin/node-agent", ExecutableSHA256: strings.Repeat("a", 64), ControlGroup: "/system.slice/node.service", BootID: "01234567-89ab-cdef-0123-456789abcdef"}
	if !checkpointLocalObserverIdentityMatches(base, base) {
		t.Fatal("known identical current identity was rejected")
	}
	mutants := map[string]func(*CheckpointLocalObserverIdentity){
		"pid":               func(i *CheckpointLocalObserverIdentity) { i.PID++ },
		"uid":               func(i *CheckpointLocalObserverIdentity) { i.UID++ },
		"gid":               func(i *CheckpointLocalObserverIdentity) { i.GID++ },
		"start":             func(i *CheckpointLocalObserverIdentity) { i.StartTicks++ },
		"namespace":         func(i *CheckpointLocalObserverIdentity) { i.PIDNamespaceInode++ },
		"executable-path":   func(i *CheckpointLocalObserverIdentity) { i.ExecutablePath += ".substitute" },
		"executable-digest": func(i *CheckpointLocalObserverIdentity) { i.ExecutableSHA256 = strings.Repeat("b", 64) },
		"cgroup":            func(i *CheckpointLocalObserverIdentity) { i.ControlGroup += ".substitute" },
		"boot":              func(i *CheckpointLocalObserverIdentity) { i.BootID += "x" },
	}
	for name, mutate := range mutants {
		t.Run(name, func(t *testing.T) {
			changed := base
			mutate(&changed)
			if checkpointLocalObserverIdentityMatches(base, changed) {
				t.Fatalf("changed %s identity was accepted", name)
			}
		})
	}
}

func TestCheckpointLocalObserverFixtureWrongGIDIsDistinct(t *testing.T) {
	for _, actual := range []uint32{988, 65533, 65532, 0, ^uint32(0)} {
		if wrong := checkpointLocalObserverFixtureWrongGID(actual); wrong == actual {
			t.Fatalf("wrong-GID fixture identity equals actual GID %d", actual)
		}
	}
}

func TestCheckpointLocalObserverPlatformEntrypointHasFixedPaths(t *testing.T) {
	if checkpointLocalObserverSocketPath != "/run/vram-governor-local-observer/observer.sock" || checkpointLocalObserverPolicyPath != "/etc/vram-governor/checkpoint-local-observer-policy.json" || checkpointLocalObserverPrivatePath != "/etc/vram-governor/checkpoint-local-observer.key" || checkpointLocalObserverPublicPath != "/etc/vram-governor/checkpoint-local-observer.pub" {
		t.Fatal("production observer path authority is no longer fixed")
	}
}
