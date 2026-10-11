//go:build linux

package nodeagent

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

func syncCommandStateDir(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	if err := dir.Sync(); err != nil {
		_ = dir.Close()
		return err
	}
	return dir.Close()
}

type warmFileIdentity struct {
	Dev, Ino uint64
	Size     int64
	Mtime    int64
	Hash     string
}

type warmRAMPin interface {
	Close() error
	ResidentBytes() int64
	LockedBytes() int64
}

type linuxWarmPin struct {
	fd               int
	mapping          []byte
	resident, locked int64
	unlocked         bool
}

func warmRAMOSSupported() bool { return true }
func warmRAMOracle() string    { return "mincore+mlock" }

func warmRAMMemlockLimit() (int64, error) {
	var limit unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &limit); err != nil {
		return 0, err
	}
	if limit.Cur == unix.RLIM_INFINITY {
		return 0, nil
	}
	return int64(limit.Cur), nil
}

func warmFileIdentityAt(path string) (warmFileIdentity, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return warmFileIdentity{}, err
	}
	defer unix.Close(fd)
	return warmFDIdentity(fd)
}

func warmSecureFileIdentity(path string, roots []string) (warmFileIdentity, error) {
	_, rel, rootfd, err := secureWarmOpenPath(path, roots)
	if err != nil {
		return warmFileIdentity{}, err
	}
	defer unix.Close(rootfd)
	how := &unix.OpenHow{Flags: uint64(unix.O_RDONLY | unix.O_CLOEXEC), Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS}
	fd, err := unix.Openat2(rootfd, rel, how)
	if err != nil {
		return warmFileIdentity{}, errors.New("open model identity failed")
	}
	defer unix.Close(fd)
	return warmFDIdentity(fd)
}

func warmFDIdentity(fd int) (warmFileIdentity, error) {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return warmFileIdentity{}, errors.New("stat opened model failed")
	}
	hash, err := warmFDHash(fd, st.Size)
	if err != nil {
		return warmFileIdentity{}, errors.New("hash opened model failed")
	}
	return warmFileIdentity{Dev: uint64(st.Dev), Ino: uint64(st.Ino), Size: st.Size, Mtime: st.Mtim.Sec*1_000_000_000 + int64(st.Mtim.Nsec), Hash: hash}, nil
}

func warmFDHash(fd int, size int64) (string, error) {
	if size < 0 {
		return "", errors.New("negative model size")
	}
	h := sha256.New()
	buf := make([]byte, 1<<20)
	var offset int64
	for offset < size {
		want := int64(len(buf))
		if remaining := size - offset; remaining < want {
			want = remaining
		}
		n, err := unix.Pread(fd, buf[:want], offset)
		if err != nil || n <= 0 {
			return "", errors.New("read model for fingerprint failed")
		}
		_, _ = h.Write(buf[:n])
		offset += int64(n)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func secureWarmOpenPath(path string, roots []string) (string, string, int, error) {
	root, err := canonicalWarmRootForPath(path, roots)
	if err != nil {
		return "", "", -1, err
	}
	rel, err := filepath.Rel(root, path)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", "", -1, errors.New("model path is outside canonical allowlist")
	}
	var authorized unix.Stat_t
	if err := unix.Stat(root, &authorized); err != nil {
		return "", "", -1, errors.New("authorize model allowlist root failed")
	}
	rootfd, err := unix.Open(root, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return "", "", -1, errors.New("open model allowlist root failed")
	}
	var opened, stated unix.Stat_t
	if err := unix.Fstat(rootfd, &opened); err != nil || opened.Dev != authorized.Dev || opened.Ino != authorized.Ino || unix.Stat(root, &stated) != nil || opened.Dev != stated.Dev || opened.Ino != stated.Ino {
		unix.Close(rootfd)
		return "", "", -1, errors.New("model allowlist root changed")
	}
	return root, rel, rootfd, nil
}

func pinWarmModelFile(path string, roots []string) (warmRAMPin, warmFileIdentity, error) {
	return pinWarmModelFileExpected(path, roots, warmFileIdentity{})
}

func pinWarmModelFileExpected(path string, roots []string, expected warmFileIdentity) (warmRAMPin, warmFileIdentity, error) {
	_, rel, rootfd, err := secureWarmOpenPath(path, roots)
	if err != nil {
		return nil, warmFileIdentity{}, err
	}
	defer unix.Close(rootfd)
	how := &unix.OpenHow{Flags: uint64(unix.O_RDONLY | unix.O_CLOEXEC), Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS}
	fd, err := unix.Openat2(rootfd, rel, how)
	if err != nil {
		return nil, warmFileIdentity{}, errors.New("open model for warm residency failed")
	}
	closeFD := func() { _ = unix.Close(fd) }
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		closeFD()
		return nil, warmFileIdentity{}, errors.New("stat opened model failed")
	}
	hash, err := warmFDHash(fd, st.Size)
	if err != nil {
		closeFD()
		return nil, warmFileIdentity{}, errors.New("hash opened model failed")
	}
	identity := warmFileIdentity{Dev: uint64(st.Dev), Ino: uint64(st.Ino), Size: st.Size, Mtime: st.Mtim.Sec*1_000_000_000 + int64(st.Mtim.Nsec), Hash: hash}
	if expected.Size > 0 && identity != expected {
		closeFD()
		return nil, warmFileIdentity{}, errors.New("model identity changed before pin")
	}
	if identity.Size <= 0 || identity.Size > int64(int(^uint(0)>>1)) {
		closeFD()
		return nil, warmFileIdentity{}, errors.New("model file size is unsupported")
	}
	mapping, err := unix.Mmap(fd, 0, int(identity.Size), unix.PROT_READ, unix.MAP_PRIVATE)
	if err != nil {
		closeFD()
		return nil, warmFileIdentity{}, fmt.Errorf("map model for warm residency: %w", err)
	}
	cleanup := func() { _ = unix.Munmap(mapping); closeFD() }
	// Touch every page to force the residency oracle to observe actual pages.
	page := unix.Getpagesize()
	for i := 0; i < len(mapping); i += page {
		_ = mapping[i]
	}
	_ = mapping[len(mapping)-1]
	vec := make([]byte, (len(mapping)+page-1)/page)
	_, _, errno := unix.Syscall6(unix.SYS_MINCORE, uintptr(unsafe.Pointer(&mapping[0])), uintptr(len(mapping)), uintptr(unsafe.Pointer(&vec[0])), 0, 0, 0)
	if errno != 0 {
		cleanup()
		return nil, warmFileIdentity{}, fmt.Errorf("mincore residency proof: %w", errno)
	}
	residentPages := int64(0)
	for _, bit := range vec {
		if bit&1 != 0 {
			residentPages++
		}
	}
	residentBytes := residentPages * int64(page)
	if residentBytes < identity.Size {
		cleanup()
		return nil, warmFileIdentity{}, errors.New("mincore did not prove all model bytes resident")
	}
	if err := unix.Mlock(mapping); err != nil {
		cleanup()
		return nil, warmFileIdentity{}, fmt.Errorf("mlock warm model bytes: %w", err)
	}
	return &linuxWarmPin{fd: fd, mapping: mapping, resident: residentBytes, locked: int64(len(mapping)+page-1) / int64(page) * int64(page)}, identity, nil
}

func (p *linuxWarmPin) Close() error {
	var first error
	if p.mapping != nil {
		if !p.unlocked {
			if err := unix.Munlock(p.mapping); err != nil {
				first = err
			} else {
				p.unlocked = true
			}
		}
		if p.unlocked {
			if err := unix.Munmap(p.mapping); err != nil {
				if first == nil {
					first = err
				}
			} else {
				p.mapping = nil
			}
		}
	}
	if p.fd >= 0 {
		if err := unix.Close(p.fd); err != nil {
			if first == nil {
				first = err
			}
		} else {
			p.fd = -1
		}
	}
	return first
}
func (p *linuxWarmPin) ResidentBytes() int64 { return p.resident }
func (p *linuxWarmPin) LockedBytes() int64   { return p.locked }

func warmRAMSnapshot(policy WarmRAMPolicy) (int64, int64, int64, int64, float64, error) {
	current, available := int64(0), int64(0)
	if policy.CurrentRAMBytes != nil {
		var err error
		current, err = policy.CurrentRAMBytes()
		if err != nil {
			return 0, 0, 0, 0, 0, err
		}
		if current < 0 {
			return 0, 0, 0, 0, 0, errors.New("invalid current RAM accounting")
		}
	}
	if policy.AvailableRAMBytes != nil {
		var err error
		available, err = policy.AvailableRAMBytes()
		if err != nil {
			return 0, 0, 0, 0, 0, err
		}
		if available < 0 {
			return 0, 0, 0, 0, 0, errors.New("invalid available RAM accounting")
		}
	}
	if current == 0 || available == 0 {
		memPath := policy.MemInfoPath
		var total, avail int64
		var err error
		if memPath != "" {
			total, avail, err = linuxMemInfoPath(memPath)
		} else {
			total, avail, err = linuxMemInfo()
		}
		if err == nil {
			if total <= 0 || avail <= 0 {
				return 0, 0, 0, 0, 0, errors.New("meminfo fields unavailable")
			}
			if current == 0 {
				current = total - avail
			}
			if available == 0 {
				available = avail
			}
		} else if policy.MemInfoPath != "" {
			return 0, 0, 0, 0, 0, err
		}
	}
	cgroup := int64(0)
	if policy.CurrentCgroupBytes != nil {
		var err error
		cgroup, err = policy.CurrentCgroupBytes()
		if err != nil {
			return 0, 0, 0, 0, 0, err
		}
		if cgroup < 0 {
			return 0, 0, 0, 0, 0, errors.New("invalid cgroup accounting")
		}
	} else if policy.CgroupCurrentPath != "" {
		var err error
		cgroup, err = readLinuxInt(policy.CgroupCurrentPath)
		if err != nil {
			return 0, 0, 0, 0, 0, errors.New("read cgroup memory.current")
		}
	} else if policy.CgroupLimitBytes > 0 {
		return 0, 0, 0, 0, 0, errors.New("cgroup memory source is required")
	}
	memlock := int64(0)
	if policy.CurrentMemlockBytes != nil {
		var err error
		memlock, err = policy.CurrentMemlockBytes()
		if err != nil {
			return 0, 0, 0, 0, 0, err
		}
		if memlock < 0 {
			return 0, 0, 0, 0, 0, errors.New("invalid locked-byte accounting")
		}
	}
	if policy.CurrentMemlockBytes == nil {
		var err error
		memlock, err = linuxLockedBytes()
		if err != nil {
			return 0, 0, 0, 0, 0, err
		}
	}
	pressure := float64(0)
	if policy.PressurePercent != nil {
		var err error
		pressure, err = policy.PressurePercent()
		if err != nil {
			return 0, 0, 0, 0, 0, err
		}
		if math.IsNaN(pressure) || math.IsInf(pressure, 0) || pressure < 0 || pressure > 100 {
			return 0, 0, 0, 0, 0, errors.New("invalid memory pressure")
		}
	} else if policy.PressurePath != "" {
		var err error
		pressure, err = linuxPressurePercentPath(policy.PressurePath)
		if err != nil {
			return 0, 0, 0, 0, 0, err
		}
	} else if policy.PressureRefusalPercent > 0 {
		return 0, 0, 0, 0, 0, errors.New("pressure source is required")
	}
	return current, available, cgroup, memlock, pressure, nil
}

func linuxLockedBytes() (int64, error) {
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0, err
	}
	return parseVmLckBytes(b)
}

func linuxMemInfoPath(path string) (int64, int64, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, 0, err
	}
	return parseMemInfoBytes(b)
}

func readLinuxInt(path string) (int64, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	return parseNonnegativeDecimal(string(b))
}

func warmRAMCgroupMax(path string) (int64, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	value := strings.TrimSpace(string(b))
	if value == "max" {
		return 0, errors.New("unbounded cgroup max is not authoritative")
	}
	n, err := parseNonnegativeDecimal(value)
	if err != nil {
		return 0, errors.New("invalid cgroup max")
	}
	return n, nil
}

func warmRAMOOMEvents(path string) (int64, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	return parseOOMBytes(b)
}

func linuxMemInfo() (int64, int64, error) {
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, 0, err
	}
	return parseMemInfoBytes(b)
}
func linuxCgroupCurrent() int64 {
	for _, path := range []string{"/sys/fs/cgroup/memory.current", "/sys/fs/cgroup/memory/memory.usage_in_bytes"} {
		if n, err := readLinuxInt(path); err == nil {
			return n
		}
	}
	return 0
}
func linuxPressurePercent() float64 {
	n, _ := linuxPressurePercentPath("/proc/pressure/memory")
	return n
}
func linuxPressurePercentPath(path string) (float64, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	return parsePSIBytes(b)
}
