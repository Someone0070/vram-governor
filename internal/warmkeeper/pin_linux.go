//go:build linux

package warmkeeper

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

const pinChunk = 256 << 20

type filePin struct {
	fd      int
	mapping []byte
}

// PinFile maps path read-only and mlocks it chunk by chunk. mlock faults the
// pages in, so the call reads the file from disk when it is not cached; abort
// is checked between chunks. The locked pages are the same page-cache pages
// llama.cpp maps, so the next load of the model reads from memory.
func PinFile(path string, abort func() bool) (Pin, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		unix.Close(fd)
		return nil, err
	}
	if st.Size <= 0 {
		unix.Close(fd)
		return nil, fmt.Errorf("%s is empty", path)
	}
	mapping, err := unix.Mmap(fd, 0, int(st.Size), unix.PROT_READ, unix.MAP_SHARED)
	if err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("mmap %s: %w", path, err)
	}
	p := &filePin{fd: fd, mapping: mapping}
	_ = unix.Madvise(mapping, unix.MADV_WILLNEED)
	for off := 0; off < len(mapping); off += pinChunk {
		if abort != nil && abort() {
			_ = p.Close()
			return nil, ErrAborted
		}
		end := off + pinChunk
		if end > len(mapping) {
			end = len(mapping)
		}
		if err := unix.Mlock(mapping[off:end]); err != nil {
			_ = p.Close()
			return nil, fmt.Errorf("mlock %s: %w", path, err)
		}
	}
	return p, nil
}

func (p *filePin) Close() error {
	var errs []error
	if p.mapping != nil {
		// munmap drops the lock; the pages stay in the page cache as ordinary,
		// reclaimable cache.
		if err := unix.Munmap(p.mapping); err != nil {
			errs = append(errs, err)
		}
		p.mapping = nil
	}
	if p.fd >= 0 {
		if err := unix.Close(p.fd); err != nil {
			errs = append(errs, err)
		}
		p.fd = -1
	}
	return errors.Join(errs...)
}

// MemAvailable reads MemAvailable from /proc/meminfo (LXCFS-virtualised inside
// a container, so it reflects the container limit).
func MemAvailable() (int64, error) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, err
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		fields := strings.Fields(s.Text())
		if len(fields) == 3 && fields[0] == "MemAvailable:" && fields[2] == "kB" {
			n, err := strconv.ParseInt(fields[1], 10, 64)
			if err != nil || n < 0 {
				return 0, errors.New("malformed MemAvailable")
			}
			return n * 1024, nil
		}
	}
	if err := s.Err(); err != nil {
		return 0, err
	}
	return 0, errors.New("MemAvailable not found in /proc/meminfo")
}

func statFile(path string) (FileID, error) {
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return FileID{}, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return FileID{}, fmt.Errorf("%s is not a regular file", path)
	}
	return FileID{Path: path, Size: st.Size, Mtime: st.Mtim.Nano(), Inode: st.Ino}, nil
}
