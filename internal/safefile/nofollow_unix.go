//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package safefile

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

func openReadOnlyNoFollow(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open safe file %q: %w", path, err)
	}
	f := os.NewFile(uintptr(fd), path)
	if f == nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("open safe file %q: descriptor could not be wrapped", path)
	}
	return f, nil
}
