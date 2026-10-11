//go:build !aix && !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !solaris && !windows

package safefile

import (
	"errors"
	"os"
)

func openReadOnlyNoFollow(string) (*os.File, error) {
	return nil, errors.New("safe no-follow file opening is unsupported on this operating system")
}
