//go:build !linux

package warmkeeper

import (
	"errors"
	"os"
)

var errUnsupported = errors.New("warm keeper requires Linux")

func PinFile(string, func() bool) (Pin, error) { return nil, errUnsupported }

func MemAvailable() (int64, error) { return 0, errUnsupported }

func statFile(path string) (FileID, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return FileID{}, err
	}
	return FileID{Path: path, Size: fi.Size(), Mtime: fi.ModTime().UnixNano()}, nil
}
