//go:build linux

package nodeagent

import "syscall"

func readRootDisk() (totalMB, usedMB, freeMB int64) {
	var stats syscall.Statfs_t
	if err := syscall.Statfs("/", &stats); err != nil {
		return 0, 0, 0
	}
	blockSize := uint64(stats.Bsize)
	total := stats.Blocks * blockSize
	free := stats.Bavail * blockSize
	used := total - stats.Bfree*blockSize
	return int64(total / (1024 * 1024)), int64(used / (1024 * 1024)), int64(free / (1024 * 1024))
}
