//go:build !linux

package nodeagent

func readRootDisk() (totalMB, usedMB, freeMB int64) {
	return 0, 0, 0
}
