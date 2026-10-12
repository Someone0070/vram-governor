//go:build !linux

package workloads

// Free space is only checked on Linux, where the controller runs.
func diskFreeBytes(string) (int64, error) { return 1 << 62, nil }
