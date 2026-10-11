//go:build !linux

package nodeagent

import (
	"context"
	"errors"
)

func runCheckpointFixedLauncherPlatform(context.Context) error {
	return errors.New("fixed checkpoint launcher requires supported Linux systemd, pidfd, fs-verity, and cgroup facilities")
}
