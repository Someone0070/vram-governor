//go:build !linux

package nodeagent

import (
	"context"
	"errors"
)

func observeCheckpointManagedBindingPlatform(context.Context) (CheckpointManagedBinding, error) {
	return CheckpointManagedBinding{}, errors.New("managed checkpoint binding requires Linux process, systemd, CUDA, and custody observations")
}
