//go:build !linux

package nodeagent

import (
	"context"
	"errors"
)

func runCheckpointLocalObserverPlatform(context.Context) error {
	return errors.New("checkpoint local observer broker is supported only on Linux")
}

func observeCheckpointLocalObserverPlatform(context.Context) (CheckpointLocalObserverResult, error) {
	return CheckpointLocalObserverResult{}, errors.New("checkpoint local observer client is supported only on Linux")
}
