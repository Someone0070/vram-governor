//go:build !linux

package nodeagent

import (
	"context"
	"errors"
)

func refreshCheckpointDevicePlacementPlatform(context.Context, CheckpointLaunchPlan) (CheckpointDevicePlacement, error) {
	return CheckpointDevicePlacement{}, errors.New("managed physical accelerator placement requires supported Linux CUDA inventory and process attribution")
}
