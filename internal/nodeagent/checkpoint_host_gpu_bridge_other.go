//go:build !linux

package nodeagent

import (
	"context"
	"errors"
)

func checkpointHostGPUBridgeProductionConfig() checkpointHostGPUBridgeRuntimeConfig {
	return checkpointHostGPUBridgeRuntimeConfig{}
}

func observeCheckpointHostGPUAttributionPlatformForRole(context.Context, int, uint64, CheckpointLaunchPlan, CheckpointDevicePlacement, string) (checkpointHostGPUObservation, error) {
	return checkpointHostGPUObservation{}, errors.New("nested-namespace host GPU attribution is unsupported on this platform")
}

func observeCheckpointHostGPUAttributionLocalObserverUsing(context.Context, int, uint64, CheckpointLaunchPlan, CheckpointDevicePlacement, checkpointHostGPUBridgeRuntimeConfig) (checkpointHostGPUObservation, error) {
	return checkpointHostGPUObservation{}, errors.New("nested-namespace host GPU attribution is unsupported on this platform")
}
