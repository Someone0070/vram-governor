//go:build !linux

package nodeagent

import (
	"context"
	"errors"
)

func runCheckpointLifecycleBrokerPlatform(context.Context, checkpointPlanBrokerPaths) error {
	return errors.New("checkpoint lifecycle broker requires Linux")
}

func invokeCheckpointPlanBroker(context.Context, checkpointPlanBrokerPaths, []byte) ([]byte, error) {
	return nil, errors.New("checkpoint lifecycle broker requires Linux")
}

func checkpointPlanBrokerPrivateFixturePathSet(checkpointPlanBrokerPaths) bool {
	return false
}
