//go:build !linux

package nodeagent

import "errors"

func readPinnedPlanBrokerPublicKeyAt(string, checkpointPlanBrokerPaths) ([]byte, error) {
	return nil, errors.New("checkpoint plan relaunch requires Linux")
}
