//go:build !linux

package nodeagent

import (
	"context"
	"errors"
)

func observeCheckpointManagedUnitPlatform(context.Context, CheckpointUnitIdentityRequest) (CheckpointVerifiedUnitAssociation, error) {
	return CheckpointVerifiedUnitAssociation{}, errors.New("managed checkpoint unit observation is unsupported on this platform")
}
