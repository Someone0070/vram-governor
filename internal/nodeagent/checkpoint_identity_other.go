//go:build !linux

package nodeagent

import (
	"context"
	"errors"
	"net"
)

func observeCheckpointIdentityPlatform(context.Context, CheckpointIdentityRequest, string, net.IP, uint16) (CheckpointLocalIdentity, error) {
	return CheckpointLocalIdentity{}, errors.New("checkpoint local process, file, and mapping observation is supported only on Linux")
}
