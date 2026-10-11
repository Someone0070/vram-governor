//go:build !linux

package nodeagent

import (
	"context"
	"errors"
)

func readPinnedRootStopPublicKey(string) ([]byte, error) {
	return nil, errors.New("owned stop acknowledgement requires supported Linux systemd")
}

func readPinnedRootStopPublicKeyAt(string, checkpointOwnedStopPaths) ([]byte, error) {
	return nil, errors.New("owned stop acknowledgement requires supported Linux systemd")
}

func invokeOwnedStopSupervisorPlatform(context.Context, ownedStopRequest) ([]byte, error) {
	return nil, errors.New("owned stop acknowledgement requires supported Linux systemd")
}

func invokeOwnedStopSupervisorAt(context.Context, ownedStopRequest, string) ([]byte, error) {
	return nil, errors.New("owned stop acknowledgement requires supported Linux systemd")
}

func observeOwnedStopReceiptPlatform(context.Context, string, []byte, []byte, string) ([]byte, error) {
	return nil, errors.New("owned stop acknowledgement requires supported Linux systemd")
}

func observeOwnedStopReceiptAt(context.Context, string, []byte, []byte, string, checkpointOwnedStopPaths) ([]byte, error) {
	return nil, errors.New("owned stop acknowledgement requires supported Linux systemd")
}
