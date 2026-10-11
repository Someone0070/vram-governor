//go:build !linux

package nodeagent

import (
	"context"
	"errors"
)

func openCheckpointLaunchPlan(context.Context, string, uint32) (*PinnedCheckpointLaunchPlan, error) {
	return nil, errors.New("pinned checkpoint launch plans are unsupported on this platform")
}
func (*PinnedCheckpointLaunchPlan) Recheck(context.Context) error {
	return errors.New("pinned checkpoint launch plans are unsupported on this platform")
}
