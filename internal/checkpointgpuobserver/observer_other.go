//go:build !linux

package checkpointgpuobserver

import (
	"context"
	"errors"
)

func Serve(context.Context) error {
	return errors.New("host GPU observer is unsupported on this platform")
}

func RunFixedService() error { return errors.New("host GPU observer is unsupported on this platform") }
