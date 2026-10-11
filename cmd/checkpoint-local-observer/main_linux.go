//go:build linux

package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"vram-governor/internal/nodeagent"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := nodeagent.RunCheckpointLocalObserver(ctx); err != nil && err != context.Canceled {
		log.Printf("checkpoint local observer stopped: %v", err)
		os.Exit(1)
	}
}
