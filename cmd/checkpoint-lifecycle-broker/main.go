package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"vram-governor/internal/nodeagent"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	if err := nodeagent.RunCheckpointLifecycleBroker(ctx); err != nil && !errors.Is(err, context.Canceled) {
		slog.New(slog.NewJSONHandler(os.Stderr, nil)).Error("fixed checkpoint lifecycle broker stopped", "error", err.Error())
		os.Exit(1)
	}
}
