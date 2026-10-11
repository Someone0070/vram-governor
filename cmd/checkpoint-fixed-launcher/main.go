package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"vram-governor/internal/nodeagent"
)

func main() {
	if len(os.Args) != 1 {
		fmt.Fprintln(os.Stderr, "checkpoint fixed launcher accepts no arguments")
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := nodeagent.RunCheckpointFixedLauncher(ctx); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
