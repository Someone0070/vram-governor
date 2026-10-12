// Command vram-warm-keeper pins recently used llama.cpp router model files in
// host RAM so models evicted from VRAM reload from memory. See
// deploy/warm-keeper/README.md.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"vram-governor/internal/warmkeeper"
)

func main() {
	var (
		router   = flag.String("router-url", "http://127.0.0.1:8080", "llama.cpp router base URL")
		budget   = flag.String("budget", "", "maximum bytes to pin, e.g. 44GiB (required)")
		floor    = flag.String("min-available", "16GiB", "release pins while MemAvailable is below this")
		headroom = flag.String("pin-headroom", "4GiB", "extra MemAvailable a new pin must leave above the floor")
		always   = flag.String("always", "", "comma-separated model IDs pinned ahead of recently used ones")
		state    = flag.String("state", "/var/lib/vram-warm-keeper/state.json", "recently-used list, kept across restarts")
		status   = flag.String("status", "/run/vram-warm-keeper/status.json", "status file rewritten every tick")
		poll     = flag.Duration("poll", 2*time.Second, "router poll interval")
		cooldown = flag.Duration("cooldown", 2*time.Minute, "pause before pinning again after memory pressure")
	)
	flag.Parse()
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	cfg := warmkeeper.Config{RouterURL: *router, StatePath: *state, StatusPath: *status, PollEvery: *poll, Cooldown: *cooldown}
	var err error
	for _, f := range []struct {
		name string
		in   string
		out  *int64
	}{{"budget", *budget, &cfg.BudgetBytes}, {"min-available", *floor, &cfg.FloorBytes}, {"pin-headroom", *headroom, &cfg.HeadroomBytes}} {
		if *f.out, err = warmkeeper.ParseBytes(f.in); err != nil {
			fmt.Fprintf(os.Stderr, "-%s: %v\n", f.name, err)
			os.Exit(2)
		}
	}
	if cfg.BudgetBytes <= 0 {
		fmt.Fprintln(os.Stderr, "-budget must be positive")
		os.Exit(2)
	}
	for _, id := range strings.Split(*always, ",") {
		if id = strings.TrimSpace(id); id != "" {
			cfg.Always = append(cfg.Always, id)
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	log.Info("vram-warm-keeper starting", "router", cfg.RouterURL, "budget_bytes", cfg.BudgetBytes, "floor_bytes", cfg.FloorBytes, "always", cfg.Always)
	if err := warmkeeper.New(cfg, log, warmkeeper.PinFile).Run(ctx); err != nil {
		log.Error("vram-warm-keeper stopped", "err", err)
		os.Exit(1)
	}
}
