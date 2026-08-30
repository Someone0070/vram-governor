// Command node-agent is the small persistent process co-located with a GPU
// (architecture.md §34). It dials the controller outbound, registers, and
// reports heartbeat + nvidia-smi GPU telemetry every ~2s, redialing on drop.
package main

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"syscall"

	"vram-governor/internal/logging"
	"vram-governor/internal/nodeagent"
)

func main() {
	cfgPath := flag.String("config", "configs/node-agent.yaml", "path to node agent config YAML")
	probeProfile := flag.String("probe", "", "run a Phase 2 on-demand measurement probe for this ServingProfile ID and exit, instead of starting the persistent agent loop")
	controllerAPI := flag.String("controller-api", "", "controller HTTP base URL to report probe results to, e.g. http://127.0.0.1:8080 (omit to just print the profile)")
	flag.Parse()

	cfg, err := nodeagent.LoadConfig(*cfgPath)
	if err != nil {
		panic(err)
	}
	log, logBuffer := logging.NewBuffered("node-agent", cfg.LogLevel, 250)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if *probeProfile != "" {
		if err := nodeagent.RunProbeOnDemand(ctx, cfg, log, nodeagent.ProbeOptions{
			ProfileID:        *probeProfile,
			ControllerAPIURL: *controllerAPI,
		}); err != nil {
			log.Error("probe run failed", "err", err)
			os.Exit(1)
		}
		return
	}

	log.Info("starting node agent", "node_id", cfg.NodeID, "controller_url", cfg.ControllerURL)
	nodeagent.Run(ctx, cfg, log, logBuffer.Snapshot)
	log.Info("node agent stopped")
}
