package nodeagent

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"vram-governor/internal/wsproto"
)

// QueryGPUTelemetry shells out to nvidia-smi and parses per-GPU telemetry.
// Handles zero or multiple GPUs generically. Returns an empty (non-nil)
// slice, not an error, if nvidia-smi is missing or returns no rows — a node
// agent running on a GPU-less box should still be able to register and
// heartbeat (architecture.md never requires every node to have a GPU).
func QueryGPUTelemetry(ctx context.Context) ([]wsproto.AcceleratorTelemetry, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "nvidia-smi",
		"--query-gpu=index,name,memory.total,memory.used,memory.free,utilization.gpu,temperature.gpu,driver_version,power.draw,power.limit,fan.speed,clocks.gr,clocks.mem,pcie.link.gen.current,pcie.link.width.current,pstate",
		"--format=csv,noheader,nounits",
	)
	var out, errBuf bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errBuf
	if err := cmd.Run(); err != nil {
		return []wsproto.AcceleratorTelemetry{}, fmt.Errorf("nvidia-smi: %w (stderr: %s)", err, strings.TrimSpace(errBuf.String()))
	}

	return parseNvidiaSMICSV(out.String())
}

func parseNvidiaSMICSV(csv string) ([]wsproto.AcceleratorTelemetry, error) {
	lines := strings.Split(strings.TrimSpace(csv), "\n")
	result := make([]wsproto.AcceleratorTelemetry, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Split(line, ",")
		if len(fields) != 7 && len(fields) != 16 {
			return result, fmt.Errorf("unexpected nvidia-smi csv row (%d fields): %q", len(fields), line)
		}
		for i := range fields {
			fields[i] = strings.TrimSpace(fields[i])
		}
		idx, err := strconv.Atoi(fields[0])
		if err != nil {
			return result, fmt.Errorf("parse index: %w", err)
		}
		total, err := strconv.ParseInt(fields[2], 10, 64)
		if err != nil {
			return result, fmt.Errorf("parse memory.total: %w", err)
		}
		used, err := strconv.ParseInt(fields[3], 10, 64)
		if err != nil {
			return result, fmt.Errorf("parse memory.used: %w", err)
		}
		free, err := strconv.ParseInt(fields[4], 10, 64)
		if err != nil {
			return result, fmt.Errorf("parse memory.free: %w", err)
		}
		util, err := strconv.ParseFloat(fields[5], 64)
		if err != nil {
			return result, fmt.Errorf("parse utilization.gpu: %w", err)
		}
		temp, err := strconv.ParseFloat(fields[6], 64)
		if err != nil {
			return result, fmt.Errorf("parse temperature.gpu: %w", err)
		}
		row := wsproto.AcceleratorTelemetry{
			Index:          idx,
			Name:           fields[1],
			VRAMTotalMB:    total,
			VRAMUsedMB:     used,
			VRAMFreeMB:     free,
			UtilizationPct: util,
			TemperatureC:   temp,
		}
		if len(fields) == 16 {
			row.Driver = fields[7]
			row.PowerDrawW = optionalFloat(fields[8])
			row.PowerLimitW = optionalFloat(fields[9])
			row.FanSpeedPct = optionalFloat(fields[10])
			row.GraphicsClockMHz = optionalFloat(fields[11])
			row.MemoryClockMHz = optionalFloat(fields[12])
			row.PCIeGeneration = int(optionalFloat(fields[13]))
			row.PCIeWidth = int(optionalFloat(fields[14]))
			row.PerformanceState = fields[15]
		}
		result = append(result, row)
	}
	return result, nil
}

func optionalFloat(value string) float64 {
	parsed, _ := strconv.ParseFloat(strings.TrimSpace(value), 64)
	return parsed
}
