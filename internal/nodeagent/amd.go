package nodeagent

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"vram-governor/internal/wsproto"
)

const mib = 1024 * 1024

// queryAMDGPUTelemetry reads Linux amdgpu sysfs counters. VRAM figures are
// driver-reported bytes; on an APU they share physical RAM with the host.
func queryAMDGPUTelemetry(ctx context.Context, drmRoot string) ([]wsproto.AcceleratorTelemetry, error) {
	cards, err := filepath.Glob(filepath.Join(drmRoot, "card[0-9]*"))
	if err != nil {
		return nil, err
	}
	rows := []wsproto.AcceleratorTelemetry{}
	for _, card := range cards {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		index, err := strconv.Atoi(strings.TrimPrefix(filepath.Base(card), "card"))
		if err != nil {
			continue
		} // Ignore card0-HDMI-A-1 and other connector paths.
		device := filepath.Join(card, "device")
		vendor, err := readSysfsString(filepath.Join(device, "vendor"))
		if err != nil || !strings.EqualFold(vendor, "0x1002") {
			continue
		}
		total, err := readSysfsInt(filepath.Join(device, "mem_info_vram_total"))
		if err != nil {
			return nil, fmt.Errorf("amdgpu card%d total memory: %w", index, err)
		}
		used, err := readSysfsInt(filepath.Join(device, "mem_info_vram_used"))
		if err != nil {
			return nil, fmt.Errorf("amdgpu card%d used memory: %w", index, err)
		}
		if total <= 0 || used < 0 {
			return nil, fmt.Errorf("amdgpu card%d reported invalid memory counters", index)
		}
		if used > total {
			used = total
		} // Counters can race while the driver updates them.
		pciID, _ := readSysfsString(filepath.Join(device, "device"))
		name, _ := readSysfsString(filepath.Join(device, "product_name"))
		if name == "" {
			revision, _ := readSysfsString(filepath.Join(device, "revision"))
			name = amdMarketingName(pciID, revision)
		}
		kind := "driver_vram"
		if strings.EqualFold(pciID, "0x1900") {
			kind = "unified"
		} // Phoenix3 APU.
		row := wsproto.AcceleratorTelemetry{
			Index: index, Name: name, Vendor: "amd", MemoryKind: kind, Driver: "amdgpu",
			VRAMTotalMB: total / mib, VRAMUsedMB: used / mib, VRAMFreeMB: (total - used) / mib,
		}
		if busy, err := readSysfsInt(filepath.Join(device, "gpu_busy_percent")); err == nil && busy >= 0 && busy <= 100 {
			row.UtilizationPct = float64(busy)
		}
		hwmons, _ := filepath.Glob(filepath.Join(device, "hwmon", "hwmon*"))
		for _, hwmon := range hwmons {
			label, _ := readSysfsString(filepath.Join(hwmon, "name"))
			if label != "amdgpu" {
				continue
			}
			if milliC, err := readSysfsInt(filepath.Join(hwmon, "temp1_input")); err == nil {
				row.TemperatureC = float64(milliC) / 1000
			}
			if microW, err := readSysfsInt(filepath.Join(hwmon, "power1_average")); err == nil {
				row.PowerDrawW = float64(microW) / 1e6
			}
			if hz, err := readSysfsInt(filepath.Join(hwmon, "freq1_input")); err == nil {
				row.GraphicsClockMHz = float64(hz) / 1e6
			}
			break
		}
		rows = append(rows, row)
	}
	return rows, nil
}

func readSysfsString(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

func readSysfsInt(path string) (int64, error) {
	value, err := readSysfsString(path)
	if err != nil {
		return 0, err
	}
	return strconv.ParseInt(value, 10, 64)
}

// amdMarketingName names cards whose driver exposes no product_name (desktop
// Navi 21 boards report only the PCI id; the revision tells the models apart).
func amdMarketingName(pciID, revision string) string {
	if strings.EqualFold(pciID, "0x73bf") {
		switch strings.ToLower(revision) {
		case "0xc0":
			return "AMD Radeon RX 6900 XT"
		case "0xc1":
			return "AMD Radeon RX 6800 XT"
		case "0xc3":
			return "AMD Radeon RX 6800"
		}
	}
	return "AMD Radeon (" + pciID + ")"
}
