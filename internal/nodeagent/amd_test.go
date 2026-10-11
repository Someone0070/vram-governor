package nodeagent

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func writeAMDFixture(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}

func TestAMDSysfsTelemetryReportsMeasuredUnifiedMemory(t *testing.T) {
	root := t.TempDir()
	device := filepath.Join(root, "card0", "device")
	writeAMDFixture(t, filepath.Join(device, "vendor"), "0x1002\n")
	writeAMDFixture(t, filepath.Join(device, "device"), "0x1900\n")
	writeAMDFixture(t, filepath.Join(device, "mem_info_vram_total"), "17179869184\n")
	writeAMDFixture(t, filepath.Join(device, "mem_info_vram_used"), "8589934592\n")
	writeAMDFixture(t, filepath.Join(device, "gpu_busy_percent"), "45\n")
	hwmon := filepath.Join(device, "hwmon", "hwmon7")
	writeAMDFixture(t, filepath.Join(hwmon, "name"), "amdgpu\n")
	writeAMDFixture(t, filepath.Join(hwmon, "temp1_input"), "42000\n")
	writeAMDFixture(t, filepath.Join(hwmon, "power1_average"), "5000000\n")
	writeAMDFixture(t, filepath.Join(hwmon, "freq1_input"), "800000000\n")
	writeAMDFixture(t, filepath.Join(root, "card1", "device", "vendor"), "0x10de\n")
	rows, err := queryAMDGPUTelemetry(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected one AMD card, got %d", len(rows))
	}
	row := rows[0]
	if row.Index != 0 || row.Vendor != "amd" || row.MemoryKind != "unified" || row.Driver != "amdgpu" || row.VRAMTotalMB != 16384 || row.VRAMUsedMB != 8192 || row.VRAMFreeMB != 8192 || row.UtilizationPct != 45 || row.TemperatureC != 42 || row.PowerDrawW != 5 || row.GraphicsClockMHz != 800 {
		t.Fatalf("unexpected AMD telemetry: %+v", row)
	}
}

func TestAMDSysfsTelemetryRejectsInvalidRequiredMemory(t *testing.T) {
	root := t.TempDir()
	device := filepath.Join(root, "card0", "device")
	writeAMDFixture(t, filepath.Join(device, "vendor"), "0x1002\n")
	writeAMDFixture(t, filepath.Join(device, "mem_info_vram_total"), "not-a-number\n")
	writeAMDFixture(t, filepath.Join(device, "mem_info_vram_used"), "10\n")
	if _, err := queryAMDGPUTelemetry(context.Background(), root); err == nil {
		t.Fatal("invalid AMD memory was accepted")
	}
}

func TestNvidiaTelemetryRetainsVendorAndDedicatedMemory(t *testing.T) {
	rows, err := parseNvidiaSMICSV("0, RTX 3080, 10240, 1024, 9216, 25, 55\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Vendor != "nvidia" || rows[0].MemoryKind != "dedicated" || rows[0].VRAMFreeMB != 9216 {
		t.Fatalf("unexpected NVIDIA telemetry: %+v", rows)
	}
}
