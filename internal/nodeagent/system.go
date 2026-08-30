package nodeagent

import (
	"bufio"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"vram-governor/internal/wsproto"
)

type SystemSampler struct {
	mu          sync.Mutex
	previousCPU cpuCounters
	previousRX  uint64
	previousTX  uint64
	previousAt  time.Time
}

type cpuCounters struct{ total, idle uint64 }

func (s *SystemSampler) Sample() wsproto.SystemTelemetry {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	row := wsproto.SystemTelemetry{Architecture: runtime.GOARCH, CPULogical: runtime.NumCPU(), SampledAt: now}
	row.Hostname, _ = os.Hostname()
	row.OS = runtime.GOOS
	if value, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		row.Kernel = strings.TrimSpace(string(value))
	}
	if value, err := os.ReadFile("/etc/os-release"); err == nil {
		for _, line := range strings.Split(string(value), "\n") {
			if strings.HasPrefix(line, "PRETTY_NAME=") {
				row.OS = strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), "\"")
				break
			}
		}
	}
	row.CPUModel = firstProcValue("/proc/cpuinfo", "model name")
	mem := procKeyValues("/proc/meminfo")
	row.RAMTotalMB = int64(mem["MemTotal"]) / 1024
	row.RAMAvailableMB = int64(mem["MemAvailable"]) / 1024
	row.RAMUsedMB = row.RAMTotalMB - row.RAMAvailableMB
	row.SwapTotalMB = int64(mem["SwapTotal"]) / 1024
	row.SwapUsedMB = row.SwapTotalMB - int64(mem["SwapFree"])/1024
	row.RootDiskTotalMB, row.RootDiskUsedMB, row.RootDiskFreeMB = readRootDisk()
	row.NetworkAddresses = networkAddresses()
	if load, err := os.ReadFile("/proc/loadavg"); err == nil {
		fields := strings.Fields(string(load))
		if len(fields) >= 3 {
			row.Load1, _ = strconv.ParseFloat(fields[0], 64)
			row.Load5, _ = strconv.ParseFloat(fields[1], 64)
			row.Load15, _ = strconv.ParseFloat(fields[2], 64)
		}
	}
	if uptime, err := os.ReadFile("/proc/uptime"); err == nil {
		if fields := strings.Fields(string(uptime)); len(fields) > 0 {
			row.UptimeSeconds, _ = strconv.ParseFloat(fields[0], 64)
		}
	}
	cpu := readCPUCounters()
	rx, tx := readNetworkCounters()
	if s.previousCPU.total > 0 && cpu.total > s.previousCPU.total {
		totalDelta := cpu.total - s.previousCPU.total
		idleDelta := cpu.idle - s.previousCPU.idle
		row.CPUUtilizationPct = 100 * (1 - float64(idleDelta)/float64(totalDelta))
	}
	if !s.previousAt.IsZero() {
		seconds := now.Sub(s.previousAt).Seconds()
		if seconds > 0 {
			if rx >= s.previousRX {
				row.NetworkRXBPS = float64(rx-s.previousRX) / seconds
			}
			if tx >= s.previousTX {
				row.NetworkTXBPS = float64(tx-s.previousTX) / seconds
			}
		}
	}
	s.previousCPU, s.previousRX, s.previousTX, s.previousAt = cpu, rx, tx, now
	return row
}

func networkAddresses() []string {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	result := make([]string, 0)
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addresses, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, address := range addresses {
			ip, _, err := net.ParseCIDR(address.String())
			if err == nil && ip != nil && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() {
				result = append(result, ip.String())
			}
		}
	}
	return result
}

func firstProcValue(path, key string) string {
	file, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		parts := strings.SplitN(scanner.Text(), ":", 2)
		if len(parts) == 2 && strings.TrimSpace(parts[0]) == key {
			return strings.TrimSpace(parts[1])
		}
	}
	return ""
}

func procKeyValues(path string) map[string]uint64 {
	result := make(map[string]uint64)
	file, err := os.Open(path)
	if err != nil {
		return result
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		value, err := strconv.ParseUint(fields[1], 10, 64)
		if err == nil {
			result[strings.TrimSuffix(fields[0], ":")] = value
		}
	}
	return result
}

func readCPUCounters() cpuCounters {
	value, err := os.ReadFile("/proc/stat")
	if err != nil {
		return cpuCounters{}
	}
	fields := strings.Fields(strings.SplitN(string(value), "\n", 2)[0])
	if len(fields) < 5 || fields[0] != "cpu" {
		return cpuCounters{}
	}
	var counters []uint64
	for _, field := range fields[1:] {
		parsed, _ := strconv.ParseUint(field, 10, 64)
		counters = append(counters, parsed)
	}
	var total uint64
	for _, value := range counters {
		total += value
	}
	idle := counters[3]
	if len(counters) > 4 {
		idle += counters[4]
	}
	return cpuCounters{total: total, idle: idle}
}

func readNetworkCounters() (uint64, uint64) {
	value, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return 0, 0
	}
	var rx, tx uint64
	for _, line := range strings.Split(string(value), "\n") {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 || strings.TrimSpace(parts[0]) == "lo" {
			continue
		}
		fields := strings.Fields(parts[1])
		if len(fields) < 9 {
			continue
		}
		received, _ := strconv.ParseUint(fields[0], 10, 64)
		transmitted, _ := strconv.ParseUint(fields[8], 10, 64)
		rx += received
		tx += transmitted
	}
	return rx, tx
}
