package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"vram-governor/internal/domain"
	"vram-governor/internal/store"
)

// SmartPlugStatus is a wall-power measurement. Zero is a valid reading, so
// numeric fields are pointers to distinguish zero from an absent sensor.
type SmartPlugStatus struct {
	NodeID          string    `json:"node_id"`
	Configured      bool      `json:"configured"`
	ControlEnabled  bool      `json:"control_enabled"`
	Reachable       bool      `json:"reachable"`
	Power           string    `json:"power"`
	Voltage         *float64  `json:"voltage_v,omitempty"`
	Current         *float64  `json:"current_a,omitempty"`
	ActivePower     *float64  `json:"active_power_w,omitempty"`
	ApparentPower   *float64  `json:"apparent_power_va,omitempty"`
	ReactivePower   *float64  `json:"reactive_power_var,omitempty"`
	PowerFactor     *float64  `json:"power_factor,omitempty"`
	EnergyToday     *float64  `json:"energy_today_kwh,omitempty"`
	EnergyYesterday *float64  `json:"energy_yesterday_kwh,omitempty"`
	EnergyTotal     *float64  `json:"energy_total_kwh,omitempty"`
	ObservedAt      time.Time `json:"observed_at,omitempty"`
	Error           string    `json:"error,omitempty"`
}

var plugValue = regexp.MustCompile(`(?is)<td[^>]*>\s*([-+]?[0-9]+(?:\.[0-9]+)?)\s*</td>`)
var plugPower = regexp.MustCompile(`(?is)font-weight:bold;font-size:62px[^>]*>\s*(ON|OFF)\s*</td>`)

func parseTasmotaWebStatus(body []byte) (SmartPlugStatus, error) {
	text := html.UnescapeString(string(body))
	status := SmartPlugStatus{}
	if match := plugPower.FindStringSubmatch(text); len(match) == 2 {
		status.Power = strings.ToUpper(match[1])
	}
	measurements := []struct {
		label string
		field **float64
	}{
		{"Voltage", &status.Voltage}, {"Current", &status.Current},
		{"Active Power", &status.ActivePower}, {"Apparent Power", &status.ApparentPower},
		{"Reactive Power", &status.ReactivePower}, {"Power Factor", &status.PowerFactor},
		{"Energy Today", &status.EnergyToday}, {"Energy Yesterday", &status.EnergyYesterday}, {"Energy Total", &status.EnergyTotal},
	}
	for _, measurement := range measurements {
		label := regexp.QuoteMeta(measurement.label)
		start := regexp.MustCompile(`(?is)` + label + `\s*\{m\}</td>`).FindStringIndex(text)
		if start == nil {
			continue
		}
		end := start[1] + 250
		if end > len(text) {
			end = len(text)
		}
		if match := plugValue.FindStringSubmatch(text[start[1]:end]); len(match) == 2 {
			if value, err := strconv.ParseFloat(match[1], 64); err == nil {
				*measurement.field = &value
			}
		}
	}
	if status.Power == "" {
		return SmartPlugStatus{}, fmt.Errorf("Tasmota relay state was absent from telemetry")
	}
	return status, nil
}

func smartPlugClient() *http.Client {
	return &http.Client{Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }, Transport: &http.Transport{Proxy: nil}}
}

func tasmotaRequest(ctx context.Context, plug SmartPlugConfig, command string) (*http.Request, error) {
	base := strings.TrimRight(plug.URL, "/")
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/cm?cmnd="+url.PathEscape(command), nil)
	if err != nil {
		return nil, err
	}
	// With Tasmota's HTTP_API option disabled, management routes require a
	// same-device Referer. This does not change the device's security setting.
	request.Header.Set("Referer", base+"/")
	return request, nil
}

func parseTasmotaJSONStatus(body []byte) (SmartPlugStatus, error) {
	var result struct {
		StatusSTS struct {
			Power  string `json:"POWER"`
			Power1 string `json:"POWER1"`
		} `json:"StatusSTS"`
		StatusSNS struct {
			Energy struct {
				Voltage       *float64 `json:"Voltage"`
				Current       *float64 `json:"Current"`
				Power         *float64 `json:"Power"`
				ApparentPower *float64 `json:"ApparentPower"`
				ReactivePower *float64 `json:"ReactivePower"`
				Factor        *float64 `json:"Factor"`
				Today         *float64 `json:"Today"`
				Yesterday     *float64 `json:"Yesterday"`
				Total         *float64 `json:"Total"`
			} `json:"ENERGY"`
		} `json:"StatusSNS"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return SmartPlugStatus{}, err
	}
	power := result.StatusSTS.Power
	if power == "" {
		power = result.StatusSTS.Power1
	}
	if power != "ON" && power != "OFF" {
		return SmartPlugStatus{}, fmt.Errorf("Tasmota JSON status did not include relay state")
	}
	energy := result.StatusSNS.Energy
	return SmartPlugStatus{Power: power, Voltage: energy.Voltage, Current: energy.Current,
		ActivePower: energy.Power, ApparentPower: energy.ApparentPower, ReactivePower: energy.ReactivePower,
		PowerFactor: energy.Factor, EnergyToday: energy.Today, EnergyYesterday: energy.Yesterday, EnergyTotal: energy.Total}, nil
}

func (s *Server) configuredPlug(nodeID string) (SmartPlugConfig, bool) {
	for _, plug := range s.cfg.SmartPlugs {
		if plug.NodeID == nodeID {
			return plug, true
		}
	}
	return SmartPlugConfig{}, false
}

func readSmartPlug(ctx context.Context, plug SmartPlugConfig) SmartPlugStatus {
	status := SmartPlugStatus{NodeID: plug.NodeID, Configured: true, ControlEnabled: plug.ControlEnabled, Power: "UNKNOWN"}
	request, err := tasmotaRequest(ctx, plug, "Status 0")
	if err == nil {
		response, requestErr := smartPlugClient().Do(request)
		if requestErr == nil {
			body, readErr := io.ReadAll(io.LimitReader(response.Body, 64<<10))
			response.Body.Close()
			if response.StatusCode == http.StatusOK && readErr == nil {
				if measured, parseErr := parseTasmotaJSONStatus(body); parseErr == nil {
					measured.NodeID, measured.Configured, measured.ControlEnabled = plug.NodeID, true, plug.ControlEnabled
					measured.Reachable, measured.ObservedAt = true, time.Now().UTC()
					return measured
				}
			}
		}
	}
	// Older or differently configured devices may still expose the web
	// telemetry fragment even if the structured command path is unavailable.
	endpoint := strings.TrimRight(plug.URL, "/") + "/?m=1"
	request, err = http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		status.Error = "invalid configured endpoint"
		return status
	}
	response, err := smartPlugClient().Do(request)
	if err != nil {
		status.Error = "smart plug is unreachable"
		return status
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		status.Error = fmt.Sprintf("smart plug returned HTTP %d", response.StatusCode)
		return status
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 64<<10))
	if err != nil {
		status.Error = "smart plug telemetry could not be read"
		return status
	}
	measured, err := parseTasmotaWebStatus(body)
	if err != nil {
		status.Error = err.Error()
		return status
	}
	measured.NodeID, measured.Configured, measured.ControlEnabled = plug.NodeID, true, plug.ControlEnabled
	measured.Reachable, measured.ObservedAt = true, time.Now().UTC()
	return measured
}

func (s *Server) handleAdminSmartPlugs(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAdmin(w, r); !ok {
		return
	}
	statuses := make([]SmartPlugStatus, len(s.cfg.SmartPlugs))
	var checks sync.WaitGroup
	for index, plug := range s.cfg.SmartPlugs {
		checks.Add(1)
		go func() {
			defer checks.Done()
			statuses[index] = readSmartPlug(r.Context(), plug)
		}()
	}
	checks.Wait()
	writeJSON(w, http.StatusOK, map[string]any{"smart_plugs": statuses})
}

func (s *Server) handleAdminSmartPlugPower(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	if r.Header.Get("Idempotency-Key") == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Idempotency-Key is required"})
		return
	}
	var body struct {
		State                   string `json:"state"`
		AcknowledgeHardPowerCut bool   `json:"acknowledge_hard_power_cut"`
	}
	if err := decodeJSONLimit(r, &body, 4<<10); err != nil || (body.State != "ON" && body.State != "OFF") {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "state must be explicitly ON or OFF"})
		return
	}
	plug, found := s.configuredPlug(r.PathValue("node_id"))
	if !found {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no plug is mapped to this rig"})
		return
	}
	if !plug.ControlEnabled {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "plug power control is disabled in configuration"})
		return
	}
	s.plugMu.Lock()
	defer s.plugMu.Unlock()
	node, err := s.nodes.GetNode(r.Context(), plug.NodeID)
	if errors.Is(err, store.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "mapped rig is not registered"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "rig state is unavailable"})
		return
	}
	if node.Desired.PowerControlMode != domain.PowerModeManual {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "rig power-control mode must be manual for plug commands"})
		return
	}
	if body.State == "OFF" {
		if !body.AcknowledgeHardPowerCut {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "OFF requires acknowledge_hard_power_cut=true"})
			return
		}
		if node.SchedulingState != domain.SchedulingDisabled || node.Desired.SchedulingEnabled {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "disable rig scheduling before cutting power"})
			return
		}
		if s.workloads == nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "workload state is unavailable"})
			return
		}
		rows, err := s.workloads.List(r.Context())
		if err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "workload state is unavailable"})
			return
		}
		for _, row := range rows {
			if row.Status == domain.WorkloadSucceeded || row.Status == domain.WorkloadFailed || row.Status == domain.WorkloadCancelled || row.Status == domain.WorkloadRejected {
				continue
			}
			for _, accelerator := range node.Accelerators {
				if (row.Plan != nil && row.Plan.AcceleratorID == accelerator.ID) || row.Decision.AcceleratorID == accelerator.ID {
					writeJSON(w, http.StatusConflict, map[string]string{"error": "active work is still assigned to this rig"})
					return
				}
			}
		}
	}
	before := readSmartPlug(r.Context(), plug)
	if !before.Reachable {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": before.Error})
		return
	}
	if before.Power == body.State {
		writeJSON(w, http.StatusOK, before)
		return
	}
	request, err := tasmotaRequest(r.Context(), plug, "Power "+body.State)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "invalid configured command"})
		return
	}
	response, err := smartPlugClient().Do(request)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "Tasmota command endpoint did not respond; relay state is unknown"})
		return
	}
	defer response.Body.Close()
	var result map[string]string
	if response.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(response.Body, 4<<10)).Decode(&result) != nil || (result["POWER"] != body.State && result["POWER1"] != body.State) {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "Tasmota did not confirm the requested relay state"})
		return
	}
	after := readSmartPlug(r.Context(), plug)
	if !after.Reachable || after.Power != body.State {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "relay changed but telemetry did not confirm the final state"})
		return
	}
	payload, _ := json.Marshal(map[string]string{"node_id": plug.NodeID, "state": body.State, "idempotency_key": r.Header.Get("Idempotency-Key")})
	_ = s.workloadStore.AppendAuditEvent(r.Context(), &domain.AuditEvent{ID: "evt-" + randomSecret()[:24], Timestamp: time.Now().UTC(), ActorID: principal.ID, Type: "smart_plug.power.changed", Severity: "warn", Payload: payload})
	writeJSON(w, http.StatusOK, after)
}
