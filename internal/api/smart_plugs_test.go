package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"vram-governor/internal/domain"
)

const smartPlugFixture = `<td>Voltage{m}</td><td style='text-align:left'>119.8</td><td> V{e}<td>Current{m}</td><td style='text-align:left'>1.250</td><td> A{e}<td>Active Power{m}</td><td style='text-align:left'>145</td><td> W{e}<td>Apparent Power{m}</td><td style='text-align:left'>150</td><td> VA{e}<td>Reactive Power{m}</td><td style='text-align:left'>10</td><td> var{e}<td>Power Factor{m}</td><td style='text-align:left'>0.97</td><td>{e}<td>Energy Today{m}</td><td style='text-align:left'>0.531</td><td> kWh{e}<td>Energy Yesterday{m}</td><td style='text-align:left'>2.500</td><td> kWh{e}<td>Energy Total{m}</td><td style='text-align:left'>100.100</td><td> kWh{e}<td style='font-weight:bold;font-size:62px'>ON</td>`
const smartPlugJSONFixture = `{"StatusSTS":{"POWER":"ON"},"StatusSNS":{"ENERGY":{"Voltage":119.8,"Current":1.25,"Power":145,"ApparentPower":150,"ReactivePower":10,"Factor":0.97,"Today":0.531,"Yesterday":2.5,"Total":100.1}}}`

func TestSmartPlugParsesTasmotaJSONStatus(t *testing.T) {
	status, err := parseTasmotaJSONStatus([]byte(smartPlugJSONFixture))
	if err != nil || status.Power != "ON" || status.ActivePower == nil || *status.ActivePower != 145 || status.Voltage == nil || *status.Voltage != 119.8 || status.EnergyTotal == nil || *status.EnergyTotal != 100.1 {
		t.Fatalf("Tasmota JSON telemetry was not parsed: %+v err=%v", status, err)
	}
	if _, err := parseTasmotaJSONStatus([]byte(`{"StatusSTS":{}}`)); err == nil {
		t.Fatal("JSON without a relay state was accepted")
	}
}

func TestSmartPlugParsesTasmotaWebTelemetry(t *testing.T) {
	status, err := parseTasmotaWebStatus([]byte(smartPlugFixture))
	if err != nil || status.Power != "ON" || status.ActivePower == nil || *status.ActivePower != 145 || status.Voltage == nil || *status.Voltage != 119.8 || status.EnergyTotal == nil || *status.EnergyTotal != 100.1 {
		t.Fatalf("Tasmota telemetry was not parsed: %+v err=%v", status, err)
	}
	if _, err := parseTasmotaWebStatus([]byte("no relay")); err == nil {
		t.Fatal("page without a relay state was accepted")
	}
}

func TestSmartPlugReadsWebTelemetryWithoutUsingToggle(t *testing.T) {
	toggles := 0
	device := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Has("o") || (r.URL.Path == "/cm" && r.URL.Query().Get("cmnd") != "Status 0") {
			toggles++
			t.Errorf("monitoring sent a control request: %s", r.URL.String())
		}
		if r.URL.Path == "/cm" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.URL.Path != "/" || r.URL.Query().Get("m") != "1" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(smartPlugFixture))
	}))
	defer device.Close()
	status := readSmartPlug(context.Background(), SmartPlugConfig{NodeID: "rig", URL: device.URL})
	if !status.Reachable || status.ActivePower == nil || *status.ActivePower != 145 || toggles != 0 {
		t.Fatalf("read-only monitoring failed: %+v toggles=%d", status, toggles)
	}
}

func TestSmartPlugReadsJSONWithSameOriginReferer(t *testing.T) {
	device := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/cm" || r.URL.Query().Get("cmnd") != "Status 0" || r.Header.Get("Referer") != "http://"+r.Host+"/" {
			t.Errorf("unexpected status request %s referer=%q", r.URL.String(), r.Header.Get("Referer"))
			w.WriteHeader(http.StatusForbidden)
			return
		}
		_, _ = w.Write([]byte(smartPlugJSONFixture))
	}))
	defer device.Close()
	status := readSmartPlug(context.Background(), SmartPlugConfig{NodeID: "rig", URL: device.URL})
	if !status.Reachable || status.ActivePower == nil || *status.ActivePower != 145 {
		t.Fatalf("JSON monitoring failed: %+v", status)
	}
}

func TestSmartPlugConfigRejectsUntrustedEndpoints(t *testing.T) {
	for _, endpoint := range []string{"http://example.com", "http://127.0.0.1", "http://10.0.0.43/cm", "http://10.0.0.43@evil.test", "https://10.0.0.43"} {
		body := "auth:\n  credentials: []\nsmart_plugs:\n  - node_id: rig\n    url: \"" + endpoint + "\"\n"
		if _, err := LoadConfig(writeConfig(t, body)); err == nil {
			t.Errorf("untrusted smart plug endpoint %q accepted", endpoint)
		}
	}
	valid := "auth:\n  credentials: []\nsmart_plugs:\n  - node_id: rig\n    url: http://10.0.0.43\n"
	if _, err := LoadConfig(writeConfig(t, valid)); err != nil {
		t.Fatalf("private fixed endpoint rejected: %v", err)
	}
}

func TestAdminSmartPlugRequiresAdminAndSafeExplicitPower(t *testing.T) {
	state, commands := "ON", 0
	device := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/cm" {
			if r.Header.Get("Referer") != "http://"+r.Host+"/" {
				t.Errorf("command lacked same-origin Referer: %q", r.Header.Get("Referer"))
			}
			if r.URL.Query().Get("cmnd") == "Status 0" {
				_, _ = w.Write([]byte(strings.Replace(smartPlugJSONFixture, `"POWER":"ON"`, `"POWER":"`+state+`"`, 1)))
				return
			}
			if !strings.Contains(r.URL.RawQuery, "Power%20") {
				t.Errorf("command did not use Tasmota's documented %%20 encoding: %s", r.URL.RawQuery)
			}
			commands++
			command := r.URL.Query().Get("cmnd")
			if command == "Power OFF" {
				state = "OFF"
			} else if command == "Power ON" {
				state = "ON"
			} else {
				t.Errorf("unexpected command %q", command)
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"POWER": state})
			return
		}
		_, _ = w.Write([]byte(strings.Replace(smartPlugFixture, ">ON</td>", ">"+state+"</td>", 1)))
	}))
	defer device.Close()
	srv, _, cancel := testServer(t)
	defer cancel()
	srv.cfg.SmartPlugs = []SmartPlugConfig{{NodeID: "rig", URL: device.URL, ControlEnabled: true}}
	getTelemetry := func(token string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/admin/api/smart-plugs", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		req.RemoteAddr = "127.0.0.1:1234"
		response := httptest.NewRecorder()
		srv.Handler().ServeHTTP(response, req)
		return response
	}
	if got := getTelemetry("alice-token"); got.Code != http.StatusForbidden {
		t.Fatalf("non-admin telemetry response %d", got.Code)
	}
	if got := getTelemetry("admin-token"); got.Code != http.StatusOK || !strings.Contains(got.Body.String(), `"active_power_w":145`) {
		t.Fatalf("admin telemetry response %d: %s", got.Code, got.Body.String())
	}
	node := &domain.Node{ID: "rig", SchedulingState: domain.SchedulingEnabled, Desired: domain.Desired{SchedulingEnabled: true, PowerControlMode: domain.PowerModeAuto}, Observed: domain.Observed{Connectivity: domain.ConnectivityConnected}, Accelerators: []domain.Accelerator{{ID: "gpu-rig"}}}
	if _, err := srv.nodes.UpsertNode(context.Background(), node); err != nil {
		t.Fatal(err)
	}
	url := "/admin/api/smart-plugs/rig/power"
	post := func(token, key, state string, ack bool) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, url, strings.NewReader(`{"state":"`+state+`","acknowledge_hard_power_cut":`+map[bool]string{true: "true", false: "false"}[ack]+`}`))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		if key != "" {
			req.Header.Set("Idempotency-Key", key)
		}
		req.RemoteAddr = "127.0.0.1:1234"
		response := httptest.NewRecorder()
		srv.Handler().ServeHTTP(response, req)
		return response
	}
	srv.cfg.SmartPlugs = nil
	if got := post("admin-token", "unmapped", "ON", false); got.Code != http.StatusNotFound || commands != 0 {
		t.Fatalf("unmapped plug response %d commands=%d", got.Code, commands)
	}
	srv.cfg.SmartPlugs = []SmartPlugConfig{{NodeID: "rig", URL: device.URL, ControlEnabled: true}}
	if got := post("alice-token", "x", "OFF", true); got.Code != http.StatusForbidden {
		t.Fatalf("non-admin power response %d", got.Code)
	}
	if got := post("admin-token", "", "OFF", true); got.Code != http.StatusBadRequest {
		t.Fatalf("missing idempotency response %d", got.Code)
	}
	if got := post("admin-token", "x", "TOGGLE", true); got.Code != http.StatusBadRequest {
		t.Fatalf("toggle response %d", got.Code)
	}
	if got := post("admin-token", "x", "OFF", true); got.Code != http.StatusForbidden {
		t.Fatalf("automatic power mode response %d", got.Code)
	}
	if err := srv.nodes.UpdateDesired(context.Background(), "rig", func(d *domain.Desired, _ *domain.SchedulingState) {
		d.PowerControlMode = domain.PowerModeManual
	}); err != nil {
		t.Fatal(err)
	}
	if got := post("admin-token", "x", "OFF", false); got.Code != http.StatusBadRequest {
		t.Fatalf("unacknowledged off response %d", got.Code)
	}
	if got := post("admin-token", "x", "OFF", true); got.Code != http.StatusConflict {
		t.Fatalf("scheduled rig off response %d", got.Code)
	}
	if commands != 0 {
		t.Fatalf("unsafe requests sent %d device commands", commands)
	}
	if err := srv.nodes.UpdateDesired(context.Background(), "rig", func(d *domain.Desired, scheduling *domain.SchedulingState) {
		d.SchedulingEnabled = false
		*scheduling = domain.SchedulingDisabled
	}); err != nil {
		t.Fatal(err)
	}
	active, _, err := srv.workloadStore.CreateWorkload(context.Background(), &domain.Workload{Request: domain.WorkloadRequest{ID: "active-rig-work", OwnerID: "owner", Adapter: "mock"}, Status: domain.WorkloadRunning, Plan: &domain.ExecutionPlan{AcceleratorID: "gpu-rig"}})
	if err != nil {
		t.Fatal(err)
	}
	if got := post("admin-token", "off-busy", "OFF", true); got.Code != http.StatusConflict || commands != 0 {
		t.Fatalf("active rig was not protected: status=%d commands=%d", got.Code, commands)
	}
	active.Status = domain.WorkloadSucceeded
	if _, err := srv.workloadStore.UpdateWorkload(context.Background(), active); err != nil {
		t.Fatal(err)
	}
	if got := post("admin-token", "off-1", "OFF", true); got.Code != http.StatusOK || state != "OFF" || commands != 1 {
		t.Fatalf("safe explicit OFF failed: status=%d state=%s commands=%d body=%s", got.Code, state, commands, got.Body.String())
	}
	if got := post("admin-token", "off-2", "OFF", true); got.Code != http.StatusOK || commands != 1 {
		t.Fatalf("repeated OFF was not idempotent: status=%d commands=%d", got.Code, commands)
	}
	if got := post("admin-token", "on-1", "ON", false); got.Code != http.StatusOK || state != "ON" || commands != 2 {
		t.Fatalf("explicit ON failed: status=%d state=%s commands=%d", got.Code, state, commands)
	}
}

func TestAdminSmartPlugCommandFailureDoesNotUseBlindToggle(t *testing.T) {
	toggleCalls, commandCalls := 0, 0
	device := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Has("o") {
			toggleCalls++
		}
		if r.URL.Path == "/cm" {
			if r.URL.Query().Get("cmnd") != "Status 0" {
				commandCalls++
			}
			w.WriteHeader(http.StatusOK)
			return
		}
		_, _ = w.Write([]byte(smartPlugFixture))
	}))
	defer device.Close()
	srv, _, cancel := testServer(t)
	defer cancel()
	srv.cfg.SmartPlugs = []SmartPlugConfig{{NodeID: "rig", URL: device.URL, ControlEnabled: true}}
	if _, err := srv.nodes.UpsertNode(context.Background(), &domain.Node{ID: "rig", SchedulingState: domain.SchedulingDisabled, Desired: domain.Desired{PowerControlMode: domain.PowerModeManual}}); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/admin/api/smart-plugs/rig/power", strings.NewReader(`{"state":"OFF","acknowledge_hard_power_cut":true}`))
	req.Header.Set("Authorization", "Bearer admin-token")
	req.Header.Set("Idempotency-Key", "failed-command")
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "127.0.0.1:1234"
	response := httptest.NewRecorder()
	srv.Handler().ServeHTTP(response, req)
	if response.Code != http.StatusBadGateway || commandCalls != 1 || toggleCalls != 0 {
		t.Fatalf("unconfirmed power command used unsafe fallback: status=%d commands=%d toggles=%d", response.Code, commandCalls, toggleCalls)
	}
}
