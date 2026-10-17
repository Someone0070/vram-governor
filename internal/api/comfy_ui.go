package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"vram-governor/internal/domain"
)

// The ComfyUI web app at /comfy/. The browser talks to the real ComfyUI (via
// a reverse proxy) for the page, node definitions, settings, saved
// workflows, uploads, outputs and the progress websocket, so previews and
// per-node progress work as usual. Queueing is the exception: the LB admits
// the prompt like any other GPU work (waits its turn, evicts LLMs, sets
// clocks) and then hands it to ComfyUI with the prompt_id it already
// returned and the browser's client_id, so ComfyUI's own events reach the
// browser. Interrupt and queue deletion cancel the user's own LB workloads.

const comfyUIPrefix = "/comfy"

// comfyUIPromptWait bounds how long "Queue Prompt" waits for the prompt to
// reach ComfyUI. Waiting lets ComfyUI's validation errors reach the UI; a
// prompt still queued after this stays queued under the id returned.
var comfyUIPromptWait = 120 * time.Second

func (s *Server) comfyUIEnabled() bool {
	return s.cfg.ComfyUI.Upstream != "" && s.cfg.ComfyUI.TargetID != ""
}

func (s *Server) handleComfyUI(w http.ResponseWriter, r *http.Request) {
	if !s.comfyUIEnabled() {
		http.NotFound(w, r)
		return
	}
	path := strings.TrimPrefix(r.URL.Path, comfyUIPrefix)
	if path == "" {
		http.Redirect(w, r, comfyUIPrefix+"/", http.StatusFound)
		return
	}
	if path == "/login" {
		s.serveComfyUILogin(w, r)
		return
	}
	p, ok := s.authenticate(r)
	if !ok {
		if r.Method == http.MethodGet && strings.Contains(r.Header.Get("Accept"), "text/html") {
			http.Redirect(w, r, comfyUIPrefix+"/login", http.StatusFound)
			return
		}
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	if !hasScope(p, "comfy:read") {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "comfy:read scope required"})
		return
	}
	// The session cookie is SameSite=Strict; state-changing requests and the
	// websocket must also come from this origin.
	if r.Method != http.MethodGet && r.Method != http.MethodHead || strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		if origin := r.Header.Get("Origin"); origin != "" {
			if parsed, err := url.Parse(origin); err != nil || parsed.Host != r.Host {
				writeJSON(w, http.StatusForbidden, map[string]string{"error": "cross-origin request refused"})
				return
			}
		}
	}
	route := path
	if strings.HasPrefix(route, "/api/") {
		route = strings.TrimPrefix(route, "/api")
	}
	switch {
	case route == "/prompt" && r.Method == http.MethodPost:
		s.comfyUIPrompt(w, r, p)
	case route == "/interrupt" && r.Method == http.MethodPost:
		s.comfyUIInterrupt(w, r, p)
	case route == "/queue" && r.Method == http.MethodPost:
		s.comfyUIQueueMutation(w, r, p)
	case route == "/queue" && r.Method == http.MethodGet:
		s.comfyUIQueue(w, r, p, path)
	case comfyUIBlocked(route):
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "not available through the load balancer"})
	default:
		s.comfyUIProxy(path).ServeHTTP(w, r)
	}
}

// comfyUIBlocked lists ComfyUI routes that would bypass or destabilize the
// scheduler (freeing memory under other work, installing nodes, ...).
func comfyUIBlocked(route string) bool {
	if route == "/free" {
		return true
	}
	for _, prefix := range []string{"/manager", "/customnode", "/v2/manager", "/v2/customnode", "/snapshot", "/comfyui_manager", "/externalmodel"} {
		if route == prefix || strings.HasPrefix(route, prefix+"/") {
			return true
		}
	}
	return false
}

func (s *Server) comfyUIProxy(path string) http.Handler {
	upstream, err := url.Parse(s.cfg.ComfyUI.Upstream)
	if err != nil {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": "invalid comfy_ui upstream"})
		})
	}
	return &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Path, pr.Out.URL.RawPath = path, ""
			pr.SetURL(upstream)
			pr.Out.Host = upstream.Host
			// LB credentials stay at the LB.
			pr.Out.Header.Del("Cookie")
			pr.Out.Header.Del("Authorization")
			if pr.In.Header.Get("Origin") != "" {
				pr.Out.Header.Set("Origin", upstream.Scheme+"://"+upstream.Host)
			}
			pr.Out.Header.Del("Referer")
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": "ComfyUI is unreachable: " + err.Error()})
		},
	}
}

func comfyUIError(w http.ResponseWriter, status int, kind, message string) {
	writeJSON(w, status, map[string]any{"error": map[string]any{"type": kind, "message": message, "details": "", "extra_info": map[string]any{}}, "node_errors": map[string]any{}})
}

func (s *Server) comfyUIPrompt(w http.ResponseWriter, r *http.Request, p Principal) {
	if s.workloadsUnavailable(w) {
		return
	}
	if !hasScope(p, "comfy:submit") {
		comfyUIError(w, http.StatusForbidden, "forbidden", "comfy:submit scope required")
		return
	}
	var body map[string]any
	if err := json.NewDecoder(io.LimitReader(r.Body, 32<<20)).Decode(&body); err != nil {
		comfyUIError(w, http.StatusBadRequest, "invalid_prompt", "invalid JSON body")
		return
	}
	if graph, ok := body["prompt"].(map[string]any); !ok || len(graph) == 0 {
		comfyUIError(w, http.StatusBadRequest, "invalid_prompt", "prompt is empty")
		return
	}
	promptID, _ := body["prompt_id"].(string)
	if promptID == "" {
		promptID = newUUID()
		body["prompt_id"] = promptID
	}
	payload, err := json.Marshal(body)
	if err != nil {
		comfyUIError(w, http.StatusBadRequest, "invalid_prompt", err.Error())
		return
	}
	req := domain.WorkloadRequest{Plane: domain.PlaneComfy, Adapter: "comfy", WorkloadType: "comfy.workflow", Payload: payload, ItemID: promptID,
		OperationVersion: "v1", IdempotencyKey: "comfy-ui:" + promptID, Priority: p.DefaultPriority, QoS: domain.QoSNormal,
		QueuePolicy: domain.QueueWait, Disruption: domain.DisruptionLocked, Egress: domain.EgressLocalOnly}
	if err := s.prepareRequest(r, p, &req); err != nil {
		comfyUIError(w, http.StatusForbidden, "forbidden", err.Error())
		return
	}
	req.PinnedTargetID = s.cfg.ComfyUI.TargetID
	row, _, err := s.workloads.Submit(r.Context(), req)
	if err != nil {
		comfyUIError(w, http.StatusBadRequest, "lb_rejected", err.Error())
		return
	}
	deadline := time.Now().Add(comfyUIPromptWait)
	for {
		current, getErr := s.workloads.Get(r.Context(), row.Request.ID)
		if getErr == nil {
			if current.Execution != nil && current.Execution.ExternalID != "" {
				writeJSON(w, http.StatusOK, map[string]any{"prompt_id": promptID, "number": 0, "node_errors": map[string]any{}})
				return
			}
			switch current.Status {
			case domain.WorkloadFailed, domain.WorkloadRejected, domain.WorkloadCancelled:
				writeComfyUIFailure(w, current)
				return
			}
		}
		if time.Now().After(deadline) {
			// Still waiting for the GPU: ComfyUI will run it under this id, and
			// the queue view lists it as pending meanwhile.
			writeJSON(w, http.StatusOK, map[string]any{"prompt_id": promptID, "number": 0, "node_errors": map[string]any{}})
			return
		}
		select {
		case <-r.Context().Done():
			// The browser left before the prompt was queued anywhere it can see.
			_ = s.workloads.Cancel(context.Background(), row.Request.ID, p.OwnerID, false)
			return
		case <-time.After(250 * time.Millisecond):
		}
	}
}

// writeComfyUIFailure returns ComfyUI's own rejection (with node_errors, so
// the UI marks the failing nodes) when the backend refused the prompt.
func writeComfyUIFailure(w http.ResponseWriter, row *domain.Workload) {
	message := row.Error
	if message == "" {
		message = row.Decision.Blocker
	}
	if _, raw, found := strings.Cut(message, "comfy backend returned 400: "); found {
		trimmed := bytes.TrimSpace([]byte(raw))
		if json.Valid(trimmed) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write(trimmed)
			return
		}
	}
	comfyUIError(w, http.StatusServiceUnavailable, "lb_error", fmt.Sprintf("load balancer: %s", message))
}

func (s *Server) comfyUIWorkloads(r *http.Request, p Principal) []*domain.Workload {
	rows, err := s.workloads.List(r.Context())
	if err != nil {
		return nil
	}
	out := make([]*domain.Workload, 0)
	for _, row := range rows {
		if row.Request.PinnedTargetID == s.cfg.ComfyUI.TargetID && (row.Request.OwnerID == p.OwnerID || hasScope(p, "admin")) {
			out = append(out, row)
		}
	}
	return out
}

func activeComfyUIStatus(status domain.WorkloadStatus) bool {
	return status == domain.WorkloadQueued || status == domain.WorkloadWaiting || status == domain.WorkloadRunning
}

func (s *Server) comfyUIInterrupt(w http.ResponseWriter, r *http.Request, p Principal) {
	var body struct {
		PromptID string `json:"prompt_id"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body)
	for _, row := range s.comfyUIWorkloads(r, p) {
		if row.Status != domain.WorkloadRunning || body.PromptID != "" && row.Request.ItemID != body.PromptID {
			continue
		}
		_ = s.workloads.Cancel(r.Context(), row.Request.ID, p.OwnerID, hasScope(p, "admin"))
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) comfyUIQueueMutation(w http.ResponseWriter, r *http.Request, p Principal) {
	var body struct {
		Delete []string `json:"delete"`
		Clear  bool     `json:"clear"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	remove := map[string]bool{}
	for _, id := range body.Delete {
		remove[id] = true
	}
	for _, row := range s.comfyUIWorkloads(r, p) {
		// Queue operations act on prompts that have not started (ComfyUI's
		// semantics); a running prompt is stopped with interrupt.
		if !activeComfyUIStatus(row.Status) || row.Status == domain.WorkloadRunning && row.Execution != nil {
			continue
		}
		if body.Clear || remove[row.Request.ItemID] {
			_ = s.workloads.Cancel(r.Context(), row.Request.ID, p.OwnerID, hasScope(p, "admin"))
		}
	}
	w.WriteHeader(http.StatusOK)
}

// comfyUIQueue is ComfyUI's queue plus the user's prompts still waiting at
// the LB for the GPU, listed as pending.
func (s *Server) comfyUIQueue(w http.ResponseWriter, r *http.Request, p Principal, path string) {
	queue := map[string][]any{"queue_running": {}, "queue_pending": {}}
	if upstream, err := url.Parse(s.cfg.ComfyUI.Upstream); err == nil {
		upstream.Path = strings.TrimRight(upstream.Path, "/") + path
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		request, _ := http.NewRequestWithContext(ctx, http.MethodGet, upstream.String(), nil)
		if response, err := http.DefaultClient.Do(request); err == nil {
			_ = json.NewDecoder(io.LimitReader(response.Body, 64<<20)).Decode(&queue)
			response.Body.Close()
		}
	}
	number := 1 << 30
	for _, row := range s.comfyUIWorkloads(r, p) {
		if !activeComfyUIStatus(row.Status) || row.Execution != nil {
			continue
		}
		var body struct {
			Prompt    json.RawMessage `json:"prompt"`
			ExtraData json.RawMessage `json:"extra_data"`
		}
		_ = json.Unmarshal(row.Request.Payload, &body)
		if len(body.ExtraData) == 0 {
			body.ExtraData = json.RawMessage(`{}`)
		}
		queue["queue_pending"] = append(queue["queue_pending"], []any{number, row.Request.ItemID, body.Prompt, body.ExtraData, []string{}})
		number++
	}
	writeJSON(w, http.StatusOK, queue)
}

var comfyUILoginPage = template.Must(template.New("login").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>ComfyUI sign in</title>
<style>
:root{--bg:#f6f7f9;--fg:#15171a;--muted:#5b616b;--card:#fff;--line:#d9dde3;--accent:#2f6fde}
@media (prefers-color-scheme:dark){:root{--bg:#121417;--fg:#e8eaed;--muted:#9aa0a8;--card:#1b1e22;--line:#2c3036;--accent:#6c9cf0}}
body{margin:0;min-height:100vh;display:grid;place-items:center;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,sans-serif}
form{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:24px;width:min(360px,calc(100vw - 32px));box-sizing:border-box}
h1{font-size:18px;margin:0 0 4px}p{margin:0 0 16px;color:var(--muted)}
input{width:100%;box-sizing:border-box;padding:9px 10px;border:1px solid var(--line);border-radius:6px;background:transparent;color:inherit;font:inherit}
button{margin-top:12px;width:100%;padding:9px;border:0;border-radius:6px;background:var(--accent);color:#fff;font:inherit;cursor:pointer}
#err{color:#d14343;min-height:1.5em;margin-top:8px}
</style></head><body>
<form id="f"><h1>ComfyUI</h1><p>Sign in with your load balancer token.</p>
<input id="t" type="password" autocomplete="current-password" placeholder="Token" required autofocus>
<button type="submit">Sign in</button><div id="err" role="alert"></div></form>
<script>
document.getElementById('f').addEventListener('submit', async (e) => {
  e.preventDefault();
  const res = await fetch('/auth/session', {method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({token: document.getElementById('t').value, kind: 'ui'})});
  if (res.ok) { location.href = '{{.}}/'; } else { document.getElementById('err').textContent = 'Sign-in failed.'; }
});
</script></body></html>`))

func (s *Server) serveComfyUILogin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = comfyUILoginPage.Execute(w, comfyUIPrefix)
}

// newUUID returns a random RFC 4122 version 4 UUID, the form ComfyUI uses
// for prompt ids.
func newUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("%08x-0000-4000-8000-%012x", time.Now().Unix(), time.Now().UnixNano()&0xffffffffffff)
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
