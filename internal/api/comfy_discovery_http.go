package api

import (
	"io"
	"net/http"
)

func (s *Server) comfyDiscoveryAccess(w http.ResponseWriter, r *http.Request) (Principal, bool) {
	if s.workloadsUnavailable(w) {
		return Principal{}, false
	}
	p, ok := s.requirePrincipal(w, r, "comfy:read")
	if !ok {
		return Principal{}, false
	}
	if !allowsAdapter(p, "comfy") {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "adapter_forbidden"})
		return Principal{}, false
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
		return Principal{}, false
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery || r.ContentLength > 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_discovery_request"})
		return Principal{}, false
	}
	if r.Body != nil {
		body, err := io.ReadAll(io.LimitReader(r.Body, 1))
		if err != nil || len(body) != 0 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_discovery_request"})
			return Principal{}, false
		}
	}
	return p, true
}

func (s *Server) handleComfyObjectInfo(w http.ResponseWriter, r *http.Request) {
	p, ok := s.comfyDiscoveryAccess(w, r)
	if !ok {
		return
	}
	result, err := s.workloads.ComfyFleetDiscovery(r.Context(), p.EgressPolicy)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "discovery_unavailable"})
		return
	}
	if len(result.Conflicts) != 0 {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "schema_conflict", "classes": result.Conflicts})
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, result.ObjectInfo)
}

func (s *Server) handleComfySystemStats(w http.ResponseWriter, r *http.Request) {
	p, ok := s.comfyDiscoveryAccess(w, r)
	if !ok {
		return
	}
	result, err := s.workloads.ComfyFleetDiscovery(r.Context(), p.EgressPolicy)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "discovery_unavailable"})
		return
	}
	response := map[string]any{
		"system": map[string]any{"name": "vram-governor", "version": "controller"},
		"devices": result.Devices,
		"availability": map[string]any{"available_sources": result.Available},
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, response)
}
