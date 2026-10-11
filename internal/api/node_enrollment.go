package api

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
	"time"

	"github.com/coder/websocket"

	"vram-governor/internal/domain"
	"vram-governor/internal/store"
)

func validEnrollmentNodeID(id string) bool {
	if len(id) < 2 || len(id) > 64 {
		return false
	}
	for _, char := range id {
		if char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || char == '.' || char == '_' || char == '-' {
			continue
		}
		return false
	}
	return true
}

func (s *Server) handleEnrollNode(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	principal, ok := s.requirePrincipal(w, r, "node:enroll")
	if !ok {
		return
	}
	if principal.Plane != "enrollment" {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "enrollment credential required"})
		return
	}
	var body struct {
		NodeID   string `json:"node_id"`
		NodeName string `json:"node_name"`
	}
	if err := decodeJSONLimit(r, &body, 4096); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid enrollment request"})
		return
	}
	body.NodeName = strings.TrimSpace(body.NodeName)
	if !validEnrollmentNodeID(body.NodeID) || len(body.NodeName) == 0 || len(body.NodeName) > 128 || strings.ContainsAny(body.NodeName, "\r\n\x00") {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid node identity"})
		return
	}
	for _, credential := range s.cfg.Auth.Credentials {
		if credential.Plane == "node" && credential.NodeID == body.NodeID {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "node ID already has a static credential"})
			return
		}
	}
	if _, err := s.nodes.GetNode(r.Context(), body.NodeID); err == nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "node ID already registered"})
		return
	} else if err != store.ErrNotFound {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "node inventory unavailable"})
		return
	}
	var secretBytes [32]byte
	if _, err := rand.Read(secretBytes[:]); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "secure randomness unavailable"})
		return
	}
	secret := hex.EncodeToString(secretBytes[:])
	hash := sha256.Sum256([]byte(secret))
	now := time.Now().UTC()
	value := &domain.NodeEnrollment{NodeID: body.NodeID, NodeName: body.NodeName, TokenHash: hex.EncodeToString(hash[:]), Status: "active", CreatedAt: now, UpdatedAt: now}
	if err := s.enrollments.CreateNodeEnrollment(r.Context(), value); err != nil {
		if err == store.ErrAlreadyExists {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "node ID already enrolled"})
		} else {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "enrollment storage unavailable"})
		}
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"node_id": body.NodeID, "status": "active", "node_token": secret})
}

func (s *Server) handleListNodeEnrollments(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAdmin(w, r); !ok {
		return
	}
	values, err := s.enrollments.ListNodeEnrollments(r.Context())
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "enrollment storage unavailable"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"nodes": values})
}

func (s *Server) handleRevokeNodeEnrollment(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAdmin(w, r); !ok {
		return
	}
	id := r.PathValue("node_id")
	if err := s.enrollments.RevokeNodeEnrollment(r.Context(), id); err != nil {
		if err == store.ErrNotFound {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "enrollment not found"})
		} else {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "enrollment storage unavailable"})
		}
		return
	}
	s.nodeConnMu.RLock()
	conn := s.nodeConnections[id]
	s.nodeConnMu.RUnlock()
	if conn != nil {
		_ = conn.conn.Close(websocket.StatusPolicyViolation, "node credential revoked")
	}
	writeJSON(w, http.StatusOK, map[string]string{"node_id": id, "status": "revoked"})
}
