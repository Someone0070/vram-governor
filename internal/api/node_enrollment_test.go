package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"vram-governor/internal/store"
)

func TestSelfEnrollmentIssuesDurableBoundRevocableCredential(t *testing.T) {
	srv, _, cancel := testServer(t)
	defer cancel()
	srv.cfg.Auth.Credentials = append(srv.cfg.Auth.Credentials, CredentialConfig{ID: "fleet", Token: "fleet-secret", OwnerID: "system", Plane: "enrollment", Scopes: []string{"node:enroll"}})
	srv.buildCredentials()
	endpoint := "/api/v1/nodes/enroll"
	body := map[string]string{"node_id": "new-780m", "node_name": "780M host"}
	for _, token := range []string{"", "alice-token", "node-a-token"} {
		response := request(t, srv.Handler(), http.MethodPost, endpoint, token, body)
		if response.Code != http.StatusUnauthorized && response.Code != http.StatusForbidden {
			t.Fatalf("non-enrollment credential accepted: %d", response.Code)
		}
	}
	created := request(t, srv.Handler(), http.MethodPost, endpoint, "fleet-secret", body)
	if created.Code != http.StatusCreated {
		t.Fatalf("enroll: %d %s", created.Code, created.Body.String())
	}
	var result struct {
		NodeToken string `json:"node_token"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if len(result.NodeToken) != 64 {
		t.Fatal("missing cryptographically random node token")
	}
	if _, ok := srv.authenticateToken(result.NodeToken); !ok {
		t.Fatal("new token not accepted")
	}
	if repeated := request(t, srv.Handler(), http.MethodPost, endpoint, "fleet-secret", body); repeated.Code != http.StatusConflict {
		t.Fatalf("duplicate enrollment: %d", repeated.Code)
	}
	backing := srv.enrollments.(*store.MemoryStore)
	list := requestAdminEnrollment(t, srv.Handler(), http.MethodGet, "/admin/api/node-enrollments")
	if list.Code != http.StatusOK || !strings.Contains(list.Body.String(), "new-780m") || strings.Contains(list.Body.String(), result.NodeToken) || strings.Contains(list.Body.String(), "token_hash") {
		t.Fatalf("admin list exposed secret or failed: %d %s", list.Code, list.Body.String())
	}
	rewired := NewServer(srv.cfg, srv.log, backing, nil, nil)
	if _, ok := rewired.authenticateToken(result.NodeToken); !ok {
		t.Fatal("enrollment did not survive server restart")
	}
	revoked := requestAdminEnrollment(t, rewired.Handler(), http.MethodPost, "/admin/api/node-enrollments/new-780m/revoke")
	if revoked.Code != http.StatusOK {
		t.Fatalf("revoke: %d %s", revoked.Code, revoked.Body.String())
	}
	if _, ok := rewired.authenticateToken(result.NodeToken); ok {
		t.Fatal("revoked token still accepted")
	}
	if _, ok := srv.authenticateToken(result.NodeToken); ok {
		t.Fatal("revocation was not authoritative across servers")
	}
}

func requestAdminEnrollment(t *testing.T, handler http.Handler, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("Authorization", "Bearer admin-token")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	return response
}

func TestEnrollmentRejectsUnsafeAndExistingNodeIDs(t *testing.T) {
	srv, _, cancel := testServer(t)
	defer cancel()
	srv.cfg.Auth.Credentials = append(srv.cfg.Auth.Credentials, CredentialConfig{ID: "fleet", Token: "fleet-secret", OwnerID: "system", Plane: "enrollment", Scopes: []string{"node:enroll"}})
	srv.buildCredentials()
	for _, id := range []string{"../other", "x", "node-a"} {
		response := request(t, srv.Handler(), http.MethodPost, "/api/v1/nodes/enroll", "fleet-secret", map[string]string{"node_id": id, "node_name": "test"})
		if response.Code != http.StatusBadRequest && response.Code != http.StatusConflict {
			t.Fatalf("unsafe/existing ID %s accepted: %d", id, response.Code)
		}
	}
}
