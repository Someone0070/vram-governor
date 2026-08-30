package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	"vram-governor/internal/store"
)

func TestAdminBrowserSessionIsIndependentFromUISession(t *testing.T) {
	srv, _, cancel := testServer(t)
	defer cancel()
	handler := srv.Handler()

	uiLogin := request(t, handler, http.MethodPost, "/auth/session", "", map[string]string{"token": "admin-token"})
	if uiLogin.Code != http.StatusOK {
		t.Fatalf("UI login failed: %d %s", uiLogin.Code, uiLogin.Body.String())
	}
	uiCookies := uiLogin.Result().Cookies()
	if len(uiCookies) != 1 || uiCookies[0].Name != uiSessionCookie {
		t.Fatalf("unexpected UI cookie: %+v", uiCookies)
	}
	adminWithUI := httptest.NewRequest(http.MethodGet, "/admin/api/overview", nil)
	adminWithUI.RemoteAddr = "127.0.0.1:1234"
	adminWithUI.AddCookie(uiCookies[0])
	denied := httptest.NewRecorder()
	handler.ServeHTTP(denied, adminWithUI)
	if denied.Code != http.StatusUnauthorized {
		t.Fatalf("admin API accepted UI cookie: %d %s", denied.Code, denied.Body.String())
	}

	nonAdminLogin := request(t, handler, http.MethodPost, "/auth/session", "", map[string]string{"token": "alice-token", "kind": "admin"})
	if nonAdminLogin.Code != http.StatusForbidden {
		t.Fatalf("non-admin obtained admin session: %d %s", nonAdminLogin.Code, nonAdminLogin.Body.String())
	}

	adminLogin := request(t, handler, http.MethodPost, "/auth/session", "", map[string]string{"token": "admin-token", "kind": "admin"})
	if adminLogin.Code != http.StatusOK {
		t.Fatalf("admin login failed: %d %s", adminLogin.Code, adminLogin.Body.String())
	}
	adminCookies := adminLogin.Result().Cookies()
	if len(adminCookies) != 1 || adminCookies[0].Name != adminSessionCookie {
		t.Fatalf("unexpected admin cookie: %+v", adminCookies)
	}
	adminRequest := httptest.NewRequest(http.MethodGet, "/admin/api/overview", nil)
	adminRequest.RemoteAddr = "127.0.0.1:1234"
	adminRequest.AddCookie(adminCookies[0])
	allowed := httptest.NewRecorder()
	handler.ServeHTTP(allowed, adminRequest)
	if allowed.Code != http.StatusOK {
		t.Fatalf("admin cookie rejected: %d %s", allowed.Code, allowed.Body.String())
	}
}

func TestDevelopmentBypassCreatesProtectedSessionsOnlyOnAdmittedNetworks(t *testing.T) {
	srv, _, cancel := testServer(t)
	defer cancel()
	srv.cfg.Auth.DevelopmentBypass = true
	handler := srv.Handler()

	loginRequest := httptest.NewRequest(http.MethodPost, "/auth/session", strings.NewReader(`{"kind":"admin"}`))
	loginRequest.Header.Set("Content-Type", "application/json")
	loginRequest.RemoteAddr = "127.0.0.1:1234"
	login := httptest.NewRecorder()
	handler.ServeHTTP(login, loginRequest)
	if login.Code != http.StatusOK {
		t.Fatalf("development bypass login failed: %d %s", login.Code, login.Body.String())
	}
	var session struct {
		CSRFToken string `json:"csrf_token"`
	}
	if err := json.Unmarshal(login.Body.Bytes(), &session); err != nil {
		t.Fatal(err)
	}
	if session.CSRFToken == "" || len(login.Result().Cookies()) != 1 || login.Result().Cookies()[0].Name != adminSessionCookie {
		t.Fatalf("bypass did not create a normal protected admin session: %s", login.Body.String())
	}

	adminRequest := httptest.NewRequest(http.MethodGet, "/admin/api/overview", nil)
	adminRequest.RemoteAddr = "127.0.0.1:1234"
	adminRequest.AddCookie(login.Result().Cookies()[0])
	admin := httptest.NewRecorder()
	handler.ServeHTTP(admin, adminRequest)
	if admin.Code != http.StatusOK {
		t.Fatalf("bypass session rejected by admin API: %d %s", admin.Code, admin.Body.String())
	}

	publicRequest := httptest.NewRequest(http.MethodPost, "/auth/session", strings.NewReader(`{"kind":"admin"}`))
	publicRequest.Header.Set("Content-Type", "application/json")
	publicRequest.RemoteAddr = "203.0.113.8:1234"
	public := httptest.NewRecorder()
	handler.ServeHTTP(public, publicRequest)
	if public.Code != http.StatusUnauthorized {
		t.Fatalf("public client received bypass session: %d %s", public.Code, public.Body.String())
	}
}

func TestBrowserSessionUsesAuthoritativeStoreAndPersistsAcrossServerRewire(t *testing.T) {
	srv, _, cancel := testServer(t)
	defer cancel()
	login := request(t, srv.Handler(), http.MethodPost, "/auth/session", "", map[string]string{"token": "admin-token"})
	if login.Code != http.StatusOK {
		t.Fatalf("login failed: %d %s", login.Code, login.Body.String())
	}
	cookie := login.Result().Cookies()[0]
	var response struct {
		CSRF string `json:"csrf_token"`
	}
	if err := json.Unmarshal(login.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	backing, ok := srv.authSessions.(*store.MemoryStore)
	if !ok {
		t.Fatalf("unexpected session store %T", srv.authSessions)
	}
	if _, err := backing.GetBrowserSession(context.Background(), cookie.Value); err != store.ErrNotFound {
		t.Fatal("raw session cookie was used as the store key")
	}
	stored, err := backing.GetBrowserSession(context.Background(), digestSecret(cookie.Value))
	if err != nil {
		t.Fatal(err)
	}
	if stored.CSRFHash == response.CSRF || stored.CSRFHash != digestSecret(response.CSRF) {
		t.Fatal("CSRF secret was not stored exclusively as a digest")
	}

	rewired := NewServer(srv.cfg, srv.log, backing, nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/nodes", nil)
	req.AddCookie(cookie)
	recorder := httptest.NewRecorder()
	rewired.Handler().ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("stored session did not survive server rewire: %d %s", recorder.Code, recorder.Body.String())
	}
}

func TestAdminShellLoadsBeforeAuthenticationOnPrivateNetwork(t *testing.T) {
	srv, _, cancel := testServer(t)
	defer cancel()
	srv.SetAppFS(fstest.MapFS{"admin.html": &fstest.MapFile{Data: []byte("<html>admin login</html>")}})

	local := httptest.NewRequest(http.MethodGet, "/admin/", nil)
	local.RemoteAddr = "127.0.0.1:1234"
	localResponse := httptest.NewRecorder()
	srv.Handler().ServeHTTP(localResponse, local)
	if localResponse.Code != http.StatusOK || localResponse.Body.String() != "<html>admin login</html>" {
		t.Fatalf("private unauthenticated admin shell: %d %s", localResponse.Code, localResponse.Body.String())
	}

	public := httptest.NewRequest(http.MethodGet, "/admin/", nil)
	public.RemoteAddr = "203.0.113.8:1234"
	publicResponse := httptest.NewRecorder()
	srv.Handler().ServeHTTP(publicResponse, public)
	if publicResponse.Code != http.StatusForbidden {
		t.Fatalf("public admin shell status=%d body=%s", publicResponse.Code, publicResponse.Body.String())
	}
}
