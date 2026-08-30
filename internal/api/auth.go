package api

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"

	"vram-governor/internal/domain"
)

type Principal struct {
	ID                  string
	Plane               string
	OwnerID             string
	Scopes              map[string]struct{}
	Adapters            map[string]struct{}
	NodeID              string
	MaxPriority         int
	MaxIncidentSeverity string
	EgressPolicy        string
	ConcurrencyLimit    int
	BudgetCents         int64
	PreemptionBudget    int
}

type storedCredential struct {
	principal Principal
	hash      [sha256.Size]byte
}

type browserSession struct {
	Principal Principal
	Kind      string
	CSRFHash  string
	ExpiresAt time.Time
}

const (
	uiSessionCookie    = "vg_ui_session"
	adminSessionCookie = "vg_admin_session"
)

func bearerToken(r *http.Request) (string, bool) {
	authz := r.Header.Get("Authorization")
	if len(authz) < 8 || !strings.EqualFold(authz[:7], "Bearer ") {
		return "", false
	}
	token := strings.TrimSpace(authz[7:])
	return token, token != ""
}

func (s *Server) buildCredentials() {
	for _, configured := range s.cfg.Auth.Credentials {
		var hash [sha256.Size]byte
		if configured.TokenSHA256 != "" {
			decoded, err := hex.DecodeString(configured.TokenSHA256)
			if err != nil || len(decoded) != sha256.Size {
				s.log.Warn("ignoring credential with invalid token_sha256", "id", configured.ID)
				continue
			}
			copy(hash[:], decoded)
		} else if configured.Token != "" {
			hash = sha256.Sum256([]byte(configured.Token))
		} else {
			continue
		}
		egress := configured.EgressPolicy
		if egress == "" {
			egress = "local_only"
		}
		p := Principal{ID: configured.ID, Plane: configured.Plane, OwnerID: configured.OwnerID, NodeID: configured.NodeID, MaxPriority: configured.MaxPriority, MaxIncidentSeverity: configured.MaxIncidentSeverity, EgressPolicy: egress, ConcurrencyLimit: configured.ConcurrencyLimit, BudgetCents: configured.BudgetCents, PreemptionBudget: configured.PreemptionBudget, Scopes: map[string]struct{}{}, Adapters: map[string]struct{}{}}
		for _, scope := range configured.Scopes {
			p.Scopes[scope] = struct{}{}
		}
		for _, adapter := range configured.Adapters {
			p.Adapters[adapter] = struct{}{}
		}
		s.credentials = append(s.credentials, storedCredential{principal: p, hash: hash})
	}
}

func (s *Server) authenticate(r *http.Request) (Principal, bool) {
	token, ok := bearerToken(r)
	if ok {
		return s.authenticateToken(token)
	}
	if session, found := s.browserSessionForRequest(r); found {
		return session.Principal, true
	}
	return Principal{}, false
}

func sessionKindForPath(path string) string {
	if path == "/admin" || strings.HasPrefix(path, "/admin/") {
		return "admin"
	}
	return "ui"
}

func sessionCookieName(kind string) string {
	if kind == "admin" {
		return adminSessionCookie
	}
	return uiSessionCookie
}

func (s *Server) browserSessionForRequest(r *http.Request) (browserSession, bool) {
	kind := sessionKindForPath(r.URL.Path)
	cookie, err := r.Cookie(sessionCookieName(kind))
	if err != nil {
		return browserSession{}, false
	}
	stored, err := s.authSessions.GetBrowserSession(r.Context(), digestSecret(cookie.Value))
	if err != nil || stored.Kind != kind {
		return browserSession{}, false
	}
	if !stored.ExpiresAt.After(time.Now()) {
		_ = s.authSessions.DeleteBrowserSession(r.Context(), stored.IDHash)
		return browserSession{}, false
	}
	return browserSession{Principal: principalFromSession(stored), Kind: stored.Kind, CSRFHash: stored.CSRFHash, ExpiresAt: stored.ExpiresAt}, true
}

func digestSecret(secret string) string {
	hash := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(hash[:])
}

func mapKeys(values map[string]struct{}) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func storedBrowserSession(id, csrf, kind string, principal Principal, now, expiry time.Time) *domain.BrowserSession {
	return &domain.BrowserSession{
		IDHash: digestSecret(id), CSRFHash: digestSecret(csrf), Kind: kind,
		PrincipalID: principal.ID, Plane: principal.Plane, OwnerID: principal.OwnerID,
		Scopes: mapKeys(principal.Scopes), Adapters: mapKeys(principal.Adapters), NodeID: principal.NodeID,
		MaxPriority: principal.MaxPriority, MaxIncidentSeverity: principal.MaxIncidentSeverity,
		EgressPolicy: principal.EgressPolicy, ConcurrencyLimit: principal.ConcurrencyLimit,
		BudgetCents: principal.BudgetCents, PreemptionBudget: principal.PreemptionBudget,
		CreatedAt: now, ExpiresAt: expiry,
	}
}

func principalFromSession(session *domain.BrowserSession) Principal {
	principal := Principal{
		ID: session.PrincipalID, Plane: session.Plane, OwnerID: session.OwnerID, NodeID: session.NodeID,
		MaxPriority: session.MaxPriority, MaxIncidentSeverity: session.MaxIncidentSeverity,
		EgressPolicy: session.EgressPolicy, ConcurrencyLimit: session.ConcurrencyLimit,
		BudgetCents: session.BudgetCents, PreemptionBudget: session.PreemptionBudget,
		Scopes: map[string]struct{}{}, Adapters: map[string]struct{}{},
	}
	for _, scope := range session.Scopes {
		principal.Scopes[scope] = struct{}{}
	}
	for _, adapter := range session.Adapters {
		principal.Adapters[adapter] = struct{}{}
	}
	return principal
}

func (s *Server) authenticateToken(token string) (Principal, bool) {
	hash := sha256.Sum256([]byte(token))
	for _, credential := range s.credentials {
		if subtle.ConstantTimeCompare(hash[:], credential.hash[:]) == 1 {
			return credential.principal, true
		}
	}
	if s.cfg.Auth.SharedToken != "" && subtle.ConstantTimeCompare([]byte(token), []byte(s.cfg.Auth.SharedToken)) == 1 {
		return Principal{ID: "legacy", Plane: "legacy", OwnerID: "legacy", MaxPriority: 100, Scopes: map[string]struct{}{"*": {}}, Adapters: map[string]struct{}{"*": {}}}, true
	}
	return Principal{}, false
}

func randomSecret() string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("fallback-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}

func (s *Server) handleCreateSession(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Token string `json:"token"`
		Kind  string `json:"kind"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}
	p, ok := s.authenticateToken(body.Token)
	if !ok && body.Token == "" && s.cfg.Auth.DevelopmentBypass && !s.cfg.Production && s.adminRemoteAllowed(r) {
		p = Principal{
			ID:                  "local-development",
			Plane:               "admin",
			OwnerID:             "local-development",
			Scopes:              map[string]struct{}{"*": {}},
			Adapters:            map[string]struct{}{"*": {}},
			MaxPriority:         100,
			MaxIncidentSeverity: "S4",
			EgressPolicy:        "cloud_allowed",
			PreemptionBudget:    100,
		}
		ok = true
	}
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	if body.Kind == "" {
		body.Kind = "ui"
	}
	if body.Kind != "ui" && body.Kind != "admin" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid session kind"})
		return
	}
	if body.Kind == "admin" && p.Plane != "admin" {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "admin credential required"})
		return
	}
	id, csrf := randomSecret(), randomSecret()
	now := time.Now().UTC()
	expiry := now.Add(12 * time.Hour)
	if err := s.authSessions.CreateBrowserSession(r.Context(), storedBrowserSession(id, csrf, body.Kind, p, now, expiry)); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "session persistence failed"})
		return
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookieName(body.Kind), Value: id, Path: "/", HttpOnly: true, Secure: s.cfg.Production, SameSite: http.SameSiteStrictMode, Expires: expiry})
	writeJSON(w, http.StatusOK, map[string]any{"principal": map[string]any{"id": p.ID, "owner_id": p.OwnerID, "plane": p.Plane}, "csrf_token": csrf})
}

func (s *Server) handleDeleteSession(w http.ResponseWriter, r *http.Request) {
	kind := r.URL.Query().Get("kind")
	if kind != "admin" {
		kind = "ui"
	}
	cookieName := sessionCookieName(kind)
	if cookie, err := r.Cookie(cookieName); err == nil {
		_ = s.authSessions.DeleteBrowserSession(r.Context(), digestSecret(cookie.Value))
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Path: "/", MaxAge: -1, HttpOnly: true, Secure: s.cfg.Production, SameSite: http.SameSiteStrictMode})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) securityMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.Production && r.TLS == nil {
			writeJSON(w, http.StatusUpgradeRequired, map[string]string{"error": "https_required"})
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions && r.URL.Path != "/auth/session" {
			if session, found := s.browserSessionForRequest(r); found && subtle.ConstantTimeCompare([]byte(digestSecret(r.Header.Get("X-CSRF-Token"))), []byte(session.CSRFHash)) != 1 {
				writeJSON(w, http.StatusForbidden, map[string]string{"error": "csrf_validation_failed"})
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func hasScope(p Principal, scope string) bool {
	_, all := p.Scopes["*"]
	_, exact := p.Scopes[scope]
	return all || exact
}

func planeAllowsScope(p Principal, scope string) bool {
	switch p.Plane {
	case "admin", "legacy":
		return true
	case "node":
		return strings.HasPrefix(scope, "node:")
	case "agent":
		return strings.HasPrefix(scope, "agent:") || strings.HasPrefix(scope, "incidents:") || scope == "workloads:read" || scope == "artifacts:read" || scope == "events:read"
	case "ui", "api", "mcp", "workflow":
		return scope != "admin" && !strings.HasPrefix(scope, "node:") && !strings.HasPrefix(scope, "agent:") && !strings.HasPrefix(scope, "incidents:")
	default:
		return false
	}
}
func allowsAdapter(p Principal, adapter string) bool {
	_, all := p.Adapters["*"]
	_, exact := p.Adapters[adapter]
	return all || exact
}

func (s *Server) requirePrincipal(w http.ResponseWriter, r *http.Request, scope string) (Principal, bool) {
	p, ok := s.authenticate(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return Principal{}, false
	}
	if !hasScope(p, scope) || !planeAllowsScope(p, scope) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "insufficient_scope", "required_scope": scope})
		return Principal{}, false
	}
	return p, true
}

func (s *Server) requireNodeReporter(w http.ResponseWriter, r *http.Request, nodeID string) (Principal, bool) {
	principal, ok := s.requirePrincipal(w, r, "node:report")
	if !ok {
		return Principal{}, false
	}
	if principal.Plane != "node" || principal.NodeID == "" || principal.NodeID != nodeID {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "credential is not authorized for this node"})
		return Principal{}, false
	}
	return principal, true
}

func (s *Server) adminRemoteAllowed(r *http.Request) bool {
	if len(s.adminNets) == 0 {
		return false
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, block := range s.adminNets {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}
