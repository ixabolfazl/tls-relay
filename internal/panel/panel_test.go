package panel_test

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ixabolfazl/tls-relay/internal/access"
	"github.com/ixabolfazl/tls-relay/internal/panel"
	"github.com/ixabolfazl/tls-relay/internal/rules"
	"github.com/ixabolfazl/tls-relay/internal/sqlitestore"
)

func TestApplyPathPrefix_RouteSwapping(t *testing.T) {
	ruleStore := rules.NewRuleStore([]int{443}, "allow_default_port")
	accessStore := access.NewAccessStore(access.ModeUser)

	srv, err := panel.New("127.0.0.1:0", "/", ruleStore, accessStore, nil, nil)
	if err != nil {
		t.Fatalf("failed to create panel server: %v", err)
	}

	// 1. Initially at root ("/") -> POST /api/login should match handler (returns 400 bad request due to empty body)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/login", nil)
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 Bad Request at root /api/login, got %d", rec.Code)
	}

	// 2. Switch prefix to "/secret-admin"
	if err := srv.ApplyPathPrefix("/secret-admin"); err != nil {
		t.Fatalf("ApplyPathPrefix failed: %v", err)
	}

	if srv.PathPrefix() != "/secret-admin" {
		t.Errorf("expected PathPrefix to be '/secret-admin', got %q", srv.PathPrefix())
	}
	if srv.DisplayPath() != "/secret-admin" {
		t.Errorf("expected DisplayPath to be '/secret-admin', got %q", srv.DisplayPath())
	}

	// Old path should now 404
	recOld := httptest.NewRecorder()
	reqOld := httptest.NewRequest("POST", "/api/login", nil)
	srv.ServeHTTP(recOld, reqOld)
	if recOld.Code != http.StatusNotFound {
		t.Errorf("expected 404 for old path /api/login, got %d", recOld.Code)
	}

	// New path /secret-admin/api/login should work (return 400 Bad Request for empty body)
	recNew := httptest.NewRecorder()
	reqNew := httptest.NewRequest("POST", "/secret-admin/api/login", nil)
	srv.ServeHTTP(recNew, reqNew)
	if recNew.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for new path /secret-admin/api/login, got %d", recNew.Code)
	}

	// New path redirect test: GET /secret-admin -> 302 redirect to /secret-admin/
	recRedir := httptest.NewRecorder()
	reqRedir := httptest.NewRequest("GET", "/secret-admin", nil)
	srv.ServeHTTP(recRedir, reqRedir)
	if recRedir.Code != http.StatusFound {
		t.Errorf("expected 302 redirect for GET /secret-admin, got %d", recRedir.Code)
	}

	// 3. Switch back to root ("/")
	if err := srv.ApplyPathPrefix("/"); err != nil {
		t.Fatalf("ApplyPathPrefix('/') failed: %v", err)
	}
	if srv.DisplayPath() != "/" {
		t.Errorf("expected DisplayPath to be '/', got %q", srv.DisplayPath())
	}

	recRoot := httptest.NewRecorder()
	reqRoot := httptest.NewRequest("POST", "/api/login", nil)
	srv.ServeHTTP(recRoot, reqRoot)
	if recRoot.Code != http.StatusBadRequest {
		t.Errorf("expected 400 at /api/login after switching back, got %d", recRoot.Code)
	}
}

func TestTimezoneValidation(t *testing.T) {
	ruleStore := rules.NewRuleStore([]int{443}, "allow_default_port")
	accessStore := access.NewAccessStore(access.ModeUser)

	srv, err := panel.New("127.0.0.1:8080", "/", ruleStore, accessStore, nil, nil)
	if err != nil {
		t.Fatalf("failed to create panel server: %v", err)
	}

	// Valid timezones
	validZones := []string{"UTC", "Asia/Tehran", "America/New_York", "Europe/London"}
	for _, tz := range validZones {
		if err := srv.SetTimezone(tz); err != nil {
			t.Errorf("expected valid timezone %q to succeed, got %v", tz, err)
		}
		if srv.Timezone() != tz {
			t.Errorf("expected Timezone() = %q, got %q", tz, srv.Timezone())
		}
	}

	// Invalid timezones
	invalidZones := []string{"Invalid/Zone_Name", "Not/A_Timezone", "Mars/City"}
	for _, tz := range invalidZones {
		if err := srv.SetTimezone(tz); err == nil {
			t.Errorf("expected invalid timezone %q to be rejected, but it succeeded", tz)
		}
	}
}

func TestFormatISO8601(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"2026-08-05 10:23:45", "2026-08-05T10:23:45Z"},
		{"2026-08-05T10:23:45Z", "2026-08-05T10:23:45Z"},
		{"", ""},
		{"   ", ""},
	}

	for _, tt := range tests {
		got := panel.FormatISO8601(tt.input)
		if got != tt.expected {
			t.Errorf("FormatISO8601(%q) = %q; want %q", tt.input, got, tt.expected)
		}
	}
}

func TestPresenceEndpoint_Unauthorized(t *testing.T) {
	ruleStore := rules.NewRuleStore([]int{443}, "allow_default_port")
	accessStore := access.NewAccessStore(access.ModeUser)

	srv, err := panel.New("127.0.0.1:0", "/", ruleStore, accessStore, nil, nil)
	if err != nil {
		t.Fatalf("failed to create panel server: %v", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/presence", nil)
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 Unauthorized for /api/presence without session cookie, got %d", rec.Code)
	}
}

func TestAdminLogin_BruteForceProtection(t *testing.T) {
	t.Setenv("PANEL_ADMIN_USER", "admin")
	t.Setenv("PANEL_ADMIN_PASSWORD", "secret123")

	ruleStore := rules.NewRuleStore([]int{443}, "allow_default_port")
	accessStore := access.NewAccessStore(access.ModeUser)

	srv, err := panel.New("127.0.0.1:0", "/", ruleStore, accessStore, nil, nil)
	if err != nil {
		t.Fatalf("failed to create panel server: %v", err)
	}

	clientIP := "198.51.100.5"

	// 5 failed login attempts
	for i := 1; i <= 5; i++ {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/api/login", strings.NewReader(`{"username":"admin","password":"wrongpassword"}`))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = clientIP + ":12345"
		srv.ServeHTTP(rec, req)

		if i < 5 {
			if rec.Code != http.StatusUnauthorized {
				t.Errorf("attempt %d: expected status 401, got %d", i, rec.Code)
			}
		} else {
			if rec.Code != http.StatusTooManyRequests {
				t.Errorf("attempt %d (lockout trigger): expected status 429, got %d", i, rec.Code)
			}
		}
	}

	// 6th attempt from locked-out IP (even with correct password)
	rec6 := httptest.NewRecorder()
	req6 := httptest.NewRequest("POST", "/api/login", strings.NewReader(`{"username":"admin","password":"secret123"}`))
	req6.Header.Set("Content-Type", "application/json")
	req6.RemoteAddr = clientIP + ":12345"
	srv.ServeHTTP(rec6, req6)
	if rec6.Code != http.StatusTooManyRequests {
		t.Errorf("expected status 429 for locked-out IP, got %d", rec6.Code)
	}

	// Different IP should still be able to log in successfully
	otherIP := "198.51.100.6"
	recOther := httptest.NewRecorder()
	reqOther := httptest.NewRequest("POST", "/api/login", strings.NewReader(`{"username":"admin","password":"secret123"}`))
	reqOther.Header.Set("Content-Type", "application/json")
	reqOther.RemoteAddr = otherIP + ":12345"
	srv.ServeHTTP(recOther, reqOther)
	if recOther.Code != http.StatusOK {
		t.Errorf("expected status 200 for clean IP, got %d", recOther.Code)
	}
}

func TestCSRFProtection(t *testing.T) {
	t.Setenv("PANEL_ADMIN_USER", "admin")
	t.Setenv("PANEL_ADMIN_PASSWORD", "secret123")

	dbPath := filepath.Join(t.TempDir(), "test.db")
	sqStore, err := sqlitestore.New(dbPath)
	if err != nil {
		t.Fatalf("failed to create sqlite store: %v", err)
	}
	defer sqStore.Close()

	ruleStore := rules.NewRuleStore([]int{443}, "allow_default_port")
	accessStore := access.NewAccessStore(access.ModeUser)

	srv, err := panel.New("127.0.0.1:0", "/", ruleStore, accessStore, sqStore, nil)
	if err != nil {
		t.Fatalf("failed to create panel server: %v", err)
	}

	// 1. Perform login to get session & CSRF cookies
	loginRec := httptest.NewRecorder()
	loginReq := httptest.NewRequest("POST", "/api/login", strings.NewReader(`{"username":"admin","password":"secret123"}`))
	loginReq.Header.Set("Content-Type", "application/json")
	loginReq.RemoteAddr = "127.0.0.1:12345"
	srv.ServeHTTP(loginRec, loginReq)

	if loginRec.Code != http.StatusOK {
		t.Fatalf("login failed: status %d", loginRec.Code)
	}

	var sessionCookie, csrfCookie *http.Cookie
	for _, c := range loginRec.Result().Cookies() {
		if c.Name == "relay_session" {
			sessionCookie = c
		}
		if c.Name == "relay_csrf" {
			csrfCookie = c
		}
	}
	if sessionCookie == nil || csrfCookie == nil {
		t.Fatalf("missing session or csrf cookie after login")
	}

	// 2. Post request without CSRF header -> should be rejected with 403
	noCSRFRec := httptest.NewRecorder()
	noCSRFReq := httptest.NewRequest("POST", "/api/blacklist", strings.NewReader(`{"entry":"1.2.3.4"}`))
	noCSRFReq.Header.Set("Content-Type", "application/json")
	noCSRFReq.AddCookie(sessionCookie)
	srv.ServeHTTP(noCSRFRec, noCSRFReq)

	if noCSRFRec.Code != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden for POST missing X-CSRF-Token, got %d", noCSRFRec.Code)
	}

	// 3. Post request with correct X-CSRF-Token header -> should pass CSRF check
	validCSRFRec := httptest.NewRecorder()
	validCSRFReq := httptest.NewRequest("POST", "/api/blacklist", strings.NewReader(`{"entry":"1.2.3.4"}`))
	validCSRFReq.Header.Set("Content-Type", "application/json")
	validCSRFReq.Header.Set("X-CSRF-Token", csrfCookie.Value)
	validCSRFReq.AddCookie(sessionCookie)
	srv.ServeHTTP(validCSRFRec, validCSRFReq)

	if validCSRFRec.Code == http.StatusForbidden {
		t.Errorf("expected non-403 status for valid CSRF token, got %d", validCSRFRec.Code)
	}
}

func TestLiveStatsEndpoint(t *testing.T) {
	t.Setenv("PANEL_ADMIN_USER", "admin")
	t.Setenv("PANEL_ADMIN_PASSWORD", "secret123")

	ruleStore := rules.NewRuleStore([]int{443}, "allow_default_port")
	accessStore := access.NewAccessStore(access.ModeUser)

	srv, err := panel.New("127.0.0.1:0", "/", ruleStore, accessStore, nil, nil)
	if err != nil {
		t.Fatalf("failed to create panel server: %v", err)
	}

	loginRec := httptest.NewRecorder()
	loginReq := httptest.NewRequest("POST", "/api/login", strings.NewReader(`{"username":"admin","password":"secret123"}`))
	loginReq.Header.Set("Content-Type", "application/json")
	srv.ServeHTTP(loginRec, loginReq)

	var sessionCookie *http.Cookie
	for _, c := range loginRec.Result().Cookies() {
		if c.Name == "relay_session" {
			sessionCookie = c
		}
	}

	statsRec := httptest.NewRecorder()
	statsReq := httptest.NewRequest("GET", "/api/stats", nil)
	statsReq.AddCookie(sessionCookie)
	srv.ServeHTTP(statsRec, statsReq)

	if statsRec.Code != http.StatusOK {
		t.Errorf("expected 200 OK for /api/stats, got %d", statsRec.Code)
	}
}

func TestBackupEndpoint(t *testing.T) {
	t.Setenv("PANEL_ADMIN_USER", "admin")
	t.Setenv("PANEL_ADMIN_PASSWORD", "secret123")

	dbPath := filepath.Join(t.TempDir(), "test.db")
	sqStore, err := sqlitestore.New(dbPath)
	if err != nil {
		t.Fatalf("failed to create sqlite store: %v", err)
	}
	defer sqStore.Close()

	ruleStore := rules.NewRuleStore([]int{443}, "allow_default_port")
	accessStore := access.NewAccessStore(access.ModeUser)

	srv, err := panel.New("127.0.0.1:0", "/", ruleStore, accessStore, sqStore, nil)
	if err != nil {
		t.Fatalf("failed to create panel server: %v", err)
	}

	loginRec := httptest.NewRecorder()
	loginReq := httptest.NewRequest("POST", "/api/login", strings.NewReader(`{"username":"admin","password":"secret123"}`))
	loginReq.Header.Set("Content-Type", "application/json")
	srv.ServeHTTP(loginRec, loginReq)

	var sessionCookie *http.Cookie
	for _, c := range loginRec.Result().Cookies() {
		if c.Name == "relay_session" {
			sessionCookie = c
		}
	}

	backupRec := httptest.NewRecorder()
	backupReq := httptest.NewRequest("GET", "/api/backup", nil)
	backupReq.AddCookie(sessionCookie)
	srv.ServeHTTP(backupRec, backupReq)

	if backupRec.Code != http.StatusOK {
		t.Errorf("expected 200 OK for /api/backup, got %d", backupRec.Code)
	}
	if ct := backupRec.Header().Get("Content-Type"); ct != "application/x-sqlite3" {
		t.Errorf("expected Content-Type application/x-sqlite3, got %q", ct)
	}
	if backupRec.Body.Len() == 0 {
		t.Errorf("expected non-empty backup database body")
	}
}
