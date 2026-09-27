package panel

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ixabolfazl/tls-relay/internal/access"
	"github.com/ixabolfazl/tls-relay/internal/rules"
)

func TestAdminLogin_BruteForceLockoutExpiry(t *testing.T) {
	t.Setenv("PANEL_ADMIN_USER", "admin")
	t.Setenv("PANEL_ADMIN_PASSWORD", "secret123")

	ruleStore := rules.NewRuleStore([]int{443}, "allow_default_port")
	accessStore := access.NewAccessStore(access.ModeUser)

	srv, err := New("127.0.0.1:0", "/", ruleStore, accessStore, nil, nil)
	if err != nil {
		t.Fatalf("failed to create panel server: %v", err)
	}

	// White-box override for tests to use short lockout window
	srv.loginLimiter.maxAttempts = 2
	srv.loginLimiter.lockoutDuration = 50 * time.Millisecond

	clientIP := "192.0.2.20"

	// 1st failed attempt
	rec1 := httptest.NewRecorder()
	req1 := httptest.NewRequest("POST", "/api/login", strings.NewReader(`{"username":"admin","password":"wrongpassword"}`))
	req1.Header.Set("Content-Type", "application/json")
	req1.RemoteAddr = clientIP + ":12345"
	srv.ServeHTTP(rec1, req1)
	if rec1.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec1.Code)
	}

	// 2nd failed attempt (lockout trigger)
	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest("POST", "/api/login", strings.NewReader(`{"username":"admin","password":"wrongpassword"}`))
	req2.Header.Set("Content-Type", "application/json")
	req2.RemoteAddr = clientIP + ":12345"
	srv.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429, got %d", rec2.Code)
	}

	// Sleep past the lockout window (50ms)
	time.Sleep(70 * time.Millisecond)

	// Attempt with correct credentials should now succeed
	rec3 := httptest.NewRecorder()
	req3 := httptest.NewRequest("POST", "/api/login", strings.NewReader(`{"username":"admin","password":"secret123"}`))
	req3.Header.Set("Content-Type", "application/json")
	req3.RemoteAddr = clientIP + ":12345"
	srv.ServeHTTP(rec3, req3)
	if rec3.Code != http.StatusOK {
		t.Errorf("expected success 200 after lockout expired, got %d", rec3.Code)
	}
}

func TestCSRFProtection_PUT_DELETE(t *testing.T) {
	t.Setenv("PANEL_ADMIN_USER", "admin")
	t.Setenv("PANEL_ADMIN_PASSWORD", "secret123")

	ruleStore := rules.NewRuleStore([]int{443}, "allow_default_port")
	accessStore := access.NewAccessStore(access.ModeUser)

	srv, err := New("127.0.0.1:0", "/", ruleStore, accessStore, nil, nil)
	if err != nil {
		t.Fatalf("failed to create panel server: %v", err)
	}

	// Create session cookies
	loginRec := httptest.NewRecorder()
	loginReq := httptest.NewRequest("POST", "/api/login", strings.NewReader(`{"username":"admin","password":"secret123"}`))
	loginReq.Header.Set("Content-Type", "application/json")
	srv.ServeHTTP(loginRec, loginReq)

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
		t.Fatalf("failed to retrieve login session/csrf cookies")
	}

	// 1. PUT request without CSRF header -> 403 Forbidden
	putRec := httptest.NewRecorder()
	putReq := httptest.NewRequest("PUT", "/api/settings", strings.NewReader(`{}`))
	putReq.Header.Set("Content-Type", "application/json")
	putReq.AddCookie(sessionCookie)
	srv.ServeHTTP(putRec, putReq)
	if putRec.Code != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden on PUT without CSRF, got %d", putRec.Code)
	}

	// 2. DELETE request without CSRF header -> 403 Forbidden
	delRec := httptest.NewRecorder()
	delReq := httptest.NewRequest("DELETE", "/api/domains/test.com", nil)
	delReq.AddCookie(sessionCookie)
	srv.ServeHTTP(delRec, delReq)
	if delRec.Code != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden on DELETE without CSRF, got %d", delRec.Code)
	}

	// 3. Expired session with valid CSRF token format -> 401 Unauthorized
	// We manually expire the session in the store
	srv.sessions.mu.Lock()
	if info, ok := srv.sessions.sessions[sessionCookie.Value]; ok {
		info.expiry = time.Now().Add(-1 * time.Hour) // expired
	}
	srv.sessions.mu.Unlock()

	expRec := httptest.NewRecorder()
	expReq := httptest.NewRequest("PUT", "/api/settings", strings.NewReader(`{}`))
	expReq.Header.Set("Content-Type", "application/json")
	expReq.Header.Set("X-CSRF-Token", csrfCookie.Value)
	expReq.AddCookie(sessionCookie)
	srv.ServeHTTP(expRec, expReq)
	if expRec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 Unauthorized for expired session + valid CSRF, got %d", expRec.Code)
	}
}

func TestCSRFProtection_JSONResponseCheck(t *testing.T) {
	ruleStore := rules.NewRuleStore([]int{443}, "allow_default_port")
	accessStore := access.NewAccessStore(access.ModeUser)

	srv, err := New("127.0.0.1:0", "/", ruleStore, accessStore, nil, nil)
	if err != nil {
		t.Fatalf("failed to create panel server: %v", err)
	}

	// Fake session token that exists in store
	sessionToken := "fakesessiontoken123"
	srv.sessions.mu.Lock()
	srv.sessions.sessions[sessionToken] = &sessionInfo{
		expiry:    time.Now().Add(1 * time.Hour),
		csrfToken: "correctcsrftoken",
	}
	srv.sessions.mu.Unlock()

	// Send POST with wrong CSRF
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/domains", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", "wrongcsrftoken")
	req.AddCookie(&http.Cookie{Name: "relay_session", Value: sessionToken})
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}

	var resp struct {
		Error string `json:"error"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode JSON response: %v", err)
	}
	if !strings.Contains(resp.Error, "CSRF") {
		t.Errorf("expected CSRF error message, got %q", resp.Error)
	}
}
