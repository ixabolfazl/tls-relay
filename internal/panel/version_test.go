package panel_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ixabolfazl/tls-relay/internal/access"
	"github.com/ixabolfazl/tls-relay/internal/panel"
	"github.com/ixabolfazl/tls-relay/internal/rules"
	"github.com/ixabolfazl/tls-relay/internal/sqlitestore"
	"github.com/ixabolfazl/tls-relay/internal/updatecheck"
)

func newTestPanelServerWithVersion(t *testing.T, ver string, checker *updatecheck.Checker) (*panel.Server, *sqlitestore.Store, *http.Cookie) {
	t.Helper()
	t.Setenv("PANEL_ADMIN_USER", "admin")
	t.Setenv("PANEL_ADMIN_PASSWORD", "secret123")

	dbPath := filepath.Join(t.TempDir(), "panel_version_test.db")
	sqStore, err := sqlitestore.New(dbPath)
	if err != nil {
		t.Fatalf("sqlitestore.New: %v", err)
	}
	t.Cleanup(func() { _ = sqStore.Close() })

	ruleStore := rules.NewRuleStore([]int{443}, "allow_default_port")
	accessStore := access.NewAccessStore(access.ModeUser)

	srv, err := panel.New("127.0.0.1:0", "/", ruleStore, accessStore, sqStore, nil)
	if err != nil {
		t.Fatalf("panel.New: %v", err)
	}
	srv.SetVersion(ver)
	if checker != nil {
		srv.SetUpdateChecker(checker)
	}

	// Login
	loginRec := httptest.NewRecorder()
	loginReq := httptest.NewRequest("POST", "/api/login",
		strings.NewReader(`{"username":"admin","password":"secret123"}`))
	loginReq.Header.Set("Content-Type", "application/json")
	srv.ServeHTTP(loginRec, loginReq)
	if loginRec.Code != http.StatusOK {
		t.Fatalf("login failed: %d", loginRec.Code)
	}

	var sessionCookie *http.Cookie
	for _, c := range loginRec.Result().Cookies() {
		if c.Name == "relay_session" {
			sessionCookie = c
			break
		}
	}
	if sessionCookie == nil {
		t.Fatal("missing session cookie")
	}

	return srv, sqStore, sessionCookie
}

func TestVersionEndpoint_UnauthorizedWithoutSession(t *testing.T) {
	srv, _, _ := newTestPanelServerWithVersion(t, "v1.3.0", nil)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/version", nil)
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 Unauthorized, got %d", rec.Code)
	}
}

func TestVersionEndpoint_ReturnsUpdateWhenAvailable(t *testing.T) {
	ghServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"tag_name": "v1.4.0",
			"html_url": "https://github.com/ixabolfazl/tls-relay/releases/tag/v1.4.0",
		})
	}))
	defer ghServer.Close()

	checker := updatecheck.NewChecker("v1.3.0",
		updatecheck.WithBaseURL(ghServer.URL),
		updatecheck.WithHTTPClient(ghServer.Client()),
	)

	srv, _, session := newTestPanelServerWithVersion(t, "v1.3.0", checker)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/version", nil)
	req.AddCookie(session)
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rec.Code, rec.Body.String())
	}

	var res struct {
		Enabled         bool   `json:"enabled"`
		CurrentVersion  string `json:"current_version"`
		LatestVersion   string `json:"latest_version"`
		UpdateAvailable bool   `json:"update_available"`
		ReleaseURL      string `json:"release_url"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if !res.Enabled {
		t.Errorf("expected enabled=true, got false")
	}
	if !res.UpdateAvailable {
		t.Errorf("expected update_available=true, got false")
	}
	if res.LatestVersion != "v1.4.0" {
		t.Errorf("expected latest_version=v1.4.0, got %q", res.LatestVersion)
	}
	if res.ReleaseURL != "https://github.com/ixabolfazl/tls-relay/releases/tag/v1.4.0" {
		t.Errorf("expected release_url, got %q", res.ReleaseURL)
	}
}

func TestVersionEndpoint_DisabledMakesNoOutboundRequest(t *testing.T) {
	var requestCount atomic.Int32
	ghServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"tag_name": "v1.4.0",
			"html_url": "https://github.com/ixabolfazl/tls-relay/releases/tag/v1.4.0",
		})
	}))
	defer ghServer.Close()

	checker := updatecheck.NewChecker("v1.3.0",
		updatecheck.WithBaseURL(ghServer.URL),
		updatecheck.WithHTTPClient(ghServer.Client()),
	)

	srv, sqStore, session := newTestPanelServerWithVersion(t, "v1.3.0", checker)

	// Disable update check in SQLite settings
	if err := sqStore.SetSetting(context.Background(), "update_check_enabled", "false"); err != nil {
		t.Fatalf("SetSetting: %v", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/version", nil)
	req.AddCookie(session)
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rec.Code, rec.Body.String())
	}

	var res struct {
		Enabled        bool   `json:"enabled"`
		CurrentVersion string `json:"current_version"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if res.Enabled {
		t.Errorf("expected enabled=false, got true")
	}
	if res.CurrentVersion != "v1.3.0" {
		t.Errorf("expected current_version=v1.3.0, got %q", res.CurrentVersion)
	}

	if count := requestCount.Load(); count != 0 {
		t.Errorf("expected 0 outbound requests when disabled, got %d", count)
	}
}
