package panel_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ixabolfazl/tls-relay/internal/access"
	"github.com/ixabolfazl/tls-relay/internal/config"
	"github.com/ixabolfazl/tls-relay/internal/panel"
	"github.com/ixabolfazl/tls-relay/internal/relay"
	"github.com/ixabolfazl/tls-relay/internal/rules"
	"github.com/ixabolfazl/tls-relay/internal/sqlitestore"
)

func TestExtendedSettingsManagement(t *testing.T) {
	t.Setenv("PANEL_ADMIN_USER", "admin")
	t.Setenv("PANEL_ADMIN_PASSWORD", "secret123")

	dbPath := filepath.Join(t.TempDir(), "test_ext_settings.db")
	store, err := sqlitestore.New(dbPath)
	if err != nil {
		t.Fatalf("failed to open sqlite store: %v", err)
	}

	rs := rules.NewRuleStore([]int{443, 8443}, "allow_default_port")
	as := access.NewAccessStore(access.ModeUser)
	refresher := &dummyRefresher{}

	panelSrv, err := panel.New("127.0.0.1:8080", "/", rs, as, store, refresher)
	if err != nil {
		t.Fatalf("failed to create panel: %v", err)
	}

	pal := relay.NewPortAllowList([]int{443, 8443})
	panelSrv.SetPortAllowList(pal)

	ed, err := relay.NewEgressDialer(config.EgressProxyConfig{
		Enabled: false,
		Addr:    "127.0.0.1:1080",
	})
	if err != nil {
		t.Fatalf("failed to init egress dialer: %v", err)
	}
	panelSrv.SetEgressDialer(ed)

	var restartTriggered atomic.Bool
	panelSrv.SetRestartHandler(func() {
		restartTriggered.Store(true)
	})

	// Log in
	loginRec := httptest.NewRecorder()
	loginReq := httptest.NewRequest("POST", "/api/login", strings.NewReader(`{"username":"admin","password":"secret123"}`))
	loginReq.Header.Set("Content-Type", "application/json")
	panelSrv.ServeHTTP(loginRec, loginReq)

	var sessCookie, csrfCookie *http.Cookie
	for _, c := range loginRec.Result().Cookies() {
		if c.Name == "relay_session" {
			sessCookie = c
		} else if c.Name == "relay_csrf" {
			csrfCookie = c
		}
	}
	if sessCookie == nil || csrfCookie == nil {
		t.Fatalf("failed to obtain session or csrf cookies")
	}

	// 1. Get initial settings
	req := httptest.NewRequest("GET", "/api/settings", nil)
	req.AddCookie(sessCookie)
	w := httptest.NewRecorder()
	panelSrv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /api/settings failed: code %d", w.Code)
	}

	var res map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&res); err != nil {
		t.Fatalf("decode settings failed: %v", err)
	}

	if ports, ok := res["allowed_dest_ports"].([]interface{}); !ok || len(ports) != 2 {
		t.Errorf("expected 2 allowed_dest_ports, got %v", res["allowed_dest_ports"])
	}

	// 2. Update allowed_dest_ports
	updatePortsPayload := map[string]interface{}{
		"allowed_dest_ports": []int{443, 8443, 2053, 9443},
	}
	body, _ := json.Marshal(updatePortsPayload)
	putReq := httptest.NewRequest("PUT", "/api/settings", bytes.NewReader(body))
	putReq.Header.Set("Content-Type", "application/json")
	putReq.Header.Set("X-CSRF-Token", csrfCookie.Value)
	putReq.AddCookie(sessCookie)
	w = httptest.NewRecorder()
	panelSrv.ServeHTTP(w, putReq)
	if w.Code != http.StatusOK {
		t.Fatalf("PUT /api/settings failed: code %d, body %s", w.Code, w.Body.String())
	}

	if !pal.Allowed(2053) || !pal.Allowed(9443) {
		t.Errorf("port allow list was not updated dynamically")
	}
	if !rs.IsPortAllowedByPolicy(2053) {
		t.Errorf("rule store global ports were not updated dynamically")
	}

	// 3. Update Egress Proxy
	updateProxyPayload := map[string]interface{}{
		"egress_proxy_enabled":  true,
		"egress_proxy_addr":     "127.0.0.1:9050",
		"egress_proxy_user":     "socksuser",
		"egress_proxy_password": "sockspassword",
	}
	body, _ = json.Marshal(updateProxyPayload)
	putReq = httptest.NewRequest("PUT", "/api/settings", bytes.NewReader(body))
	putReq.Header.Set("Content-Type", "application/json")
	putReq.Header.Set("X-CSRF-Token", csrfCookie.Value)
	putReq.AddCookie(sessCookie)
	w = httptest.NewRecorder()
	panelSrv.ServeHTTP(w, putReq)
	if w.Code != http.StatusOK {
		t.Fatalf("PUT /api/settings proxy failed: code %d, body %s", w.Code, w.Body.String())
	}

	if !ed.Enabled() {
		t.Errorf("expected egress dialer enabled")
	}
	if ed.Config().Addr != "127.0.0.1:9050" {
		t.Errorf("expected addr 127.0.0.1:9050, got %s", ed.Config().Addr)
	}

	// 4. Test Proxy API
	testReq := httptest.NewRequest("POST", "/api/settings/test-proxy", nil)
	testReq.Header.Set("X-CSRF-Token", csrfCookie.Value)
	testReq.AddCookie(sessCookie)
	w = httptest.NewRecorder()
	panelSrv.ServeHTTP(w, testReq)
	if w.Code != http.StatusOK {
		t.Fatalf("POST /api/settings/test-proxy failed: code %d", w.Code)
	}

	// 5. Update Admin Credentials
	credPayload := map[string]interface{}{
		"current_password": "secret123",
		"new_username":     "newadmin",
		"new_password":     "newsecurepassword123",
	}
	body, _ = json.Marshal(credPayload)
	credReq := httptest.NewRequest("PUT", "/api/admin/credentials", bytes.NewReader(body))
	credReq.Header.Set("Content-Type", "application/json")
	credReq.Header.Set("X-CSRF-Token", csrfCookie.Value)
	credReq.AddCookie(sessCookie)
	w = httptest.NewRecorder()
	panelSrv.ServeHTTP(w, credReq)
	if w.Code != http.StatusOK {
		t.Fatalf("PUT /api/admin/credentials failed: code %d, body %s", w.Code, w.Body.String())
	}
	if panelSrv.AdminUsername() != "newadmin" {
		t.Errorf("expected newadmin, got %s", panelSrv.AdminUsername())
	}

	// Verify persistence in SQLite
	persistedUser, found, _ := store.GetSetting(context.Background(), "panel_admin_user")
	if !found || persistedUser != "newadmin" {
		t.Errorf("expected persisted user 'newadmin', got %s", persistedUser)
	}

	// 6. Test Service Restart
	restartReq := httptest.NewRequest("POST", "/api/service/restart", nil)
	restartReq.Header.Set("X-CSRF-Token", csrfCookie.Value)
	restartReq.AddCookie(sessCookie)
	w = httptest.NewRecorder()
	panelSrv.ServeHTTP(w, restartReq)
	if w.Code != http.StatusOK {
		t.Fatalf("POST /api/service/restart failed: code %d", w.Code)
	}

	// 7. Update HTTP front limits
	frontLimits := relay.NewLimitTracker(5000, 60)
	panelSrv.SetFrontLimits(frontLimits)

	frontPayload := map[string]interface{}{
		"http_front_max_conns_per_ip": 120,
		"http_front_max_global_conns": 3000,
	}
	body, _ = json.Marshal(frontPayload)
	frontReq := httptest.NewRequest("PUT", "/api/settings", bytes.NewReader(body))
	frontReq.Header.Set("Content-Type", "application/json")
	frontReq.Header.Set("X-CSRF-Token", csrfCookie.Value)
	frontReq.AddCookie(sessCookie)
	w = httptest.NewRecorder()
	panelSrv.ServeHTTP(w, frontReq)
	if w.Code != http.StatusOK {
		t.Fatalf("PUT front limits failed: code %d, body %s", w.Code, w.Body.String())
	}
	if frontLimits.MaxPerIP() != 120 {
		t.Errorf("expected MaxPerIP 120, got %d", frontLimits.MaxPerIP())
	}
	if frontLimits.MaxGlobal() != 3000 {
		t.Errorf("expected MaxGlobal 3000, got %d", frontLimits.MaxGlobal())
	}

	// Verify persistence
	valIP, found, _ := store.GetSetting(context.Background(), "http_front_max_conns_per_ip")
	if !found || valIP != "120" {
		t.Errorf("expected persisted 120, got %s", valIP)
	}
	valGlobal, found, _ := store.GetSetting(context.Background(), "http_front_max_global_conns")
	if !found || valGlobal != "3000" {
		t.Errorf("expected persisted 3000, got %s", valGlobal)
	}

	// Negative limit rejected with 400
	badPayload := map[string]interface{}{
		"http_front_max_conns_per_ip": -1,
	}
	body, _ = json.Marshal(badPayload)
	badReq := httptest.NewRequest("PUT", "/api/settings", bytes.NewReader(body))
	badReq.Header.Set("Content-Type", "application/json")
	badReq.Header.Set("X-CSRF-Token", csrfCookie.Value)
	badReq.AddCookie(sessCookie)
	w = httptest.NewRecorder()
	panelSrv.ServeHTTP(w, badReq)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for negative limit, got %d", w.Code)
	}
}
