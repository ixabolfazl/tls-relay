package panel_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/ixabolfazl/tls-relay/internal/config"
	"github.com/ixabolfazl/tls-relay/internal/relay"
)

func TestEgressProxySettingsAndDomainOptions(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test_egress.db")
	panelSrv, _, _, sessCookie, csrfCookie := setupTestPanel(t, dbPath)

	// 1. Initially egressDialer is nil -> egress_proxy_enabled should be false
	req := httptest.NewRequest("GET", "/api/settings", nil)
	req.AddCookie(sessCookie)
	w := httptest.NewRecorder()
	panelSrv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var settings map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&settings); err != nil {
		t.Fatalf("failed to decode settings: %v", err)
	}
	if enabled, ok := settings["egress_proxy_enabled"].(bool); !ok || enabled {
		t.Errorf("expected egress_proxy_enabled false, got %v", settings["egress_proxy_enabled"])
	}

	// 2. Set egress dialer with enabled=true -> egress_proxy_enabled should be true
	ed, err := relay.NewEgressDialer(config.EgressProxyConfig{
		Enabled: true,
		Addr:    "127.0.0.1:1080",
	})
	if err != nil {
		t.Fatalf("failed to build egress dialer: %v", err)
	}
	panelSrv.SetEgressDialer(ed)

	w = httptest.NewRecorder()
	panelSrv.ServeHTTP(w, req)
	if err := json.NewDecoder(w.Body).Decode(&settings); err != nil {
		t.Fatalf("failed to decode settings: %v", err)
	}
	if enabled, ok := settings["egress_proxy_enabled"].(bool); !ok || !enabled {
		t.Errorf("expected egress_proxy_enabled true, got %v", settings["egress_proxy_enabled"])
	}

	// 3. Add domain with use_egress_proxy="false" (Server Proxy)
	addPayload := map[string]interface{}{
		"domain":           "server-proxy.com",
		"mode":             "proxy",
		"ports":            "443",
		"use_egress_proxy": "false",
	}
	body, _ := json.Marshal(addPayload)
	addReq := httptest.NewRequest("POST", "/api/domains", bytes.NewReader(body))
	addReq.Header.Set("Content-Type", "application/json")
	addReq.Header.Set("X-CSRF-Token", csrfCookie.Value)
	addReq.AddCookie(sessCookie)
	w = httptest.NewRecorder()
	panelSrv.ServeHTTP(w, addReq)
	if w.Code != http.StatusOK {
		t.Fatalf("POST /api/domains failed: code %d, body %s", w.Code, w.Body.String())
	}

	// 4. Add domain with use_egress_proxy="true" (Custom Proxy)
	addPayload["domain"] = "custom-proxy.com"
	addPayload["use_egress_proxy"] = "true"
	body, _ = json.Marshal(addPayload)
	addReq = httptest.NewRequest("POST", "/api/domains", bytes.NewReader(body))
	addReq.Header.Set("Content-Type", "application/json")
	addReq.Header.Set("X-CSRF-Token", csrfCookie.Value)
	addReq.AddCookie(sessCookie)
	w = httptest.NewRecorder()
	panelSrv.ServeHTTP(w, addReq)
	if w.Code != http.StatusOK {
		t.Fatalf("POST /api/domains failed: code %d, body %s", w.Code, w.Body.String())
	}

	// 5. Bulk assign egress
	bulkPayload := map[string]interface{}{
		"domains":          []string{"server-proxy.com"},
		"use_egress_proxy": "true",
	}
	body, _ = json.Marshal(bulkPayload)
	bulkReq := httptest.NewRequest("POST", "/api/domains/bulk-assign-egress", bytes.NewReader(body))
	bulkReq.Header.Set("Content-Type", "application/json")
	bulkReq.Header.Set("X-CSRF-Token", csrfCookie.Value)
	bulkReq.AddCookie(sessCookie)
	w = httptest.NewRecorder()
	panelSrv.ServeHTTP(w, bulkReq)
	if w.Code != http.StatusOK {
		t.Fatalf("POST /api/domains/bulk-assign-egress failed: code %d, body %s", w.Code, w.Body.String())
	}
}
