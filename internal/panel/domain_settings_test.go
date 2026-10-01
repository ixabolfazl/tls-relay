package panel_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ixabolfazl/tls-relay/internal/access"
	"github.com/ixabolfazl/tls-relay/internal/panel"
	"github.com/ixabolfazl/tls-relay/internal/portal"
	"github.com/ixabolfazl/tls-relay/internal/rules"
	"github.com/ixabolfazl/tls-relay/internal/sqlitestore"
)

type dummyRefresher struct{}

func (d *dummyRefresher) RefreshDomains(ctx context.Context) error   { return nil }
func (d *dummyRefresher) RefreshBlacklist(ctx context.Context) error { return nil }
func (d *dummyRefresher) RefreshUserIPs(ctx context.Context) error   { return nil }

func setupTestPanel(t *testing.T, dbPath string) (*panel.Server, *sqlitestore.Store, *portal.Server, *http.Cookie, *http.Cookie) {
	t.Helper()
	t.Setenv("PANEL_ADMIN_USER", "admin")
	t.Setenv("PANEL_ADMIN_PASSWORD", "secret123")

	store, err := sqlitestore.New(dbPath)
	if err != nil {
		t.Fatalf("failed to open sqlite store: %v", err)
	}

	rs := rules.NewRuleStore([]int{80, 443}, "allow_default_port")
	as := access.NewAccessStore(access.ModeUser)
	refresher := &dummyRefresher{}

	panelSrv, err := panel.New("127.0.0.1:8080", "/", rs, as, store, refresher)
	if err != nil {
		t.Fatalf("failed to create panel: %v", err)
	}

	portalSrv := portal.New("127.0.0.1:80", store, as, refresher)
	portalSrv.SetServerIP("198.51.100.1")
	panelSrv.SetPortalServer(portalSrv)

	// Log in to obtain auth session and CSRF cookies
	loginRec := httptest.NewRecorder()
	loginReq := httptest.NewRequest("POST", "/api/login", strings.NewReader(`{"username":"admin","password":"secret123"}`))
	loginReq.Header.Set("Content-Type", "application/json")
	panelSrv.ServeHTTP(loginRec, loginReq)

	var sessionCookie, csrfCookie *http.Cookie
	for _, c := range loginRec.Result().Cookies() {
		if c.Name == "relay_session" {
			sessionCookie = c
		} else if c.Name == "relay_csrf" {
			csrfCookie = c
		}
	}

	return panelSrv, store, portalSrv, sessionCookie, csrfCookie
}

// 1. server_domain does not exist -> uses IP/Host
func TestServerDomain_NotSet(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	panelSrv, store, portalSrv, _, _ := setupTestPanel(t, dbPath)
	defer store.Close()

	req := httptest.NewRequest("GET", "http://198.51.100.1/test", nil)

	if domain := panelSrv.ServerDomain(); domain != "" {
		t.Errorf("expected empty domain, got %q", domain)
	}
	if host := panelSrv.BaseHost(req); host != "198.51.100.1" {
		t.Errorf("expected fallback to host '198.51.100.1', got %q", host)
	}
	if url := panelSrv.BaseURL(req); url != "http://198.51.100.1" {
		t.Errorf("expected fallback URL 'http://198.51.100.1', got %q", url)
	}
	if pHost := portalSrv.BaseHost(req); pHost != "198.51.100.1" {
		t.Errorf("expected portal BaseHost '198.51.100.1', got %q", pHost)
	}
}

// 2. server_domain is empty -> uses IP/Host
func TestServerDomain_Empty(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	panelSrv, store, _, _, _ := setupTestPanel(t, dbPath)
	defer store.Close()

	panelSrv.SetServerDomain("")
	req := httptest.NewRequest("GET", "http://198.51.100.1:8080/test", nil)

	if host := panelSrv.BaseHost(req); host != "198.51.100.1" {
		t.Errorf("expected host '198.51.100.1', got %q", host)
	}
	if url := panelSrv.BaseURL(req); url != "http://198.51.100.1" {
		t.Errorf("expected BaseURL 'http://198.51.100.1', got %q", url)
	}
}

// 3. server_domain is valid -> uses domain
func TestServerDomain_Valid(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	panelSrv, store, portalSrv, _, _ := setupTestPanel(t, dbPath)
	defer store.Close()

	panelSrv.SetServerDomain("dns.example.com")
	req := httptest.NewRequest("GET", "http://198.51.100.1/test", nil)

	if host := panelSrv.BaseHost(req); host != "dns.example.com" {
		t.Errorf("expected host 'dns.example.com', got %q", host)
	}
	if url := panelSrv.BaseURL(req); url != "http://dns.example.com" {
		t.Errorf("expected BaseURL 'http://dns.example.com', got %q", url)
	}
	if pUrl := portalSrv.BaseURL(req); pUrl != "http://dns.example.com" {
		t.Errorf("expected portal BaseURL 'http://dns.example.com', got %q", pUrl)
	}
}

// 4. domain with http:// or https:// -> properly normalized
func TestServerDomain_Normalization_Schemes(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"http://dns.example.com", "dns.example.com"},
		{"https://dns.example.com", "dns.example.com"},
		{"https://DNS.EXAMPLE.COM", "dns.example.com"},
		{"//my-relay.net", "my-relay.net"},
	}

	for _, tt := range tests {
		normalized, err := panel.NormalizeAndValidateServerDomain(tt.input)
		if err != nil {
			t.Errorf("NormalizeAndValidateServerDomain(%q) unexpected error: %v", tt.input, err)
		}
		if normalized != tt.expected {
			t.Errorf("NormalizeAndValidateServerDomain(%q) = %q; want %q", tt.input, normalized, tt.expected)
		}
	}
}

// 5. domain with trailing / or path -> properly normalized
func TestServerDomain_Normalization_PathsAndTrailingSlashes(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"dns.example.com/", "dns.example.com"},
		{"dns.example.com/some/path", "dns.example.com"},
		{"https://dns.example.com/admin/?tab=users", "dns.example.com"},
		{"   relay.mydns.org/   ", "relay.mydns.org"},
	}

	for _, tt := range tests {
		normalized, err := panel.NormalizeAndValidateServerDomain(tt.input)
		if err != nil {
			t.Errorf("NormalizeAndValidateServerDomain(%q) unexpected error: %v", tt.input, err)
		}
		if normalized != tt.expected {
			t.Errorf("NormalizeAndValidateServerDomain(%q) = %q; want %q", tt.input, normalized, tt.expected)
		}
	}
}

// 6. invalid domain -> validation error and previous value remains unchanged
func TestServerDomain_InvalidValidationAndNoMutation(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	panelSrv, store, _, sess, csrf := setupTestPanel(t, dbPath)
	defer store.Close()

	ctx := context.Background()
	_ = store.SetSetting(ctx, "server_domain", "original.example.com")
	panelSrv.SetServerDomain("original.example.com")

	invalidInputs := []string{
		"invalid domain with spaces",
		"..bad..dots..",
		"-leading-dash.com",
		"trailing-dash-.com",
		"invalid_chars$.com",
	}

	for _, invalid := range invalidInputs {
		_, err := panel.NormalizeAndValidateServerDomain(invalid)
		if err == nil {
			t.Errorf("expected error for invalid domain %q, got nil", invalid)
		}

		// Test via HTTP API PUT /api/settings
		bodyBytes, _ := json.Marshal(map[string]string{
			"server_domain": invalid,
		})
		req := httptest.NewRequest("PUT", "/api/settings", bytes.NewReader(bodyBytes))
		req.Header.Set("Content-Type", "application/json")
		if sess != nil {
			req.AddCookie(sess)
		}
		if csrf != nil {
			req.AddCookie(csrf)
			req.Header.Set("X-CSRF-Token", csrf.Value)
		}
		w := httptest.NewRecorder()

		panelSrv.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("expected status 400 for domain %q, got %d (body: %s)", invalid, w.Code, w.Body.String())
		}

		// Ensure previous value did not change
		val, _, _ := store.GetSetting(ctx, "server_domain")
		if val != "original.example.com" {
			t.Errorf("stored setting was mutated to %q after invalid input %q", val, invalid)
		}
		if current := panelSrv.ServerDomain(); current != "original.example.com" {
			t.Errorf("in-memory domain was mutated to %q after invalid input %q", current, invalid)
		}
	}
}

// 7. runtime update -> new URLs immediately use the new value
func TestServerDomain_RuntimeUpdate(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	panelSrv, store, portalSrv, sess, csrf := setupTestPanel(t, dbPath)
	defer store.Close()

	// Update via API
	bodyBytes, _ := json.Marshal(map[string]string{
		"server_domain": "https://new-relay.com/",
	})
	req := httptest.NewRequest("PUT", "/api/settings", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	if sess != nil {
		req.AddCookie(sess)
	}
	if csrf != nil {
		req.AddCookie(csrf)
		req.Header.Set("X-CSRF-Token", csrf.Value)
	}
	w := httptest.NewRecorder()

	panelSrv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", w.Code, w.Body.String())
	}

	testReq := httptest.NewRequest("GET", "http://198.51.100.1/test", nil)
	if url := panelSrv.BaseURL(testReq); url != "http://new-relay.com" {
		t.Errorf("expected BaseURL 'http://new-relay.com', got %q", url)
	}
	if pUrl := portalSrv.BaseURL(testReq); pUrl != "http://new-relay.com" {
		t.Errorf("expected portal BaseURL 'http://new-relay.com', got %q", pUrl)
	}

	// Verify clearing in runtime reverts back immediately
	clearBytes, _ := json.Marshal(map[string]string{
		"server_domain": "",
	})
	reqClear := httptest.NewRequest("PUT", "/api/settings", bytes.NewReader(clearBytes))
	reqClear.Header.Set("Content-Type", "application/json")
	if sess != nil {
		reqClear.AddCookie(sess)
	}
	if csrf != nil {
		reqClear.AddCookie(csrf)
		reqClear.Header.Set("X-CSRF-Token", csrf.Value)
	}
	wClear := httptest.NewRecorder()
	panelSrv.ServeHTTP(wClear, reqClear)

	if wClear.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for clear, got %d: %s", wClear.Code, wClear.Body.String())
	}
	if url := panelSrv.BaseURL(testReq); url != "http://198.51.100.1" {
		t.Errorf("expected reverted BaseURL 'http://198.51.100.1', got %q", url)
	}
}

// 8. restart / reload -> loaded from SQLite
func TestServerDomain_ReloadOnRestart(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	// Phase 1: Set setting in store
	store1, err := sqlitestore.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := store1.SetSetting(ctx, "server_domain", "persisted-domain.org"); err != nil {
		t.Fatal(err)
	}
	_ = store1.Close()

	// Phase 2: Start new server instance (simulating restart)
	panelSrv2, store2, portalSrv2, _, _ := setupTestPanel(t, dbPath)
	defer store2.Close()

	if domain := panelSrv2.ServerDomain(); domain != "persisted-domain.org" {
		t.Errorf("expected reloaded domain 'persisted-domain.org', got %q", domain)
	}

	req := httptest.NewRequest("GET", "http://198.51.100.1/test", nil)
	if pUrl := portalSrv2.BaseURL(req); pUrl != "http://persisted-domain.org" {
		t.Errorf("expected portal BaseURL 'http://persisted-domain.org', got %q", pUrl)
	}
}

// 9. all Portal and Panel URLs share Base URL logic
func TestServerDomain_SharedBaseURLLogic(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	panelSrv, store, portalSrv, _, _ := setupTestPanel(t, dbPath)
	defer store.Close()

	panelSrv.SetServerDomain("shared.example.com")
	req := httptest.NewRequest("GET", "http://127.0.0.1:80/connect/token123", nil)

	panelBase := panelSrv.BaseURL(req)
	portalBase := portalSrv.BaseURL(req)

	if panelBase != portalBase {
		t.Errorf("mismatch between panel BaseURL (%q) and portal BaseURL (%q)", panelBase, portalBase)
	}
	if panelBase != "http://shared.example.com" {
		t.Errorf("expected 'http://shared.example.com', got %q", panelBase)
	}
}

// 10. protocol is strictly http:// (port 80 default)
func TestServerDomain_ProtocolIsHTTP(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	panelSrv, store, portalSrv, _, _ := setupTestPanel(t, dbPath)
	defer store.Close()

	panelSrv.SetServerDomain("dns.relay.local")
	req := httptest.NewRequest("GET", "http://127.0.0.1/setup", nil)

	if url := panelSrv.BaseURL(req); url != "http://dns.relay.local" {
		t.Errorf("expected 'http://dns.relay.local', got %q", url)
	}
	if url := portalSrv.BaseURL(req); url != "http://dns.relay.local" {
		t.Errorf("expected 'http://dns.relay.local', got %q", url)
	}
}

// ---------------------------------------------------------------------------
// TXT Export / Import
// ---------------------------------------------------------------------------

func doAuthedRequest(t *testing.T, srv *panel.Server, method, path, contentType, body string, session, csrf *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	var bodyReader *strings.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	} else {
		bodyReader = strings.NewReader("")
	}
	req := httptest.NewRequest(method, path, bodyReader)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	req.Header.Set("X-CSRF-Token", csrf.Value)
	req.AddCookie(session)
	req.AddCookie(csrf)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	return rec
}

// ---------------------------------------------------------------------------
// JSON Export / Import (version 2 & v1-compat)
// ---------------------------------------------------------------------------

func TestExportDomainsJSON_EmptyStore(t *testing.T) {
	dir := t.TempDir()
	srv, store, _, session, csrf := setupTestPanel(t, filepath.Join(dir, "test.db"))
	defer store.Close()

	rec := doAuthedRequest(t, srv, "GET", "/api/domains/export.json", "", "", session, csrf)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	ct := rec.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, "application/json") {
		t.Errorf("expected application/json, got %q", ct)
	}
	var payload map[string]interface{}
	if err := json.NewDecoder(rec.Body).Decode(&payload); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if v, _ := payload["version"].(float64); int(v) != 2 {
		t.Errorf("expected version=2, got %v", payload["version"])
	}
	cats, _ := payload["categories"].([]interface{})
	if len(cats) != 0 {
		t.Errorf("expected empty categories array, got %d items", len(cats))
	}
	uncat, _ := payload["uncategorized"].([]interface{})
	if len(uncat) != 0 {
		t.Errorf("expected empty uncategorized array, got %d items", len(uncat))
	}
}

func TestImportDomainsJSON_V2RoundTrip(t *testing.T) {
	dir := t.TempDir()
	srv, store, _, session, csrf := setupTestPanel(t, filepath.Join(dir, "test.db"))
	defer store.Close()

	body := `{
		"version": 2,
		"categories": [
			{
				"id": "social",
				"name": "Social Media",
				"enabled": true,
				"subcategories": [
					{
						"id": "social.telegram",
						"name": "Telegram",
						"enabled": true,
						"domains": [
							{"domain": "telegram.org", "mode": "proxy", "ports": [443]}
						]
					}
				]
			}
		],
		"uncategorized": [
			{"domain": "example.com", "mode": "direct", "ports": "all", "group": "test"}
		]
	}`

	rec := doAuthedRequest(t, srv, "POST", "/api/domains/import-json", "application/json", body, session, csrf)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var result map[string]interface{}
	_ = json.NewDecoder(rec.Body).Decode(&result)
	if int(result["domains_added"].(float64)) != 2 {
		t.Errorf("expected 2 added, got %v", result["domains_added"])
	}
	if int(result["categories_added"].(float64)) != 2 {
		t.Errorf("expected 2 categories added, got %v", result["categories_added"])
	}

	// Round-trip export v2
	expRec := doAuthedRequest(t, srv, "GET", "/api/domains/export.json", "", "", session, csrf)
	if expRec.Code != http.StatusOK {
		t.Fatalf("expected 200 on export, got %d", expRec.Code)
	}
	var exported map[string]interface{}
	_ = json.NewDecoder(expRec.Body).Decode(&exported)
	if int(exported["version"].(float64)) != 2 {
		t.Errorf("expected version 2, got %v", exported["version"])
	}
	cats, _ := exported["categories"].([]interface{})
	if len(cats) != 1 {
		t.Fatalf("expected 1 category, got %d", len(cats))
	}
	cat0 := cats[0].(map[string]interface{})
	if cat0["id"] != "social" {
		t.Errorf("expected category social, got %v", cat0["id"])
	}
	subs, _ := cat0["subcategories"].([]interface{})
	if len(subs) != 1 {
		t.Fatalf("expected 1 subcategory, got %d", len(subs))
	}
	sub0 := subs[0].(map[string]interface{})
	doms, _ := sub0["domains"].([]interface{})
	if len(doms) != 1 {
		t.Fatalf("expected 1 domain under social.telegram, got %d", len(doms))
	}
	d0 := doms[0].(map[string]interface{})
	if d0["domain"] != "telegram.org" {
		t.Errorf("expected telegram.org, got %v", d0["domain"])
	}

	uncat, _ := exported["uncategorized"].([]interface{})
	if len(uncat) != 1 {
		t.Fatalf("expected 1 uncategorized domain, got %d", len(uncat))
	}
	u0 := uncat[0].(map[string]interface{})
	if u0["domain"] != "example.com" {
		t.Errorf("expected example.com, got %v", u0["domain"])
	}
}

func TestImportDomainsJSON_V1Compat(t *testing.T) {
	dir := t.TempDir()
	srv, store, _, session, csrf := setupTestPanel(t, filepath.Join(dir, "test.db"))
	defer store.Close()

	body := `{"domains":[
		{"domain":"v1.example.com","mode":"proxy","ports":[443],"group":"streaming"}
	]}`

	rec := doAuthedRequest(t, srv, "POST", "/api/domains/import-json", "application/json", body, session, csrf)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 on v1 import, got %d: %s", rec.Code, rec.Body.String())
	}
	var result map[string]interface{}
	_ = json.NewDecoder(rec.Body).Decode(&result)
	if int(result["domains_added"].(float64)) != 1 {
		t.Errorf("expected 1 added, got %v", result["domains_added"])
	}

	// In v2 export, it should be in uncategorized
	expRec := doAuthedRequest(t, srv, "GET", "/api/domains/export.json", "", "", session, csrf)
	var exported map[string]interface{}
	_ = json.NewDecoder(expRec.Body).Decode(&exported)
	uncat, _ := exported["uncategorized"].([]interface{})
	if len(uncat) != 1 {
		t.Fatalf("expected 1 uncategorized domain for v1 import, got %d", len(uncat))
	}
	u0 := uncat[0].(map[string]interface{})
	if u0["domain"] != "v1.example.com" {
		t.Errorf("expected v1.example.com, got %v", u0["domain"])
	}
}

func TestImportDomainsJSON_EgressIgnoredWhenGloballyOff(t *testing.T) {
	dir := t.TempDir()
	// egressDialer is nil → global switch is off
	srv, store, _, session, csrf := setupTestPanel(t, filepath.Join(dir, "test.db"))
	defer store.Close()

	body := `{"domains":[
		{"domain":"egress.example.com","mode":"proxy","ports":[443],"use_egress":true},
		{"domain":"normal.example.com","mode":"proxy","ports":[443]}
	]}`
	rec := doAuthedRequest(t, srv, "POST", "/api/domains/import-json", "application/json", body, session, csrf)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	rows, err := store.ListDomainRules(context.Background())
	if err != nil {
		t.Fatalf("ListDomainRules: %v", err)
	}
	for _, row := range rows {
		if row.UseEgressProxy == "true" {
			t.Errorf("use_egress should be ignored when global switch is off, but %s has use_egress=true", row.Domain)
		}
	}
}

func TestImportDomainsJSON_DuplicatesDeduplicated(t *testing.T) {
	dir := t.TempDir()
	srv, store, _, session, csrf := setupTestPanel(t, filepath.Join(dir, "test.db"))
	defer store.Close()

	body := `{"domains":[
		{"domain":"example.com","mode":"proxy","ports":[443]},
		{"domain":"example.com","mode":"direct","ports":[443]}
	]}`
	rec := doAuthedRequest(t, srv, "POST", "/api/domains/import-json", "application/json", body, session, csrf)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var result map[string]interface{}
	_ = json.NewDecoder(rec.Body).Decode(&result)
	if int(result["domains_added"].(float64)) != 1 {
		t.Errorf("expected 1 added (deduplicated), got %v", result["domains_added"])
	}
}

func TestImportDomainsJSON_InvalidDomainReported(t *testing.T) {
	dir := t.TempDir()
	srv, store, _, session, csrf := setupTestPanel(t, filepath.Join(dir, "test.db"))
	defer store.Close()

	body := `{"domains":[
		{"domain":"valid.example.com","mode":"proxy","ports":[443]},
		{"domain":"!!BAD!!","mode":"proxy","ports":[443]},
		{"domain":"also.valid.com","mode":"direct","ports":[443]}
	]}`
	rec := doAuthedRequest(t, srv, "POST", "/api/domains/import-json", "application/json", body, session, csrf)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var result map[string]interface{}
	_ = json.NewDecoder(rec.Body).Decode(&result)
	if int(result["domains_added"].(float64)) != 2 {
		t.Errorf("expected 2 added, got %v", result["domains_added"])
	}
	if int(result["failed"].(float64)) != 1 {
		t.Errorf("expected 1 failed, got %v", result["failed"])
	}
}
