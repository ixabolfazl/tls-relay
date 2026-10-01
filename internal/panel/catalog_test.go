package panel_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/ixabolfazl/tls-relay/internal/catalog"
	"github.com/ixabolfazl/tls-relay/internal/panel"
	"github.com/ixabolfazl/tls-relay/internal/rules"
	"github.com/ixabolfazl/tls-relay/internal/sqlitestore"
)

type syncerRefresher struct {
	store     *sqlitestore.Store
	ruleStore *rules.RuleStore
}

func (s *syncerRefresher) RefreshDomains(ctx context.Context) error {
	rawRules, err := s.store.AllDomainRulesRaw(ctx)
	if err != nil {
		return err
	}
	return s.ruleStore.Swap(rawRules)
}
func (s *syncerRefresher) RefreshBlacklist(ctx context.Context) error { return nil }
func (s *syncerRefresher) RefreshUserIPs(ctx context.Context) error   { return nil }

func setupCatalogPanel(t *testing.T) (*panel.Server, *sqlitestore.Store, *rules.RuleStore, *http.Cookie, *http.Cookie) {
	t.Helper()
	t.Setenv("PANEL_ADMIN_USER", "admin")
	t.Setenv("PANEL_ADMIN_PASSWORD", "secret123")

	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	store, err := sqlitestore.New(dbPath)
	if err != nil {
		t.Fatalf("failed to open sqlite store: %v", err)
	}

	rs := rules.NewRuleStore([]int{80, 443}, "allow_default_port")
	refresher := &syncerRefresher{store: store, ruleStore: rs}

	panelSrv, err := panel.New("127.0.0.1:8080", "/", rs, nil, store, refresher)
	if err != nil {
		t.Fatalf("failed to create panel: %v", err)
	}

	loginRec := httptest.NewRecorder()
	loginReq := httptest.NewRequest("POST", "/api/login", bytes.NewBufferString(`{"username":"admin","password":"secret123"}`))
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

	return panelSrv, store, rs, sessionCookie, csrfCookie
}

func doRequest(panelSrv *panel.Server, method, path string, body []byte, session, csrf *http.Cookie) *httptest.ResponseRecorder {
	var bodyReader *bytes.Buffer
	if body != nil {
		bodyReader = bytes.NewBuffer(body)
	} else {
		bodyReader = bytes.NewBuffer(nil)
	}
	req := httptest.NewRequest(method, path, bodyReader)
	if session != nil {
		req.AddCookie(session)
	}
	if csrf != nil {
		req.AddCookie(csrf)
		req.Header.Set("X-CSRF-Token", csrf.Value)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	panelSrv.ServeHTTP(rec, req)
	return rec
}

func TestCatalogAuthAndCSRF(t *testing.T) {
	panelSrv, store, _, session, csrf := setupCatalogPanel(t)
	defer store.Close()

	// 1. Unauthenticated GET /api/catalog -> 401
	rec := doRequest(panelSrv, "GET", "/api/catalog", nil, nil, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}

	// 2. Authenticated GET /api/catalog -> 200
	rec = doRequest(panelSrv, "GET", "/api/catalog", nil, session, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	// 3. POST /api/catalog/preview without CSRF -> 403
	rec = doRequest(panelSrv, "POST", "/api/catalog/preview", []byte(`{"source":"embedded"}`), session, nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}

	// 4. POST /api/catalog/preview with CSRF -> 200
	rec = doRequest(panelSrv, "POST", "/api/catalog/preview", []byte(`{"source":"embedded"}`), session, csrf)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestCatalogStatusAndRemote(t *testing.T) {
	panelSrv, store, _, session, csrf := setupCatalogPanel(t)
	defer store.Close()

	// Initial status with embedded
	rec := doRequest(panelSrv, "GET", "/api/catalog/status", nil, session, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var status struct {
		InstalledVersion int  `json:"installed_version"`
		EmbeddedVersion  int  `json:"embedded_version"`
		RemoteVersion    int  `json:"remote_version"`
		UpdateAvailable  bool `json:"update_available"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &status); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if status.EmbeddedVersion <= 0 {
		t.Errorf("expected embedded version > 0, got %d", status.EmbeddedVersion)
	}
	if status.InstalledVersion != 0 {
		t.Errorf("expected installed version 0, got %d", status.InstalledVersion)
	}
	if !status.UpdateAvailable {
		t.Errorf("expected update_available true since embedded > installed")
	}

	// Mock remote checker with version 99
	mockRemote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{
			"version": 99,
			"updated_at": "2026-10-01",
			"categories": [
				{
					"id": "mock",
					"name": "Mock",
					"subcategories": [
						{
							"id": "mock.sub",
							"name": "Mock Sub",
							"domains": [
								{ "domain": "mock.example.com", "wildcard": false }
							]
						}
					]
				}
			]
		}`)
	}))
	defer mockRemote.Close()

	checker := catalog.NewChecker(catalog.WithURL(mockRemote.URL), catalog.WithHTTPClient(mockRemote.Client()))
	panelSrv.SetCatalogChecker(checker)

	// Refresh status
	rec = doRequest(panelSrv, "GET", "/api/catalog/status?refresh=1", nil, session, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &status); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if status.RemoteVersion != 99 {
		t.Errorf("expected remote version 99, got %d", status.RemoteVersion)
	}
	if !status.UpdateAvailable {
		t.Errorf("expected update_available true")
	}

	// Preview remote
	rec = doRequest(panelSrv, "POST", "/api/catalog/preview", []byte(`{"source":"github"}`), session, csrf)
	if rec.Code != http.StatusOK {
		t.Fatalf("preview failed: %s", rec.Body.String())
	}
	var previewRes sqlitestore.CatalogApplyResult
	if err := json.Unmarshal(rec.Body.Bytes(), &previewRes); err != nil {
		t.Fatalf("preview unmarshal error: %v", err)
	}
	if previewRes.Version != 99 {
		t.Errorf("expected preview version 99, got %d", previewRes.Version)
	}
	if previewRes.DomainsAdded != 1 {
		t.Errorf("expected 1 domain added in preview, got %d", previewRes.DomainsAdded)
	}

	// Load with version mismatch (e.g. expected 98) -> 409
	rec = doRequest(panelSrv, "POST", "/api/catalog/load", []byte(`{"source":"github","expected_version":98}`), session, csrf)
	if rec.Code != http.StatusConflict {
		t.Fatalf("expected 409 Conflict on version mismatch, got %d: %s", rec.Code, rec.Body.String())
	}

	// Load with correct version 99 -> 200
	rec = doRequest(panelSrv, "POST", "/api/catalog/load", []byte(`{"source":"github","expected_version":99}`), session, csrf)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// Check installed version is now 99
	rec = doRequest(panelSrv, "GET", "/api/catalog/status", nil, session, nil)
	if err := json.Unmarshal(rec.Body.Bytes(), &status); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if status.InstalledVersion != 99 {
		t.Errorf("expected installed version 99, got %d", status.InstalledVersion)
	}
	if status.UpdateAvailable {
		t.Errorf("expected update_available false after installing latest")
	}
}

func TestCatalogToggleAndRuleStoreReflection(t *testing.T) {
	panelSrv, store, rs, session, csrf := setupCatalogPanel(t)
	defer store.Close()

	// Load embedded catalog
	rec := doRequest(panelSrv, "POST", "/api/catalog/load", []byte(`{"source":"embedded","expected_version":1}`), session, csrf)
	if rec.Code != http.StatusOK {
		t.Fatalf("load embedded failed: %s", rec.Body.String())
	}

	// Pick a domain that exists in the catalog, e.g. "telegram.org" under subcategory "social.telegram"
	_, ok := rs.LookupRule("telegram.org")
	if !ok {
		t.Fatalf("expected telegram.org in ruleStore after catalog load")
	}

	// Disable subcategory "social.telegram"
	rec = doRequest(panelSrv, "PUT", "/api/catalog/nodes/social.telegram", []byte(`{"enabled":false}`), session, csrf)
	if rec.Code != http.StatusOK {
		t.Fatalf("toggle subcategory failed: %d %s", rec.Code, rec.Body.String())
	}

	// Check ruleStore: telegram.org should no longer be active!
	_, ok = rs.LookupRule("telegram.org")
	if ok {
		t.Fatalf("expected telegram.org to be inactive after disabling subcategory")
	}

	// Re-enable subcategory
	rec = doRequest(panelSrv, "PUT", "/api/catalog/nodes/social.telegram", []byte(`{"enabled":true}`), session, csrf)
	if rec.Code != http.StatusOK {
		t.Fatalf("re-enable subcategory failed: %d %s", rec.Code, rec.Body.String())
	}
	_, ok = rs.LookupRule("telegram.org")
	if !ok {
		t.Fatalf("expected telegram.org to be active again after re-enabling subcategory")
	}

	// Disable parent category "social"
	rec = doRequest(panelSrv, "PUT", "/api/catalog/nodes/social", []byte(`{"enabled":false}`), session, csrf)
	if rec.Code != http.StatusOK {
		t.Fatalf("toggle category failed: %d %s", rec.Code, rec.Body.String())
	}
	_, ok = rs.LookupRule("telegram.org")
	if ok {
		t.Fatalf("expected telegram.org to be inactive after disabling parent category")
	}
}

func TestCatalogNodeCRUD(t *testing.T) {
	panelSrv, store, _, session, csrf := setupCatalogPanel(t)
	defer store.Close()

	// 1. Create a new category
	rec := doRequest(panelSrv, "POST", "/api/catalog/nodes", []byte(`{"id":"custom_cat","name":"Custom Category","parent_id":""}`), session, csrf)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create category failed: %d %s", rec.Code, rec.Body.String())
	}

	// 2. Create a new subcategory
	rec = doRequest(panelSrv, "POST", "/api/catalog/nodes", []byte(`{"id":"custom_cat.sub","name":"Custom Sub","parent_id":"custom_cat"}`), session, csrf)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create subcategory failed: %d %s", rec.Code, rec.Body.String())
	}

	// 3. Verify in GET /api/catalog
	rec = doRequest(panelSrv, "GET", "/api/catalog", nil, session, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("get catalog failed: %d", rec.Code)
	}
	var catRes struct {
		Categories []struct {
			ID            string `json:"id"`
			Name          string `json:"name"`
			Subcategories []struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"subcategories"`
		} `json:"categories"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &catRes); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	var foundCat, foundSub bool
	for _, c := range catRes.Categories {
		if c.ID == "custom_cat" {
			foundCat = true
			for _, s := range c.Subcategories {
				if s.ID == "custom_cat.sub" {
					foundSub = true
				}
			}
		}
	}
	if !foundCat || !foundSub {
		t.Fatalf("expected custom_cat and custom_cat.sub in tree, foundCat=%v, foundSub=%v", foundCat, foundSub)
	}

	// 4. Update node name
	rec = doRequest(panelSrv, "PUT", "/api/catalog/nodes/custom_cat.sub", []byte(`{"name":"Updated Sub"}`), session, csrf)
	if rec.Code != http.StatusOK {
		t.Fatalf("update subcategory name failed: %d %s", rec.Code, rec.Body.String())
	}

	// 5. Delete subcategory
	rec = doRequest(panelSrv, "DELETE", "/api/catalog/nodes/custom_cat.sub", nil, session, csrf)
	if rec.Code != http.StatusOK {
		t.Fatalf("delete subcategory failed: %d %s", rec.Code, rec.Body.String())
	}

	// 6. Delete category
	rec = doRequest(panelSrv, "DELETE", "/api/catalog/nodes/custom_cat", nil, session, csrf)
	if rec.Code != http.StatusOK {
		t.Fatalf("delete category failed: %d %s", rec.Code, rec.Body.String())
	}
}
