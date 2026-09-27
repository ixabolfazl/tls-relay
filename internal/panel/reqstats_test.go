package panel_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ixabolfazl/tls-relay/internal/access"
	"github.com/ixabolfazl/tls-relay/internal/panel"
	"github.com/ixabolfazl/tls-relay/internal/rules"
	"github.com/ixabolfazl/tls-relay/internal/sqlitestore"
)

func TestRequestStatsAPI_Endpoints(t *testing.T) {
	t.Setenv("PANEL_ADMIN_USER", "admin")
	t.Setenv("PANEL_ADMIN_PASSWORD", "secret123")

	dbPath := filepath.Join(t.TempDir(), "test.db")
	sqStore, err := sqlitestore.New(dbPath)
	if err != nil {
		t.Fatalf("failed to create sqlite store: %v", err)
	}
	defer sqStore.Close()

	ctx := context.Background()
	now := time.Now().UTC()

	_ = sqStore.IncrementRequestStat(ctx, now, "DNS", "authorized", 15)
	_ = sqStore.IncrementRequestStat(ctx, now, "DNS", "unauthorized_passthrough", 5)
	_ = sqStore.IncrementRequestStat(ctx, now, "TLS", "registered", 25)

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

	// 1. GET /api/stats
	statsRec := httptest.NewRecorder()
	statsReq := httptest.NewRequest("GET", "/api/stats", nil)
	statsReq.AddCookie(sessionCookie)
	srv.ServeHTTP(statsRec, statsReq)

	if statsRec.Code != http.StatusOK {
		t.Fatalf("GET /api/stats status %d", statsRec.Code)
	}

	var statsResp map[string]interface{}
	if err := json.Unmarshal(statsRec.Body.Bytes(), &statsResp); err != nil {
		t.Fatalf("unmarshal /api/stats: %v", err)
	}

	if dnsTotal, ok := statsResp["dns_requests_total"].(float64); !ok || dnsTotal != 20 {
		t.Errorf("dns_requests_total got %v, want 20", statsResp["dns_requests_total"])
	}
	if dnsAuth, ok := statsResp["dns_requests_authorized"].(float64); !ok || dnsAuth != 15 {
		t.Errorf("dns_requests_authorized got %v, want 15", statsResp["dns_requests_authorized"])
	}
	if tlsReg, ok := statsResp["tls_requests_registered"].(float64); !ok || tlsReg != 25 {
		t.Errorf("tls_requests_registered got %v, want 25", statsResp["tls_requests_registered"])
	}

	// 2. GET /api/request-stats/daily?type=DNS&days=30
	dailyRec := httptest.NewRecorder()
	dailyReq := httptest.NewRequest("GET", "/api/request-stats/daily?type=DNS&days=30", nil)
	dailyReq.AddCookie(sessionCookie)
	srv.ServeHTTP(dailyRec, dailyReq)

	if dailyRec.Code != http.StatusOK {
		t.Fatalf("GET /api/request-stats/daily status %d", dailyRec.Code)
	}

	var dailyResp struct {
		Days []struct {
			Category string `json:"category"`
			Count    int64  `json:"count"`
		} `json:"days"`
	}
	if err := json.Unmarshal(dailyRec.Body.Bytes(), &dailyResp); err != nil {
		t.Fatalf("unmarshal request stats daily: %v", err)
	}
	if len(dailyResp.Days) != 2 {
		t.Errorf("expected 2 DNS stat daily rows, got %d", len(dailyResp.Days))
	}
}
