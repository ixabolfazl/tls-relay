package panel_test

import (
	"context"
	"encoding/json"
	"fmt"
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

func TestDomainUsageAPI_EndpointsAndNoFK(t *testing.T) {
	t.Setenv("PANEL_ADMIN_USER", "admin")
	t.Setenv("PANEL_ADMIN_PASSWORD", "secret123")

	dbPath := filepath.Join(t.TempDir(), "test.db")
	sqStore, err := sqlitestore.New(dbPath)
	if err != nil {
		t.Fatalf("failed to create sqlite store: %v", err)
	}
	defer sqStore.Close()

	ctx := context.Background()

	// Create user
	u1, err := sqStore.CreateUser(ctx, "panel_alice", 3)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	// Create domain rule
	if err := sqStore.AddDomainRule(ctx, "app.example.com", "grp1", "[443]", "default", "proxy"); err != nil {
		t.Fatalf("AddDomainRule: %v", err)
	}

	// Simulate increments
	d1 := time.Date(2026, 4, 10, 0, 0, 0, 0, time.UTC)
	d2 := time.Date(2026, 5, 10, 0, 0, 0, 0, time.UTC)

	_ = sqStore.IncrementDomainUsage(ctx, "app.example.com", 1000, 2000, d1)
	_ = sqStore.IncrementUserDomainUsage(ctx, u1.ID, "app.example.com", 1000, 2000, d1)
	_ = sqStore.IncrementDomainUsage(ctx, "app.example.com", 3000, 4000, d2)

	ruleStore := rules.NewRuleStore([]int{443}, "allow_default_port")
	accessStore := access.NewAccessStore(access.ModeUser)

	srv, err := panel.New("127.0.0.1:0", "/", ruleStore, accessStore, sqStore, nil)
	if err != nil {
		t.Fatalf("failed to create panel server: %v", err)
	}

	// Login to get session cookie
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
	if sessionCookie == nil {
		t.Fatal("session cookie not found")
	}

	// 1. GET /api/domains -> total_bytes_sent & total_bytes_received present
	domRec := httptest.NewRecorder()
	domReq := httptest.NewRequest("GET", "/api/domains", nil)
	domReq.AddCookie(sessionCookie)
	srv.ServeHTTP(domRec, domReq)

	if domRec.Code != http.StatusOK {
		t.Fatalf("GET /api/domains got status %d", domRec.Code)
	}

	var domResp struct {
		Domains []struct {
			Domain             string `json:"domain"`
			TotalBytesSent     int64  `json:"total_bytes_sent"`
			TotalBytesReceived int64  `json:"total_bytes_received"`
		} `json:"domains"`
	}
	if err := json.Unmarshal(domRec.Body.Bytes(), &domResp); err != nil {
		t.Fatalf("unmarshal /api/domains: %v", err)
	}
	if len(domResp.Domains) == 0 {
		t.Fatal("expected at least 1 domain row")
	}
	if domResp.Domains[0].TotalBytesSent != 4000 || domResp.Domains[0].TotalBytesReceived != 6000 {
		t.Errorf("domain total bytes got %d/%d, want 4000/6000", domResp.Domains[0].TotalBytesSent, domResp.Domains[0].TotalBytesReceived)
	}

	// 2. GET /api/domains/app.example.com/usage?days=365
	dailyRec := httptest.NewRecorder()
	dailyReq := httptest.NewRequest("GET", "/api/domains/app.example.com/usage?days=365", nil)
	dailyReq.AddCookie(sessionCookie)
	srv.ServeHTTP(dailyRec, dailyReq)

	if dailyRec.Code != http.StatusOK {
		t.Fatalf("GET /api/domains/app.example.com/usage got status %d", dailyRec.Code)
	}
	var dailyResp struct {
		Days []struct {
			Date          string `json:"date"`
			BytesSent     int64  `json:"bytes_sent"`
			BytesReceived int64  `json:"bytes_received"`
		} `json:"days"`
	}
	if err := json.Unmarshal(dailyRec.Body.Bytes(), &dailyResp); err != nil {
		t.Fatalf("unmarshal daily usage: %v", err)
	}
	if len(dailyResp.Days) != 2 {
		t.Fatalf("expected 2 daily usage rows, got %d", len(dailyResp.Days))
	}

	// 3. GET /api/domains/app.example.com/usage/monthly?months=12
	monRec := httptest.NewRecorder()
	monReq := httptest.NewRequest("GET", "/api/domains/app.example.com/usage/monthly?months=12", nil)
	monReq.AddCookie(sessionCookie)
	srv.ServeHTTP(monRec, monReq)

	if monRec.Code != http.StatusOK {
		t.Fatalf("GET monthly usage status %d", monRec.Code)
	}
	var monResp struct {
		Months []struct {
			Month         string `json:"month"`
			BytesSent     int64  `json:"bytes_sent"`
			BytesReceived int64  `json:"bytes_received"`
		} `json:"months"`
	}
	if err := json.Unmarshal(monRec.Body.Bytes(), &monResp); err != nil {
		t.Fatalf("unmarshal monthly usage: %v", err)
	}
	if len(monResp.Months) != 2 {
		t.Fatalf("expected 2 monthly rows, got %d", len(monResp.Months))
	}

	// 4. GET /api/domains/app.example.com/usage/users
	uRec := httptest.NewRecorder()
	uReq := httptest.NewRequest("GET", "/api/domains/app.example.com/usage/users", nil)
	uReq.AddCookie(sessionCookie)
	srv.ServeHTTP(uRec, uReq)

	if uRec.Code != http.StatusOK {
		t.Fatalf("GET domain usage users status %d", uRec.Code)
	}
	var uResp struct {
		Users []struct {
			UserID        int64  `json:"user_id"`
			Username      string `json:"username"`
			BytesSent     int64  `json:"bytes_sent"`
			BytesReceived int64  `json:"bytes_received"`
		} `json:"users"`
	}
	if err := json.Unmarshal(uRec.Body.Bytes(), &uResp); err != nil {
		t.Fatalf("unmarshal domain users: %v", err)
	}
	if len(uResp.Users) != 1 || uResp.Users[0].Username != "panel_alice" {
		t.Errorf("domain users got %+v, want user panel_alice", uResp.Users)
	}

	// 5. GET /api/users/{id}/usage/domains
	userDomRec := httptest.NewRecorder()
	userDomReq := httptest.NewRequest("GET", fmt.Sprintf("/api/users/%d/usage/domains", u1.ID), nil)
	userDomReq.AddCookie(sessionCookie)
	srv.ServeHTTP(userDomRec, userDomReq)

	if userDomRec.Code != http.StatusOK {
		t.Fatalf("GET user usage domains status %d", userDomRec.Code)
	}
	var userDomResp struct {
		Domains []struct {
			Domain        string `json:"domain"`
			BytesSent     int64  `json:"bytes_sent"`
			BytesReceived int64  `json:"bytes_received"`
		} `json:"domains"`
	}
	if err := json.Unmarshal(userDomRec.Body.Bytes(), &userDomResp); err != nil {
		t.Fatalf("unmarshal user domains: %v", err)
	}
	if len(userDomResp.Domains) != 1 || userDomResp.Domains[0].Domain != "app.example.com" {
		t.Errorf("user domains got %+v, want app.example.com", userDomResp.Domains)
	}

	// 6. Delete domain rule from domain_rules, verify historical usage survives
	if err := sqStore.DeleteDomainRule(ctx, "app.example.com"); err != nil {
		t.Fatalf("DeleteDomainRule: %v", err)
	}

	delDailyRec := httptest.NewRecorder()
	delDailyReq := httptest.NewRequest("GET", "/api/domains/app.example.com/usage?days=365", nil)
	delDailyReq.AddCookie(sessionCookie)
	srv.ServeHTTP(delDailyRec, delDailyReq)

	if delDailyRec.Code != http.StatusOK {
		t.Fatalf("GET /api/domains/app.example.com/usage after rule deletion status %d", delDailyRec.Code)
	}
	var delDailyResp struct {
		Days []struct {
			Date string `json:"date"`
		} `json:"days"`
	}
	_ = json.Unmarshal(delDailyRec.Body.Bytes(), &delDailyResp)
	if len(delDailyResp.Days) != 2 {
		t.Errorf("expected 2 historical daily rows after rule deletion, got %d", len(delDailyResp.Days))
	}
}
