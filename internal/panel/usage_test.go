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

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// newUsagePanelServer creates a panel Server backed by a real SQLite store for
// usage endpoint tests, logs in, and returns the server plus auth cookies.
func newUsagePanelServer(t *testing.T) (*panel.Server, *sqlitestore.Store, *http.Cookie, *http.Cookie) {
	t.Helper()
	t.Setenv("PANEL_ADMIN_USER", "admin")
	t.Setenv("PANEL_ADMIN_PASSWORD", "secret123")

	dbPath := filepath.Join(t.TempDir(), "usage_test.db")
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

	// Log in.
	loginRec := httptest.NewRecorder()
	loginReq := httptest.NewRequest("POST", "/api/login",
		strings.NewReader(`{"username":"admin","password":"secret123"}`))
	loginReq.Header.Set("Content-Type", "application/json")
	srv.ServeHTTP(loginRec, loginReq)
	if loginRec.Code != http.StatusOK {
		t.Fatalf("login failed: status %d, body: %s", loginRec.Code, loginRec.Body.String())
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
		t.Fatal("missing session or csrf cookie after login")
	}
	return srv, sqStore, sessionCookie, csrfCookie
}

// authGET sends an authenticated GET request.
func authGET(t *testing.T, srv *panel.Server, path string, session *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", path, nil)
	req.AddCookie(session)
	srv.ServeHTTP(rec, req)
	return rec
}

// authPOST sends an authenticated POST request with CSRF header.
func authPOST(t *testing.T, srv *panel.Server, path, body string, session, csrf *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", csrf.Value)
	req.AddCookie(session)
	srv.ServeHTTP(rec, req)
	return rec
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// TestUsageAPI_UsersListHasTotalUsageFields verifies that /api/users includes
// the new total_bytes_sent and total_bytes_received fields.
func TestUsageAPI_UsersListHasTotalUsageFields(t *testing.T) {
	srv, sqStore, session, csrf := newUsagePanelServer(t)

	// Create a user and add some usage.
	u, err := sqStore.CreateUser(context.Background(), "usagealice", 3)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := sqStore.IncrementUserUsage(context.Background(), u.ID, 1000, 2000, time.Now()); err != nil {
		t.Fatalf("IncrementUserUsage: %v", err)
	}

	rec := authGET(t, srv, "/api/users", session)
	_ = csrf // keep linter quiet
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/users: status %d, body: %s", rec.Code, rec.Body.String())
	}

	var resp struct {
		Users []struct {
			ID                 int64 `json:"id"`
			TotalBytesSent     int64 `json:"total_bytes_sent"`
			TotalBytesReceived int64 `json:"total_bytes_received"`
		} `json:"users"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode /api/users response: %v", err)
	}
	if len(resp.Users) == 0 {
		t.Fatal("expected at least one user in response")
	}

	var found bool
	for _, uu := range resp.Users {
		if uu.ID == u.ID {
			found = true
			if uu.TotalBytesSent != 1000 {
				t.Errorf("total_bytes_sent: got %d, want 1000", uu.TotalBytesSent)
			}
			if uu.TotalBytesReceived != 2000 {
				t.Errorf("total_bytes_received: got %d, want 2000", uu.TotalBytesReceived)
			}
		}
	}
	if !found {
		t.Errorf("user %d not found in /api/users response", u.ID)
	}
}

// TestUsageAPI_GetUserUsageDaily verifies /api/users/{id}/usage returns daily rows.
func TestUsageAPI_GetUserUsageDaily(t *testing.T) {
	srv, sqStore, session, _ := newUsagePanelServer(t)

	u, err := sqStore.CreateUser(context.Background(), "dailyuser", 3)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	day := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	if err := sqStore.IncrementUserUsage(context.Background(), u.ID, 500, 750, day); err != nil {
		t.Fatalf("IncrementUserUsage: %v", err)
	}

	// Request with days=400 to include the historical date we inserted.
	rec := authGET(t, srv, fmt.Sprintf("/api/users/%d/usage?days=400", u.ID), session)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/users/%d/usage: status %d, body: %s", u.ID, rec.Code, rec.Body.String())
	}

	var resp struct {
		Days []struct {
			Date          string `json:"date"`
			BytesSent     int64  `json:"bytes_sent"`
			BytesReceived int64  `json:"bytes_received"`
		} `json:"days"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(resp.Days) == 0 {
		t.Fatal("expected at least one daily row")
	}
	r := resp.Days[0]
	if r.Date != "2026-06-01" {
		t.Errorf("date: got %q, want %q", r.Date, "2026-06-01")
	}
	if r.BytesSent != 500 {
		t.Errorf("bytes_sent: got %d, want 500", r.BytesSent)
	}
	if r.BytesReceived != 750 {
		t.Errorf("bytes_received: got %d, want 750", r.BytesReceived)
	}
}

// TestUsageAPI_GetGlobalUsageDaily verifies /api/usage/daily aggregates across users.
func TestUsageAPI_GetGlobalUsageDaily(t *testing.T) {
	srv, sqStore, session, _ := newUsagePanelServer(t)

	u1, _ := sqStore.CreateUser(context.Background(), "globalA", 3)
	u2, _ := sqStore.CreateUser(context.Background(), "globalB", 3)

	day := time.Date(2026, 7, 4, 0, 0, 0, 0, time.UTC)
	_ = sqStore.IncrementUserUsage(context.Background(), u1.ID, 100, 200, day)
	_ = sqStore.IncrementUserUsage(context.Background(), u2.ID, 300, 400, day)

	rec := authGET(t, srv, "/api/usage/daily?days=400", session)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/usage/daily: status %d, body: %s", rec.Code, rec.Body.String())
	}

	var resp struct {
		Days []struct {
			Date          string `json:"date"`
			BytesSent     int64  `json:"bytes_sent"`
			BytesReceived int64  `json:"bytes_received"`
		} `json:"days"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(resp.Days) == 0 {
		t.Fatal("expected at least one aggregated day")
	}

	// Find the day we inserted.
	var found bool
	for _, r := range resp.Days {
		if r.Date == "2026-07-04" {
			found = true
			if r.BytesSent != 400 {
				t.Errorf("global bytes_sent: got %d, want 400 (100+300)", r.BytesSent)
			}
			if r.BytesReceived != 600 {
				t.Errorf("global bytes_received: got %d, want 600 (200+400)", r.BytesReceived)
			}
		}
	}
	if !found {
		t.Error("expected 2026-07-04 in global daily response")
	}
}

// TestUsageAPI_ResetUserUsage verifies POST /api/users/{id}/usage/reset wipes history.
func TestUsageAPI_ResetUserUsage(t *testing.T) {
	srv, sqStore, session, csrf := newUsagePanelServer(t)

	u, _ := sqStore.CreateUser(context.Background(), "resetuser", 3)
	day := time.Now().UTC()
	_ = sqStore.IncrementUserUsage(context.Background(), u.ID, 9999, 8888, day)

	// Reset.
	rec := authPOST(t, srv, fmt.Sprintf("/api/users/%d/usage/reset", u.ID), `{}`, session, csrf)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /api/users/%d/usage/reset: status %d, body: %s", u.ID, rec.Code, rec.Body.String())
	}

	// Verify daily rows are empty.
	rows, err := sqStore.GetUserUsageDaily(context.Background(), u.ID, day.AddDate(0, 0, -1))
	if err != nil {
		t.Fatalf("GetUserUsageDaily after reset: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("expected 0 daily rows after reset, got %d", len(rows))
	}

	// Verify total is zeroed.
	totals, err := sqStore.GetUsersTotalUsage(context.Background(), time.Time{})
	if err != nil {
		t.Fatalf("GetUsersTotalUsage after reset: %v", err)
	}
	if tot := totals[u.ID]; tot.Sent != 0 || tot.Received != 0 {
		t.Errorf("totals after reset: sent=%d received=%d (want 0,0)", tot.Sent, tot.Received)
	}
}
