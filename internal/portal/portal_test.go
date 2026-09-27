package portal_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ixabolfazl/tls-relay/internal/access"
	"github.com/ixabolfazl/tls-relay/internal/portal"
	"github.com/ixabolfazl/tls-relay/internal/sqlitestore"
)

// mockRefresher is a no-op refresher for tests.
type mockRefresher struct{}

func (m *mockRefresher) RefreshUserIPs(ctx context.Context) error { return nil }

func newTestStore(t *testing.T) *sqlitestore.Store {
	t.Helper()
	dir := t.TempDir()
	store, err := sqlitestore.New(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func createHandler(t *testing.T, store *sqlitestore.Store, as *access.AccessStore) (*portal.Server, http.Handler) {
	t.Helper()
	srv := portal.New(":0", store, as, &mockRefresher{})
	srv.SetServerIP("203.0.113.10")
	mux := http.NewServeMux()
	mux.HandleFunc("GET /connect/{magic_link}", srv.HandleConnectForTest)
	mux.HandleFunc("GET /setup/{magic_link}", srv.HandleConnectForTest)
	mux.HandleFunc("GET /setup", srv.HandleConnectForTest)
	return srv, mux
}

func TestValidRegistrationCurl(t *testing.T) {
	store := newTestStore(t)
	as := access.NewAccessStore(access.ModeUser)
	ctx := context.Background()

	user, _ := store.CreateUser(ctx, "alice", 3)

	_, handler := createHandler(t, store, as)
	req := httptest.NewRequest("GET", "/connect/"+user.MagicLink, nil)
	req.Header.Set("User-Agent", "curl/7.88.1")
	req.RemoteAddr = "1.2.3.4:12345"
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if contentType := w.Header().Get("Content-Type"); !strings.HasPrefix(contentType, "text/plain") {
		t.Errorf("expected text/plain content type, got %q", contentType)
	}
	if body := w.Body.String(); body != "1.2.3.4\n" {
		t.Errorf("unexpected body for curl request: %q", body)
	}

	// Verify IP was registered
	ips, _ := store.ListUserIPs(ctx, user.ID)
	if len(ips) != 1 || ips[0].IPAddress != "1.2.3.4" {
		t.Error("IP should be registered in database")
	}
}

func TestValidRegistrationBrowser(t *testing.T) {
	store := newTestStore(t)
	as := access.NewAccessStore(access.ModeUser)
	ctx := context.Background()

	user, _ := store.CreateUser(ctx, "alice", 3)

	_, handler := createHandler(t, store, as)
	req := httptest.NewRequest("GET", "/connect/"+user.MagicLink, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	req.RemoteAddr = "198.51.100.55:12345"
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	body := w.Body.String()
	if !strings.Contains(body, "198.51.100.55") {
		t.Errorf("expected body to contain registered IP 198.51.100.55, got: %s", body)
	}
}

func TestSetupEndpoint(t *testing.T) {
	store := newTestStore(t)
	as := access.NewAccessStore(access.ModeUser)

	_, handler := createHandler(t, store, as)

	// Direct /setup request without magic_link token
	req := httptest.NewRequest("GET", "/setup", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.RemoteAddr = "192.0.2.1:12345"
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "192.0.2.1") {
		t.Errorf("expected body to contain client IP, got: %s", body)
	}
	if !strings.Contains(body, "203.0.113.10") {
		t.Errorf("expected body to contain primary DNS IP, got: %s", body)
	}
}

func TestInvalidLink(t *testing.T) {
	store := newTestStore(t)
	as := access.NewAccessStore(access.ModeUser)

	_, handler := createHandler(t, store, as)
	req := httptest.NewRequest("GET", "/connect/nonexistent-link", nil)
	req.Header.Set("User-Agent", "curl/7.88.1")
	req.RemoteAddr = "1.2.3.4:12345"
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestDisabledUser(t *testing.T) {
	store := newTestStore(t)
	as := access.NewAccessStore(access.ModeUser)
	ctx := context.Background()

	user, _ := store.CreateUser(ctx, "bob", 3)
	_ = store.UpdateUser(ctx, user.ID, false, 3)

	_, handler := createHandler(t, store, as)
	req := httptest.NewRequest("GET", "/connect/"+user.MagicLink, nil)
	req.Header.Set("User-Agent", "curl/7.88.1")
	req.RemoteAddr = "1.2.3.4:12345"
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}
}

func TestBlacklistRejection(t *testing.T) {
	store := newTestStore(t)
	as := access.NewAccessStore(access.ModeUser)
	_ = as.SwapBlacklist([]string{"1.2.3.4"})
	ctx := context.Background()

	user, _ := store.CreateUser(ctx, "charlie", 3)

	_, handler := createHandler(t, store, as)
	req := httptest.NewRequest("GET", "/connect/"+user.MagicLink, nil)
	req.Header.Set("User-Agent", "curl/7.88.1")
	req.RemoteAddr = "1.2.3.4:12345"
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for blacklisted IP, got %d", w.Code)
	}
}

func TestMaxIPsEviction(t *testing.T) {
	store := newTestStore(t)
	as := access.NewAccessStore(access.ModeUser)
	ctx := context.Background()

	user, _ := store.CreateUser(ctx, "dave", 2)

	_, handler := createHandler(t, store, as)

	for _, ip := range []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"} {
		req := httptest.NewRequest("GET", "/connect/"+user.MagicLink, nil)
		req.Header.Set("User-Agent", "curl/7.88.1")
		req.RemoteAddr = ip + ":12345"
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("registration failed for %s: %d", ip, w.Code)
		}
	}

	ips, _ := store.ListUserIPs(ctx, user.ID)
	if len(ips) != 2 {
		t.Fatalf("expected 2 IPs, got %d", len(ips))
	}
	// Oldest IP (10.0.0.1) should have been evicted
	for _, ip := range ips {
		if ip.IPAddress == "10.0.0.1" {
			t.Error("oldest IP 10.0.0.1 should have been evicted")
		}
	}
}

func TestDuplicateIPUpdatesLastUsed(t *testing.T) {
	store := newTestStore(t)
	as := access.NewAccessStore(access.ModeUser)
	ctx := context.Background()

	user, _ := store.CreateUser(ctx, "eve", 2)

	_, handler := createHandler(t, store, as)

	req := httptest.NewRequest("GET", "/connect/"+user.MagicLink, nil)
	req.Header.Set("User-Agent", "curl/7.88.1")
	req.RemoteAddr = "10.0.0.1:12345"

	w1 := httptest.NewRecorder()
	handler.ServeHTTP(w1, req)
	if w1.Code != http.StatusOK {
		t.Fatalf("first registration failed: %d", w1.Code)
	}

	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, req)
	if w2.Code != http.StatusOK {
		t.Fatalf("second registration failed: %d", w2.Code)
	}

	ips, _ := store.ListUserIPs(ctx, user.ID)
	if len(ips) != 1 {
		t.Fatalf("expected 1 IP entry, got %d", len(ips))
	}
}

func TestBaseHostAndBaseURL(t *testing.T) {
	srv := portal.New(":0", nil, nil, nil)
	srv.SetServerIP("198.51.100.1")

	req := httptest.NewRequest("GET", "http://198.51.100.1/test", nil)

	// 1. Without domain -> uses server IP
	if host := srv.BaseHost(req); host != "198.51.100.1" {
		t.Errorf("expected BaseHost '198.51.100.1', got %q", host)
	}
	if url := srv.BaseURL(req); url != "http://198.51.100.1" {
		t.Errorf("expected BaseURL 'http://198.51.100.1', got %q", url)
	}

	// 2. With domain set -> uses domain
	srv.SetServerDomain("dns.example.com")
	if host := srv.BaseHost(req); host != "dns.example.com" {
		t.Errorf("expected BaseHost 'dns.example.com', got %q", host)
	}
	if url := srv.BaseURL(req); url != "http://dns.example.com" {
		t.Errorf("expected BaseURL 'http://dns.example.com', got %q", url)
	}

	// 3. Clear domain -> reverts to IP
	srv.SetServerDomain("")
	if host := srv.BaseHost(req); host != "198.51.100.1" {
		t.Errorf("expected BaseHost '198.51.100.1', got %q", host)
	}
	if url := srv.BaseURL(req); url != "http://198.51.100.1" {
		t.Errorf("expected BaseURL 'http://198.51.100.1', got %q", url)
	}
}
