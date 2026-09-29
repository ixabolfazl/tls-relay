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

func TestConnect_RateLimiting(t *testing.T) {
	store := newTestStore(t)
	as := access.NewAccessStore(access.ModeUser)
	ctx := context.Background()

	user, _ := store.CreateUser(ctx, "ratelimited_user", 20)
	_, handler := createHandler(t, store, as)

	// Burst is 10. First 10 should succeed.
	for i := 0; i < 10; i++ {
		req := httptest.NewRequest("GET", "/connect/"+user.MagicLink, nil)
		req.Header.Set("User-Agent", "curl/7.88.1")
		req.RemoteAddr = "192.0.2.1:12345"
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("request %d failed: %d", i+1, w.Code)
		}
	}

	// 11th request from the same IP must hit rate limit (429)
	req := httptest.NewRequest("GET", "/connect/"+user.MagicLink, nil)
	req.Header.Set("User-Agent", "curl/7.88.1")
	req.RemoteAddr = "192.0.2.1:12345"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 Too Many Requests, got %d", w.Code)
	}
	if retryAfter := w.Header().Get("Retry-After"); retryAfter == "" {
		t.Errorf("expected Retry-After header on 429 response")
	}
}

func TestConnect_BotUserAgent(t *testing.T) {
	store := newTestStore(t)
	as := access.NewAccessStore(access.ModeUser)
	ctx := context.Background()

	user, _ := store.CreateUser(ctx, "bot_user", 5)
	_, handler := createHandler(t, store, as)

	botUAs := []string{
		"TelegramBot (like TwitterBot)",
		"WhatsApp/2.21.12.21 A",
		"facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)",
		"Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)",
		"Mozilla/5.0 (compatible; Discordbot/2.0; +https://discordapp.com)",
		"Twitterbot/1.0",
		"Googlebot/2.1 (+http://www.google.com/bot.html)",
		"bingbot/2.0; +http://www.bing.com/bingbot.htm",
	}

	for _, ua := range botUAs {
		req := httptest.NewRequest("GET", "/connect/"+user.MagicLink, nil)
		req.Header.Set("User-Agent", ua)
		req.RemoteAddr = "192.0.2.55:12345"
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("UA %q: expected 200, got %d", ua, w.Code)
		}
	}

	// Verify NO IP was registered by any bot
	ips, _ := store.ListUserIPs(ctx, user.ID)
	if len(ips) != 0 {
		t.Errorf("bots should NOT register IPs, found: %d IPs", len(ips))
	}
}

func TestLookup_Policy(t *testing.T) {
	store := newTestStore(t)
	as := access.NewAccessStore(access.ModeUser)
	ctx := context.Background()

	srv := portal.New(":0", store, as, &mockRefresher{})
	mux := http.NewServeMux()
	srv.RegisterHandlersWithLandingAt(mux)

	// 1. Lookup disabled -> 404
	srv.SetLookupPolicy(false, false)
	req := httptest.NewRequest("GET", "/api/lookup?domain=example.com", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 when lookup disabled, got %d: %s", w.Code, w.Body.String())
	}

	// 2. Lookup enabled, require_registered = true, unregistered caller -> 403
	srv.SetLookupPolicy(true, true)
	req = httptest.NewRequest("GET", "/api/lookup?domain=example.com", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for unregistered client, got %d: %s", w.Code, w.Body.String())
	}

	// 3. Register IP -> 200
	user, _ := store.CreateUser(ctx, "reg_user", 2)
	_ = store.RegisterIP(ctx, user.ID, "10.0.0.1", 2)

	req = httptest.NewRequest("GET", "/api/lookup?domain=example.com", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for registered client, got %d: %s", w.Code, w.Body.String())
	}
}

func TestLandingAndSetup_LookupCardHiddenWhenDisabled(t *testing.T) {
	store := newTestStore(t)
	as := access.NewAccessStore(access.ModeUser)

	srv := portal.New(":0", store, as, &mockRefresher{})
	mux := http.NewServeMux()
	srv.RegisterHandlersWithLandingAt(mux)

	// Disabled
	srv.SetLookupPolicy(false, false)
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "1.2.3.4:12345"
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if strings.Contains(w.Body.String(), "Domain Support Check") {
		t.Errorf("landing page should NOT contain Domain Support Check when lookup is disabled")
	}

	// Enabled
	srv.SetLookupPolicy(true, false)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if !strings.Contains(w.Body.String(), "Domain Support Check") {
		t.Errorf("landing page SHOULD contain Domain Support Check when lookup is enabled")
	}
}

func TestLandingPage_PublicModeOmitsRegistrationUI(t *testing.T) {
	store := newTestStore(t)
	as := access.NewAccessStore(access.ModePublic)

	srv := portal.New(":0", store, as, &mockRefresher{})
	srv.SetServerIP("203.0.113.10")
	mux := http.NewServeMux()
	srv.RegisterHandlersWithLandingAt(mux)

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.0.2.10:12345"
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	body := w.Body.String()

	// Must NOT contain registration UI
	forbiddenSubstrings := []string{
		"Register via Magic Link",
		"Registered",
		"Not Registered",
	}
	for _, sub := range forbiddenSubstrings {
		if strings.Contains(body, sub) {
			t.Errorf("landing page in public mode should not contain %q", sub)
		}
	}

	// Must still contain IP card and basic setup steps (without step 3)
	if !strings.Contains(body, "192.0.2.10") {
		t.Errorf("expected body to contain client IP")
	}
	if !strings.Contains(body, "Setup Instructions") {
		t.Errorf("expected body to contain Setup Instructions")
	}
	if !strings.Contains(body, "Open your device") {
		t.Errorf("expected body to contain device settings step")
	}
	if !strings.Contains(body, "Change DNS server to") {
		t.Errorf("expected body to contain change DNS server step")
	}
	if strings.Contains(body, "Ensure your IP is registered") {
		t.Errorf("setup instructions should omit registration step in public mode")
	}
}

func TestLandingPage_UserModeShowsRegistrationUI(t *testing.T) {
	store := newTestStore(t)
	as := access.NewAccessStore(access.ModeUser)
	ctx := context.Background()

	srv := portal.New(":0", store, as, &mockRefresher{})
	srv.SetServerIP("203.0.113.10")
	mux := http.NewServeMux()
	srv.RegisterHandlersWithLandingAt(mux)

	// 1. Unregistered IP
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.0.2.20:12345"
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "Not Registered") {
		t.Errorf("expected unregistered IP to show 'Not Registered' badge")
	}
	if !strings.Contains(body, "Register via Magic Link") {
		t.Errorf("expected body to contain 'Register via Magic Link' card")
	}
	if !strings.Contains(body, "Ensure your IP is registered (via Magic Link above).") {
		t.Errorf("expected setup instructions to contain registration step")
	}

	// 2. Registered IP
	user, err := store.CreateUser(ctx, "testuser", 2)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}
	if err := store.RegisterIP(ctx, user.ID, "192.0.2.20", 2); err != nil {
		t.Fatalf("failed to register IP: %v", err)
	}

	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	body = w.Body.String()
	if !strings.Contains(body, "✓ Registered") {
		t.Errorf("expected registered IP to show '✓ Registered' badge")
	}
}

func TestLandingPage_NilAccessStoreHandlesGracefully(t *testing.T) {
	srv := portal.New(":0", nil, nil, nil)
	srv.SetServerIP("203.0.113.10")
	mux := http.NewServeMux()
	srv.RegisterHandlersWithLandingAt(mux)

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.0.2.30:12345"
	w := httptest.NewRecorder()

	// Must not panic
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "192.0.2.30") {
		t.Errorf("expected body to contain client IP")
	}
}

func TestSetupSuccessPage_PublicModeOmitsRegisteredBadge(t *testing.T) {
	store := newTestStore(t)
	as := access.NewAccessStore(access.ModePublic)
	ctx := context.Background()

	user, err := store.CreateUser(ctx, "scriptuser", 3)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	_, handler := createHandler(t, store, as)

	// Browser request to /setup
	req := httptest.NewRequest("GET", "/setup", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.RemoteAddr = "192.0.2.40:12345"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if strings.Contains(w.Body.String(), "Registered") {
		t.Errorf("setup page in public mode should not contain 'Registered'")
	}

	// Browser request to /connect/{token}
	req = httptest.NewRequest("GET", "/connect/"+user.MagicLink, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.RemoteAddr = "192.0.2.40:12345"
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if strings.Contains(w.Body.String(), "Registered") {
		t.Errorf("connect success page in public mode should not contain 'Registered'")
	}

	// CLI request (curl) still succeeds and returns plain IP
	req = httptest.NewRequest("GET", "/connect/"+user.MagicLink, nil)
	req.Header.Set("User-Agent", "curl/7.88.1")
	req.RemoteAddr = "192.0.2.41:12345"
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if body := strings.TrimSpace(w.Body.String()); body != "192.0.2.41" {
		t.Errorf("expected '192.0.2.41', got %q", body)
	}
}
