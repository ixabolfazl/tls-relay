// Package panel provides the HTTP admin panel server.
package panel

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/ixabolfazl/tls-relay/internal/access"
	"github.com/ixabolfazl/tls-relay/internal/dnsresolver"
	"github.com/ixabolfazl/tls-relay/internal/relay"
	"github.com/ixabolfazl/tls-relay/internal/requestlog"
	"github.com/ixabolfazl/tls-relay/internal/rules"
	"github.com/ixabolfazl/tls-relay/internal/sqlitestore"
)

//go:embed static
var staticFiles embed.FS

// sessionInfo holds session expiration and CSRF token.
type sessionInfo struct {
	expiry    time.Time
	csrfToken string
}

// sessionStore is a minimal in-memory session store.
type sessionStore struct {
	mu       sync.Mutex
	sessions map[string]*sessionInfo // token → info
}

func newSessionStore() *sessionStore {
	return &sessionStore{sessions: make(map[string]*sessionInfo)}
}

const sessionCookieName = "relay_session"
const csrfCookieName = "relay_csrf"
const csrfHeaderName = "X-CSRF-Token"
const sessionTTL = 8 * time.Hour

func (s *sessionStore) create() (sessionToken string, csrfToken string) {
	sessionToken = randomHex(32)
	csrfToken = randomHex(16)
	now := time.Now()
	s.mu.Lock()
	// Passive expiration cleanup of stale sessions on creation:
	for tok, info := range s.sessions {
		if now.After(info.expiry) {
			delete(s.sessions, tok)
		}
	}
	s.sessions[sessionToken] = &sessionInfo{
		expiry:    now.Add(sessionTTL),
		csrfToken: csrfToken,
	}
	s.mu.Unlock()
	return sessionToken, csrfToken
}

func (s *sessionStore) valid(token string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	info, ok := s.sessions[token]
	if !ok {
		return false
	}
	if time.Now().After(info.expiry) {
		delete(s.sessions, token)
		return false
	}
	return true
}

func (s *sessionStore) validCSRF(sessionToken string, csrfHeader string) bool {
	if csrfHeader == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	info, ok := s.sessions[sessionToken]
	if !ok {
		return false
	}
	if time.Now().After(info.expiry) {
		delete(s.sessions, sessionToken)
		return false
	}
	return info.csrfToken != "" && info.csrfToken == csrfHeader
}

func (s *sessionStore) delete(token string) {
	s.mu.Lock()
	delete(s.sessions, token)
	s.mu.Unlock()
}

// loginAttempt tracks failed login attempt count and lockout expiration per IP.
type loginAttempt struct {
	count        int
	lockoutUntil time.Time
}

// loginLimiter protects the login endpoint against brute-force attacks.
type loginLimiter struct {
	mu              sync.Mutex
	maxAttempts     int
	lockoutDuration time.Duration
	attempts        map[string]*loginAttempt
}

func newLoginLimiter(maxAttempts int, lockoutDuration time.Duration) *loginLimiter {
	return &loginLimiter{
		maxAttempts:     maxAttempts,
		lockoutDuration: lockoutDuration,
		attempts:        make(map[string]*loginAttempt),
	}
}

func (l *loginLimiter) isLockedOut(ip string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	att, ok := l.attempts[ip]
	if !ok {
		return false, 0
	}
	if now.Before(att.lockoutUntil) {
		return true, att.lockoutUntil.Sub(now)
	}
	return false, 0
}

func (l *loginLimiter) recordFailure(ip string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()

	// Periodic cleanup of stale attempts if map grows large
	if len(l.attempts) > 100 {
		for k, v := range l.attempts {
			if !v.lockoutUntil.IsZero() && now.After(v.lockoutUntil) {
				delete(l.attempts, k)
			}
		}
	}

	att, ok := l.attempts[ip]
	if !ok {
		att = &loginAttempt{}
		l.attempts[ip] = att
	}
	if !att.lockoutUntil.IsZero() && now.After(att.lockoutUntil) {
		att.count = 0
		att.lockoutUntil = time.Time{}
	}
	att.count++
	if att.count >= l.maxAttempts {
		att.lockoutUntil = now.Add(l.lockoutDuration)
		return true, l.lockoutDuration
	}
	return false, 0
}

func (l *loginLimiter) recordSuccess(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.attempts, ip)
}

func getClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func randomHex(n int) string {
	const hex = "0123456789abcdef"
	b := make([]byte, n)
	if _, err := cryptoRandRead(b); err != nil {
		panic("panel: random token generation failed: " + err.Error())
	}
	out := make([]byte, n*2)
	for i, v := range b {
		out[i*2] = hex[v>>4]
		out[i*2+1] = hex[v&0xf]
	}
	return string(out)
}

// Refresher is the interface for triggering cache refreshes after writes.
type Refresher interface {
	RefreshDomains(ctx context.Context) error
	RefreshBlacklist(ctx context.Context) error
	RefreshUserIPs(ctx context.Context) error
}

// PortalHandlerRegistrar is implemented by the portal.Server so the
// panel can embed its public routes (landing page, /connect/, /setup/, /api/lookup)
// into the panel's HTTP mux without running a separate listener.
type PortalHandlerRegistrar interface {
	RegisterHandlersWithLandingAt(mux *http.ServeMux)
	SetServerDomain(domain string)
}

// MagicLinkHandlerRegistrar is an alias for backward compatibility.
type MagicLinkHandlerRegistrar = PortalHandlerRegistrar

// Server is the admin panel HTTP server.
type Server struct {
	addr            string
	mu              sync.RWMutex
	pathPrefix      string // normalized active path prefix: e.g. "" for root "/", or "/admin"
	activeMux       atomic.Pointer[http.ServeMux]
	timezone        atomic.Pointer[string]
	passHash        []byte
	username        string
	serverDomain    string
	ruleStore       *rules.RuleStore
	accessStore     *access.AccessStore
	sqlStore        *sqlitestore.Store
	connTracker     *relay.ConnTracker
	reqLogger       *requestlog.Logger
	limits          *relay.LimitTracker
	dnsServer       *dnsresolver.Server
	egressDialer    *relay.EgressDialer
	allowList       *relay.PortAllowList
	listenPorts     []int
	listenHTTPPorts []int
	restartHandler  func()
	refresher       Refresher
	sessions        *sessionStore
	loginLimiter    *loginLimiter
	startTime       time.Time
	httpServer      *http.Server
	portalSrv       PortalHandlerRegistrar
}

// New creates a Server. Username and password are read from SQLite if stored,
// or fallback to environment variables PANEL_ADMIN_USER and PANEL_ADMIN_PASSWORD.
func New(
	addr string,
	pathPrefix string,
	rs *rules.RuleStore,
	as *access.AccessStore,
	sq *sqlitestore.Store,
	refresher Refresher,
) (*Server, error) {
	user := os.Getenv("PANEL_ADMIN_USER")
	pass := os.Getenv("PANEL_ADMIN_PASSWORD")

	var hash []byte
	// Check SQLite for persisted admin credentials
	if sq != nil {
		if dbUser, found, _ := sq.GetSetting(context.Background(), "panel_admin_user"); found && strings.TrimSpace(dbUser) != "" {
			user = strings.TrimSpace(dbUser)
		}
		if dbHash, found, _ := sq.GetSetting(context.Background(), "panel_admin_password_hash"); found && strings.TrimSpace(dbHash) != "" {
			hash = []byte(strings.TrimSpace(dbHash))
		}
	}

	if len(hash) == 0 && pass != "" {
		var err error
		hash, err = bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
		if err != nil {
			return nil, fmt.Errorf("hashing panel password: %w", err)
		}
	}

	if user == "" || len(hash) == 0 {
		slog.Warn("PANEL_ADMIN_USER or PANEL_ADMIN_PASSWORD is not set; panel login will be disabled until configured")
	}

	var initialDomain string
	if sq != nil {
		if val, found, err := sq.GetSetting(context.Background(), "server_domain"); err == nil && found {
			initialDomain = strings.TrimSpace(val)
		}
	}

	s := &Server{
		addr:         addr,
		passHash:     hash,
		username:     user,
		serverDomain: initialDomain,
		ruleStore:    rs,
		accessStore:  as,
		sqlStore:     sq,
		refresher:    refresher,
		sessions:     newSessionStore(),
		loginLimiter: newLoginLimiter(5, 5*time.Minute),
		startTime:    time.Now(),
	}

	if err := s.ApplyPathPrefix(pathPrefix); err != nil {
		return nil, fmt.Errorf("applying path prefix: %w", err)
	}

	return s, nil
}

// SetPortAllowList registers a PortAllowList for runtime allowed destination ports management.
func (s *Server) SetPortAllowList(pal *relay.PortAllowList) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.allowList = pal
}

// SetListenPorts registers the active TLS listen ports for status display.
func (s *Server) SetListenPorts(ports []int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.listenPorts = ports
}

// SetListenHTTPPorts registers the active HTTP listen ports for status display.
func (s *Server) SetListenHTTPPorts(ports []int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.listenHTTPPorts = ports
}

// SetRestartHandler registers the callback to invoke when a service restart is requested from the panel.
func (s *Server) SetRestartHandler(fn func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.restartHandler = fn
}

// AdminUsername returns the current admin username.
func (s *Server) AdminUsername() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.username
}

// UpdateAdminCredentials validates the current password and sets a new username and password.
func (s *Server) UpdateAdminCredentials(ctx context.Context, currentPass, newUser, newPass string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.passHash) > 0 {
		if err := bcrypt.CompareHashAndPassword(s.passHash, []byte(currentPass)); err != nil {
			return fmt.Errorf("invalid current password")
		}
	}

	newUser = strings.TrimSpace(newUser)
	if newUser == "" {
		newUser = s.username
	}
	if newUser == "" {
		return fmt.Errorf("username cannot be empty")
	}

	newPass = strings.TrimSpace(newPass)
	if newPass == "" {
		return fmt.Errorf("new password cannot be empty")
	}
	if len(newPass) < 6 {
		return fmt.Errorf("new password must be at least 6 characters")
	}

	newHash, err := bcrypt.GenerateFromPassword([]byte(newPass), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hashing new password: %w", err)
	}

	if s.sqlStore != nil {
		if err := s.sqlStore.SetSetting(ctx, "panel_admin_user", newUser); err != nil {
			return fmt.Errorf("saving admin user: %w", err)
		}
		if err := s.sqlStore.SetSetting(ctx, "panel_admin_password_hash", string(newHash)); err != nil {
			return fmt.Errorf("saving admin password: %w", err)
		}
	}

	s.username = newUser
	s.passHash = newHash
	return nil
}

// SetConnTracker registers a ConnTracker for live user presence monitoring.
func (s *Server) SetConnTracker(ct *relay.ConnTracker) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.connTracker = ct
}

// SetPortalServer registers a portal server whose public routes
// (landing page, /connect/, /setup/, /api/lookup) will be embedded into
// the panel mux when the panel path prefix is non-root.
func (s *Server) SetPortalServer(p PortalHandlerRegistrar) {
	s.mu.Lock()
	s.portalSrv = p
	domain := s.serverDomain
	prefix := s.pathPrefix
	s.mu.Unlock()

	if p != nil && domain != "" {
		p.SetServerDomain(domain)
	}

	// Rebuild mux to include the new handler (outside lock to avoid deadlock).
	_ = s.applyPathPrefixInternal(prefix)
}

// SetMagicLinkServer is an alias for SetPortalServer.
func (s *Server) SetMagicLinkServer(ml PortalHandlerRegistrar) {
	s.SetPortalServer(ml)
}

// SetServerDomain sets the public domain name or hostname for client URLs.
func (s *Server) SetServerDomain(domain string) {
	s.mu.Lock()
	s.serverDomain = strings.TrimSpace(domain)
	portal := s.portalSrv
	s.mu.Unlock()

	if portal != nil {
		portal.SetServerDomain(s.serverDomain)
	}
}

// ServerDomain returns the configured server domain.
func (s *Server) ServerDomain() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.serverDomain
}

// BaseHost returns the server domain if configured, otherwise falls back to request host or server IP.
func (s *Server) BaseHost(r *http.Request) string {
	s.mu.RLock()
	domain := s.serverDomain
	s.mu.RUnlock()

	if domain != "" {
		return domain
	}
	if r != nil {
		host, _, err := net.SplitHostPort(r.Host)
		if err == nil && host != "" {
			return host
		}
		if r.Host != "" {
			return r.Host
		}
	}
	return "—"
}

// BaseURL returns the canonical base URL (using http:// for the standard port 80 service).
func (s *Server) BaseURL(r *http.Request) string {
	host := s.BaseHost(r)
	if host == "—" || host == "" {
		return "http://localhost"
	}
	return "http://" + host
}

// SetRequestLogger registers a request logger instance with the panel.
func (s *Server) SetRequestLogger(l *requestlog.Logger) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reqLogger = l
}

// SetLimitTracker registers a LimitTracker instance for dynamic limit adjustments.
func (s *Server) SetLimitTracker(lt *relay.LimitTracker) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.limits = lt
}

// SetDNSServer registers a DNS server instance for runtime settings management.
func (s *Server) SetDNSServer(dns *dnsresolver.Server) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dnsServer = dns
}

// SetEgressDialer registers the EgressDialer instance for egress proxy status inspection.
func (s *Server) SetEgressDialer(ed *relay.EgressDialer) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.egressDialer = ed
}

func (s *Server) refreshDomains(ctx context.Context) error {
	if s.refresher != nil {
		return s.refresher.RefreshDomains(ctx)
	}
	return nil
}

func (s *Server) refreshBlacklist(ctx context.Context) error {
	if s.refresher != nil {
		return s.refresher.RefreshBlacklist(ctx)
	}
	return nil
}

func (s *Server) refreshUserIPs(ctx context.Context) error {
	if s.refresher != nil {
		return s.refresher.RefreshUserIPs(ctx)
	}
	return nil
}

// ServeHTTP implements http.Handler, loading the current active ServeMux atomically.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Baseline defensive HTTP security headers
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

	// Limit request body size to 10MB to prevent memory exhaustion DoS
	if r.Body != nil {
		r.Body = http.MaxBytesReader(w, r.Body, 10<<20)
	}

	mux := s.activeMux.Load()
	if mux != nil {
		mux.ServeHTTP(w, r)
		return
	}
	http.NotFound(w, r)
}

// PathPrefix returns the normalized active path prefix (e.g. "" for root "/", or "/admin").
func (s *Server) PathPrefix() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.pathPrefix
}

// DisplayPath returns a human-readable representation of the active path ("/" or "/admin").
func (s *Server) DisplayPath() string {
	p := s.PathPrefix()
	if p == "" {
		return "/"
	}
	return p
}

func (s *Server) displayPath() string {
	return s.DisplayPath()
}

// Addr returns the configured listen address string (read-only).
func (s *Server) Addr() string {
	return s.addr
}

// SetTimezone validates and updates the active timezone setting.
func (s *Server) SetTimezone(tz string) error {
	tz = strings.TrimSpace(tz)
	if tz == "" {
		tz = "UTC"
	}
	if _, err := time.LoadLocation(tz); err != nil {
		return fmt.Errorf("invalid timezone %q: %w", tz, err)
	}
	s.timezone.Store(&tz)
	return nil
}

// Timezone returns the active timezone string (e.g. "UTC", "Asia/Tehran").
func (s *Server) Timezone() string {
	tz := s.timezone.Load()
	if tz == nil || *tz == "" {
		return "UTC"
	}
	return *tz
}

// applyPathPrefixInternal rebuilds the mux for the given (already normalized) prefix.
// Must NOT be called while holding s.mu — registerRoutesWithPrefix acquires it via RLock.
func (s *Server) applyPathPrefixInternal(norm string) error {
	mux := http.NewServeMux()
	s.registerRoutesWithPrefix(mux, norm)
	s.activeMux.Store(mux)

	s.mu.Lock()
	s.pathPrefix = norm
	s.mu.Unlock()

	slog.Info("admin panel path prefix applied", "prefix", s.DisplayPath())
	return nil
}

// ApplyPathPrefix rebuilds the http.ServeMux with newPrefix and atomically swaps it in.
func (s *Server) ApplyPathPrefix(newPrefix string) error {
	norm := normalizePanelPathPrefix(newPrefix)
	return s.applyPathPrefixInternal(norm)
}

func normalizePanelPathPrefix(p string) string {
	p = strings.TrimRight(strings.TrimSpace(p), "/")
	if p == "/" || p == "" {
		return ""
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return p
}

// Serve starts the panel HTTP server on the provided listener and blocks until ctx is cancelled.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	s.httpServer = &http.Server{
		Addr:         s.addr,
		Handler:      s,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
	}
	slog.Info("admin panel listening", "addr", ln.Addr().String(), "path", s.DisplayPath())

	// Close the listener when ctx is cancelled.
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.httpServer.Shutdown(shutCtx)
	}()

	if err := s.httpServer.Serve(ln); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("panel server: %w", err)
	}
	return nil
}

// ListenAndServe starts the panel HTTP server and blocks until ctx is cancelled.
func (s *Server) ListenAndServe(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("panel listen on %s: %w", s.addr, err)
	}
	return s.Serve(ctx, ln)
}

func (s *Server) registerRoutes(mux *http.ServeMux) {
	s.registerRoutesWithPrefix(mux, s.PathPrefix())
}

func (s *Server) registerRoutesWithPrefix(mux *http.ServeMux, prefix string) {
	// Static files — serve index.html from embedded FS.
	staticFS, err := fs.Sub(staticFiles, "static")
	if err != nil {
		panic("panel: failed to sub static FS: " + err.Error())
	}

	// Static files endpoint
	fileServer := http.FileServer(http.FS(staticFS))
	mux.Handle("GET "+prefix+"/static/", http.StripPrefix(prefix+"/static/", fileServer))
	if prefix == "" {
		mux.Handle("GET /css/", fileServer)
		mux.Handle("GET /js/", fileServer)
		mux.Handle("GET /pages/", fileServer)
	} else {
		mux.Handle("GET "+prefix+"/css/", http.StripPrefix(prefix, fileServer))
		mux.Handle("GET "+prefix+"/js/", http.StripPrefix(prefix, fileServer))
		mux.Handle("GET "+prefix+"/pages/", http.StripPrefix(prefix, fileServer))
	}

	// Serve index.html for root or custom panel path
	if prefix == "" {
		mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/" {
				http.NotFound(w, r)
				return
			}
			s.serveIndex(w, r)
		})
	} else {
		// Non-root panel prefix: embed portal public routes at root.
		// This registers /connect/, /setup/, /api/lookup and GET /.
		s.mu.RLock()
		ml := s.portalSrv
		s.mu.RUnlock()
		if ml != nil {
			ml.RegisterHandlersWithLandingAt(mux)
		}

		// Redirect /admin to /admin/
		mux.HandleFunc("GET "+prefix, func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, prefix+"/", http.StatusFound)
		})

		indexPath := prefix + "/"
		mux.HandleFunc("GET "+indexPath, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != indexPath {
				http.NotFound(w, r)
				return
			}
			s.serveIndex(w, r)
		})
	}

	route := func(method, path string) string {
		return method + " " + prefix + path
	}

	// Auth endpoints (no auth required).
	mux.HandleFunc(route("POST", "/api/login"), s.handleLogin)
	mux.HandleFunc(route("POST", "/api/logout"), s.handleLogout)

	// Protected API endpoints — Domain rules.
	mux.HandleFunc(route("GET", "/api/domains"), s.auth(s.handleListDomains))
	mux.HandleFunc(route("POST", "/api/domains"), s.auth(s.handleAddDomain))
	mux.HandleFunc(route("POST", "/api/domains/bulk-delete"), s.auth(s.handleBulkDeleteDomains))
	mux.HandleFunc(route("POST", "/api/domains/bulk-assign-group"), s.auth(s.handleBulkAssignGroup))
	mux.HandleFunc(route("POST", "/api/domains/bulk-assign-egress"), s.auth(s.handleBulkAssignEgress))
	mux.HandleFunc(route("POST", "/api/domains/bulk-assign-mode"), s.auth(s.handleBulkAssignMode))
	mux.HandleFunc(route("PUT", "/api/domains/{domain}"), s.auth(s.handleUpdateDomain))
	mux.HandleFunc(route("DELETE", "/api/domains/{domain}"), s.auth(s.handleDeleteDomain))
	mux.HandleFunc(route("GET", "/api/domains/{domain}/usage"), s.auth(s.handleGetDomainUsage))
	mux.HandleFunc(route("GET", "/api/domains/{domain}/usage/monthly"), s.auth(s.handleGetDomainUsageMonthly))
	mux.HandleFunc(route("GET", "/api/domains/{domain}/usage/users"), s.auth(s.handleGetDomainUsageUsers))

	// Global blacklist.
	mux.HandleFunc(route("GET", "/api/blacklist"), s.auth(s.handleListBlacklist))
	mux.HandleFunc(route("POST", "/api/blacklist"), s.auth(s.handleAddBlacklist))
	mux.HandleFunc(route("POST", "/api/blacklist/bulk-delete"), s.auth(s.handleBulkDeleteBlacklist))
	mux.HandleFunc(route("DELETE", "/api/blacklist/{id}"), s.auth(s.handleDeleteBlacklist))

	// Users.
	mux.HandleFunc(route("GET", "/api/users"), s.auth(s.handleListUsers))
	mux.HandleFunc(route("POST", "/api/users"), s.auth(s.handleCreateUser))
	mux.HandleFunc(route("PUT", "/api/users/{id}"), s.auth(s.handleUpdateUser))
	mux.HandleFunc(route("DELETE", "/api/users/{id}"), s.auth(s.handleDeleteUser))
	mux.HandleFunc(route("GET", "/api/users/{id}/ips"), s.auth(s.handleListUserIPs))
	mux.HandleFunc(route("POST", "/api/users/{id}/ips"), s.auth(s.handleAddUserIP))
	mux.HandleFunc(route("DELETE", "/api/users/{id}/ips/{ip}"), s.auth(s.handleDeleteUserIP))
	mux.HandleFunc(route("POST", "/api/users/{id}/magic-link/reset"), s.auth(s.handleResetMagicLink))
	mux.HandleFunc(route("POST", "/api/users/{id}/magic-link/new"), s.auth(s.handleNewMagicLink))
	mux.HandleFunc(route("GET", "/api/users/{id}/usage"), s.auth(s.handleGetUserUsage))
	mux.HandleFunc(route("POST", "/api/users/{id}/usage/reset"), s.auth(s.handleResetUserUsage))
	mux.HandleFunc(route("GET", "/api/users/{id}/usage/domains"), s.auth(s.handleGetUserUsageDomains))

	// Presence / Online Users tracking.
	mux.HandleFunc(route("GET", "/api/presence"), s.auth(s.handleGetPresence))

	// Usage aggregation.
	mux.HandleFunc(route("GET", "/api/usage/daily"), s.auth(s.handleGetGlobalUsageDaily))

	// Export / Import / Backup.
	mux.HandleFunc(route("GET", "/api/export"), s.auth(s.handleExport))
	mux.HandleFunc(route("POST", "/api/import"), s.auth(s.handleImport))
	mux.HandleFunc(route("GET", "/api/backup"), s.auth(s.handleBackup))

	// Request Logs.
	mux.HandleFunc(route("GET", "/api/request-logs"), s.auth(s.handleListRequestLogs))
	mux.HandleFunc(route("POST", "/api/request-logs/clear"), s.auth(s.handleClearRequestLogs))

	// Live Statistics.
	mux.HandleFunc(route("GET", "/api/stats"), s.auth(s.handleGetStats))

	// Settings.
	mux.HandleFunc(route("GET", "/api/settings"), s.auth(s.handleGetSettings))
	mux.HandleFunc(route("PUT", "/api/settings"), s.auth(s.handleUpdateSettings))
	mux.HandleFunc(route("POST", "/api/settings/test-proxy"), s.auth(s.handleTestProxy))
	mux.HandleFunc(route("PUT", "/api/admin/credentials"), s.auth(s.handleUpdateAdminCredentials))
	mux.HandleFunc(route("POST", "/api/service/restart"), s.auth(s.handleServiceRestart))
	mux.HandleFunc(route("GET", "/api/request-stats/daily"), s.auth(s.handleGetRequestStatsDaily))
}

func (s *Server) serveIndex(w http.ResponseWriter, r *http.Request) {
	data, _ := staticFiles.ReadFile("static/index.html")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(data)
}

// ---------------------------------------------------------------------------
// Auth middleware
// ---------------------------------------------------------------------------

func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(sessionCookieName)
		if err != nil || !s.sessions.valid(cookie.Value) {
			jsonErr(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Enforce CSRF protection on state-modifying requests (POST, PUT, DELETE)
		if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodDelete {
			csrfHeader := r.Header.Get(csrfHeaderName)
			if !s.sessions.validCSRF(cookie.Value, csrfHeader) {
				jsonErr(w, "CSRF token missing or invalid", http.StatusForbidden)
				return
			}
		}

		next(w, r)
	}
}

// ---------------------------------------------------------------------------
// Login / Logout
// ---------------------------------------------------------------------------

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	clientIP := getClientIP(r)

	if locked, rem := s.loginLimiter.isLockedOut(clientIP); locked {
		mins := int(rem.Minutes()) + 1
		slog.Warn("admin panel login attempt blocked due to lockout", "remote_addr", r.RemoteAddr, "client_ip", clientIP)
		jsonErr(w, fmt.Sprintf("Too many failed login attempts. Account locked out for %d minutes.", mins), http.StatusTooManyRequests)
		return
	}

	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		slog.Warn("admin panel login request decoding error", "remote_addr", r.RemoteAddr, "error", err)
		jsonErr(w, "invalid request body", http.StatusBadRequest)
		return
	}

	s.mu.RLock()
	currentUsername := s.username
	currentPassHash := s.passHash
	s.mu.RUnlock()

	if currentUsername == "" || len(currentPassHash) == 0 {
		slog.Warn("admin panel login attempted but credentials are unconfigured", "remote_addr", r.RemoteAddr)
		jsonErr(w, "Admin credentials not configured on the server.", http.StatusForbidden)
		return
	}

	if req.Username != currentUsername || bcrypt.CompareHashAndPassword(currentPassHash, []byte(req.Password)) != nil {
		locked, rem := s.loginLimiter.recordFailure(clientIP)
		slog.Warn("admin panel login failed: invalid credentials", "username", req.Username, "remote_addr", r.RemoteAddr, "client_ip", clientIP)
		if locked {
			mins := int(rem.Minutes()) + 1
			jsonErr(w, fmt.Sprintf("Too many failed login attempts. Account locked out for %d minutes.", mins), http.StatusTooManyRequests)
			return
		}
		jsonErr(w, "Invalid credentials.", http.StatusUnauthorized)
		return
	}

	s.loginLimiter.recordSuccess(clientIP)

	token, csrfToken := s.sessions.create()
	isSecure := r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   isSecure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(sessionTTL.Seconds()),
	})
	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookieName,
		Value:    csrfToken,
		Path:     "/",
		HttpOnly: false,
		Secure:   isSecure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(sessionTTL.Seconds()),
	})
	slog.Info("admin panel login successful", "username", req.Username, "remote_addr", r.RemoteAddr, "client_ip", clientIP)
	jsonOK(w, map[string]string{"status": "ok", "csrf_token": csrfToken})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(sessionCookieName); err == nil {
		s.sessions.delete(cookie.Value)
	}
	isSecure := r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   isSecure,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: false,
		Secure:   isSecure,
	})
	slog.Info("admin panel logout", "remote_addr", r.RemoteAddr)
	jsonOK(w, map[string]string{"status": "ok"})
}

// formatISO8601 converts a raw SQLite datetime string ("2026-08-05 10:23:45")
// into an explicit ISO-8601 UTC string ("2026-08-05T10:23:45Z").
func formatISO8601(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if strings.Contains(raw, "T") && strings.HasSuffix(raw, "Z") {
		return raw
	}
	if t, err := time.Parse("2006-01-02 15:04:05", raw); err == nil {
		return t.UTC().Format("2006-01-02T15:04:05Z")
	}
	if t, err := time.Parse(time.RFC3339, raw); err == nil {
		return t.UTC().Format("2006-01-02T15:04:05Z")
	}
	return strings.Replace(raw, " ", "T", 1) + "Z"
}

func jsonOK(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func jsonErr(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func validateIPOrCIDR(s string) error {
	if net.ParseIP(s) != nil {
		return nil
	}
	if _, _, err := net.ParseCIDR(s); err == nil {
		return nil
	}
	return fmt.Errorf("invalid IP address or CIDR range: %q", s)
}

// marshalPortsJSON converts a PortsSpec to its JSON representation for storage.
func marshalPortsJSON(ps rules.PortsSpec) string {
	if ps.All {
		return `"all"`
	}
	b, _ := json.Marshal(ps.Ports)
	return string(b)
}
