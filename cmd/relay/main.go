// Package main is the entry point for the TLS SNI relay proxy.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	_ "time/tzdata"

	"golang.org/x/crypto/bcrypt"

	"github.com/ixabolfazl/tls-relay/internal/access"
	"github.com/ixabolfazl/tls-relay/internal/config"
	"github.com/ixabolfazl/tls-relay/internal/dnsresolver"
	"github.com/ixabolfazl/tls-relay/internal/frontrouter"
	"github.com/ixabolfazl/tls-relay/internal/httprelay"
	"github.com/ixabolfazl/tls-relay/internal/logging"
	"github.com/ixabolfazl/tls-relay/internal/panel"
	"github.com/ixabolfazl/tls-relay/internal/portal"
	"github.com/ixabolfazl/tls-relay/internal/relay"
	"github.com/ixabolfazl/tls-relay/internal/reqstats"
	"github.com/ixabolfazl/tls-relay/internal/requestlog"
	"github.com/ixabolfazl/tls-relay/internal/rules"
	"github.com/ixabolfazl/tls-relay/internal/sqlitestore"
	"github.com/ixabolfazl/tls-relay/internal/syncer"
)

var (
	version   = "dev"
	commit    = "none"
	buildDate = "unknown"
)

func main() {
	cfgPath := flag.String("config", "config.yaml", "path to config.yaml")
	showVersion := flag.Bool("version", false, "display version and build information")
	flag.BoolVar(showVersion, "v", false, "display version and build information (shorthand)")
	initAdmin := flag.Bool("init-admin", false, "initialize or reset admin credentials in database")
	adminUser := flag.String("user", "admin", "admin username for -init-admin")
	adminPass := flag.String("pass", "", "admin password for -init-admin")
	flag.Parse()

	if *showVersion {
		fmt.Printf("tls-relay %s (commit: %s, built: %s)\n", version, commit, buildDate)
		os.Exit(0)
	}

	if *initAdmin {
		if err := handleInitAdmin(*cfgPath, *adminUser, *adminPass); err != nil {
			fmt.Fprintf(os.Stderr, "error initializing admin credentials: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	if err := run(*cfgPath); err != nil {
		fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
		os.Exit(1)
	}
}

func run(cfgPath string) error {
	// -----------------------------------------------------------------------
	// Load configuration
	// -----------------------------------------------------------------------
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	// -----------------------------------------------------------------------
	// Set up logging
	// -----------------------------------------------------------------------
	closeLog, err := logging.Setup(&cfg.Logging)
	if err != nil {
		return fmt.Errorf("setting up logging: %w", err)
	}
	defer closeLog()

	// -----------------------------------------------------------------------
	// Initialize SQLite store (source of truth)
	// -----------------------------------------------------------------------
	sqlStore, err := sqlitestore.New(cfg.SQLite.Path)
	if err != nil {
		return fmt.Errorf("initializing SQLite: %w", err)
	}
	defer func() { _ = sqlStore.Close() }()

	// -----------------------------------------------------------------------
	// Resolve settings using strict precedence (Env Var > SQLite DB > Defaults)
	// -----------------------------------------------------------------------
	dbSettings, err := sqlStore.AllSettings(context.Background())
	if err != nil {
		slog.Warn("could not load app settings from sqlite", "error", err)
		dbSettings = make(map[string]string)
	}

	envAccessMode := os.Getenv("ACCESS_MODE")
	dbAccessMode, hasAccessMode := dbSettings["access_mode"]
	rawAccessMode := config.ResolveSetting(envAccessMode, dbAccessMode, hasAccessMode, cfg.AccessMode)
	validAccessMode, err := config.ValidateAccessMode(rawAccessMode)
	if err != nil {
		slog.Warn("invalid access mode configured; falling back to user", "access_mode", rawAccessMode, "error", err)
	}
	cfg.AccessMode = validAccessMode

	envPanelPath := os.Getenv("PANEL_PATH")
	if envPanelPath == "" {
		envPanelPath = os.Getenv("PANEL_ADMIN_PATH")
	}
	dbPanelPath, hasPanelPath := dbSettings["panel_path"]
	rawPanelPath := config.ResolveSetting(envPanelPath, dbPanelPath, hasPanelPath, cfg.Panel.Path)
	validPanelPath, err := config.ValidatePanelPath(rawPanelPath)
	if err != nil {
		slog.Error("invalid panel path configured; falling back to config value or /admin", "path", rawPanelPath, "error", err)
		validPanelPath, err = config.ValidatePanelPath(cfg.Panel.Path)
		if err != nil {
			validPanelPath = "/admin"
		}
	}
	cfg.Panel.Path = validPanelPath

	envTimezone := os.Getenv("TIMEZONE")
	dbTimezone, hasTimezone := dbSettings["timezone"]
	cfg.Timezone = config.ResolveSetting(envTimezone, dbTimezone, hasTimezone, cfg.Timezone)
	if _, err := time.LoadLocation(cfg.Timezone); err != nil {
		slog.Warn("invalid timezone configured; falling back to UTC", "timezone", cfg.Timezone, "error", err)
		cfg.Timezone = "UTC"
	}

	envPolicy := os.Getenv("UNKNOWN_DOMAIN_POLICY")
	dbPolicy, hasPolicy := dbSettings["unknown_domain_policy"]
	rawPolicy := config.ResolveSetting(envPolicy, dbPolicy, hasPolicy, cfg.UnknownDomainPolicy)
	validPolicy, err := config.ValidateUnknownDomainPolicy(rawPolicy, cfg.UnknownDomainPolicy)
	if err != nil {
		slog.Warn("invalid unknown domain policy configured; falling back", "policy", rawPolicy, "fallback", validPolicy, "error", err)
	}
	cfg.UnknownDomainPolicy = validPolicy

	// Resolve allowed destination ports from SQLite if configured
	if dbPorts, hasPorts := dbSettings["allowed_dest_ports"]; hasPorts && strings.TrimSpace(dbPorts) != "" {
		var parsedPorts []int
		if err := json.Unmarshal([]byte(dbPorts), &parsedPorts); err == nil && len(parsedPorts) > 0 {
			cfg.AllowedDestPorts = parsedPorts
		}
	}

	// Resolve listen ports from SQLite if configured
	if dbListenPorts, hasListenPorts := dbSettings["listen_ports"]; hasListenPorts && strings.TrimSpace(dbListenPorts) != "" {
		var parsedPorts []int
		if err := json.Unmarshal([]byte(dbListenPorts), &parsedPorts); err == nil && len(parsedPorts) > 0 {
			cfg.Listen.Ports = parsedPorts
		}
	}

	// Resolve listen http ports from SQLite if configured
	if dbHTTPPorts, hasHTTPPorts := dbSettings["listen_http_ports"]; hasHTTPPorts && strings.TrimSpace(dbHTTPPorts) != "" {
		var parsedPorts []int
		if err := json.Unmarshal([]byte(dbHTTPPorts), &parsedPorts); err == nil && len(parsedPorts) > 0 {
			cfg.Listen.HTTPPorts = parsedPorts
		}
	}

	// Resolve egress proxy configuration (Env > SQLite > Config)
	envEgressEnabled := os.Getenv("EGRESS_PROXY_ENABLED")
	dbEgressEnabled, hasEgressEnabled := dbSettings["egress_proxy_enabled"]
	egressEnabledStr := config.ResolveSetting(envEgressEnabled, dbEgressEnabled, hasEgressEnabled, fmt.Sprintf("%t", cfg.EgressProxy.Enabled))
	cfg.EgressProxy.Enabled = egressEnabledStr == "true" || egressEnabledStr == "1"

	envEgressAddr := os.Getenv("EGRESS_PROXY_ADDR")
	dbEgressAddr, hasEgressAddr := dbSettings["egress_proxy_addr"]
	cfg.EgressProxy.Addr = config.ResolveSetting(envEgressAddr, dbEgressAddr, hasEgressAddr, cfg.EgressProxy.Addr)

	envEgressUser := os.Getenv("EGRESS_PROXY_USER")
	dbEgressUser, hasEgressUser := dbSettings["egress_proxy_user"]
	cfg.EgressProxy.User = config.ResolveSetting(envEgressUser, dbEgressUser, hasEgressUser, cfg.EgressProxy.User)

	envEgressPass := os.Getenv("EGRESS_PROXY_PASSWORD")
	dbEgressPass, hasEgressPass := dbSettings["egress_proxy_password"]
	cfg.EgressProxy.Password = config.ResolveSetting(envEgressPass, dbEgressPass, hasEgressPass, cfg.EgressProxy.Password)

	slog.Info("tls-relay starting",
		"listen_addr", cfg.Listen.Addr,
		"ports", cfg.Listen.Ports,
		"allowed_dest_ports", cfg.AllowedDestPorts,
		"unknown_domain_policy", cfg.UnknownDomainPolicy,
		"access_mode", cfg.AccessMode,
		"panel_path", cfg.Panel.Path,
		"timezone", cfg.Timezone,
	)

	// -----------------------------------------------------------------------
	// Build shared in-memory caches
	// -----------------------------------------------------------------------
	ruleStore := rules.NewRuleStore(cfg.AllowedDestPorts, cfg.UnknownDomainPolicy)
	accessStore := access.NewAccessStore(access.AccessMode(cfg.AccessMode))

	// ConnTracker tracks every active TCP connection by client IP.
	// It is wired to the AccessStore so that when user IPs are swapped
	// (after a disable / delete), connections for revoked IPs are closed
	// immediately without waiting for an idle timeout.
	connTracker := relay.NewConnTracker()
	accessStore.SetEvictionHook(connTracker)

	// -----------------------------------------------------------------------
	// Create syncer and load initial state from SQLite into in-memory caches
	// -----------------------------------------------------------------------
	syncer := syncer.New(ruleStore, accessStore, sqlStore)
	syncer.SetConnTracker(connTracker)
	if err := syncer.LoadInitial(context.Background()); err != nil {
		return fmt.Errorf("loading initial state from SQLite: %w", err)
	}

	// -----------------------------------------------------------------------
	// Build shared relay components
	// -----------------------------------------------------------------------
	allowList := relay.NewPortAllowList(cfg.AllowedDestPorts)

	checker, err := relay.NewSecurityChecker(
		cfg.Security.BlockPrivateIPs,
		cfg.Security.BlockOwnIPs,
		cfg.Security.ExtraBlockedCIDRs,
	)
	if err != nil {
		return fmt.Errorf("building security checker: %w", err)
	}
	if cfg.Security.BlockOwnIPs && cfg.DNS.RelayIP != "" {
		checker.AddOwnIPs(cfg.DNS.RelayIP)
	}

	envMaxConn := os.Getenv("MAX_CONNECTIONS_PER_IP")
	dbMaxConn, hasMaxConn := dbSettings["max_connections_per_ip"]
	maxConnStr := config.ResolveSetting(envMaxConn, dbMaxConn, hasMaxConn, fmt.Sprintf("%d", cfg.Limits.MaxConnectionsPerIP))
	if maxConn, err := strconv.Atoi(maxConnStr); err == nil && maxConn > 0 {
		cfg.Limits.MaxConnectionsPerIP = maxConn
	}

	limits := relay.NewLimitTracker(
		cfg.Limits.MaxGlobalConnections,
		cfg.Limits.MaxConnectionsPerIP,
	)

	egressDialer, err := relay.NewEgressDialer(cfg.EgressProxy)
	if err != nil {
		return fmt.Errorf("building egress dialer: %w", err)
	}
	slog.Info("egress proxy configuration",
		"enabled", egressDialer.Enabled(),
		"mode", egressDialer.Mode(),
	)

	// -----------------------------------------------------------------------
	// Contexts for graceful shutdown:
	// - listenerCtx controls listeners (stops accepting incoming conns on shutdown)
	// - bgCtx controls background workers (flushes telemetry and writes after conns close)
	// -----------------------------------------------------------------------
	listenerCtx, listenerCancel := context.WithCancel(context.Background())
	defer listenerCancel()

	bgCtx, bgCancel := context.WithCancel(context.Background())
	defer bgCancel()

	// -----------------------------------------------------------------------
	// Initialize Async Request Logger
	// -----------------------------------------------------------------------
	envReqLogEnabled := os.Getenv("REQUEST_LOGS_ENABLED")
	dbReqLogEnabled, hasReqLogEnabled := dbSettings["request_logs_enabled"]
	reqLogEnabledStr := config.ResolveSetting(envReqLogEnabled, dbReqLogEnabled, hasReqLogEnabled, fmt.Sprintf("%t", cfg.Logging.RequestLogs.Enabled))
	reqLogEnabled := reqLogEnabledStr == "true" || reqLogEnabledStr == "1"

	envReqLogRetention := os.Getenv("REQUEST_LOGS_RETENTION")
	dbReqLogRetention, hasReqLogRetention := dbSettings["request_logs_retention"]
	reqLogRetentionStr := config.ResolveSetting(envReqLogRetention, dbReqLogRetention, hasReqLogRetention, cfg.Logging.RequestLogs.Retention.Duration.String())
	reqLogRetention, err := parseDurationWithDays(reqLogRetentionStr)
	if err != nil {
		slog.Warn("invalid request log retention configured; falling back to default", "retention", reqLogRetentionStr, "error", err)
		reqLogRetention = 24 * time.Hour
	}

	reqLogger := requestlog.New(sqlStore, reqLogRetention, reqLogEnabled)
	reqLogger.Start(bgCtx)

	// Start background Last Seen writer for ConnTracker
	connTracker.StartLastSeenWriter(bgCtx, sqlStore)

	// Start background usage event writer.
	usageTracker := relay.NewUsageTracker()
	usageTracker.StartWriter(bgCtx, sqlStore)

	// Start background request stats collector.
	reqStats := reqstats.New()
	reqStats.StartWriter(bgCtx, sqlStore)

	// Handle SIGINT / SIGTERM.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// WaitGroup tracks in-flight connection goroutines across all listeners.
	var connWG sync.WaitGroup

	// -----------------------------------------------------------------------
	// Start one TCP relay listener per configured port
	// -----------------------------------------------------------------------
	var listenerWG sync.WaitGroup
	errs := make(chan error, len(cfg.Listen.Ports)+len(cfg.Listen.HTTPPorts)+2) // +2 for panel/router + dns

	for _, port := range cfg.Listen.Ports {
		port := port // capture
		srv := relay.NewServer(cfg, port, allowList, checker, limits, ruleStore, accessStore, egressDialer, connTracker)
		srv.SetLogger(reqLogger)
		srv.SetUsageTracker(usageTracker)
		srv.SetStatsCollector(reqStats)

		listenerWG.Add(1)
		go func() {
			defer listenerWG.Done()
			if err := srv.ListenAndServe(listenerCtx, &connWG); err != nil {
				errs <- fmt.Errorf("relay listener on port %d: %w", port, err)
			}
		}()
	}

	// -----------------------------------------------------------------------
	// Start Admin Panel
	// -----------------------------------------------------------------------
	panelSrv, err := panel.New(cfg.Panel.Addr, cfg.Panel.Path, ruleStore, accessStore, sqlStore, syncer)
	if err != nil {
		return fmt.Errorf("building panel server: %w", err)
	}
	panelSrv.SetConnTracker(connTracker)
	panelSrv.SetRequestLogger(reqLogger)
	panelSrv.SetLimitTracker(limits)
	panelSrv.SetEgressDialer(egressDialer)
	panelSrv.SetPortAllowList(allowList)
	panelSrv.SetListenPorts(cfg.Listen.Ports)
	panelSrv.SetListenHTTPPorts(cfg.Listen.HTTPPorts)
	_ = panelSrv.SetTimezone(cfg.Timezone)
	if cfg.DNS.RelayIP != "" {
		panelSrv.SetRelayIP(cfg.DNS.RelayIP)
	}
	if cfg.Users.DefaultMaxIPs > 0 {
		panelSrv.SetDefaultMaxIPs(cfg.Users.DefaultMaxIPs)
	}

	lookupEnabled := dbSettings["lookup_enabled"] != "false"
	lookupRequireRegistered := dbSettings["lookup_require_registered"] == "true"
	panelSrv.SetLookupPolicy(lookupEnabled, lookupRequireRegistered)

	restartCh := make(chan struct{}, 1)
	panelSrv.SetRestartHandler(func() {
		select {
		case restartCh <- struct{}{}:
		default:
		}
	})

	// -----------------------------------------------------------------------
	// Build Public Portal Service and embed its routes into the panel mux.
	// Both the landing page, client setup, and admin panel share port 80.
	// -----------------------------------------------------------------------
	portalSrv := portal.New(cfg.MagicLink.Addr, sqlStore, accessStore, syncer)
	portalSrv.SetServerIP(cfg.DNS.RelayIP)
	portalSrv.SetLookupPolicy(lookupEnabled, lookupRequireRegistered)
	if panelSrv.ServerDomain() != "" {
		portalSrv.SetServerDomain(panelSrv.ServerDomain())
	}
	portalSrv.SetRuleStore(ruleStore)
	// Embed portal routes into panel (no separate listener).
	panelSrv.SetPortalServer(portalSrv)

	// -----------------------------------------------------------------------
	// Start Front Router (shares panel.Addr for Admin Panel & HTTP Relay)
	// -----------------------------------------------------------------------
	router, err := frontrouter.New(
		cfg,
		panelSrv,
		ruleStore,
		accessStore,
		checker,
		limits,
		egressDialer,
		connTracker,
		reqLogger,
		usageTracker,
		reqStats,
	)
	if err != nil {
		return fmt.Errorf("building front router: %w", err)
	}

	listenerWG.Add(1)
	go func() {
		defer listenerWG.Done()
		if err := router.ListenAndServe(listenerCtx, &connWG); err != nil {
			errs <- fmt.Errorf("front router on %s: %w", cfg.Panel.Addr, err)
		}
	}()

	// -----------------------------------------------------------------------
	// Start standalone HTTP relay listeners for any extra ports in http_ports
	// that do not match the panel listen port.
	// -----------------------------------------------------------------------
	_, panelPortStr, _ := net.SplitHostPort(cfg.Panel.Addr)
	panelPort, _ := strconv.Atoi(panelPortStr)

	for _, httpPort := range cfg.Listen.HTTPPorts {
		if httpPort == panelPort {
			continue // Handled by front router
		}
		httpPort := httpPort
		httpSrv := httprelay.NewServer(cfg, httpPort, allowList, checker, limits, ruleStore, accessStore, egressDialer, connTracker)
		httpSrv.SetLogger(reqLogger)
		httpSrv.SetUsageTracker(usageTracker)
		httpSrv.SetStatsCollector(reqStats)

		listenerWG.Add(1)
		go func() {
			defer listenerWG.Done()
			if err := httpSrv.ListenAndServe(listenerCtx, &connWG); err != nil {
				errs <- fmt.Errorf("http relay listener on port %d: %w", httpPort, err)
			}
		}()
	}

	// Resolve DNS Unauthorized Passthrough Setting
	envDNSPassthrough := os.Getenv("DNS_UNAUTHORIZED_PASSTHROUGH_ENABLED")
	dbDNSPassthrough, hasDNSPassthrough := dbSettings["dns_unauthorized_passthrough_enabled"]
	fallbackDNSPassthrough := fmt.Sprintf("%t", cfg.DNS.UnauthorizedPassthrough.Enabled)
	resolvedDNSPassthrough := config.ResolveSetting(envDNSPassthrough, dbDNSPassthrough, hasDNSPassthrough, fallbackDNSPassthrough) == "true"

	// -----------------------------------------------------------------------
	// Start DNS Resolver
	// -----------------------------------------------------------------------
	dnsSrv, err := dnsresolver.New(dnsresolver.Config{
		Addr:               cfg.DNS.Addr,
		RelayIP:            cfg.DNS.RelayIP,
		UpstreamAddr:       cfg.DNS.UpstreamAddr,
		TTL:                uint32(cfg.DNS.TTL),
		QPS:                cfg.DNS.RateLimit.QPS,
		Burst:              cfg.DNS.RateLimit.Burst,
		EDNSBufSize:        cfg.DNS.EDNSBufSize,
		PassthroughEnabled: resolvedDNSPassthrough,
		PassthroughQPS:     cfg.DNS.UnauthorizedPassthrough.RateLimit.QPS,
		PassthroughBurst:   cfg.DNS.UnauthorizedPassthrough.RateLimit.Burst,
	}, ruleStore, accessStore)
	if err != nil {
		return fmt.Errorf("building DNS resolver: %w", err)
	}
	dnsSrv.SetLogger(reqLogger, connTracker)
	dnsSrv.SetStatsCollector(reqStats)
	dnsSrv.SetUsageTracker(usageTracker)
	panelSrv.SetDNSServer(dnsSrv)
	listenerWG.Add(1)
	go func() {
		defer listenerWG.Done()
		if err := dnsSrv.ListenAndServe(listenerCtx); err != nil {
			errs <- fmt.Errorf("dns resolver: %w", err)
		}
	}()

	// -----------------------------------------------------------------------
	// Wait for a signal or a listener error
	// -----------------------------------------------------------------------
	var listenerErr error
	select {
	case sig := <-sigCh:
		slog.Info("received signal, shutting down", "signal", sig.String())
	case <-restartCh:
		slog.Info("received restart request via admin panel, performing graceful restart")
	case listenerErr = <-errs:
		slog.Error("listener error", "error", listenerErr)
	}

	// 1. Cancel listener context → all listeners stop accepting, listener goroutines return.
	listenerCancel()

	// Drain any additional errors from the channel (don't block forever).
	go func() {
		listenerWG.Wait()
		close(errs)
	}()

	// -----------------------------------------------------------------------
	// Graceful shutdown: wait for in-flight connections up to grace period
	// -----------------------------------------------------------------------
	gracePeriod := cfg.Shutdown.GracePeriod.Duration
	slog.Info("waiting for in-flight connections to finish", "grace_period", gracePeriod.String())

	done := make(chan struct{})
	go func() {
		connWG.Wait()
		close(done)
	}()

	graceCtx, graceCancel := context.WithTimeout(context.Background(), gracePeriod)
	defer graceCancel()

	select {
	case <-done:
		slog.Info("all connections closed; exiting cleanly")
	case <-graceCtx.Done():
		slog.Warn("grace period elapsed; forcing exit with active connections")
	}

	// 2. Stop background workers so final telemetry from in-flight connections is committed to SQLite.
	bgCancel()
	time.Sleep(100 * time.Millisecond)

	return listenerErr
}

func parseDurationWithDays(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty duration")
	}
	if strings.HasSuffix(s, "d") || strings.HasSuffix(s, "D") {
		numStr := s[:len(s)-1]
		days, err := strconv.Atoi(numStr)
		if err != nil {
			return 0, fmt.Errorf("invalid days format %q: %w", s, err)
		}
		if days <= 0 {
			return 0, fmt.Errorf("duration must be positive")
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	dur, err := time.ParseDuration(s)
	if err != nil {
		return 0, err
	}
	if dur <= 0 {
		return 0, fmt.Errorf("duration must be positive")
	}
	return dur, nil
}

func handleInitAdmin(cfgPath, username, password string) error {
	username = strings.TrimSpace(username)
	if username == "" {
		username = "admin"
	}
	password = strings.TrimSpace(password)
	if password == "" {
		return fmt.Errorf("password cannot be empty")
	}
	if len(password) < 6 {
		return fmt.Errorf("password must be at least 6 characters")
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	sqlStore, err := sqlitestore.New(cfg.SQLite.Path)
	if err != nil {
		return fmt.Errorf("opening SQLite database at %q: %w", cfg.SQLite.Path, err)
	}
	defer sqlStore.Close()

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hashing password: %w", err)
	}

	ctx := context.Background()
	if err := sqlStore.SetSetting(ctx, "panel_admin_user", username); err != nil {
		return fmt.Errorf("saving admin user: %w", err)
	}
	if err := sqlStore.SetSetting(ctx, "panel_admin_password_hash", string(hash)); err != nil {
		return fmt.Errorf("saving admin password hash: %w", err)
	}

	fmt.Printf("Admin credentials initialized successfully for user: %s\n", username)
	return nil
}
