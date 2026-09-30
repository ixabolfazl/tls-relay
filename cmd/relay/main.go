// Package main is the entry point for the TLS SNI relay proxy.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"sort"
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
	"github.com/ixabolfazl/tls-relay/internal/settings"
	"github.com/ixabolfazl/tls-relay/internal/sqlitestore"
	"github.com/ixabolfazl/tls-relay/internal/syncer"
)

var (
	version   = "dev"
	commit    = "none"
	buildDate = "unknown"
)

// RuntimeComponents holds references to runtime services and stores for dynamic reload.
type RuntimeComponents struct {
	Cfg          *config.Config
	SqlStore     *sqlitestore.Store
	RuleStore    *rules.RuleStore
	AccessStore  *access.AccessStore
	AllowList    *relay.PortAllowList
	Limits       *relay.LimitTracker
	EgressDialer *relay.EgressDialer
	ReqLogger    *requestlog.Logger
	PanelSrv     *panel.Server
	PortalSrv    *portal.Server
	Router       *frontrouter.Router
	DNSSrv       *dnsresolver.Server
}

func main() {
	cfgPath := flag.String("config", "config.yaml", "path to config.yaml")
	showVersion := flag.Bool("version", false, "display version and build information")
	flag.BoolVar(showVersion, "v", false, "display version and build information (shorthand)")
	initAdmin := flag.Bool("init-admin", false, "initialize or reset admin credentials in database")
	adminUser := flag.String("user", "admin", "admin username for -init-admin")
	passStdin := flag.Bool("pass-stdin", false, "read admin password from stdin for -init-admin")
	flag.Parse()

	if *showVersion {
		fmt.Printf("tls-relay %s (commit: %s, built: %s)\n", version, commit, buildDate)
		os.Exit(0)
	}

	if *initAdmin {
		var pass string
		if *passStdin {
			data, err := io.ReadAll(os.Stdin)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error reading password from stdin: %v\n", err)
				os.Exit(1)
			}
			pass = strings.TrimRight(string(data), "\r\n")
		} else if envPass := os.Getenv("TLS_RELAY_ADMIN_PASS"); envPass != "" {
			pass = envPass
		} else {
			fmt.Fprintln(os.Stderr, "error: password required via TLS_RELAY_ADMIN_PASS environment variable or -pass-stdin")
			os.Exit(1)
		}

		if err := handleInitAdmin(*cfgPath, *adminUser, pass); err != nil {
			fmt.Fprintf(os.Stderr, "error initializing admin credentials: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	args := flag.Args()
	if len(args) > 0 {
		cmd := args[0]
		switch cmd {
		case "settings":
			if err := handleSettingsCmd(*cfgPath, args[1:]); err != nil {
				fmt.Fprintf(os.Stderr, "error: %v\n", err)
				os.Exit(1)
			}
			os.Exit(0)
		case "backup":
			if len(args) < 2 {
				fmt.Fprintln(os.Stderr, "usage: tls-relay backup <dest-path>")
				os.Exit(1)
			}
			if err := handleBackupCmd(*cfgPath, args[1]); err != nil {
				fmt.Fprintf(os.Stderr, "error: %v\n", err)
				os.Exit(1)
			}
			os.Exit(0)
		default:
			fmt.Fprintf(os.Stderr, "unknown subcommand: %s\nUsage: tls-relay [-config <path>] [settings get|set | backup <dest-path>]\n", cmd)
			os.Exit(1)
		}
	}

	if err := run(*cfgPath); err != nil {
		fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
		os.Exit(1)
	}
}

func handleSettingsCmd(cfgPath string, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: tls-relay settings get [key] | settings set <key> <value>")
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

	ctx := context.Background()

	switch args[0] {
	case "get":
		if len(args) > 1 {
			key := args[1]
			val, found, err := sqlStore.GetSetting(ctx, key)
			if err != nil {
				return fmt.Errorf("getting setting %q: %w", key, err)
			}
			if !found {
				fmt.Printf("%s: (not set in database)\n", key)
			} else {
				fmt.Printf("%s=%s\n", key, val)
			}
		} else {
			all, err := sqlStore.AllSettings(ctx)
			if err != nil {
				return fmt.Errorf("getting all settings: %w", err)
			}
			var keys []string
			for k := range all {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				fmt.Printf("%s=%s\n", k, all[k])
			}
		}
		fmt.Println("Note: Environment variables in the service environment override SQLite settings.")
		return nil

	case "set":
		if len(args) < 3 {
			return fmt.Errorf("usage: tls-relay settings set <key> <value>")
		}
		key := args[1]
		val := args[2]

		canonVal, err := settings.ValidateSetting(key, val)
		if err != nil {
			return fmt.Errorf("validation error: %w", err)
		}

		if err := sqlStore.SetSetting(ctx, key, canonVal); err != nil {
			return fmt.Errorf("saving setting %q: %w", key, err)
		}

		fmt.Printf("%s=%s\n", key, canonVal)
		fmt.Println("Note: Environment variables in the service environment override SQLite settings.")
		return nil

	default:
		return fmt.Errorf("unknown settings subcommand %q (expected get or set)", args[0])
	}
}

func handleBackupCmd(cfgPath, destPath string) error {
	destPath = strings.TrimSpace(destPath)
	if destPath == "" {
		return fmt.Errorf("destination path cannot be empty")
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

	ctx := context.Background()
	if err := sqlStore.Backup(ctx, destPath); err != nil {
		return fmt.Errorf("backup failed: %w", err)
	}
	fmt.Printf("Database backup created successfully at %s\n", destPath)
	return nil
}

// ApplyConfigSettings applies database and environment settings over configuration defaults.
func ApplyConfigSettings(cfg *config.Config, dbSettings map[string]string) {
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

	if dbPorts, hasPorts := dbSettings["allowed_dest_ports"]; hasPorts && strings.TrimSpace(dbPorts) != "" {
		var parsedPorts []int
		if err := json.Unmarshal([]byte(dbPorts), &parsedPorts); err == nil && len(parsedPorts) > 0 {
			cfg.AllowedDestPorts = parsedPorts
		}
	}

	if dbListenPorts, hasListenPorts := dbSettings["listen_ports"]; hasListenPorts && strings.TrimSpace(dbListenPorts) != "" {
		var parsedPorts []int
		if err := json.Unmarshal([]byte(dbListenPorts), &parsedPorts); err == nil && len(parsedPorts) > 0 {
			cfg.Listen.Ports = parsedPorts
		}
	}

	if dbHTTPPorts, hasHTTPPorts := dbSettings["listen_http_ports"]; hasHTTPPorts && strings.TrimSpace(dbHTTPPorts) != "" {
		var parsedPorts []int
		if err := json.Unmarshal([]byte(dbHTTPPorts), &parsedPorts); err == nil && len(parsedPorts) > 0 {
			cfg.Listen.HTTPPorts = parsedPorts
		}
	}

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

	envDNSUpstream := os.Getenv("DNS_UPSTREAM_ADDR")
	dbDNSUpstream, hasDNSUpstream := dbSettings["dns_upstream_addr"]
	rawDNSUpstream := config.ResolveSetting(envDNSUpstream, dbDNSUpstream, hasDNSUpstream, cfg.DNS.UpstreamAddr)
	if _, canon, err := settings.ValidateUpstreamList(rawDNSUpstream); err == nil {
		cfg.DNS.UpstreamAddr = canon
	} else if strings.TrimSpace(rawDNSUpstream) != "" {
		slog.Warn("invalid dns upstream address configured; falling back", "raw", rawDNSUpstream, "fallback", cfg.DNS.UpstreamAddr, "error", err)
	}
}

// ReloadSettings re-reads settings from SQLite and dynamically updates running components without dropping connections.
func ReloadSettings(ctx context.Context, comp *RuntimeComponents) error {
	dbSettings, err := comp.SqlStore.AllSettings(ctx)
	if err != nil {
		return fmt.Errorf("reading settings from sqlite: %w", err)
	}

	ApplyConfigSettings(comp.Cfg, dbSettings)

	// 1. Access Mode
	if comp.AccessStore != nil {
		comp.AccessStore.SetMode(access.AccessMode(comp.Cfg.AccessMode))
	}

	// 2. Unknown Domain Policy
	if comp.RuleStore != nil {
		comp.RuleStore.SetUnknownDomainPolicy(comp.Cfg.UnknownDomainPolicy)
	}

	// 3. Panel Path Prefix
	if comp.PanelSrv != nil {
		if err := comp.PanelSrv.ApplyPathPrefix(comp.Cfg.Panel.Path); err != nil {
			slog.Error("failed applying panel path prefix on reload", "path", comp.Cfg.Panel.Path, "error", err)
		}
	}

	// 4. Timezone
	if comp.PanelSrv != nil {
		_ = comp.PanelSrv.SetTimezone(comp.Cfg.Timezone)
	}

	// 5. Max connections per IP
	envMaxConn := os.Getenv("MAX_CONNECTIONS_PER_IP")
	dbMaxConn, hasMaxConn := dbSettings["max_connections_per_ip"]
	maxConnStr := config.ResolveSetting(envMaxConn, dbMaxConn, hasMaxConn, fmt.Sprintf("%d", comp.Cfg.Limits.MaxConnectionsPerIP))
	if maxConn, err := strconv.Atoi(maxConnStr); err == nil && maxConn > 0 {
		comp.Cfg.Limits.MaxConnectionsPerIP = maxConn
		if comp.Limits != nil {
			comp.Limits.SetMaxPerIP(maxConn)
		}
	}

	// 6. Request log settings
	envReqLogEnabled := os.Getenv("REQUEST_LOGS_ENABLED")
	dbReqLogEnabled, hasReqLogEnabled := dbSettings["request_logs_enabled"]
	reqLogEnabledStr := config.ResolveSetting(envReqLogEnabled, dbReqLogEnabled, hasReqLogEnabled, fmt.Sprintf("%t", comp.Cfg.Logging.RequestLogs.Enabled))
	reqLogEnabled := reqLogEnabledStr == "true" || reqLogEnabledStr == "1"
	if comp.ReqLogger != nil {
		comp.ReqLogger.SetEnabled(reqLogEnabled)
	}

	envReqLogRetention := os.Getenv("REQUEST_LOGS_RETENTION")
	dbReqLogRetention, hasReqLogRetention := dbSettings["request_logs_retention"]
	reqLogRetentionStr := config.ResolveSetting(envReqLogRetention, dbReqLogRetention, hasReqLogRetention, comp.Cfg.Logging.RequestLogs.Retention.Duration.String())
	if retentionDur, err := settings.ParseDurationWithDays(reqLogRetentionStr); err == nil && comp.ReqLogger != nil {
		comp.ReqLogger.SetRetention(retentionDur)
	}

	// 7. Lookup Policy
	lookupEnabled := dbSettings["lookup_enabled"] != "false"
	lookupRequireRegistered := dbSettings["lookup_require_registered"] == "true"
	if comp.PanelSrv != nil {
		comp.PanelSrv.SetLookupPolicy(lookupEnabled, lookupRequireRegistered)
	}
	if comp.PortalSrv != nil {
		comp.PortalSrv.SetLookupPolicy(lookupEnabled, lookupRequireRegistered)
	}

	// 8. Front limits
	frontMaxIP := 60
	if v, ok := dbSettings["http_front_max_conns_per_ip"]; ok {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			frontMaxIP = n
		}
	}
	frontMaxGlobal := 5000
	if v, ok := dbSettings["http_front_max_global_conns"]; ok {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			frontMaxGlobal = n
		}
	}
	if comp.Router != nil && comp.Router.FrontLimits() != nil {
		comp.Router.FrontLimits().SetMaxPerIP(frontMaxIP)
		comp.Router.FrontLimits().SetMaxGlobal(frontMaxGlobal)
	}

	// 9. Allowed destination ports
	if comp.AllowList != nil {
		comp.AllowList.SetPorts(comp.Cfg.AllowedDestPorts)
	}
	if comp.RuleStore != nil {
		comp.RuleStore.SetGlobalPorts(comp.Cfg.AllowedDestPorts)
	}

	// 10. Egress proxy config
	if comp.EgressDialer != nil {
		_ = comp.EgressDialer.UpdateConfig(comp.Cfg.EgressProxy)
	}

	// 11. DNS passthrough
	envDNSPassthrough := os.Getenv("DNS_UNAUTHORIZED_PASSTHROUGH_ENABLED")
	dbDNSPassthrough, hasDNSPassthrough := dbSettings["dns_unauthorized_passthrough_enabled"]
	fallbackDNSPassthrough := fmt.Sprintf("%t", comp.Cfg.DNS.UnauthorizedPassthrough.Enabled)
	resolvedDNSPassthrough := config.ResolveSetting(envDNSPassthrough, dbDNSPassthrough, hasDNSPassthrough, fallbackDNSPassthrough) == "true"
	if comp.DNSSrv != nil {
		comp.DNSSrv.SetUnauthorizedPassthrough(resolvedDNSPassthrough)
	}

	// 12. Server domain
	if domain, ok := dbSettings["server_domain"]; ok {
		if comp.PortalSrv != nil {
			comp.PortalSrv.SetServerDomain(domain)
		}
		if comp.PanelSrv != nil {
			comp.PanelSrv.SetServerDomain(domain)
		}
	}

	// 13. Admin Credentials reload (clears active sessions)
	if comp.PanelSrv != nil {
		if err := comp.PanelSrv.ReloadCredentials(ctx); err != nil {
			slog.Error("failed reloading admin credentials on SIGHUP", "error", err)
		}
	}

	// 14. DNS Upstream Addr
	if comp.DNSSrv != nil {
		if upstreams, _, err := settings.ValidateUpstreamList(comp.Cfg.DNS.UpstreamAddr); err == nil {
			comp.DNSSrv.SetUpstreams(upstreams)
		}
	}

	return nil
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

	ApplyConfigSettings(cfg, dbSettings)

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
	// Contexts for graceful shutdown
	// -----------------------------------------------------------------------
	listenerCtx, listenerCancel := context.WithCancel(context.Background())
	defer listenerCancel()

	connCtx, connCancel := context.WithCancel(context.Background())
	defer connCancel()

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
	reqLogRetention, err := settings.ParseDurationWithDays(reqLogRetentionStr)
	if err != nil {
		slog.Warn("invalid request log retention configured; falling back to default", "retention", reqLogRetentionStr, "error", err)
		reqLogRetention = 24 * time.Hour
	}

	reqLogger := requestlog.New(sqlStore, reqLogRetention, reqLogEnabled)
	reqLoggerDone := reqLogger.Start(bgCtx)

	connTrackerDone := connTracker.StartLastSeenWriter(bgCtx, sqlStore)

	usageTracker := relay.NewUsageTracker()
	usageTrackerDone := usageTracker.StartWriter(bgCtx, sqlStore)

	reqStats := reqstats.New()
	reqStatsDone := reqStats.StartWriter(bgCtx, sqlStore)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	hupCh := make(chan os.Signal, 1)
	signal.Notify(hupCh, syscall.SIGHUP)

	var connWG sync.WaitGroup

	// -----------------------------------------------------------------------
	// Start one TCP relay listener per configured port
	// -----------------------------------------------------------------------
	var listenerWG sync.WaitGroup
	errs := make(chan error, len(cfg.Listen.Ports)+len(cfg.Listen.HTTPPorts)+2)

	for _, port := range cfg.Listen.Ports {
		port := port
		srv := relay.NewServer(cfg, port, allowList, checker, limits, ruleStore, accessStore, egressDialer, connTracker)
		srv.SetConnContext(connCtx)
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
	panelSrv.SetVersion(version)
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
	// Build Public Portal Service
	// -----------------------------------------------------------------------
	portalSrv := portal.New(cfg.MagicLink.Addr, sqlStore, accessStore, syncer)
	portalSrv.SetServerIP(cfg.DNS.RelayIP)
	portalSrv.SetLookupPolicy(lookupEnabled, lookupRequireRegistered)
	if panelSrv.ServerDomain() != "" {
		portalSrv.SetServerDomain(panelSrv.ServerDomain())
	}
	portalSrv.SetRuleStore(ruleStore)
	panelSrv.SetPortalServer(portalSrv)

	// -----------------------------------------------------------------------
	// Start Front Router
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
	router.SetConnContext(connCtx)

	frontMaxIP := 60
	if v, ok := dbSettings["http_front_max_conns_per_ip"]; ok {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			frontMaxIP = n
		}
	}
	frontMaxGlobal := 5000
	if v, ok := dbSettings["http_front_max_global_conns"]; ok {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			frontMaxGlobal = n
		}
	}
	router.FrontLimits().SetMaxPerIP(frontMaxIP)
	router.FrontLimits().SetMaxGlobal(frontMaxGlobal)
	panelSrv.SetFrontLimits(router.FrontLimits())

	listenerWG.Add(1)
	go func() {
		defer listenerWG.Done()
		if err := router.ListenAndServe(listenerCtx, &connWG); err != nil {
			errs <- fmt.Errorf("front router on %s: %w", cfg.Panel.Addr, err)
		}
	}()

	// -----------------------------------------------------------------------
	// Start standalone HTTP relay listeners for extra ports
	// -----------------------------------------------------------------------
	_, panelPortStr, _ := net.SplitHostPort(cfg.Panel.Addr)
	panelPort, _ := strconv.Atoi(panelPortStr)

	for _, httpPort := range cfg.Listen.HTTPPorts {
		if httpPort == panelPort {
			continue
		}
		httpPort := httpPort
		httpSrv := httprelay.NewServer(cfg, httpPort, allowList, checker, limits, ruleStore, accessStore, egressDialer, connTracker)
		httpSrv.SetConnContext(connCtx)
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

	// -----------------------------------------------------------------------
	// Start DNS Resolver
	// -----------------------------------------------------------------------
	envDNSPassthrough := os.Getenv("DNS_UNAUTHORIZED_PASSTHROUGH_ENABLED")
	dbDNSPassthrough, hasDNSPassthrough := dbSettings["dns_unauthorized_passthrough_enabled"]
	fallbackDNSPassthrough := fmt.Sprintf("%t", cfg.DNS.UnauthorizedPassthrough.Enabled)
	resolvedDNSPassthrough := config.ResolveSetting(envDNSPassthrough, dbDNSPassthrough, hasDNSPassthrough, fallbackDNSPassthrough) == "true"

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
	if upstreams, _, err := settings.ValidateUpstreamList(cfg.DNS.UpstreamAddr); err == nil {
		dnsSrv.SetUpstreams(upstreams)
	}
	dnsSrv.SetLogger(reqLogger, connTracker)
	dnsSrv.SetStatsCollector(reqStats)
	dnsSrv.SetUsageTracker(usageTracker)
	panelSrv.SetDNSServer(dnsSrv)

	// Wire DNS check registry so the landing page can test whether the client
	// has the relay configured as its DNS server.
	dnsCheckReg := dnsresolver.NewDNSCheckRegistry()
	dnsSrv.SetDNSCheckRegistry(dnsCheckReg)
	portalSrv.SetDNSCheckFuncs(
		func(token string) { dnsCheckReg.Issue(token) },
		func(token string) (bool, time.Time, string) {
			entry, ok := dnsCheckReg.Lookup(token)
			if !ok {
				return false, time.Time{}, ""
			}
			return true, entry.SeenAt, entry.SourceIP
		},
	)

	listenerWG.Add(1)
	go func() {
		defer listenerWG.Done()
		if err := dnsSrv.ListenAndServe(listenerCtx); err != nil {
			errs <- fmt.Errorf("dns resolver: %w", err)
		}
	}()

	// -----------------------------------------------------------------------
	// SIGHUP Live Reload Loop
	// -----------------------------------------------------------------------
	runtimeComp := &RuntimeComponents{
		Cfg:          cfg,
		SqlStore:     sqlStore,
		RuleStore:    ruleStore,
		AccessStore:  accessStore,
		AllowList:    allowList,
		Limits:       limits,
		EgressDialer: egressDialer,
		ReqLogger:    reqLogger,
		PanelSrv:     panelSrv,
		PortalSrv:    portalSrv,
		Router:       router,
		DNSSrv:       dnsSrv,
	}

	go func() {
		for {
			select {
			case <-listenerCtx.Done():
				return
			case <-hupCh:
				slog.Info("received SIGHUP, reloading configuration and credentials from database")
				if err := ReloadSettings(context.Background(), runtimeComp); err != nil {
					slog.Error("error during SIGHUP reload", "error", err)
				} else {
					slog.Info("SIGHUP reload completed successfully")
				}
			}
		}
	}()

	// -----------------------------------------------------------------------
	// Wait for a shutdown signal, panel restart, or a listener error
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

	// 1. Cancel listener context
	listenerCancel()

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

	// 2. Cancel connection context
	connCancel()

	// 3. Cancel background context
	bgCancel()

	// 4. Wait for all background writers to drain
	writersDone := make(chan struct{})
	go func() {
		<-reqLoggerDone
		<-connTrackerDone
		<-usageTrackerDone
		<-reqStatsDone
		close(writersDone)
	}()

	select {
	case <-writersDone:
		slog.Info("all background writers flushed and stopped")
	case <-time.After(10 * time.Second):
		slog.Warn("timeout waiting for background writers to flush; proceeding with shutdown")
	}

	return listenerErr
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
