// Package frontrouter dispatches incoming TCP connections on the panel/HTTP port
// between the Admin Panel/Landing HTTP server and the HTTP Relay pipeline based on
// Host header domain rules.
package frontrouter

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/ixabolfazl/tls-relay/internal/access"
	"github.com/ixabolfazl/tls-relay/internal/config"
	"github.com/ixabolfazl/tls-relay/internal/httphost"
	"github.com/ixabolfazl/tls-relay/internal/httprelay"
	"github.com/ixabolfazl/tls-relay/internal/logging"
	"github.com/ixabolfazl/tls-relay/internal/relay"
	"github.com/ixabolfazl/tls-relay/internal/reqstats"
	"github.com/ixabolfazl/tls-relay/internal/requestlog"
	"github.com/ixabolfazl/tls-relay/internal/rules"
)

// Router owns the front-facing listener on the panel address and dispatches connections.
type Router struct {
	cfg          *config.Config
	panelHandler http.Handler
	listenAddr   string
	listenPort   int
	ruleStore    *rules.RuleStore
	accessStore  *access.AccessStore
	security     *relay.SecurityChecker
	limits       *relay.LimitTracker
	egressDialer *relay.EgressDialer
	connTracker  *relay.ConnTracker
	logger       *requestlog.Logger
	usageTracker *relay.UsageTracker
	stats        *reqstats.Collector
	relayServer  *httprelay.Server
	connCtx      context.Context
}

// New constructs a new FrontRouter.
func New(
	cfg *config.Config,
	panelHandler http.Handler,
	ruleStore *rules.RuleStore,
	accessStore *access.AccessStore,
	security *relay.SecurityChecker,
	limits *relay.LimitTracker,
	egressDialer *relay.EgressDialer,
	connTracker *relay.ConnTracker,
	logger *requestlog.Logger,
	usageTracker *relay.UsageTracker,
	stats *reqstats.Collector,
) (*Router, error) {
	listenAddr := cfg.Panel.Addr
	_, portStr, err := net.SplitHostPort(listenAddr)
	if err != nil {
		return nil, fmt.Errorf("invalid panel address %q: %w", listenAddr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("invalid panel port %q: %w", portStr, err)
	}

	allowList := relay.NewPortAllowList(cfg.AllowedDestPorts)
	httpRelay := httprelay.NewServer(cfg, port, allowList, security, limits, ruleStore, accessStore, egressDialer, connTracker)
	httpRelay.SetLogger(logger)
	httpRelay.SetUsageTracker(usageTracker)
	httpRelay.SetStatsCollector(stats)

	return &Router{
		cfg:          cfg,
		panelHandler: panelHandler,
		listenAddr:   listenAddr,
		listenPort:   port,
		ruleStore:    ruleStore,
		accessStore:  accessStore,
		security:     security,
		limits:       limits,
		egressDialer: egressDialer,
		connTracker:  connTracker,
		logger:       logger,
		usageTracker: usageTracker,
		stats:        stats,
		relayServer:  httpRelay,
	}, nil
}

// SetCustomDialer sets a custom dialer on the internal HTTP relay server (useful for tests).
func (r *Router) SetCustomDialer(fn func(ctx context.Context, network, addr string) (net.Conn, error)) {
	if r.relayServer != nil {
		r.relayServer.SetCustomDialer(fn)
	}
}

// SetConnContext sets the connection context for graceful draining.
func (r *Router) SetConnContext(ctx context.Context) {
	r.connCtx = ctx
	if r.relayServer != nil {
		r.relayServer.SetConnContext(ctx)
	}
}

// ServeListener accepts connections from ln and dispatches them until ctx is cancelled.
// connWG tracks in-flight connection processing for graceful shutdown.
func (r *Router) ServeListener(ctx context.Context, ln net.Listener, connWG *sync.WaitGroup) error {
	pln := newPanelListener(ln.Addr())
	defer pln.Close()

	// Launch panel HTTP server fed by synthetic listener
	panelHTTPServer := &http.Server{
		Addr:         r.listenAddr,
		Handler:      r.panelHandler,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = panelHTTPServer.Shutdown(shutCtx)
	}()

	go func() {
		_ = panelHTTPServer.Serve(pln)
	}()

	slog.Info("front router listening", "addr", ln.Addr().String(), "panel_port", r.listenPort)

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			slog.Error("front router accept error", "error", err)
			continue
		}

		relay.SetTCPKeepalive(conn, r.cfg.Timeouts.TCPKeepalive.Duration)

		connCtx := r.connCtx
		if connCtx == nil {
			connCtx = ctx
		}

		if connWG != nil {
			connWG.Add(1)
		}
		go func() {
			if connWG != nil {
				defer connWG.Done()
			}
			r.dispatchConn(connCtx, conn, pln)
		}()
	}
}

// ListenAndServe creates a listener on cfg.Panel.Addr and calls ServeListener.
func (r *Router) ListenAndServe(ctx context.Context, connWG *sync.WaitGroup) error {
	lc := net.ListenConfig{}
	ln, err := lc.Listen(ctx, "tcp", r.listenAddr)
	if err != nil {
		return fmt.Errorf("front router listen on %s: %w", r.listenAddr, err)
	}

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	return r.ServeListener(ctx, ln, connWG)
}

func (r *Router) dispatchConn(ctx context.Context, conn net.Conn, pln *panelListener) {
	start := time.Now()
	clientIP := relay.ExtractIP(conn.RemoteAddr().String())

	// 1. Check IP Access control (Blacklist only at this stage to allow unregistered IPs to reach the landing/setup page)
	var ip net.IP
	if r.accessStore != nil {
		ip = net.ParseIP(clientIP)
		if ip == nil {
			r.logRejection(clientIP, "", r.listenPort, "rejected_ip_invalid", start)
			_ = conn.Close()
			return
		}
		if r.accessStore.IsBlacklisted(ip) {
			r.logRejection(clientIP, "", r.listenPort, "rejected_blacklisted", start)
			_ = conn.Close()
			return
		}
	}

	// 2. Read initial HTTP request headers with timeout
	headerTimeout := r.cfg.Timeouts.HTTPHeader.Duration
	if headerTimeout > 0 {
		_ = conn.SetReadDeadline(time.Now().Add(headerTimeout))
	}

	peeked, host, err := httphost.ReadHostAndRequestLine(conn)
	_ = conn.SetReadDeadline(time.Time{})

	if err != nil {
		status := "rejected_parse_error"
		if relay.IsTimeout(err) {
			status = "rejected_timeout"
		} else if errors.Is(err, httphost.ErrNotHTTP) {
			status = "rejected_not_http"
		} else if errors.Is(err, httphost.ErrNoHost) {
			status = "rejected_no_host"
		} else if errors.Is(err, httphost.ErrHeaderTooLarge) {
			status = "rejected_header_too_large"
		} else if errors.Is(err, httphost.ErrAmbiguousHost) {
			status = "rejected_ambiguous_host"
		}
		r.logRejection(clientIP, "", r.listenPort, status, start)
		_ = conn.Close()
		return
	}

	// 3. Perform domain rule lookup (single atomic snapshot read)
	if r.ruleStore != nil {
		allowed, rule, matchInfo := r.ruleStore.LookupDetailed(host, r.listenPort)
		if matchInfo.Matched {
			// Validate registered IP access control now that a domain rule matched
			if r.accessStore != nil && ip != nil {
				allowedAccess, reason := r.accessStore.CheckAccess(ip)
				if !allowedAccess {
					r.logRejection(clientIP, host, r.listenPort, "rejected_"+reason, start)
					_ = conn.Close()
					return
				}
			}

			// Rule matched -> check Mode and Ports
			ruleMode := rule.Mode
			if ruleMode == "" {
				ruleMode = "proxy"
			}

			switch ruleMode {
			case "block":
				r.logRejection(clientIP, host, r.listenPort, "rejected_domain_blocked", start)
				_ = conn.Close()
				return
			case "direct":
				r.logRejection(clientIP, host, r.listenPort, "rejected_direct_mode", start)
				_ = conn.Close()
				return
			case "proxy":
				if allowed {
					// Route to HTTP Relay pipeline with prevalidated rule (avoids redundant checks)
					r.relayServer.HandlePrevalidatedConn(ctx, conn, peeked, host, rule, matchInfo)
					return
				}
				r.logRejection(clientIP, host, r.listenPort, "rejected_port", start)
				_ = conn.Close()
				return
			}
		}
	}

	// 4. Unmatched Host -> route to Panel HTTP Server
	rc := newReplayConn(conn, peeked)
	if !pln.Send(rc) {
		_ = conn.Close()
	}
}

func (r *Router) logRejection(clientIP, host string, port int, status string, start time.Time) {
	dur := time.Since(start)
	logging.LogConnection(logging.ConnFields{
		ClientIP: clientIP,
		SNI:      host,
		DestPort: port,
		Protocol: "HTTP",
		Status:   status,
		Duration: dur,
		Egress:   "direct",
	})

	if r.logger != nil && r.logger.IsEnabled() {
		var userID int64
		username := "Unknown"
		if r.connTracker != nil {
			if uid, uname, ok := r.connTracker.LookupUser(clientIP); ok {
				userID = uid
				if uname != "" {
					username = uname
				}
			}
		}
		r.logger.Emit(requestlog.Event{
			UserID:      userID,
			Username:    username,
			ClientIP:    clientIP,
			RequestType: requestlog.TypeHTTP,
			Protocol:    "HTTP",
			Domain:      host,
			Port:        port,
			Status:      status,
			Timestamp:   time.Now(),
		})
	}
}

// ---------------------------------------------------------------------------
// Helpers: panelListener & replayConn
// ---------------------------------------------------------------------------

type panelListener struct {
	addr      net.Addr
	conns     chan net.Conn
	closeOnce sync.Once
	closed    chan struct{}
}

func newPanelListener(addr net.Addr) *panelListener {
	return &panelListener{
		addr:   addr,
		conns:  make(chan net.Conn, 1024),
		closed: make(chan struct{}),
	}
}

func (l *panelListener) Accept() (net.Conn, error) {
	select {
	case c, ok := <-l.conns:
		if !ok {
			return nil, net.ErrClosed
		}
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *panelListener) Close() error {
	l.closeOnce.Do(func() {
		close(l.closed)
		close(l.conns)
	})
	return nil
}

func (l *panelListener) Addr() net.Addr {
	return l.addr
}

func (l *panelListener) Send(c net.Conn) bool {
	select {
	case <-l.closed:
		return false
	case l.conns <- c:
		return true
	default:
		// Queue full
		return false
	}
}

type replayConn struct {
	net.Conn
	r io.Reader
}

func newReplayConn(c net.Conn, peeked []byte) net.Conn {
	if len(peeked) == 0 {
		return c
	}
	return &replayConn{
		Conn: c,
		r:    io.MultiReader(bytes.NewReader(peeked), c),
	}
}

func (rc *replayConn) Read(b []byte) (int, error) {
	return rc.r.Read(b)
}
