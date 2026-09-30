// Package httprelay implements plain-HTTP stream relaying mirroring the TLS relay pipeline.
package httprelay

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ixabolfazl/tls-relay/internal/access"
	"github.com/ixabolfazl/tls-relay/internal/config"
	"github.com/ixabolfazl/tls-relay/internal/httphost"
	"github.com/ixabolfazl/tls-relay/internal/logging"
	"github.com/ixabolfazl/tls-relay/internal/relay"
	"github.com/ixabolfazl/tls-relay/internal/reqstats"
	"github.com/ixabolfazl/tls-relay/internal/requestlog"
	"github.com/ixabolfazl/tls-relay/internal/rules"
)

// Server manages plain HTTP relaying on a given port.
type Server struct {
	cfg          *config.Config
	port         int
	allowList    *relay.PortAllowList
	security     *relay.SecurityChecker
	limits       *relay.LimitTracker
	ruleStore    *rules.RuleStore
	accessStore  *access.AccessStore
	egressDialer *relay.EgressDialer
	connTracker  *relay.ConnTracker
	logger       *requestlog.Logger
	usageTracker *relay.UsageTracker
	stats        *reqstats.Collector
	customDialer func(ctx context.Context, network, addr string) (net.Conn, error)
	connCtx      context.Context
}

// NewServer constructs a new HTTP relay server.
func NewServer(
	cfg *config.Config,
	port int,
	allowList *relay.PortAllowList,
	security *relay.SecurityChecker,
	limits *relay.LimitTracker,
	ruleStore *rules.RuleStore,
	accessStore *access.AccessStore,
	egressDialer *relay.EgressDialer,
	connTracker *relay.ConnTracker,
) *Server {
	return &Server{
		cfg:          cfg,
		port:         port,
		allowList:    allowList,
		security:     security,
		limits:       limits,
		ruleStore:    ruleStore,
		accessStore:  accessStore,
		egressDialer: egressDialer,
		connTracker:  connTracker,
	}
}

// SetLogger sets the request logger.
func (s *Server) SetLogger(l *requestlog.Logger) {
	s.logger = l
}

// SetUsageTracker sets the usage tracker.
func (s *Server) SetUsageTracker(ut *relay.UsageTracker) {
	s.usageTracker = ut
}

// SetStatsCollector sets the request stats collector.
func (s *Server) SetStatsCollector(sc *reqstats.Collector) {
	s.stats = sc
}

// SetCustomDialer sets a custom dialer function (useful for tests).
func (s *Server) SetCustomDialer(fn func(ctx context.Context, network, addr string) (net.Conn, error)) {
	s.customDialer = fn
}

// SetConnContext sets the connection context for graceful draining.
func (s *Server) SetConnContext(ctx context.Context) {
	s.connCtx = ctx
}

func (s *Server) egressMode() string {
	if s.egressDialer != nil {
		return s.egressDialer.Mode()
	}
	return "direct"
}

func (s *Server) resolveEgressMode(ruleUseProxy string) string {
	if s.egressDialer != nil {
		return s.egressDialer.ResolveMode(ruleUseProxy)
	}
	return "direct"
}

// ListenAndServe starts a standalone relay-only HTTP listener on s.port and blocks until ctx is cancelled.
func (s *Server) ListenAndServe(ctx context.Context, wg *sync.WaitGroup) error {
	addr := fmt.Sprintf("%s:%d", s.cfg.Listen.Addr, s.port)
	lc := net.ListenConfig{}
	ln, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("http relay listening on %s: %w", addr, err)
	}
	slog.Info("http relay listening", "addr", addr)

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			slog.Error("http relay accept error", "error", err)
			continue
		}

		relay.SetTCPKeepalive(conn, s.cfg.Timeouts.TCPKeepalive.Duration)

		connCtx := s.connCtx
		if connCtx == nil {
			connCtx = ctx
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			s.HandleConn(connCtx, conn, nil, "")
		}()
	}
}

// HandleConn manages the complete HTTP relay connection lifecycle.
// If peeked is non-nil, peeked bytes and host are already supplied (e.g. from front router).
func (s *Server) HandleConn(ctx context.Context, clientConn net.Conn, peeked []byte, host string) {
	s.handleConn(ctx, clientConn, peeked, host, nil, nil)
}

// HandlePrevalidatedConn handles an HTTP relay connection whose IP access and domain rule
// have already been validated (e.g. by frontrouter).
func (s *Server) HandlePrevalidatedConn(ctx context.Context, clientConn net.Conn, peeked []byte, host string, rule rules.DomainRule, matchInfo rules.MatchInfo) {
	s.handleConn(ctx, clientConn, peeked, host, &rule, &matchInfo)
}

func (s *Server) handleConn(
	ctx context.Context,
	clientConn net.Conn,
	peeked []byte,
	host string,
	prevalidatedRule *rules.DomainRule,
	prevalidatedMatchInfo *rules.MatchInfo,
) {
	start := time.Now()
	clientIP := relay.ExtractIP(clientConn.RemoteAddr().String())

	fields := logging.ConnFields{
		ClientIP: clientIP,
		DestPort: s.port,
		Protocol: "HTTP",
		Egress:   s.egressMode(),
		SNI:      host,
	}

	var userID int64
	username := "Unknown"
	if s.connTracker != nil {
		if uid, uname, ok := s.connTracker.LookupUser(clientIP); ok {
			userID = uid
			if uname != "" {
				username = uname
			}
		}
	}

	if s.stats != nil {
		if userID > 0 {
			s.stats.Emit("HTTP", "registered")
		} else {
			s.stats.Emit("HTTP", "unregistered")
		}
	}

	defer func() {
		_ = clientConn.Close()
		fields.Duration = time.Since(start)
		logging.LogConnection(fields)

		if s.logger != nil && s.logger.IsEnabled() {
			s.logger.Emit(requestlog.Event{
				UserID:      userID,
				Username:    username,
				ClientIP:    clientIP,
				RequestType: requestlog.TypeHTTP,
				Protocol:    "HTTP",
				Domain:      fields.SNI,
				Port:        s.port,
				Status:      fields.Status,
				Timestamp:   time.Now(),
			})
		}
	}()

	// -----------------------------------------------------------------------
	// 1. IP access control (skip if already pre-validated by frontrouter)
	// -----------------------------------------------------------------------
	if prevalidatedRule == nil {
		if allowed, status := relay.CheckClientAccess(s.accessStore, clientIP); !allowed {
			fields.Status = status
			slog.Warn("http connection rejected: access denied", "client_ip", clientIP, "status", status)
			return
		}
	}

	// -----------------------------------------------------------------------
	// 1b. Register connection in tracker
	// -----------------------------------------------------------------------
	if s.connTracker != nil {
		s.connTracker.Register(clientIP, clientConn)
		defer s.connTracker.Unregister(clientIP, clientConn)
	}

	// -----------------------------------------------------------------------
	// 2. Connection limits
	// -----------------------------------------------------------------------
	release, ok := s.limits.Acquire(clientIP)
	if !ok {
		fields.Status = "rejected_limit"
		slog.Warn("http connection rejected: limit exceeded", "client_ip", clientIP)
		return
	}
	defer release()

	// -----------------------------------------------------------------------
	// 3. HTTP Header read (if not already peeked)
	// -----------------------------------------------------------------------
	if peeked == nil {
		headerTimeout := s.cfg.Timeouts.HTTPHeader.Duration
		if headerTimeout > 0 {
			if err := clientConn.SetReadDeadline(time.Now().Add(headerTimeout)); err != nil {
				fields.Status = "error"
				slog.Error("set http read deadline", "error", err)
				return
			}
		}

		var err error
		peeked, host, err = httphost.ReadHostAndRequestLine(clientConn)
		if err != nil {
			if relay.IsTimeout(err) {
				fields.Status = "rejected_timeout"
				slog.Warn("http connection rejected: header timeout", "client_ip", clientIP)
			} else if errors.Is(err, httphost.ErrNotHTTP) {
				fields.Status = "rejected_not_http"
				slog.Warn("http connection rejected: not HTTP", "client_ip", clientIP, "error", err)
			} else if errors.Is(err, httphost.ErrNoHost) {
				fields.Status = "rejected_no_host"
				slog.Warn("http connection rejected: missing Host header", "client_ip", clientIP, "error", err)
			} else if errors.Is(err, httphost.ErrHeaderTooLarge) {
				fields.Status = "rejected_header_too_large"
				slog.Warn("http connection rejected: header too large", "client_ip", clientIP, "error", err)
			} else if errors.Is(err, httphost.ErrAmbiguousHost) {
				fields.Status = "rejected_ambiguous_host"
				slog.Warn("http connection rejected: ambiguous host", "client_ip", clientIP, "error", err)
			} else {
				fields.Status = "rejected_parse_error"
				slog.Warn("http connection rejected: parse error", "client_ip", clientIP, "error", err)
			}
			return
		}
		fields.SNI = host

		// Clear read deadline
		if err := clientConn.SetReadDeadline(time.Time{}); err != nil {
			fields.Status = "error"
			slog.Error("clear http read deadline", "error", err)
			return
		}
	}

	// -----------------------------------------------------------------------
	// 4. Domain rule check (single atomic read or use pre-validated rule)
	// -----------------------------------------------------------------------
	decision := relay.EvaluateRoute(s.ruleStore, s.allowList, host, s.port, prevalidatedRule, prevalidatedMatchInfo)
	fields.MatchedRule = decision.MatchedRule
	fields.Egress = s.resolveEgressMode(decision.RuleUseProxy)
	if !decision.Allowed {
		if decision.Status == "rejected_port" && TryHTTPSRedirect(clientConn, peeked, host, s.ruleStore) {
			fields.Status = "redirected_https"
			slog.Info("http connection redirected to https", "client_ip", clientIP, "host", host)
			return
		}
		fields.Status = decision.Status
		slog.Warn("http connection rejected: route not allowed",
			"client_ip", clientIP, "host", host, "port", s.port, "status", decision.Status, "matched_rule", fields.MatchedRule)
		return
	}

	// -----------------------------------------------------------------------
	// 5. SSRF / internal IP validation
	// -----------------------------------------------------------------------
	destIPs, reason, err := s.security.ResolveAndValidateAll(ctx, host)
	if err != nil {
		fields.Status = "rejected_dns"
		slog.Warn("http connection rejected: DNS error", "client_ip", clientIP, "host", host, "error", err)
		return
	}
	if reason != "" {
		fields.Status = "rejected_internal_target"
		slog.Warn("http connection rejected: blocked internal target",
			"client_ip", clientIP, "host", host, "reason", reason)
		return
	}
	if len(destIPs) > 0 {
		fields.DestIP = destIPs[0].String()
	}

	// -----------------------------------------------------------------------
	// 6. Dial destination
	// -----------------------------------------------------------------------
	dialFunc := relay.BuildDialer(s.customDialer, s.egressDialer, decision.RuleUseProxy)

	destConn, err := relay.DialAny(ctx, destIPs, s.port, dialFunc)
	if err != nil {
		fields.Status = "rejected_dial"
		slog.Warn("http connection rejected: dial failed", "client_ip", clientIP, "host", host, "error", err)
		return
	}
	relay.SetTCPKeepalive(destConn, s.cfg.Timeouts.TCPKeepalive.Duration)
	defer func() { _ = destConn.Close() }()

	// -----------------------------------------------------------------------
	// 7. Replay peeked bytes
	// -----------------------------------------------------------------------
	if _, err := destConn.Write(peeked); err != nil {
		fields.Status = "rejected_replay"
		slog.Warn("failed to replay HTTP request headers to destination", "error", err)
		return
	}

	fields.Status = "connected"
	slog.Info("http relay established",
		"client_ip", clientIP, "host", host, "dest", destConn.RemoteAddr().String())

	// -----------------------------------------------------------------------
	// 8. Bidirectional pipe with in-flight usage accounting
	// -----------------------------------------------------------------------
	var domainKey string
	if fields.MatchedRule == "exact" {
		domainKey = fields.SNI
	} else if fields.MatchedRule != "" && fields.MatchedRule != "none" {
		domainKey = fields.MatchedRule
	}

	onDelta := func(dSent, dRecv int64) {
		if s.usageTracker != nil && (userID > 0 || domainKey != "" || dSent > 0 || dRecv > 0) {
			s.usageTracker.EmitProtocol("HTTP", userID, domainKey, dSent, dRecv)
		}
	}

	var atomicSent, atomicReceived atomic.Int64
	atomicSent.Add(int64(len(peeked)))
	relay.Pipe(ctx, clientConn, destConn,
		s.cfg.Timeouts.Idle.Duration,
		s.cfg.Timeouts.MaxConnectionDuration.Duration,
		&atomicSent, &atomicReceived,
		onDelta,
	)

	fields.BytesSent = atomicSent.Load()
	fields.BytesReceived = atomicReceived.Load()
	fields.Status = "relayed"
}

// TryHTTPSRedirect inspects a request that matched a proxy-mode domain rule where
// the listen port was NOT allowed. If the rule allows port 443, it writes an HTTPS redirect
// response and returns true.
func TryHTTPSRedirect(conn net.Conn, peeked []byte, host string, rs *rules.RuleStore) bool {
	if rs == nil || conn == nil || host == "" {
		return false
	}

	allowed443, rule, matchInfo := rs.LookupDetailed(host, 443)
	if !matchInfo.Matched {
		return false
	}
	mode := rule.Mode
	if mode == "" {
		mode = "proxy"
	}
	if mode != "proxy" || !allowed443 {
		return false
	}

	// Parse method and target from peeked request line
	method := "GET"
	rawTarget := "/"
	if len(peeked) > 0 {
		firstLine := peeked
		if idx := bytes.IndexByte(peeked, '\n'); idx != -1 {
			firstLine = peeked[:idx]
		}
		firstLine = bytes.TrimRight(firstLine, "\r")
		parts := bytes.SplitN(firstLine, []byte(" "), 3)
		if len(parts) >= 1 && len(parts[0]) > 0 {
			method = strings.ToUpper(string(parts[0]))
		}
		if len(parts) >= 2 && len(parts[1]) > 0 {
			rawTarget = string(parts[1])
		}
	}

	target := "/"
	if strings.HasPrefix(rawTarget, "/") && len(rawTarget) <= 2048 && !strings.ContainsAny(rawTarget, "\r\n ") {
		target = rawTarget
	}

	statusCode := 308
	statusText := "Permanent Redirect"
	if method == "GET" || method == "HEAD" {
		statusCode = 301
		statusText = "Moved Permanently"
	}

	normHost := strings.ToLower(strings.TrimSpace(host))
	if h, _, err := net.SplitHostPort(normHost); err == nil {
		normHost = h
	}

	resp := fmt.Sprintf("HTTP/1.1 %d %s\r\nLocation: https://%s%s\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
		statusCode, statusText, normHost, target)

	_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_, _ = conn.Write([]byte(resp))
	_ = conn.Close()
	return true
}
