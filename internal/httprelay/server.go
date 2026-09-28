// Package httprelay implements plain-HTTP stream relaying mirroring the TLS relay pipeline.
package httprelay

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
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

		wg.Add(1)
		go func() {
			defer wg.Done()
			s.HandleConn(ctx, conn, nil, "")
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
	if prevalidatedRule == nil && s.accessStore != nil {
		ip := net.ParseIP(clientIP)
		if ip == nil {
			fields.Status = "rejected_ip_invalid"
			slog.Warn("http connection rejected: invalid client IP", "client_ip", clientIP)
			return
		}
		allowed, reason := s.accessStore.CheckAccess(ip)
		if !allowed {
			fields.Status = "rejected_" + reason
			slog.Warn("http connection rejected: access denied",
				"client_ip", clientIP, "reason", reason,
				"mode", string(s.accessStore.Mode()))
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
	ruleUseProxy := "default"
	if prevalidatedRule != nil && prevalidatedMatchInfo != nil {
		ruleUseProxy = prevalidatedRule.UseEgressProxy
		if prevalidatedMatchInfo.Kind == "exact" {
			fields.MatchedRule = "exact"
		} else if prevalidatedMatchInfo.Kind == "wildcard" {
			fields.MatchedRule = prevalidatedMatchInfo.Rule
		} else {
			fields.MatchedRule = "none"
		}
	} else if s.ruleStore != nil {
		allowed, rule, matchInfo := s.ruleStore.LookupDetailed(host, s.port)
		if matchInfo.Kind == "exact" {
			fields.MatchedRule = "exact"
		} else if matchInfo.Kind == "wildcard" {
			fields.MatchedRule = matchInfo.Rule
		} else {
			fields.MatchedRule = "none"
		}

		if matchInfo.Matched {
			ruleUseProxy = rule.UseEgressProxy
			switch rule.Mode {
			case "block":
				fields.Egress = s.resolveEgressMode(ruleUseProxy)
				fields.Status = "rejected_domain_blocked"
				slog.Warn("http connection rejected: domain in block mode", "client_ip", clientIP, "host", host)
				return
			case "direct":
				fields.Egress = s.resolveEgressMode(ruleUseProxy)
				fields.Status = "rejected_direct_mode"
				slog.Warn("http connection rejected: domain in direct mode", "client_ip", clientIP, "host", host)
				return
			}

			if !allowed {
				fields.Egress = s.resolveEgressMode(ruleUseProxy)
				fields.Status = "rejected_port"
				slog.Warn("http connection rejected: port not allowed by domain rule",
					"client_ip", clientIP, "host", host, "port", s.port, "matched_rule", fields.MatchedRule)
				return
			}
		} else {
			// Unmatched domain on standalone HTTP listener
			fields.Egress = s.resolveEgressMode(ruleUseProxy)
			if !s.ruleStore.IsPortAllowedByPolicy(s.port) {
				fields.Status = "rejected_domain"
				slog.Warn("http connection rejected: domain not in rules and policy is reject",
					"client_ip", clientIP, "host", host)
				return
			}
			if !s.allowList.Allowed(s.port) {
				fields.Status = "rejected_port"
				slog.Warn("http connection rejected: port not in global allow-list (fallback)",
					"client_ip", clientIP, "port", s.port)
				return
			}
		}
	} else {
		fields.MatchedRule = "none"
		fields.Egress = s.resolveEgressMode(ruleUseProxy)
		if !s.allowList.Allowed(s.port) {
			fields.Status = "rejected_port"
			slog.Warn("http connection rejected: port not in allow-list", "client_ip", clientIP, "port", s.port)
			return
		}
	}
	fields.Egress = s.resolveEgressMode(ruleUseProxy)

	// -----------------------------------------------------------------------
	// 5. SSRF / internal IP validation
	// -----------------------------------------------------------------------
	destIP, reason, err := s.security.ResolveAndValidate(host)
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
	fields.DestIP = destIP.String()

	// -----------------------------------------------------------------------
	// 6. Dial destination
	// -----------------------------------------------------------------------
	dialAddr := relay.AddrForIP(destIP, s.port)
	var destConn net.Conn
	if s.customDialer != nil {
		destConn, err = s.customDialer(ctx, "tcp", dialAddr)
	} else if s.egressDialer != nil {
		destConn, err = s.egressDialer.DialContextWithOverride(ctx, "tcp", dialAddr, ruleUseProxy)
	} else {
		var dialer net.Dialer
		destConn, err = dialer.DialContext(ctx, "tcp", dialAddr)
	}
	if err != nil {
		fields.Status = "rejected_dial"
		slog.Warn("http connection rejected: dial failed", "client_ip", clientIP, "host", host, "addr", dialAddr, "error", err)
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
		"client_ip", clientIP, "host", host, "dest", dialAddr)

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
	fields.Status = "closed"
}
