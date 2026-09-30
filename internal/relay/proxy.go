// Package relay implements the core TCP relay: accept loop, per-connection
// handling, SNI extraction, outbound dialing, and bidirectional piping.
package relay

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ixabolfazl/tls-relay/internal/access"
	"github.com/ixabolfazl/tls-relay/internal/config"
	"github.com/ixabolfazl/tls-relay/internal/logging"
	"github.com/ixabolfazl/tls-relay/internal/reqstats"
	"github.com/ixabolfazl/tls-relay/internal/requestlog"
	"github.com/ixabolfazl/tls-relay/internal/rules"
	"github.com/ixabolfazl/tls-relay/internal/sni"
)

// Server holds all shared state for a single listening TCP port.
type Server struct {
	cfg          *config.Config
	port         int
	allowList    *PortAllowList
	security     *SecurityChecker
	limits       *LimitTracker
	ruleStore    *rules.RuleStore
	accessStore  *access.AccessStore
	egressDialer *EgressDialer
	connTracker  *ConnTracker
	logger       *requestlog.Logger
	usageTracker *UsageTracker
	stats        *reqstats.Collector
	customDialer func(ctx context.Context, network, addr string) (net.Conn, error)
	connCtx      context.Context
}

// NewServer constructs a relay Server for a specific port.
func NewServer(
	cfg *config.Config,
	port int,
	allowList *PortAllowList,
	security *SecurityChecker,
	limits *LimitTracker,
	ruleStore *rules.RuleStore,
	accessStore *access.AccessStore,
	egressDialer *EgressDialer,
	connTracker *ConnTracker,
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

// SetCustomDialer sets a custom dialer function on the relay server (useful for tests).
func (s *Server) SetCustomDialer(fn func(ctx context.Context, network, addr string) (net.Conn, error)) {
	s.customDialer = fn
}

// SetConnContext sets the context used for managing active connections.
func (s *Server) SetConnContext(ctx context.Context) {
	s.connCtx = ctx
}

// SetLogger sets the request log system for the relay server.
func (s *Server) SetLogger(l *requestlog.Logger) {
	s.logger = l
}

// SetUsageTracker sets the async usage tracker for the relay server.
func (s *Server) SetUsageTracker(ut *UsageTracker) {
	s.usageTracker = ut
}

// SetStatsCollector sets the async request stats collector for the relay server.
func (s *Server) SetStatsCollector(sc *reqstats.Collector) {
	s.stats = sc
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

// ListenAndServe starts accepting connections on the configured port and blocks
// until ctx is cancelled. It uses wg to signal when all in-flight connections
// have finished (for graceful shutdown).
func (s *Server) ListenAndServe(ctx context.Context, wg *sync.WaitGroup) error {
	addr := fmt.Sprintf("%s:%d", s.cfg.Listen.Addr, s.port)
	lc := net.ListenConfig{}
	ln, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", addr, err)
	}
	return s.Serve(ctx, ln, wg)
}

// Serve accepts connections on ln until ctx is cancelled.
func (s *Server) Serve(ctx context.Context, ln net.Listener, wg *sync.WaitGroup) error {
	slog.Info("relay listening", "addr", ln.Addr().String())

	// Close the listener when ctx is cancelled to unblock Accept.
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				// Listener was closed due to context cancellation — expected.
				return nil
			}
			slog.Error("accept error", "error", err)
			continue
		}

		// Enable OS-level TCP keepalive so dead network connections are detected
		// faster than the idle timeout, preventing ghost-online presence entries.
		SetTCPKeepalive(conn, s.cfg.Timeouts.TCPKeepalive.Duration)

		connCtx := s.connCtx
		if connCtx == nil {
			connCtx = ctx
		}

		if wg != nil {
			wg.Add(1)
		}
		go func() {
			if wg != nil {
				defer wg.Done()
			}
			s.handleConn(connCtx, conn)
		}()
	}
}

// handleConn manages the full lifecycle of a single client connection.
func (s *Server) handleConn(ctx context.Context, clientConn net.Conn) {
	start := time.Now()
	clientIP := ExtractIP(clientConn.RemoteAddr().String())

	fields := logging.ConnFields{
		ClientIP: clientIP,
		DestPort: s.port,
		Egress:   s.egressMode(),
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
			s.stats.Emit("TLS", "registered")
		} else {
			s.stats.Emit("TLS", "unregistered")
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
				RequestType: requestlog.TypeTLS,
				Protocol:    "TLS",
				Domain:      fields.SNI,
				Port:        s.port,
				Status:      fields.Status,
				Timestamp:   time.Now(),
			})
		}
	}()

	// -----------------------------------------------------------------------
	// 1. IP access control — check before anything else to reject blocked IPs
	//    with minimal resource use (before reading the ClientHello).
	// -----------------------------------------------------------------------
	if s.accessStore != nil {
		ip := net.ParseIP(clientIP)
		if ip == nil {
			fields.Status = "rejected_ip_invalid"
			slog.Warn("connection rejected: invalid client IP", "client_ip", clientIP)
			return
		}
		allowed, reason := s.accessStore.CheckAccess(ip)
		if !allowed {
			fields.Status = "rejected_" + reason
			slog.Warn("connection rejected: access denied",
				"client_ip", clientIP, "reason", reason,
				"mode", string(s.accessStore.Mode()))
			return
		}
	}

	// -----------------------------------------------------------------------
	// 1b. Register connection in the tracker so it can be forcibly closed if
	//     the user is disabled/deleted while the relay is active.
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
		slog.Warn("connection rejected: limit exceeded", "client_ip", clientIP)
		return
	}
	defer release()

	// -----------------------------------------------------------------------
	// 3. ClientHello read timeout
	// -----------------------------------------------------------------------
	helloTimeout := s.cfg.Timeouts.ClientHello.Duration
	if helloTimeout > 0 {
		if err := clientConn.SetReadDeadline(time.Now().Add(helloTimeout)); err != nil {
			fields.Status = "error"
			slog.Error("set deadline", "error", err)
			return
		}
	}

	peeked, hostname, err := sni.ReadSNI(clientConn)
	if err != nil {
		if IsTimeout(err) {
			fields.Status = "rejected_timeout"
			slog.Warn("connection rejected: ClientHello timeout", "client_ip", clientIP)
		} else if errors.Is(err, sni.ErrNotTLS) || errors.Is(err, sni.ErrNoSNI) {
			fields.Status = "rejected_no_sni"
			slog.Warn("connection rejected: no SNI", "client_ip", clientIP, "error", err)
		} else {
			fields.Status = "rejected_parse_error"
			slog.Warn("connection rejected: parse error", "client_ip", clientIP, "error", err)
		}
		return
	}

	hostname = strings.ToLower(strings.TrimSuffix(hostname, "."))
	if isInvalidSNI(hostname) {
		fields.SNI = hostname
		fields.Status = "rejected_bad_sni"
		slog.Warn("connection rejected: bad SNI", "client_ip", clientIP, "sni", hostname)
		return
	}
	fields.SNI = hostname

	// Clear the read deadline so it doesn't interfere with the relay.
	if err := clientConn.SetReadDeadline(time.Time{}); err != nil {
		fields.Status = "error"
		slog.Error("clear deadline", "error", err)
		return
	}

	// -----------------------------------------------------------------------
	// 4. Domain rule check & Mode validation (single atomic read)
	// -----------------------------------------------------------------------
	ruleUseProxy := "default"
	if s.ruleStore != nil {
		allowed, rule, matchInfo := s.ruleStore.LookupDetailed(hostname, s.port)
		if matchInfo.Kind == "exact" {
			fields.MatchedRule = "exact"
		} else if matchInfo.Kind == "wildcard" {
			fields.MatchedRule = matchInfo.Rule
		} else {
			fields.MatchedRule = "none"
		}

		if matchInfo.Matched {
			ruleUseProxy = rule.UseEgressProxy
			fields.Egress = s.resolveEgressMode(ruleUseProxy)

			switch rule.Mode {
			case "block":
				fields.Status = "rejected_domain_blocked"
				slog.Warn("connection rejected: domain in block mode", "client_ip", clientIP, "sni", hostname)
				return
			case "direct":
				fields.Status = "rejected_direct_mode"
				slog.Warn("connection rejected: domain in direct mode", "client_ip", clientIP, "sni", hostname)
				return
			}

			if !allowed {
				fields.Status = "rejected_port"
				slog.Warn("connection rejected: port not allowed by domain rule",
					"client_ip", clientIP, "sni", hostname, "port", s.port, "matched_rule", fields.MatchedRule)
				return
			}
			// Explicit rule allows — skip the global port allow-list check.
		} else {
			fields.Egress = s.resolveEgressMode(ruleUseProxy)
			// No rule matches — apply unknown_domain_policy.
			if !s.ruleStore.IsPortAllowedByPolicy(s.port) {
				fields.Status = "rejected_domain"
				slog.Warn("connection rejected: domain not in rules and policy is reject",
					"client_ip", clientIP, "sni", hostname)
				return
			}
			// Policy is allow_default_port — fall through to global allow-list check.
			if !s.allowList.Allowed(s.port) {
				fields.Status = "rejected_port"
				slog.Warn("connection rejected: port not in global allow-list (fallback)",
					"client_ip", clientIP, "port", s.port)
				return
			}
		}
	} else {
		fields.MatchedRule = "none"
		fields.Egress = s.resolveEgressMode(ruleUseProxy)
		// No rule store configured — use the global port allow-list (v1 behaviour).
		if !s.allowList.Allowed(s.port) {
			fields.Status = "rejected_port"
			slog.Warn("connection rejected: port not in allow-list", "client_ip", clientIP, "port", s.port)
			return
		}
	}

	// -----------------------------------------------------------------------
	// 5. SSRF / internal IP validation
	// -----------------------------------------------------------------------
	destIPs, reason, err := s.security.ResolveAndValidateAll(ctx, hostname)
	if err != nil {
		fields.Status = "rejected_dns"
		slog.Warn("connection rejected: DNS error", "client_ip", clientIP, "sni", hostname, "error", err)
		return
	}
	if reason != "" {
		fields.Status = "rejected_internal_target"
		slog.Warn("connection rejected: blocked internal target",
			"client_ip", clientIP, "sni", hostname, "reason", reason)
		return
	}
	if len(destIPs) > 0 {
		fields.DestIP = destIPs[0].String()
	}

	// -----------------------------------------------------------------------
	// 6. Dial destination (by validated IP to prevent DNS rebinding)
	// -----------------------------------------------------------------------
	dialFunc := func(dCtx context.Context, network, addr string) (net.Conn, error) {
		if s.egressDialer != nil {
			return s.egressDialer.DialContextWithOverride(dCtx, network, addr, ruleUseProxy)
		}
		if s.customDialer != nil {
			return s.customDialer(dCtx, network, addr)
		}
		var dialer net.Dialer
		return dialer.DialContext(dCtx, network, addr)
	}

	destConn, err := DialAny(ctx, destIPs, s.port, dialFunc)
	if err != nil {
		fields.Status = "rejected_dial"
		slog.Warn("connection rejected: dial failed", "client_ip", clientIP, "sni", hostname, "error", err)
		return
	}
	// Apply TCP keepalive on directly-dialed destination connections too.
	// Skip for SOCKS5-proxied connections: the conn is not a *net.TCPConn
	// when routed through a SOCKS5 proxy, so the type assertion is a no-op.
	SetTCPKeepalive(destConn, s.cfg.Timeouts.TCPKeepalive.Duration)
	defer func() { _ = destConn.Close() }()

	// -----------------------------------------------------------------------
	// 7. Replay peeked bytes to destination before starting bidirectional pipe
	// -----------------------------------------------------------------------
	if _, err := destConn.Write(peeked); err != nil {
		fields.Status = "rejected_replay"
		slog.Warn("failed to replay ClientHello to destination", "error", err)
		return
	}

	fields.Status = "connected"
	slog.Info("relay established",
		"client_ip", clientIP, "sni", hostname, "dest", destConn.RemoteAddr().String())

	// -----------------------------------------------------------------------
	// 8. Bidirectional pipe with idle + max-duration timeouts & in-flight usage accounting
	// -----------------------------------------------------------------------
	var domainKey string
	if fields.MatchedRule == "exact" {
		domainKey = fields.SNI
	} else if fields.MatchedRule != "" && fields.MatchedRule != "none" {
		domainKey = fields.MatchedRule
	}

	onDelta := func(dSent, dRecv int64) {
		if s.usageTracker != nil && (userID > 0 || domainKey != "" || dSent > 0 || dRecv > 0) {
			s.usageTracker.EmitProtocol("TLS", userID, domainKey, dSent, dRecv)
		}
	}

	var atomicSent, atomicReceived atomic.Int64
	atomicSent.Add(int64(len(peeked)))
	Pipe(ctx, clientConn, destConn,
		s.cfg.Timeouts.Idle.Duration,
		s.cfg.Timeouts.MaxConnectionDuration.Duration,
		&atomicSent, &atomicReceived,
		onDelta,
	)

	fields.BytesSent = atomicSent.Load()
	fields.BytesReceived = atomicReceived.Load()
	fields.Status = "relayed"
}

// HalfCloseTimeout is the maximum duration to wait for the other direction after clean EOF.
var HalfCloseTimeout = 60 * time.Second
var halfCloseMu sync.RWMutex

func getHalfCloseTimeout() time.Duration {
	halfCloseMu.RLock()
	defer halfCloseMu.RUnlock()
	return HalfCloseTimeout
}

// SetHalfCloseTimeout safely updates HalfCloseTimeout.
func SetHalfCloseTimeout(d time.Duration) {
	halfCloseMu.Lock()
	defer halfCloseMu.Unlock()
	HalfCloseTimeout = d
}

// Pipe runs a bidirectional copy between client and dest, enforcing idle and
// max-duration timeouts. It blocks until both directions are done.
func Pipe(
	ctx context.Context,
	client, dest net.Conn,
	idleTimeout, maxDuration time.Duration,
	bytesSent, bytesReceived *atomic.Int64,
	onProgress ...func(sentDelta, recvDelta int64),
) {
	var progressCb func(sentDelta, recvDelta int64)
	if len(onProgress) > 0 {
		progressCb = onProgress[0]
	}

	var closeOnce sync.Once
	closeBoth := func() {
		closeOnce.Do(func() {
			_ = client.Close()
			_ = dest.Close()
		})
	}

	// MaxConnectionDuration enforced via time.AfterFunc, not SetDeadline.
	if maxDuration > 0 {
		timer := time.AfterFunc(maxDuration, closeBoth)
		defer timer.Stop()
	}

	var lastActivity atomic.Int64
	lastActivity.Store(time.Now().UnixNano())

	ctxDone := make(chan struct{})
	// If context is cancelled (shutdown), close both connections immediately.
	go func() {
		select {
		case <-ctx.Done():
			closeBoth()
		case <-ctxDone:
		}
	}()

	var wg sync.WaitGroup
	wg.Add(2)

	copyDir := func(dst, src net.Conn, counter *atomic.Int64, halfClose func()) {
		defer wg.Done()
		bufPtr := copyBufPool.Get().(*[]byte)
		defer copyBufPool.Put(bufPtr)
		buf := *bufPtr

		for {
			if idleTimeout > 0 {
				_ = src.SetReadDeadline(time.Now().Add(idleTimeout))
			}

			nr, readErr := src.Read(buf)
			if nr > 0 {
				lastActivity.Store(time.Now().UnixNano())
				if idleTimeout > 0 {
					_ = dst.SetWriteDeadline(time.Now().Add(idleTimeout))
				}
				nw, writeErr := dst.Write(buf[:nr])
				if nw > 0 {
					lastActivity.Store(time.Now().UnixNano())
					if counter != nil {
						counter.Add(int64(nw))
					}
				}
				if writeErr != nil {
					closeBoth()
					return
				}
			}

			if readErr != nil {
				if readErr == io.EOF {
					halfClose()
					time.AfterFunc(getHalfCloseTimeout(), closeBoth)
					return
				}

				if IsTimeout(readErr) && idleTimeout > 0 {
					last := time.Unix(0, lastActivity.Load())
					if time.Since(last) < idleTimeout {
						// Other direction was active recently: re-arm and continue
						continue
					}
				}

				// Non-EOF error (reset, real timeout, etc.) closes both immediately
				closeBoth()
				return
			}
		}
	}

	// client → destination
	go copyDir(dest, client, bytesSent, func() {
		if tc, ok := dest.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		} else if cw, ok := dest.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	})

	// destination → client
	go copyDir(client, dest, bytesReceived, func() {
		if tc, ok := client.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		} else if cw, ok := client.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	})

	tickerDone := make(chan struct{})
	if progressCb != nil {
		go func() {
			ticker := time.NewTicker(3 * time.Second)
			defer ticker.Stop()
			var lastSent, lastRecv int64
			for {
				select {
				case <-ticker.C:
					curSent := bytesSent.Load()
					curRecv := bytesReceived.Load()
					dSent := curSent - lastSent
					dRecv := curRecv - lastRecv
					if dSent > 0 || dRecv > 0 {
						lastSent = curSent
						lastRecv = curRecv
						progressCb(dSent, dRecv)
					}
				case <-tickerDone:
					curSent := bytesSent.Load()
					curRecv := bytesReceived.Load()
					dSent := curSent - lastSent
					dRecv := curRecv - lastRecv
					if dSent > 0 || dRecv > 0 {
						progressCb(dSent, dRecv)
					}
					return
				}
			}
		}()
	}

	wg.Wait()
	close(ctxDone)
	closeBoth()
	if progressCb != nil {
		close(tickerDone)
	}
}

// copyBufPool recycles 32 KiB buffers for bidirectional connection piping,
// drastically reducing heap allocations and GC pressure under high connection concurrency.
var copyBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 32*1024)
		return &b
	},
}

// CopyWithIdle copies from src to dst, resetting the read deadline after each
// read to implement the per-connection idle timeout. If counter is provided,
// it atomically increments counter as data is transferred.
func CopyWithIdle(dst, src net.Conn, idleTimeout time.Duration, counter ...*atomic.Int64) (int64, error) {
	var atomicCounter *atomic.Int64
	if len(counter) > 0 {
		atomicCounter = counter[0]
	}

	bufPtr := copyBufPool.Get().(*[]byte)
	defer copyBufPool.Put(bufPtr)
	buf := *bufPtr

	var total int64
	for {
		if idleTimeout > 0 {
			_ = src.SetReadDeadline(time.Now().Add(idleTimeout))
		}

		nr, readErr := src.Read(buf)
		if nr > 0 {
			if idleTimeout > 0 {
				_ = dst.SetWriteDeadline(time.Now().Add(idleTimeout))
			}
			nw, writeErr := dst.Write(buf[:nr])
			if nw > 0 {
				total += int64(nw)
				if atomicCounter != nil {
					atomicCounter.Add(int64(nw))
				}
			}
			if writeErr != nil {
				return total, writeErr
			}
		}
		if readErr != nil {
			if readErr == io.EOF {
				return total, nil
			}
			return total, readErr
		}
	}
}

// ExtractIP strips the port from a host:port remote address string and normalizes to canonical IP.
func ExtractIP(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	host = strings.TrimSpace(host)
	if parsed := net.ParseIP(host); parsed != nil {
		if v4 := parsed.To4(); v4 != nil {
			return v4.String()
		}
		return parsed.String()
	}
	return host
}

// IsTimeout returns true if the error is a net timeout.
func IsTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

// SetTCPKeepalive enables OS-level TCP keepalive on conn if it is a *net.TCPConn
// and the period is non-zero. This causes the OS to detect and report dead
// connections faster than the relay's idle timeout, so Unregister() is called
// promptly and ghost-online presence entries are cleaned up.
func SetTCPKeepalive(conn net.Conn, period time.Duration) {
	if period <= 0 {
		return
	}
	tc, ok := conn.(*net.TCPConn)
	if !ok {
		return
	}
	_ = tc.SetKeepAlive(true)
	_ = tc.SetKeepAlivePeriod(period)
}

func isInvalidSNI(s string) bool {
	if s == "" || len(s) > 253 {
		return true
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c == 0x7f || c == ' ' || c == '/' || c == '\\' {
			return true
		}
	}
	return false
}
